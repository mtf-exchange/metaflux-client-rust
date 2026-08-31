//! WS frame-compression negotiation, end to end against a local server.
//!
//! There is no live endpoint that compresses yet, so the binary frames here are
//! GOLDEN BYTES: one real `l2_book` frame compressed by the `zstd` tool at
//! level 3, with and without the shipped dictionary. Decoding bytes an
//! independent zstd produced is what proves cross-implementation compatibility.
//!
//! The three cases are the whole contract:
//!
//! 1. A server that grants no subprotocol keeps the plain text stream.
//! 2. `mtf-zstd.v1` decodes binary frames with no dictionary.
//! 3. `mtf-zstd.v1.de3e136e4` decodes binary frames with the shipped dictionary.

use std::time::Duration;

use metaflux_client::{
    types::MarketId,
    ws::{WsClient, WsConfig, WsMessage},
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;

/// The offer this SDK sends. Pinned here because it is the wire contract the
/// gateway and the other SDKs match against.
const OFFER: &str = "mtf-zstd.v1.de3e136e4,mtf-zstd.v1";

/// The `l2_book` golden frame, compressed at level 3 with the shipped
/// dictionary `e3e136e4`.
const GOLDEN_DICT: &str = "28b52ffd6766103d2c48056d070043050b6d3865100319d2b9271be2a5921d968db616f374af5749a9b9d7d467a6f5368914abeceece6e55d79d7c5f3356fc6902cf086d5c739905b36b3020ad4285253c813e45db7067041b4e8fe048a5774b51aca856abb81f909cd71a0dd33be0466154adb862c989d42b2e94e7b2537a35d06aa9a6d05a666c0026fcca278b0286a0ed5a060aa6ce77e75fef42e8006e6e1ca92a8289cd6e309b3b87f5257ff6b939442cbad39c262e6bf1767d180791651b69c79cf668a51c56ba1dcf00f7f05eb842e4b9328dbc255a25b06c7f0e823d12eba9a49984decc5dc51ec8ac69519232c5e039f71a4ee4db414020e2d6d1";

/// The SAME `l2_book` frame, compressed at level 3 with no dictionary.
const GOLDEN_NODICT: &str = "28b52ffd6448053d0a0086d031206069d3068873e81bc5b69ee8b67d7b7f15c183d34864f7d2ca04d99082208a0b2e00250023005f5760fcd8fa7287c1b0de284942a2fc3c4000e0ebcb8249dcb18e3410829f1730cc00e294af2bc9b2208ac41d017b880c71916254d8ab144a978c34331173a6354a5494cee3aab60aa5af2f343f37b4a9bc01a8ac8f53e7a566b5568bc89dcab896964d53fb1c58f77637790f7b53ea4d8758d9d9a98f04e1a0b1de60140d03591a44b3f8796c6eeb6132e6b5f5c460d1f8391c5a55715e4a3cd5acb075395d3320d0626a460f0d4b8624e4b0899c14f0df8334c821cb1d741dcef21892241945876c72a80fe4f040eab0511943a27588e91814a8a77cd461c1819fc4c43a64cc81e73a7cc6613cf24507aed78cf3c21b3f3b44d5e408c5217b31620fc89118b5bdc9611c8f9a518b0189a725477dd48f1a463d1ff10e81335b9a851920e2d6d1";

/// A plain text frame with the same envelope shape.
const TEXT_FRAME: &str =
    r#"{"channel":"l2_book","data":{"coin":"BTC","levels":[[],[]],"time":1},"is_snapshot":true}"#;

/// Accept connections forever. Answer with `echo` when the client offered it,
/// then send `payload` once the client has sent its subscribe frame. Every
/// offered `Sec-WebSocket-Protocol` header goes back over the returned channel.
// `ErrorResponse` is a whole HTTP response; the handshake callback's signature
// is tungstenite's, not ours.
#[allow(clippy::result_large_err)]
fn spawn_server(
    listener: TcpListener,
    echo: Option<&'static str>,
    payload: Message,
) -> mpsc::UnboundedReceiver<Option<String>> {
    let (offers_tx, offers_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let offers_tx = offers_tx.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                let callback =
                    move |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
                        let offered = req
                            .headers()
                            .get(SEC_WEBSOCKET_PROTOCOL)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let _ = offers_tx.send(offered.clone());
                        let selected = echo.filter(|token| {
                            offered
                                .as_deref()
                                .is_some_and(|o| o.split(',').any(|t| t.trim() == *token))
                        });
                        if let Some(token) = selected {
                            resp.headers_mut()
                                .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static(token));
                        }
                        Ok(resp)
                    };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(sock, callback).await else {
                    return;
                };
                use futures_util::{SinkExt, StreamExt};
                while let Some(Ok(msg)) = ws.next().await {
                    if let Message::Text(text) = msg {
                        if text.contains("subscribe") && ws.send(payload.clone()).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    offers_rx
}

fn config() -> WsConfig {
    WsConfig {
        ping_interval: Duration::from_secs(30),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(100),
        channel_capacity: 64,
        post_timeout: Duration::from_secs(5),
    }
}

/// Connect, subscribe, and return the first `l2_book` frame the client yields.
async fn first_l2_book(url: String) -> (WsClient, serde_json::Value, bool) {
    let client = WsClient::connect_with(url, config()).await.unwrap();
    let mut rx = client.messages();
    client.subscribe_l2_book(MarketId(1)).await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a frame must arrive")
        .expect("broadcast is live");
    let WsMessage::L2Book(data) = frame.message else {
        panic!("expected an l2_book frame, got {:?}", frame.message);
    };
    (client, data, frame.is_snapshot)
}

/// THE COMPATIBILITY RULE. A server that grants no subprotocol must keep
/// serving plain text, exactly as before compression existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_subprotocol_server_still_streams_text() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut offers = spawn_server(listener, None, Message::Text(TEXT_FRAME.to_owned()));

    let (client, data, is_snapshot) = first_l2_book(format!("ws://{addr}")).await;
    assert_eq!(data["coin"], "BTC");
    assert!(is_snapshot);

    let mut seen = Vec::new();
    while let Ok(offer) = offers.try_recv() {
        seen.push(offer);
    }
    assert!(
        seen.contains(&Some(OFFER.to_owned())),
        "the client must offer compression: {seen:?}"
    );
    assert!(
        seen.contains(&None),
        "a refused offer must be retried without one: {seen:?}"
    );
    client.shutdown().await;
}

/// `mtf-zstd.v1`: binary frames decode with no dictionary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zstd_binary_frames_decode_without_a_dictionary() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let golden = Message::Binary(hex::decode(GOLDEN_NODICT).unwrap());
    let _offers = spawn_server(listener, Some("mtf-zstd.v1"), golden);

    let (client, data, is_snapshot) = first_l2_book(format!("ws://{addr}")).await;
    assert_eq!(data["coin"], "BTC");
    assert_eq!(data["levels"][0].as_array().unwrap().len(), 20);
    assert_eq!(data["levels"][1][0]["px"], "78696.5");
    assert!(is_snapshot);
    client.shutdown().await;
}

/// `mtf-zstd.v1.de3e136e4`: binary frames decode with the shipped dictionary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zstd_binary_frames_decode_with_the_shipped_dictionary() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let golden = Message::Binary(hex::decode(GOLDEN_DICT).unwrap());
    let _offers = spawn_server(listener, Some("mtf-zstd.v1.de3e136e4"), golden);

    let (client, data, is_snapshot) = first_l2_book(format!("ws://{addr}")).await;
    assert_eq!(data["coin"], "BTC");
    assert_eq!(data["levels"][0].as_array().unwrap().len(), 20);
    assert_eq!(data["levels"][1][0]["px"], "78696.5");
    assert!(is_snapshot);
    client.shutdown().await;
}
