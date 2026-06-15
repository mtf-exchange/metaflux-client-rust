//! WS `post` request/response integration test.
//!
//! Spins up a local WS server that speaks the node's HL-style `post` protocol
//! (`{method:"post",id,request:{type,payload}}` →
//! `{channel:"post",data:{id,response:{type,payload}}}`) and exercises the
//! [`WsClient`] post path:
//!
//! 1. A typed `submit_order` over WS decodes the `OrderResponse`, and the
//!    payload the server received carries a valid EIP-712 signature that
//!    recovers to the wallet address — proving the WS action path signs the
//!    SAME digest as `POST /exchange`.
//! 2. A `post_info` read round-trips its payload.
//! 3. A node `{type:"error"}` reply surfaces as [`ClientError::WebSocket`]
//!    without dropping the connection.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use metaflux_client::{
    ClientError,
    rest::exchange::_recover_for_test,
    rest::exchange_typed::_typed_trade_digest_for_test,
    types::{
        MarketId,
        order::{Order, OrderKind, Side, StpMode, TimeInForce},
    },
    wallet::{Signature, TypedTradingAction, Wallet},
    ws::{WsClient, WsConfig},
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

fn sample_wallet() -> Wallet {
    Wallet::from_hex("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899").unwrap()
}

fn decode_sig(hex_str: &str) -> Signature {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).unwrap();
    assert_eq!(bytes.len(), 65);
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..64]);
    Signature { r, s, v: bytes[64] }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_post_action_info_and_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}");

    // Captured `action` payloads (the {signature,nonce,action} envelopes) the
    // mock server received, so the test can verify the signature.
    let (captured_tx, mut captured_rx) = mpsc::unbounded_channel::<Value>();

    // Mock node speaking the `post` protocol. Accepts the SDK's connect-probe
    // (immediately dropped) plus the real background connection.
    tokio::spawn(async move {
        let mut accepts = 0u32;
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            accepts += 1;
            let captured_tx = captured_tx.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(sock).await else {
                    return;
                };
                let deadline = tokio::time::sleep(Duration::from_secs(5));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => {
                            let _ = ws.send(Message::Close(None)).await;
                            return;
                        }
                        msg = ws.next() => match msg {
                            Some(Ok(Message::Text(t))) => {
                                let txt = t.to_string();
                                let Ok(v) = serde_json::from_str::<Value>(&txt) else { continue };
                                if v.get("method").and_then(Value::as_str) != Some("post") {
                                    continue;
                                }
                                let id = v.pointer("/id").and_then(Value::as_u64).unwrap_or(0);
                                let req = v.get("request").cloned().unwrap_or(Value::Null);
                                let rtype =
                                    req.get("type").and_then(Value::as_str).unwrap_or("").to_string();
                                let payload = req.get("payload").cloned().unwrap_or(Value::Null);

                                let response = match rtype.as_str() {
                                    "action" => {
                                        let _ = captured_tx.send(payload.clone());
                                        json!({
                                            "type": "action",
                                            "payload": {
                                                "statuses": [
                                                    { "resting": { "oid": 1234, "cloid": "0x000102030405060708090a0b0c0d0e0f" } }
                                                ]
                                            }
                                        })
                                    }
                                    "info" => {
                                        if payload.get("type").and_then(Value::as_str) == Some("boom") {
                                            json!({ "type": "error", "payload": "boom: not a real info type" })
                                        } else {
                                            json!({ "type": "info", "payload": { "echo": payload } })
                                        }
                                    }
                                    _ => json!({ "type": "error", "payload": "unknown request type" }),
                                };
                                let frame = json!({
                                    "channel": "post",
                                    "data": { "id": id, "response": response },
                                });
                                let _ = ws.send(Message::Text(frame.to_string())).await;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(_)) | None => return,
                        }
                    }
                }
            });
            if accepts >= 4 {
                return;
            }
        }
    });

    let client = WsClient::connect_with(
        url,
        WsConfig {
            post_timeout: Duration::from_secs(5),
            ..WsConfig::default()
        },
    )
    .await
    .unwrap();

    let wallet = sample_wallet();

    // 1. Typed submit_order over WS.
    let order = Order {
        owner: wallet.address(),
        market: MarketId(1),
        side: Side::Bid,
        kind: OrderKind::Limit,
        size: 1000,
        limit_px: 5_000_000_000_000,
        tif: TimeInForce::Gtc,
        stp_mode: StpMode::CancelOldest,
        reduce_only: false,
        cloid: None,
        builder: None,
        position_side: None,
        trigger: None,
    };
    let resp = client.submit_order(&wallet, &order).await.unwrap();
    assert_eq!(resp.statuses.len(), 1, "one resting status");

    // The server captured the signed envelope — verify the signature recovers
    // to the wallet, exactly like the REST `/exchange` path.
    let payload = captured_rx.recv().await.expect("server captured an action");
    let action = payload.get("action").cloned().expect("payload.action");
    let nonce = payload
        .get("nonce")
        .and_then(Value::as_u64)
        .expect("payload.nonce");
    let sig_hex = payload
        .get("signature")
        .and_then(Value::as_str)
        .expect("payload.signature");
    assert_eq!(
        action.get("type").and_then(Value::as_str),
        Some("submit_order")
    );
    assert_eq!(
        payload.get("sig_scheme").and_then(Value::as_str),
        Some("typed"),
        "WS trading actions must sign under sig_scheme=typed"
    );
    let digest = _typed_trade_digest_for_test(TypedTradingAction::SubmitOrder(&order), nonce);
    let recovered = _recover_for_test(&digest, &decode_sig(sig_hex)).expect("recover");
    assert_eq!(
        recovered,
        wallet.address(),
        "WS post action must sign the same typed EIP-712 digest as REST"
    );

    // 2. post_info round-trips its payload through the echo.
    let info = client
        .post_info(json!({ "type": "node_info" }))
        .await
        .unwrap();
    assert_eq!(
        info.pointer("/echo/type").and_then(Value::as_str),
        Some("node_info"),
        "info payload should echo back"
    );

    // 3. A node error reply surfaces as a WebSocket error (connection stays up).
    let err = client
        .post_info(json!({ "type": "boom" }))
        .await
        .expect_err("error reply should map to Err");
    match err {
        ClientError::WebSocket(m) => assert!(m.contains("boom"), "got: {m}"),
        other => panic!("expected WebSocket error, got {other:?}"),
    }
}

/// A `post` whose response never arrives (socket stays open) fails with a
/// timeout — exercising the `CancelPost` cleanup path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_post_times_out_when_node_never_replies() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}");

    // Accept + read frames, but never send a post response, and keep the socket
    // open so the client hits the post timeout (not a disconnect).
    tokio::spawn(async move {
        let mut accepts = 0u32;
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            accepts += 1;
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(sock).await else {
                    return;
                };
                let deadline = tokio::time::sleep(Duration::from_secs(3));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => {
                            let _ = ws.send(Message::Close(None)).await;
                            return;
                        }
                        msg = ws.next() => match msg {
                            Some(Ok(_)) => { /* swallow; deliberately never reply */ }
                            Some(Err(_)) | None => return,
                        }
                    }
                }
            });
            if accepts >= 4 {
                return;
            }
        }
    });

    let client = WsClient::connect_with(
        url,
        WsConfig {
            post_timeout: Duration::from_millis(200),
            ..WsConfig::default()
        },
    )
    .await
    .unwrap();

    let err = client
        .post_info(json!({ "type": "node_info" }))
        .await
        .expect_err("should time out");
    match err {
        ClientError::WebSocket(m) => assert!(m.contains("timed out"), "got: {m}"),
        other => panic!("expected WebSocket timeout, got {other:?}"),
    }
}
