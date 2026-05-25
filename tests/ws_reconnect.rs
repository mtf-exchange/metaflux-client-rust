//! WS reconnect-with-backoff integration test.
//!
//! Strategy:
//! 1. Spin up a local TCP listener that accepts ONE WS connection then drops.
//! 2. Connect a [`WsClient`] to it; subscribe to a stream.
//! 3. The listener's second iteration accepts a fresh connection — the SDK
//!    should have reconnected with backoff and re-sent the subscribe frame.
//! 4. Assert the re-sent subscribe frame matches the original.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use metaflux_client::{
    types::MarketId,
    ws::{WsClient, WsConfig},
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_reconnects_and_replays_subscriptions() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}");

    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<String>();

    // Spawn a listener task that accepts connections, reads frames, then
    // drops the connection after one second — forcing the client to reconnect.
    let server_task = tokio::spawn(async move {
        let mut accepts: u32 = 0;
        loop {
            // Accept up to 3 connections then bail.
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            accepts += 1;
            let frame_tx = frame_tx.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(sock).await else {
                    return;
                };
                // Read frames for up to 750 ms then close.
                let deadline = tokio::time::sleep(Duration::from_millis(750));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => {
                            let _ = ws.send(Message::Close(None)).await;
                            return;
                        }
                        msg = ws.next() => match msg {
                            Some(Ok(Message::Text(t))) => {
                                let _ = frame_tx.send(t.to_string());
                            }
                            Some(Ok(_)) => {},
                            Some(Err(_)) | None => return,
                        }
                    }
                }
            });
            if accepts >= 3 {
                return;
            }
        }
    });

    let config = WsConfig {
        ping_interval: Duration::from_secs(30),
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(200),
        channel_capacity: 64,
    };
    let client = WsClient::connect_with(url, config).await.unwrap();
    client.subscribe_l2_book(MarketId(1)).await.unwrap();

    // Collect up to 4 inbound subscribe frames across reconnects.
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline && frames.len() < 2 {
        if let Ok(Some(f)) = tokio::time::timeout(Duration::from_millis(800), frame_rx.recv()).await
        {
            frames.push(f);
        }
    }

    assert!(
        frames.len() >= 2,
        "expected at least 2 subscribe frames across reconnect, got {}: {frames:?}",
        frames.len()
    );

    // Every captured frame must be a subscribe frame for l2_book on market_id=1.
    for f in &frames {
        let parsed: serde_json::Value = serde_json::from_str(f).expect("subscribe frame is JSON");
        assert_eq!(parsed["method"], "subscribe");
        assert_eq!(parsed["subscription"]["type"], "l2_book");
        assert_eq!(parsed["subscription"]["market_id"], 1);
    }

    // Cleanup.
    client.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_millis(500), server_task).await;
    // Drain the Arc — drop the WsClient, the background task exits.
    drop(client);
}
