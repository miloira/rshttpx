//! Live verification of decompression, Digest auth, streaming and the blocking
//! client. Run with: `cargo run --example verify_features`

use futures_util::StreamExt;
use rshttpx::Client;

#[tokio::main]
async fn main() -> rshttpx::Result<()> {
    let client = Client::builder()
        .base_url("https://httpbin.org")
        .follow_redirects(true)
        .build();

    // 1. Transparent gzip decompression: /gzip returns gzipped JSON.
    let resp = client.get("/gzip").send().await?;
    let json: serde_json::Value = resp.json()?;
    assert_eq!(json["gzipped"], serde_json::Value::Bool(true));
    println!("gzip: decoded ok, gzipped={}", json["gzipped"]);

    // 2. Brotli decompression: /brotli returns brotli-encoded JSON.
    let resp = client.get("/brotli").send().await?;
    let json: serde_json::Value = resp.json()?;
    println!("brotli: decoded ok, brotli={}", json["brotli"]);

    // 3. Digest auth: expects 200 after the challenge/response round trip.
    let resp = client
        .get("/digest-auth/auth/testuser/testpass")
        .digest_auth("testuser", "testpass")
        .send()
        .await?;
    println!("digest: status={}", resp.status_code());
    assert_eq!(resp.status_code(), 200);

    // 4. Streaming: consume /stream-bytes in chunks.
    let stream = client.get("/stream-bytes/2048").send_stream().await?;
    let mut total = 0usize;
    let mut body = Box::pin(stream.bytes_stream());
    while let Some(chunk) = body.next().await {
        total += chunk?.len();
    }
    println!("stream: received {total} bytes");
    assert_eq!(total, 2048);

    // 5. Elapsed timing is populated.
    let resp = client.get("/get").send().await?;
    println!("elapsed: {:?}", resp.elapsed());
    assert!(resp.elapsed().as_nanos() > 0);

    println!("all async feature checks passed (see `blocking` example for the sync client)");
    Ok(())
}
