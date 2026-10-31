//! A small end-to-end demo mirroring httpx's quick-start usage.
//!
//! Run with: `cargo run --example quickstart`

use rshttpx::Client;

#[tokio::main]
async fn main() -> rshttpx::Result<()> {
    let client = Client::builder()
        .base_url("https://httpbin.org")
        .follow_redirects(true)
        .build()?;

    // GET with query params.
    let resp = client
        .get("/get")
        .query("hello", "world")
        .query("lang", "rust")
        .send()
        .await?;
    println!("GET /get -> {}", resp.status_code());
    resp.raise_for_status()?;

    // POST a JSON body and read it back.
    let resp = client
        .post("/post")
        .json(&serde_json::json!({ "framework": "rshttpx" }))
        .send()
        .await?;
    println!("POST /post -> {}", resp.status_code());
    let body: serde_json::Value = resp.json()?;
    println!("echoed json: {}", body["json"]);

    Ok(())
}
