//! The blocking (synchronous) client, mirroring `httpx.Client`.
//!
//! Note: a blocking client owns its own runtime and must NOT be called from
//! inside an existing async runtime. Run with: `cargo run --example blocking`

fn main() -> rshttpx::Result<()> {
    let client = rshttpx::blocking::Client::builder()
        .base_url("https://httpbin.org")
        .follow_redirects(true)
        .build()?;

    let resp = client
        .post("/post")
        .json(&serde_json::json!({ "sync": true }))
        .send()?;
    println!("POST /post -> {}", resp.status_code());

    let body: serde_json::Value = resp.json()?;
    println!("echoed: {}", body["json"]);
    Ok(())
}
