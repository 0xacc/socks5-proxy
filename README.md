# socks5-proxy
socks5-proxy is a socks5 library based on [tokio](https://github.com/tokio-rs/tokio) offering both server and client functions.

# Usage
Add this to your Cargo.toml dependency
```toml
socks5-proxy = "0.1"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
```

## Server
```rust
use anyhow::Result;
use socks5_proxy::server;

#[tokio::main]
async fn main() -> Result<()> {
    let s = server::new("127.0.0.1:8080".parse()?, None)?;
    s.run().await?;

    Ok(())
}
```

## Client
```rust
use anyhow::Result;
use socks5_proxy::{client, Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    let mut client = client::new(
        "localhost:1080",
        &Addr::HostnamePort("www.google.com:80".into()),
        None,
    )
    .await?;

    client.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
    let mut buffer = Vec::new();
    client.read_to_end(&mut buffer).await?;
    println!("{}", String::from_utf8_lossy(&buffer));

    Ok(())
}
```

# Improvement
All kinds of issues and PRs are welcome!
