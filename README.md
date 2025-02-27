## XTLS-VISION-like protocol implementation in Async Rust
xtls-vision-rs provides `XTlsVisionStream`, encrypted alternative for `TcpStream`.
It encrypts data and sends it wrapped with TLS header. If it detects that inner data
is already TLS, it stops encrypting and wrapping data and sends it as-is, saving
resources needed for the encryption.

Example usage as server:
```rust
use tokio::net::TcpListener;
use xtls_vision_rs::XTlsVisionStream;
async {
    let l = TcpListener::bind("0.0.0.0:443").await.unwrap();
    let c = l.accept().await.unwrap().0;
    // Here you probably want to mimic a TLS handshake using `c`
    let mut stream = XTlsVisionStream::negotiate_as_server(
        c,
        // Your rsa_private_key here
    ).await.unwrap();
    // Here you can exchange data with the client before the proxification process
    // (e.g. client can send TCP endpoint address to connect)
    // You should do it before ending the early data because otherwise XTlsStream would likely
    // detect your connection as "not TLS".
    // Early data is encrypted
    stream.end_early_data();
    // Here you can start [`tokio::io::copy`] between `stream` and `remote_stream`
}
```

Example usage as client:
```rust
use tokio::net::TcpStream;
use xtls_vision_rs::XTlsVisionStream;
async {
    let mut stream = XTlsVisionStream::negotiate_as_client(
        TcpStream::connect("0.0.0.0:1234").await.unwrap(),
        // Your rsa_public_key here
    ).await.unwrap();
    // Here you can exchange data with the server before the proxification process
    // (e.g. you can send TCP endpoint address to connect)
    // You should do it before ending the early data because otherwise XTlsStream would likely
    // detect your connection as "not TLS".
    // Early data is encrypted
    stream.end_early_data();
    // Here you can start [`tokio::io::copy`] between `stream` and `local_stream`
}
```