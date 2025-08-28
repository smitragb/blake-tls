use hkdf::hkdf_hello;
use std::error::Error;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};


async fn handle_client (mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    let req = String::from_utf8_lossy(&buffer[..n]);
    println!("Received from client: {}", req.trim());
    hkdf_hello();
    let resp = "Hello World!\n";
    stream.write_all(resp.as_bytes()).await?;
    println!("Sent response to client");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Server running on Port 127.0.0.1:50051");
    let listener = TcpListener::bind("127.0.0.1:50051").await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New client connected {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Error handling client: {}", e);
            }
        });

    }
}

