use std::error::Error;

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:50051").await?;
    println!("Connected to server!");

    let msg = "Hello from client!";
    stream.write_all(msg.as_bytes()).await?;
    println!("Sent: {}", msg);

    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let resp = String::from_utf8_lossy(&buffer[..n]);
    println!("Received from server!: {}", resp);
    Ok(())
}
