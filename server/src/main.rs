use handshake::message::{payloads::{Header, Message}, types::{MessageType, ServerHelloPayload}};
use hkdf::hkdf_hello;
use ring::rand::SystemRandom;
use std::error::Error;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};


async fn handle_client (mut stream: TcpStream, rng: &SystemRandom) -> Result<(), Box<dyn Error>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let data_len = u32::from_be_bytes(len_bytes) as usize;

    let mut data = vec![0u8; data_len];
    stream.read_exact(&mut data).await?;
    let req = Message::decode(&data)?;
    println!("Received from client: {:?}", req);

    hkdf_hello();
    
    let header  = Header::new(1234u64, "Server".to_string(), MessageType::ServerHello);
    let payload = ServerHelloPayload::new(&rng);
    let message = Message::new(header, payload.into());
    let data = message.encode()?;

    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(&data).await?;
    println!("Sent message {:?}", message);
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
            let rng = SystemRandom::new();
            if let Err(e) = handle_client(stream, &rng).await {
                eprintln!("Error handling client: {}", e);
            }
        });

    }
}

