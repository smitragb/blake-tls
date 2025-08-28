use std::error::Error;

use handshake::message::{
    payloads::{Header, Message},
    types::{ClientHelloPayload, MessageType}
};
use ring::rand::SystemRandom;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:50051").await?;
    println!("Connected to server!");
    let rng = SystemRandom::new();

    let header  = Header::new(0u64, "Client1".to_string(), MessageType::ClientHello);
    let payload = ClientHelloPayload::new(&rng);
    let message = Message::new(header, payload.into());
    let data = message.encode()?;

    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(&data).await?;
    println!("Sent: {:?}", message);

    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let data_len = u32::from_be_bytes(len_bytes) as usize;

    let mut data = vec![0u8; data_len];
    stream.read_exact(&mut data).await?;
    let resp = Message::decode(&data)?;
    println!("Received from server!: {:?}", resp);
    Ok(())
}
