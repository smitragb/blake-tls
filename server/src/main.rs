use handshake::message::{payloads::{Header, Message}, types::{MessageType, Payload, ServerHelloDonePayload, ServerHelloPayload, ServerInfoPayload}};
use hkdf::hkdf_hello;
use server::{expect_payload, ServerState};
use std::error::Error;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

async fn receive_message (stream: &mut TcpStream) -> Result<Message, Box<dyn Error>> {
    let n = stream.read_u32().await? as usize;
    let mut data = vec![0u8; n];
    stream.read_exact(&mut data).await?;
    let resp = Message::decode(&data)?;
    Ok(resp) 
}

async fn send_message (stream: &mut TcpStream, msg: Message) -> Result<(), Box<dyn Error>> {
    let data = msg.encode()?;
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(&data).await?;
    Ok(())
}

async fn handle_client (mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    // Client Hello
    let server = ServerState::new();
    let req = receive_message(&mut stream).await?;
    let payload = expect_payload!(req.get_payload(), ClientHello)?;
    let server = server.on_client_hello(payload);
    hkdf_hello();
    
    // Server Hello
    let header  = Header::new(1234u64, "Server".to_string(), MessageType::ServerHello);
    let payload = ServerHelloPayload::fill_nonce(server.session_data.my_nonce);
    let msg     = ServerHelloPayload::prepare_message(header, payload.clone());
    let server  = server.on_server_hello(payload); 
    send_message(&mut stream, msg).await?;
    
    // Server Info
    let header  = Header::new(1234u64, "Server".to_string(), MessageType::ServerInfo);
    let payload = ServerInfoPayload::compute_and_fill(&server.session_data.my_sk);
    let msg     = ServerInfoPayload::prepare_message(header, payload.clone());
    let server  = server.on_server_info(payload);
    send_message(&mut stream, msg).await?;

    // Server Hello Done
    let header  = Header::new(1234u64, "Server".to_string(), MessageType::ServerHelloDone);
    let payload = ServerHelloDonePayload {};
    let msg     = ServerHelloDonePayload::prepare_message(header);
    let server  = server.on_server_hello_done(payload);
    send_message(&mut stream, msg).await?;

    println!("Session Data: {:#?}", server.session_data);

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

