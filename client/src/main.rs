use std::error::Error;

use client::{ClientState,expect_payload};
use handshake::message::{
    payloads::{Header, Message},
    types::{ClientFinishedPayload, ClientHelloPayload, ClientKXPayload, MessageType, Payload}
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

async fn send_message (
    stream: &mut TcpStream, 
    msg: Message
) -> Result<(), Box<dyn Error>> {
    let data = msg.encode()?;
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(&data).await?;
    Ok(())
}

async fn receive_message (
    stream: &mut TcpStream
) -> Result<Message, Box<dyn Error>> {
    let n = stream.read_u32().await? as usize;
    let mut data = vec![0u8; n];
    stream.read_exact(&mut data).await?;
    let resp = Message::decode(&data)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:50051").await?;
    println!("Connected to server!");
    let client  = ClientState::new();

    let header  = Header::new(0u64, "Client1".to_string(), MessageType::ClientHello);
    let payload = ClientHelloPayload::fill_nonce(client.session_data.my_nonce);
    let msg     = ClientHelloPayload::prepare_message(header, payload.clone());
    let client  = client.on_client_hello(payload);
    send_message(&mut stream, msg).await?;

    let resp    = receive_message(&mut stream).await?;
    let payload = expect_payload!(resp.get_payload(), ServerHello)?;
    let client  = client.on_server_hello(payload);

    let resp    = receive_message(&mut stream).await?;
    let payload = expect_payload!(resp.get_payload(), ServerInfo)?;
    let client  = client.on_server_info(payload);

    let resp        = receive_message(&mut stream).await?;
    let payload     = expect_payload!(resp.get_payload(), ServerHelloDone)?;
    let mut client  = client.on_server_hello_done(payload);
    
    let header  = Header::new(0u64, "Client1".to_string(), MessageType::ClientKeyExchange);
    let my_sk   = client.session_data.get_sk();
    let payload = ClientKXPayload::compute_and_fill(my_sk);
    let msg     = ClientKXPayload::prepare_message(header, payload.clone());
    let client  = client.on_client_pk_info(payload);
    send_message(&mut stream, msg).await?;

    let header  = Header::new(0u64, "Client1".to_string(), MessageType::ClientFinished);
    let payload = ClientFinishedPayload::encrypt_and_fill (
        &client.session_data.my_sym_key, 
        &client.session_data.transcript_hash,
        client.session_data.aead_nonce,
    );
    let msg     = ClientFinishedPayload::prepare_message(header, payload.clone());
    let client  = client.on_client_finished(payload);
    send_message(&mut stream, msg).await?;
    
    let resp    = receive_message(&mut stream).await?;
    let payload = expect_payload!(resp.get_payload(), ServerFinished)?;
    let _client = client.on_server_finished(payload);
    println!("Handshake successful!");
    Ok(())
}
