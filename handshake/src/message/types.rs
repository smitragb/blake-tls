use ring::agreement::{EphemeralPrivateKey, PublicKey};
use serde::{Deserialize, Serialize};

use super::payloads::{Header, Message};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    ClientHello, 
    ServerHello,
    ServerInfo,
    ServerHelloDone,
    ClientPreMasterKey,
    ClientKeyExchange,
    Error
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    ServerInfo(ServerInfoPayload),
    ServerHelloDone(ServerHelloDonePayload),
    ClientPreMasterKey(ClientPMKPayload),
    ClientKeyExchange(ClientKXPayload),
    Error(ErrorPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHelloPayload {
    nonce: [u8; 32],
}

impl ClientHelloPayload {
    #[inline(always)]
    pub fn fill_nonce (nonce: [u8; 32]) -> Self {
        Self { nonce }
    }
    
    #[inline(always)]
    pub fn get_nonce(&self) -> [u8; 32] {
        self.nonce.clone()
    }

    #[inline(always)]
    pub fn prepare_message (header: Header, payload: ClientHelloPayload) -> Message {
        Message::new(header, payload.into())
    }
}

impl From<ClientHelloPayload> for Payload {
    fn from(p: ClientHelloPayload) -> Self {
        Payload::ClientHello(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHelloPayload {
    nonce: [u8; 32],
}

impl ServerHelloPayload {
    #[inline(always)]
    pub fn fill_nonce(nonce: [u8; 32]) -> Self {
        Self { nonce }
    }

    #[inline(always)]
    pub fn get_nonce(&self) -> [u8; 32] {
        self.nonce.clone()
    }

    #[inline(always)]
    pub fn prepare_message (header: Header, payload: ServerHelloPayload)  -> Message {
        Message::new(header, payload.into())
    }
}

impl From<ServerHelloPayload> for Payload {
    fn from(p: ServerHelloPayload) -> Self {
        Payload::ServerHello(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoPayload {
    ephemeral_pk: Vec<u8>,
}

impl ServerInfoPayload {
    pub fn fill(pk: &PublicKey) -> Self {
        let pk_bytes = pk.as_ref().to_vec();
        Self { ephemeral_pk: pk_bytes }
    }

    pub fn compute_and_fill(sk: &EphemeralPrivateKey) -> Self {
        let pk = sk.compute_public_key().expect("Failed to compute Public key");
        let pk_bytes = pk.as_ref().to_vec();
        Self { ephemeral_pk: pk_bytes }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.ephemeral_pk.clone()
    }
}

impl From<ServerInfoPayload> for Payload {
    fn from(p: ServerInfoPayload) -> Self {
        Payload::ServerInfo(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHelloDonePayload {}

impl From<ServerHelloDonePayload> for Payload {
    fn from(p: ServerHelloDonePayload) -> Self {
        Payload::ServerHelloDone(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPMKPayload {
    encrypted_shared: Vec<u8>,
}

impl ClientPMKPayload {
    pub fn fill(data: Vec<u8>) -> Self {
        Self { encrypted_shared: data.clone() }
    }
}

impl From<ClientPMKPayload> for Payload {
    fn from(p: ClientPMKPayload) -> Self {
        Payload::ClientPreMasterKey(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)] 
pub struct ClientKXPayload {
    ephemeral_pk: Vec<u8>,
}

impl ClientKXPayload {
    pub fn fill(pk: &PublicKey) -> Self {
        let pk_bytes = pk.as_ref().to_vec();
        Self { ephemeral_pk: pk_bytes }
    }

    pub fn compute_and_fill(sk: &EphemeralPrivateKey) -> Self {
        let pk = sk.compute_public_key().expect("Failed to compute Public key");
        let pk_bytes = pk.as_ref().to_vec();
        Self { ephemeral_pk: pk_bytes }
    }
}

impl From<ClientKXPayload> for Payload {
    fn from(p: ClientKXPayload) -> Self {
        Payload::ClientKeyExchange(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    code: u8,
    errmsg: String,
}

impl ErrorPayload {
    pub fn new(code: u8, errmsg: String) -> Self {
        Self { code, errmsg }
    }
}

impl From<ErrorPayload> for Payload {
    fn from(p: ErrorPayload) -> Self {
        Payload::Error(p)
    }
}
