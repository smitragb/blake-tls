use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ring::agreement::{EphemeralPrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use super::payloads::{Header, Message};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    ClientHello, 
    ServerHello,
    ServerInfo,
    ServerHelloDone,
    ClientKeyExchange,
    ClientFinished,
    ServerFinished,
    Error
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    ServerInfo(ServerInfoPayload),
    ServerHelloDone(ServerHelloDonePayload),
    ClientKeyExchange(ClientKXPayload),
    ClientFinished(ClientFinishedPayload),
    ServerFinished(ServerFinishedPayload),
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
    #[inline(always)]
    pub fn fill(pk: &PublicKey) -> Self {
        let pk_bytes = pk.as_ref().to_vec();
        Self { ephemeral_pk: pk_bytes }
    }

    #[inline(always)]
    pub fn compute_and_fill(sk: &EphemeralPrivateKey) -> Self {
        let pk = sk.compute_public_key().expect("Failed to compute Public key");
        let pk_bytes = pk.as_ref().to_vec();
        Self { ephemeral_pk: pk_bytes }
    }

    #[inline(always)]
    pub fn get_bytes(&self) -> Vec<u8> {
        self.ephemeral_pk.clone()
    }

    #[inline(always)]
    pub fn prepare_message(header: Header, payload: ServerInfoPayload) -> Message {
        Message::new(header, payload.into())
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

impl ServerHelloDonePayload {
    #[inline(always)]
    pub fn prepare_message(header: Header) -> Message {
        Message::new(header, ServerHelloDonePayload {}.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinishedPayload {
    enc_transcript_hash: Vec<u8>,
}

impl ClientFinishedPayload {
    pub fn encrypt_and_fill(key_bytes: &[u8], data: &[u8], nonce: [u8; 12]) -> Self {
        let key   = chacha20poly1305::Key::from_slice(key_bytes);
        let aead  = ChaCha20Poly1305::new(key);
        let ad    = Nonce::from_slice(&nonce);
        let ct    = aead.encrypt(ad, data).expect("Encryption Failed!");
        Self { enc_transcript_hash: ct }
    }

    pub fn decrypt (&self, key_bytes: &[u8], nonce: [u8; 12]) -> Vec<u8> {
        let ciphertext = self.enc_transcript_hash.as_ref();
        let key   = chacha20poly1305::Key::from_slice(key_bytes);
        let aead  = ChaCha20Poly1305::new(key);
        let ad    = Nonce::from_slice(&nonce);
        let plaintext  = aead.decrypt(ad, ciphertext).expect("Decryption failed");
        plaintext
    }

    #[inline(always)]
    pub fn prepare_message (header: Header, payload: ClientFinishedPayload) -> Message {
        Message::new(header, payload.into())
    }
}

impl From<ClientFinishedPayload> for Payload {
    fn from(p: ClientFinishedPayload) -> Self {
        Payload::ClientFinished(p)
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

    #[inline(always)]
    pub fn compute_and_fill(sk: &EphemeralPrivateKey) -> Self {
        let pk = sk.compute_public_key().expect("Failed to compute Public key");
        let pk_bytes = pk.as_ref().to_vec();
        Self { ephemeral_pk: pk_bytes }
    }

    #[inline(always)]
    pub fn prepare_message (header: Header, payload: ClientKXPayload) -> Message {
        Message::new(header, payload.into())
    }
    
    #[inline(always)]
    pub fn get_bytes(&self) -> Vec<u8> {
        self.ephemeral_pk.clone()
    }

}

impl From<ClientKXPayload> for Payload {
    fn from(p: ClientKXPayload) -> Self {
        Payload::ClientKeyExchange(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFinishedPayload {
    enc_transcript_hash: Vec<u8>,
}

impl ServerFinishedPayload {
    pub fn encrypt_and_fill(key_bytes: &[u8], data: &[u8], nonce: [u8; 12]) -> Self {
        let key   = chacha20poly1305::Key::from_slice(key_bytes);
        let aead  = ChaCha20Poly1305::new(key);
        let ad    = Nonce::from_slice(&nonce);
        let ct    = aead.encrypt(ad, data).expect("Encryption Failed!");
        Self { enc_transcript_hash: ct }
    }

    pub fn decrypt (&self, key_bytes: &[u8], nonce: [u8; 12]) -> Vec<u8> {
        let ciphertext = self.enc_transcript_hash.as_ref();
        let key   = chacha20poly1305::Key::from_slice(key_bytes);
        let aead  = ChaCha20Poly1305::new(key);
        let ad    = Nonce::from_slice(&nonce);
        let plaintext  = aead.decrypt(ad, ciphertext).expect("Decryption failed");
        plaintext
    }
    
    #[inline(always)]
    pub fn prepare_message (header: Header, payload: ServerFinishedPayload) -> Message {
        Message::new(header, payload.into())
    }
}

impl From<ServerFinishedPayload> for Payload {
    fn from(p: ServerFinishedPayload) -> Self {
        Payload::ServerFinished(p)
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
