#![allow(dead_code)]

use handshake::{
    message::types::{
        ClientHelloPayload, Payload, ServerHelloDonePayload, 
        ServerHelloPayload, ServerInfoPayload
    },
    protocol::state::ServerHandshakeState
};
use ring::{
    agreement::{EphemeralPrivateKey, X25519}, 
    rand::{SecureRandom, SystemRandom}
};

pub struct AwaitingClientHello;
pub struct Finished;

#[macro_export]
macro_rules! expect_payload {
    ($expr:expr, $variant:ident) => {
        match $expr {
            Payload::$variant(inner) => Ok(inner),
            other => Err(format!("Expected {:?}, got: {:?}", stringify!($variant), other))
        }
    };
}

pub struct SessionData {
    rng: SystemRandom,
    pub transcript: Vec<Payload>,
    pub client_nonce: [u8; 32],
    pub my_nonce: [u8; 32],
    pub my_sk: EphemeralPrivateKey,
    pub shared_secret: Vec<u8>,
}

impl SessionData {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let sk = EphemeralPrivateKey::generate(&X25519, &rng)
            .expect("Unable to generate private key");
        let mut out = [0u8; 32];
        rng.fill(&mut out).expect("Unable to generate nonce");
        Self {
            rng,
            transcript: Vec::new(),
            client_nonce: [0u8; 32],
            my_nonce: out.clone(),
            my_sk: sk,
            shared_secret: Vec::new(),
        }
    }
}

pub struct ServerState<S> {
    handshake_state: ServerHandshakeState,
    pub session_data: SessionData,
    _marker: std::marker::PhantomData<S>,
}

impl ServerState<AwaitingClientHello> {
    pub fn new() -> Self {
        ServerState {
            handshake_state: ServerHandshakeState::AwaitingClientHello,
            session_data: SessionData::new(),
            _marker: std::marker::PhantomData,
        }
    } 

    pub fn on_client_hello (
        mut self, 
        msg: ClientHelloPayload,
    ) -> Self {
        let client_nonce = msg.get_nonce();
        self.session_data.transcript.push(msg.into());
        self.session_data.client_nonce = client_nonce;
        ServerState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData,
        }
    }

    pub fn on_server_hello (
        mut self,
        msg: ServerHelloPayload
    ) -> Self {
        self.session_data.transcript.push(msg.into());
        ServerState {
            handshake_state: self.handshake_state,
            session_data   : self.session_data,
            _marker        : std::marker::PhantomData,
        }
    }

    pub fn on_server_info (
        mut self, 
        msg: ServerInfoPayload
    ) -> Self {
        self.session_data.transcript.push(msg.into());
        ServerState {
            handshake_state: self.handshake_state,
            session_data   : self.session_data,
            _marker        : std::marker::PhantomData,
        } 
    }

    pub fn on_server_hello_done (
        mut self,
        msg: ServerHelloDonePayload
    ) -> ServerState<Finished> {
        self.handshake_state = ServerHandshakeState::Finished;
        self.session_data.transcript.push(msg.into());
        ServerState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}
