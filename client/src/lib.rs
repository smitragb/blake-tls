#![allow(dead_code)]
use handshake::{
    message::types::{
        ClientFinishedPayload, ClientHelloPayload, ClientKXPayload, Payload, ServerFinishedPayload, ServerHelloDonePayload, ServerHelloPayload, ServerInfoPayload
    }, 
    protocol::state::ClientHandshakeState
};
use ring::{
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519}, 
    rand::{SecureRandom, SystemRandom}
};

pub struct Start;
pub struct AwaitingServerHello;
pub struct AwaitingServerInfo;
pub struct AwaitingServerHelloDone;
pub struct SendingPublicKeyInfo;
pub struct SendingFinished;
pub struct AwaitingServerFinished;
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

pub struct ClientState<S> {
    handshake_state: ClientHandshakeState,
    pub session_data : SessionData,
    _marker: std::marker::PhantomData<S>,
}

#[derive(Debug)]
pub struct SessionData {
    rng: SystemRandom, 
    pub transcript: Vec<Payload>,
    pub server_nonce: [u8; 32],
    pub my_nonce: [u8; 32],
    pub server_pk_bytes: Vec<u8>,
    my_sk: Option<EphemeralPrivateKey>,
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
            server_nonce: [0u8; 32],
            my_nonce: out.clone(),
            server_pk_bytes: Vec::new(),
            my_sk: Some(sk),
            shared_secret: Vec::new(),
        }
    }

    pub fn take_sk(&mut self) -> Option<EphemeralPrivateKey> {
        self.my_sk.take()
    } 

    pub fn get_sk(&mut self) -> &EphemeralPrivateKey {
        if self.my_sk.is_none() {
            let sk = EphemeralPrivateKey::generate(&X25519, &self.rng)
                .expect("Unable to generate private key");
            self.my_sk = Some(sk);
        }
        self.my_sk.as_ref().unwrap()
    }
}

impl ClientState<Start> {
    pub fn new() -> Self {
        ClientState { 
            handshake_state: ClientHandshakeState::Start, 
            session_data   : SessionData::new(),
            _marker        : std::marker::PhantomData, 
        }
    }

    pub fn on_client_hello(
        mut self,
        msg: ClientHelloPayload
    ) -> ClientState<AwaitingServerHello> {
        self.handshake_state = ClientHandshakeState::AwaitingServerHello;
        self.session_data.transcript.push(msg.into());
        ClientState {
            handshake_state: self.handshake_state,
            session_data   : self.session_data,
            _marker        : std::marker::PhantomData,
        }
    } 
}

impl ClientState<AwaitingServerHello> {
    pub fn on_server_hello (
        mut self, 
        msg: ServerHelloPayload
    ) -> ClientState<AwaitingServerInfo> {
        let server_nonce = msg.get_nonce();
        self.handshake_state = ClientHandshakeState::AwaitingServerInfo;
        self.session_data.transcript.push(msg.into());
        self.session_data.server_nonce = server_nonce;
        ClientState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}

impl ClientState<AwaitingServerInfo> {
    pub fn on_server_info (
        mut self, 
        msg: ServerInfoPayload
    ) -> ClientState<AwaitingServerHelloDone> {
        let server_pk_bytes = msg.get_bytes();
        self.handshake_state = ClientHandshakeState::AwaitingServerHelloDone;
        self.session_data.transcript.push(msg.into());
        self.session_data.server_pk_bytes = server_pk_bytes;
        ClientState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}


impl ClientState<AwaitingServerHelloDone> {
    pub fn on_server_hello_done (
        mut self, 
        msg: ServerHelloDonePayload
    ) -> ClientState<SendingPublicKeyInfo> {
        self.handshake_state = ClientHandshakeState::SendingPublicKeyInfo;
        self.session_data.transcript.push(msg.into());
        ClientState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}

impl ClientState<SendingPublicKeyInfo> {
    pub fn on_client_pk_info (
        mut self,
        msg: ClientKXPayload
    ) -> ClientState<SendingFinished> {
        self.handshake_state = ClientHandshakeState::SendingFinished;
        self.session_data.transcript.push(msg.into());
        
        // Using unwrap here because sk is guaranteed to be present since the 
        // ClientKXPayload contains the public key.
        let sk = self.session_data.take_sk().unwrap();
        let peer_pk = UnparsedPublicKey::new(&X25519, self.session_data.server_pk_bytes.clone());
        let shared = ring::agreement::agree_ephemeral(sk, &peer_pk,
            |ss| { ss.to_vec() }).expect("Unable to generate shared secret");
        self.session_data.shared_secret = shared;

        ClientState {
            handshake_state: self.handshake_state,
            session_data   : self.session_data,
            _marker        : std::marker::PhantomData
        }
    }
}

impl ClientState<SendingFinished> {
    pub fn on_client_finished (
        mut self,
        msg: ClientFinishedPayload,
    ) -> ClientState<AwaitingServerFinished> {
        self.handshake_state = ClientHandshakeState::AwaitingServerFinished;
        self.session_data.transcript.push(msg.into());
        ClientState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    } 
}

impl ClientState<AwaitingServerFinished> {
    pub fn on_server_finished (
        mut self,
        msg: ServerFinishedPayload,
    ) -> ClientState<Finished> {
        self.handshake_state = ClientHandshakeState::Finished;
        self.session_data.transcript.push(msg.into());
        ClientState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }

    }
}

