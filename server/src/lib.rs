#![allow(dead_code)]

use handshake::{
    message::types::{
        ClientFinishedPayload, ClientHelloPayload, ClientKXPayload, 
        Payload, ServerHelloDonePayload, ServerHelloPayload, ServerInfoPayload
    },
    protocol::state::ServerHandshakeState
};
use hkdf::Blake3Hkdf;
use ring::{
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519}, 
    rand::{SecureRandom, SystemRandom}
};

pub struct AwaitingClientHello;
pub struct SendingServerHello;
pub struct SendingServerInfo;
pub struct SendingServerHelloDone;
pub struct AwaitingClientKeyExchange;
pub struct AwaitingClientFinished;
pub struct SendingFinished;
pub struct Finished;
static SYM_KEY_LEN: usize = 32;

#[macro_export]
macro_rules! expect_payload {
    ($expr:expr, $variant:ident) => {
        match $expr {
            Payload::$variant(inner) => Ok(inner),
            other => Err(format!("Expected {:?}, got: {:?}", stringify!($variant), other))
        }
    };
}

#[derive(Debug)]
pub struct SessionData {
    rng: SystemRandom,
    pub transcript: Vec<Payload>,
    pub client_nonce: [u8; 32],
    pub my_nonce: [u8; 32],
    my_sk: Option<EphemeralPrivateKey>,
    pub client_pk: Vec<u8>,
    pub shared_secret: Vec<u8>,
    pub my_sym_key: Vec<u8>,
    pub client_sym_key: Vec<u8>,
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
            my_sk: Some(sk),
            client_pk: Vec::new(),
            shared_secret: Vec::new(),
            my_sym_key: Vec::new(),
            client_sym_key: Vec::new(),
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
    ) -> ServerState<SendingServerHello> {
        self.handshake_state = ServerHandshakeState::SendingServerHello;
        let client_nonce = msg.get_nonce();
        self.session_data.transcript.push(msg.into());
        self.session_data.client_nonce = client_nonce;
        ServerState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData,
        }
    }
}

impl ServerState<SendingServerHello> {
    pub fn on_server_hello (
        mut self,
        msg: ServerHelloPayload
    ) -> ServerState<SendingServerInfo> {
        self.handshake_state = ServerHandshakeState::SendingServerInfo;
        self.session_data.transcript.push(msg.into());
        ServerState {
            handshake_state: self.handshake_state,
            session_data   : self.session_data,
            _marker        : std::marker::PhantomData,
        }
    }
}

impl ServerState<SendingServerInfo> {
    pub fn on_server_info (
        mut self, 
        msg: ServerInfoPayload
    ) -> ServerState<SendingServerHelloDone> {
        self.handshake_state = ServerHandshakeState::SendingServerHelloDone;
        self.session_data.transcript.push(msg.into());
        ServerState {
            handshake_state: self.handshake_state,
            session_data   : self.session_data,
            _marker        : std::marker::PhantomData,
        } 
    }
}

impl ServerState<SendingServerHelloDone> {
    pub fn on_server_hello_done (
        mut self,
        msg: ServerHelloDonePayload
    ) -> ServerState<AwaitingClientKeyExchange> {
        self.handshake_state = ServerHandshakeState::AwaitingClientKeyExchange;
        self.session_data.transcript.push(msg.into());
        ServerState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}

impl ServerState<AwaitingClientKeyExchange> {
    pub fn on_client_kx (
        mut self, 
        msg: ClientKXPayload
    ) -> ServerState<AwaitingClientFinished> {
        let my_nonce = self.session_data.my_nonce;
        let client_nonce = self.session_data.client_nonce;
        let client_pk_bytes = msg.get_bytes();
        self.handshake_state = ServerHandshakeState::AwaitingClientFinished;
        self.session_data.transcript.push(msg.into());

        // Using unwrap here since server shared corresponding public key
        // in the previous messages and no operation on sk was done since
        let sk = self.session_data.take_sk().unwrap();
        let peer_pk = UnparsedPublicKey::new(&X25519, client_pk_bytes);
        let shared = ring::agreement::agree_ephemeral(sk, &peer_pk, 
            |ss| { ss.to_vec() }).expect("Unable to agree shared secret");
        let mut hkdf = Blake3Hkdf::new();
        hkdf.absorb(shared.clone())
            .absorb(b"Key Expansion")
            .absorb(my_nonce)
            .absorb(client_nonce)
            .squeeze(64);
        let my_sym_key     = hkdf.read_at(0, SYM_KEY_LEN); 
        let client_sym_key = hkdf.read_at(SYM_KEY_LEN as u64, SYM_KEY_LEN);
        self.session_data.shared_secret  = shared;
        self.session_data.my_sym_key     = my_sym_key;
        self.session_data.client_sym_key = client_sym_key;

        ServerState {
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}

impl ServerState<AwaitingClientFinished> {
    pub fn on_client_finished (
        mut self,
        msg: ClientFinishedPayload
    ) -> ServerState<SendingFinished> {
        self.handshake_state = ServerHandshakeState::SendingFinished;
        self.session_data.transcript.push(msg.into());
        ServerState {
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}

impl ServerState<SendingFinished> {
    pub fn on_server_finished (
        mut self
    ) -> ServerState<Finished> {
        self.handshake_state = ServerHandshakeState::Finished;
        ServerState {
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}
