#![allow(dead_code)]
use handshake::{
    message::types::{
        ClientFinishedPayload, ClientHelloPayload, ClientKXPayload, 
        ServerFinishedPayload, ServerHelloDonePayload, ServerHelloPayload, ServerInfoPayload
    }, 
    protocol::state::ClientHandshakeState
};
use hkdf::Blake3Hkdf;
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

pub struct ClientState<S> {
    handshake_state: ClientHandshakeState,
    pub session_data : SessionData,
    _marker: std::marker::PhantomData<S>,
}

#[derive(Debug)]
pub struct SessionData {
    rng: SystemRandom, 
    hasher: Blake3Hkdf,
    pub transcript_hash: [u8; 32],
    pub server_nonce: [u8; 32],
    pub my_nonce: [u8; 32],
    pub server_pk_bytes: Vec<u8>,
    my_sk: Option<EphemeralPrivateKey>,
    pub shared_secret: Vec<u8>,
    pub server_sym_key: Vec<u8>,
    pub my_sym_key: Vec<u8>,
    pub aead_nonce: [u8; 12],
}

impl SessionData {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let sk = EphemeralPrivateKey::generate(&X25519, &rng)
            .expect("Unable to generate private key");
        let mut out = [0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill(&mut out).expect("Unable to generate nonce");
        rng.fill(&mut nonce).expect("Unable to generate AEAD nonce");
        Self {
            rng,
            hasher: Blake3Hkdf::new(),
            transcript_hash: [0u8; 32],
            server_nonce: [0u8; 32],
            my_nonce: out.clone(),
            server_pk_bytes: Vec::new(),
            my_sk: Some(sk),
            shared_secret: Vec::new(),
            server_sym_key: Vec::new(),
            my_sym_key: Vec::new(),
            aead_nonce: nonce,
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
        let msg_bytes = bincode::serialize(&msg).unwrap(); 
        self.handshake_state = ClientHandshakeState::AwaitingServerHello;
        self.session_data.hasher.absorb(&msg_bytes);
        self.session_data.transcript_hash = self.session_data.hasher.finalize();
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
        let msg_bytes = bincode::serialize(&msg).unwrap(); 
        let server_nonce = msg.get_nonce();
        self.handshake_state = ClientHandshakeState::AwaitingServerInfo;
        self.session_data.hasher.absorb(&msg_bytes);
        self.session_data.server_nonce = server_nonce;
        self.session_data.transcript_hash = self.session_data.hasher.finalize();
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
        let msg_bytes = bincode::serialize(&msg).unwrap(); 
        let server_pk_bytes = msg.get_bytes();
        self.handshake_state = ClientHandshakeState::AwaitingServerHelloDone;
        self.session_data.hasher.absorb(&msg_bytes);
        self.session_data.server_pk_bytes = server_pk_bytes;
        self.session_data.transcript_hash = self.session_data.hasher.finalize();
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
        let msg_bytes = bincode::serialize(&msg).unwrap(); 
        self.handshake_state = ClientHandshakeState::SendingPublicKeyInfo;
        self.session_data.hasher.absorb(&msg_bytes);
        self.session_data.transcript_hash = self.session_data.hasher.finalize();
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
        let server_nonce = self.session_data.server_nonce;
        let my_nonce = self.session_data.my_nonce;
        let msg_bytes = bincode::serialize(&msg).unwrap(); 
        self.handshake_state = ClientHandshakeState::SendingFinished;
        self.session_data.hasher.absorb(&msg_bytes);
        self.session_data.transcript_hash = self.session_data.hasher.finalize();
        
        // Using unwrap here because sk is guaranteed to be present since the 
        // ClientKXPayload contains the public key.
        let sk = self.session_data.take_sk().unwrap();
        let peer_pk = UnparsedPublicKey::new(&X25519, self.session_data.server_pk_bytes.clone());
        let shared = ring::agreement::agree_ephemeral(sk, &peer_pk,
            |ss| { ss.to_vec() }).expect("Unable to generate shared secret");
        let mut hkdf = Blake3Hkdf::new();
        hkdf.absorb(shared.clone())
            .absorb(b"Key Expansion")
            .absorb(server_nonce)
            .absorb(my_nonce)
            .squeeze(64);
        let server_sym_key = hkdf.read_at(0, SYM_KEY_LEN);
        let my_sym_key     = hkdf.read_at(SYM_KEY_LEN as u64, SYM_KEY_LEN);
        self.session_data.shared_secret  = shared;
        self.session_data.server_sym_key = server_sym_key;
        self.session_data.my_sym_key     = my_sym_key;

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
        let msg_bytes = bincode::serialize(&msg).unwrap(); 
        self.handshake_state = ClientHandshakeState::AwaitingServerFinished;
        self.session_data.hasher.absorb(&msg_bytes);
        self.session_data.transcript_hash = self.session_data.hasher.finalize();
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
        let msg_bytes  = bincode::serialize(&msg).unwrap(); 
        let aead_nonce = msg.get_aead_nonce(); 
        let transcript_hash = self.session_data.transcript_hash;
        let decrypted_hash = msg.decrypt(&self.session_data.server_sym_key, aead_nonce);
        assert_eq!(decrypted_hash, transcript_hash);
        self.handshake_state = ClientHandshakeState::Finished;
        self.session_data.hasher.absorb(&msg_bytes);
        self.session_data.transcript_hash = self.session_data.hasher.finalize();
        ClientState { 
            handshake_state: self.handshake_state, 
            session_data   : self.session_data, 
            _marker        : std::marker::PhantomData
        }
    }
}

