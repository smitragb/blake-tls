use serde::{Deserialize, Serialize};

use super::types::{MessageType, Payload};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    header: Header,
    payload: Payload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    session_id: u64,
    sender_id: String,
    message_type: MessageType,
}

impl Header {
    pub fn new(session_id: u64, sender_id: String, message_type: MessageType) -> Self {
        Self { session_id, sender_id, message_type }
    }
}

impl Message {
    pub fn new (header: Header, payload: Payload) -> Self {
        Self { header, payload }
    }

    #[inline(always)]
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    #[inline(always)]
    pub fn decode(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    #[inline(always)]
    pub fn get_payload(self) -> Payload {
        self.payload
    }
}
