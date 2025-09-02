#![allow(dead_code)]

use std::io::{Read, Seek, SeekFrom};
pub fn hkdf_hello() {
    println!("HKDF says: Hello, world!");
}

pub struct Blake3Hkdf {
    hasher: blake3::Hasher,
}

impl Blake3Hkdf {
    pub fn new() -> Self {
        Self { hasher: blake3::Hasher::new() }
    }

    pub fn absorb (&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        self.hasher.update(data.as_ref());
        self
    }

    pub fn reset (&mut self) {
        self.hasher.reset();
    }
    
    pub fn finalize(&mut self) -> [u8; 32] {
        let out = self.hasher.clone().finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(out.as_bytes());
        arr
    }

    pub fn squeeze(&mut self, len: usize) -> Vec<u8> {
        let mut reader = self.hasher.clone().finalize_xof();
        let mut out = vec![0u8; len];
        reader.read_exact(&mut out).expect("XOF operation failed!");
        out
    }

    pub fn read_at(&mut self, offset: u64, len: usize) -> Vec<u8> {
        let mut reader = self.hasher.clone().finalize_xof();
        let mut out = vec![0u8; len];
        if reader.seek(SeekFrom::Start(offset)).is_ok() {
            reader.read_exact(&mut out).expect("Seek failed");
        } else {
            let mut dummy = vec![0u8; offset as usize];
            reader.read_exact(&mut dummy).expect("Offset seek failed");
            reader.read_exact(&mut out).expect("XOF operation failed!");
        }
        out
    }
    
    pub fn extract_nth_key (&mut self, key_len: usize, index: u64) -> Vec<u8> {
        let prk = self.finalize();

        let mut ctx = blake3::Hasher::new_keyed(&prk);
        ctx.update(b"BLAKE3-HKDF-Expand");
        ctx.update(&index.to_le_bytes());
        ctx.update(&(key_len as u32).to_le_bytes());

        let mut reader = ctx.finalize_xof();
        let mut out = vec![0u8; key_len];
        reader.read_exact(&mut out).expect("XOF operation failed");
        out
    }
}































