# blake-tls: Experimental TLS 1.2 Handshake with BLAKE3 as KDF
This project implements a **type-safe TLS 1.2 handshake** in Rust, replacing the standard SHA2-based HKDF with a BLAKE3-based KDF. The design enforces protocol correctness at the type level and validates transcript integrity during the Finished message exchange. The goal is not interoperability with existing TLS stacks, but to explore how **modern cryptographic primitives** can be integrated into widely deployed protocols while maintaining strong safety guarantees. Therefore, it goes to say, **DO NOT USE IN PRODUCTION**

## Features
- **Type-safe state machine**:
  TLS handshake is a stateful protocol that allows session resumption and restarts. For this project, the handshake flow is a linear state machine; therefore, the project doesn't support the features mentioned earlier. Rust offers the nice feature to disable illegal state transitions at compile-time, making it an attractive choice. The implementation expects the right message payload for the current state on both client and server, thus enforcing correctness through compile-time safety.
- **Custom KDF using BLAKE3**
  After establishing a shared secret through RSA-based/Elliptic curve Diffie-Hellman-based/Kyber-Dilithium-based key exchange, the protocol generates the symmetric keys to encrypt the TCP pipe in either direction. For this project, I use ``blake3`` in XOF mode to generate the symmetric keys for ChaCha20Poly1305 symmetric cipher. 
- **Transcript Validation**
  With the symmetric keys established, each participant sends the encrypted hash of the conversation, thus safeguarding against replay attacks. This feature is supported in this project.

## Motivation
- **Potential Performance gains?**
  ``blake3`` is a parallelizable hash function that is optimized for modern hardware with **5-6x** performance gains over SHA2/SHA3-based hash functions.
- **Protocol rigor**
  Rust's type-safety enables a compile-time safe implementation of the protocol that retains the correctness guarantees of the theoretical construction.

## Requirements
The project was written with a Rust compiler and Cargo version of ``1.83.0``. At the root directory, run ``cargo build`` to compile the project. Once ready, run

```bash
cargo run -p server
cargo run -p client
```
in separate terminals. 
