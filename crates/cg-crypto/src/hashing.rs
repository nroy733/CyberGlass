use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Cryptographic hash chain for immutable audit trails and tamper-evident logs
pub fn hash_chain(previous_hash: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(data);
    hasher.finalize().into()
}
