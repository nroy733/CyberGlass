use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        Self { signing_key }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Invalid 32-byte secret key".into()))?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok(Self { signing_key })
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

pub fn verify_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Public key must be 32 bytes".into()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::Verification("Signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(data, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_sign_and_verify() {
        let keypair = KeyPair::generate();
        let data = b"CyberGlass Signature Payload";
        let signature = keypair.sign(data);
        let pubkey = keypair.public_key_bytes();

        let is_valid = verify_signature(&pubkey, data, &signature).expect("Verification failed");
        assert!(is_valid, "Valid signature must pass");

        let is_invalid =
            verify_signature(&pubkey, b"Tampered data", &signature).expect("Verification failed");
        assert!(!is_invalid, "Tampered data signature must fail");
    }
}
