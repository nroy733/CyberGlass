use crate::error::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
}

impl TlsConfig {
    pub fn new<P: AsRef<Path>>(cert_path: P, key_path: P) -> Self {
        Self {
            cert_path: cert_path.as_ref().to_path_buf(),
            key_path: key_path.as_ref().to_path_buf(),
            ca_path: None,
        }
    }

    pub fn with_ca<P: AsRef<Path>>(mut self, ca_path: P) -> Self {
        self.ca_path = Some(ca_path.as_ref().to_path_buf());
        self
    }

    pub fn load_server_certs(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let cert = std::fs::read(&self.cert_path).map_err(|e| {
            crate::error::CryptoError::Encoding(format!("Failed to read cert: {}", e))
        })?;
        let key = std::fs::read(&self.key_path).map_err(|e| {
            crate::error::CryptoError::Encoding(format!("Failed to read key: {}", e))
        })?;
        Ok((cert, key))
    }
}
