use crate::error::{Result, StorageError};

pub trait Compressor: Send + Sync {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub struct ZstdCompressor {
    level: i32,
}

impl ZstdCompressor {
    pub fn new(level: i32) -> Self {
        Self { level }
    }
}

impl Compressor for ZstdCompressor {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::encode_all(data, self.level).map_err(|e| StorageError::Compression(e.to_string()))
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::decode_all(data).map_err(|e| StorageError::Decompression(e.to_string()))
    }
}

pub struct Lz4Compressor;

impl Compressor for Lz4Compressor {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(lz4_flex::compress_prepend_size(data))
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| StorageError::Decompression(e.to_string()))
    }
}

pub fn create_compressor(compression_type: &str, level: u32) -> Box<dyn Compressor> {
    match compression_type.to_lowercase().as_str() {
        "lz4" => Box::new(Lz4Compressor),
        _ => Box::new(ZstdCompressor::new(level as i32)),
    }
}
