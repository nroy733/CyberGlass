pub mod compressor;
pub mod error;
pub mod segment;
pub mod tier;

pub use compressor::{create_compressor, Compressor, Lz4Compressor, ZstdCompressor};
pub use error::{Result, StorageError};
pub use segment::{Segment, SegmentReader, SegmentWriter};
pub use tier::{TierManager, TierUsage};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compressor_roundtrip_zstd() {
        let compressor = create_compressor("zstd", 3);
        let data = b"Hello, CyberGlass! This is test data for compression roundtrip.";
        let compressed = compressor.compress(data).expect("compress");
        let decompressed = compressor.decompress(&compressed).expect("decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compressor_roundtrip_lz4() {
        let compressor = create_compressor("lz4", 1);
        let data = b"Hello, CyberGlass! This is test data for compression roundtrip.";
        let compressed = compressor.compress(data).expect("compress");
        let decompressed = compressor.decompress(&compressed).expect("decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compressor_defaults_to_zstd() {
        let compressor = create_compressor("invalid_type", 3);
        let data = b"test data";
        let compressed = compressor.compress(data).expect("compress");
        let decompressed = compressor.decompress(&compressed).expect("decompress");
        assert_eq!(decompressed, data);
    }
}
