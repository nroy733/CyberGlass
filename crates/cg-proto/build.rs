//! Build script for `cg-proto` — compiles `.proto` files into Rust code
//! using `tonic-build` and `prost-build`.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Directory containing all .proto files
    let proto_dir = PathBuf::from("../../proto");

    // All proto files to compile
    let protos: Vec<PathBuf> = [
        "common.proto",
        "ingest.proto",
        "query.proto",
        "detection.proto",
        "ontology.proto",
        "ai.proto",
        "admin.proto",
    ]
    .iter()
    .map(|p| proto_dir.join(p))
    .collect();

    // Output directory for compiled protos
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    // File descriptor set path for gRPC reflection support
    let descriptor_set_path = out_dir.join("cyberglass_descriptor.bin");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(&descriptor_set_path)
        .compile_protos(&protos, &[&proto_dir])?;

    // Re-run if any proto files change
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    Ok(())
}
