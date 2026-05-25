//! Compile the protobuf bindings when the `grpc` feature is enabled.
//!
//! Without the `grpc` feature this build script is a no-op so users who
//! don't need gRPC don't pay the protoc / tonic-build cost.

fn main() {
    #[cfg(feature = "grpc")]
    {
        // tonic-build re-runs protoc and emits Rust into OUT_DIR.
        tonic_build::configure()
            .build_server(false)
            .build_client(true)
            .compile_protos(&["proto/metaflux.proto"], &["proto"])
            .expect("tonic-build: failed to compile proto/metaflux.proto");
    }
}
