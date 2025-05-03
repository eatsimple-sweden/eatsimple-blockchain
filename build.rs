fn main() {
    if std::env::var("CARGO_FEATURE_GRPC").is_ok() {
        tonic_build::configure()
            .build_server(true)      // generate server traits
            .build_client(true)      // generate client stubs (default)
            .type_attribute(
                "TxRequest",
                "#[derive(serde::Serialize, serde::Deserialize)]",
            )
            .compile_protos(
                &["proto/transaction.proto"],
                &["proto"],
            )
            .expect("failed to compile protos");
    }
}