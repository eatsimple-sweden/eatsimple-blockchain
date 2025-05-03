fn main() {
    if std::env::var("CARGO_FEATURE_GRPC").is_ok() {
        let mut cfg = tonic_build::configure()
            .build_server(true)
            .build_client(true);

        cfg = cfg.type_attribute(
            ".",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        );

        cfg.compile_protos(
            &["proto/transaction.proto"],
            &["proto"],
        )
        .expect("failed to compile protos");
    }
}