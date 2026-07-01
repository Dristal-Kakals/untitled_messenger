use std::sync::Arc;
use um_server::{listener::serve, Store};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr = std::env::var("UM_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:7000".into());
    let store = Arc::new(Store::new());
    let bound = serve(&addr, store).await?;
    tracing::info!("um-server listening on {bound}");
    // Serve runs in spawned tasks; keep the main task alive forever.
    std::future::pending::<()>().await;
    Ok(())
}
