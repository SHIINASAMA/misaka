use clap::Parser;
use misaka_relay::RelayService;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(name = "misaka-relay")]
struct Args {
    /// TCP address on which the byte-forwarding relay listens.
    #[arg(long, default_value = "0.0.0.0:443")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), misaka_relay::RelayError> {
    let args = Args::parse();
    tracing_subscriber::fmt().with_target(false).init();
    RelayService::bind(args.bind).await?.run().await
}
