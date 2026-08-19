use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    codexwatch_client::run_cli(codexwatch_client::Cli::parse()).await
}
