use clap::Parser;

#[derive(Parser)]
#[command(
    name = "wayjournal",
    version,
    about = "Federated immutable Git journal substrate"
)]
struct Cli;

fn main() {
    Cli::parse();
}
