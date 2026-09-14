use clap::Parser;
use unoc_rs::cli::{AppCommand, Cli};

fn main() {
    let cli = Cli::parse();
    let memory_limit = cli.memory_limit;
    let result = unoc_rs::memory::apply_memory_limit(memory_limit)
        .and_then(|_| cli.into_command())
        .and_then(|command| match command {
            AppCommand::Compare(config) => unoc_rs::pipeline::run(config),
            AppCommand::Inspect(config) => unoc_rs::inspect::run(config),
            AppCommand::AuditRefs(config) => unoc_rs::audit::run(config),
            AppCommand::Query(config) => unoc_rs::query::run(config),
            AppCommand::Remap(config) => unoc_rs::remap::run(config),
        });

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
