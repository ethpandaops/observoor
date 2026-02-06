mod agent;
mod beacon;
mod clock;
mod config;
mod export;
mod migrate;
mod pid;
mod sink;
mod tracer;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

/// eBPF-based Ethereum client monitoring agent.
#[derive(Parser)]
#[command(name = "observoor", about)]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Logging verbosity level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print version information and exit.
    Version,
}

/// Build-time version info, injected via RUSTFLAGS or build.rs.
mod version {
    /// Release version string (set at build time).
    pub const RELEASE: &str = env!("CARGO_PKG_VERSION");

    /// Git commit hash (set at build time via env, or "unknown").
    pub fn git_commit() -> &'static str {
        option_env!("GIT_COMMIT").unwrap_or("unknown")
    }

    /// Target OS.
    pub fn target_os() -> &'static str {
        std::env::consts::OS
    }

    /// Target architecture.
    pub fn target_arch() -> &'static str {
        std::env::consts::ARCH
    }

    /// Full version string with platform info.
    pub fn full() -> String {
        format!(
            "{} (commit: {}, {}/{})",
            RELEASE,
            git_commit(),
            target_os(),
            target_arch(),
        )
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle version subcommand before anything else.
    if let Some(Command::Version) = &cli.command {
        println!("observoor {}", version::full());
        return Ok(());
    }

    // Initialize tracing.
    let filter = EnvFilter::try_new(&cli.log_level)
        .with_context(|| format!("invalid log level: {}", cli.log_level))?;

    fmt().with_env_filter(filter).with_target(true).init();

    // Config is required for the main agent run.
    let config_path = cli
        .config
        .context("--config is required (use --help for usage)")?;

    let cfg = config::Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    tracing::info!(
        version = version::RELEASE,
        commit = version::git_commit(),
        "starting observoor",
    );

    // Build and run the tokio runtime.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    rt.block_on(async { run(cfg).await })
}

async fn run(cfg: config::Config) -> Result<()> {
    // Set up signal handling.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, shutting down");
            }
        }

        let _ = shutdown_tx.send(());
    });

    // Start the agent.
    let mut agent = agent::Agent::new(cfg)?;
    agent.start().await?;

    // Wait for shutdown signal.
    let _ = shutdown_rx.await;

    // Graceful shutdown.
    agent.stop().await?;

    tracing::info!("observoor stopped");

    Ok(())
}
