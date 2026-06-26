//! `pgp-chat-demo` — interactive console demo for `pgp-chat-core`.
//!
//! Entry point: detects terminal capabilities, enables raw mode, runs the
//! interactive menu, then restores the terminal on exit (even on panic).

mod commands;
mod menu;
mod ui;

use anyhow::Result;
use crossterm::terminal;
use tracing_subscriber::EnvFilter;

/// RAII guard that disables raw mode on drop — handles panics and early returns.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Best-effort restore; ignore errors during unwinding.
        let _ = terminal::disable_raw_mode();
        // Move to a clean line in case the cursor was mid-line.
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::style::Print("\r\n"),
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise tracing to stderr so it doesn't corrupt the TUI.
    // Set RUST_LOG=debug to see libp2p internals.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    terminal::enable_raw_mode()?;
    // Guard ensures disable_raw_mode() is called even if menu() panics.
    let _guard = RawModeGuard;

    menu::run().await
}
