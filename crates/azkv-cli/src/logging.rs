use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, filter_fn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Events with this target are command output: bare lines on stdout.
pub const OUTPUT: &str = "azkv::output";

pub fn init() {
    // Output keeps stdout pipe-friendly (no timestamp/level); diagnostics go to stderr.
    let output = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(false)
        .without_time()
        .with_level(false)
        .with_target(false)
        .with_filter(filter_fn(|meta| meta.target() == OUTPUT));
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into());
    let diagnostics = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::builder().parse_lossy(filter));
    let _ = tracing_subscriber::registry().with(output).with(diagnostics).try_init();
}
