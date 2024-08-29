use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

pub fn setup_subscriber(log_level_env_var: &str, default_log_level: LevelFilter) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var(log_level_env_var)
                .with_default_directive(default_log_level.into())
                .from_env_lossy(),
        )
        .init();

    info!("Logger initiated with log level {}", std::env::var(log_level_env_var).unwrap_or(default_log_level.to_string()));
}
