use std::path::PathBuf;

use clap::Parser;

/// A rudimentary, SOCKS-as-a-Service proxy service for outgoing connections from a domain.
#[derive(Parser)]
#[clap(name = "brane-prx", version, author)]
pub(crate) struct Cli {
    /// Print debug info
    #[clap(long, action, help = "If given, shows additional logging information.", env = "DEBUG")]
    pub(crate) debug: bool,

    /// Node environment metadata store.
    #[clap(
        short,
        long,
        default_value = "/node.yml",
        help = "The path to the node environment configuration. This defines things such as where local services may be found or where to store \
                files, as wel as this service's service address.",
        env = "NODE_CONFIG_PATH"
    )]
    pub(crate) node_config_path: PathBuf,
}
