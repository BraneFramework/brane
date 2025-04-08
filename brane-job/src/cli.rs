use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[clap(name = "brane-job", version, author)]
pub(crate) struct Cli {
    /// Print debug info
    #[clap(long, action, help = "If given, shows additional logging information.", env = "DEBUG")]
    pub(crate) debug: bool,
    /// Whether to keep containers after execution or not.
    #[clap(long, action, help = "If given, will not remove job containers after removing them.", env = "KEEP_CONTAINERS")]
    pub(crate) keep_containers: bool,

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
