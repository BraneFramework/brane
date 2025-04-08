use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[clap(name = "brane-plr", version, author)]
pub(crate) struct Cli {
    /// Print debug info
    #[clap(short, long, action, help = "If given, prints additional logging information.", env = "TRACE")]
    pub(crate) trace: bool,

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
