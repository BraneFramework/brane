/***** ARGUMENTS *****/
use std::path::PathBuf;

use clap::Parser;

/// Defines the arguments that may be given to the service.
#[derive(Parser)]
#[clap(name = "brane-drv", version, author)]
pub(crate) struct Cli {
    /// Print debug info
    #[clap(short, long, action, help = "If given, prints additional logging information.", env = "DEBUG")]
    pub(crate) debug:    bool,
    /// Consumer group id
    #[clap(short, long, default_value = "brane-drv", help = "The group ID of this service's consumer")]
    pub(crate) group_id: String,

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
