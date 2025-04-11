use std::path::PathBuf;

use clap::Parser;

/// Defines the arguments for the `brane-reg` service.
#[derive(Parser)]
#[clap(name = "brane-reg", version, author)]
pub(crate) struct Cli {
    #[clap(long, action, help = "If given, provides additional debug prints on the logger.", env = "DEBUG")]
    pub(crate) debug: bool,

    /// Load everything from the node.yml file
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
