use std::path::PathBuf;

use clap::Parser;

/// Defines the arguments for the `brane-reg` service.
#[derive(Parser)]
pub(crate) struct Cli {
    #[clap(flatten)]
    pub(crate) logging: specifications::cli::Tracing,

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
