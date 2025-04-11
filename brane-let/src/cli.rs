/***** ARGUMENTS *****/
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[clap(name = "branelet", version, author)]
pub(crate) struct Cli {
    #[clap(short, long, env = "BRANE_APPLICATION_ID")]
    pub(crate) application_id: String,
    #[clap(short, long, env = "BRANE_LOCATION_ID")]
    pub(crate) location_id: String,
    #[clap(short, long, env = "BRANE_JOB_ID")]
    pub(crate) job_id: String,
    #[clap(short, long, env = "BRANE_CALLBACK_TO")]
    pub(crate) callback_to: Option<String>,
    #[clap(short, long, env = "BRANE_PROXY_ADDRESS")]
    pub(crate) proxy_address: Option<String>,
    #[clap(short, long, env = "BRANE_MOUNT_DFS")]
    pub(crate) mount_dfs: Option<String>,
    /// Prints debug info
    #[clap(short, long, action, env = "DEBUG")]
    pub(crate) debug: bool,
    #[clap(subcommand)]
    pub(crate) sub_command: SubCommand,
}

#[derive(Parser, Clone)]
pub(crate) enum SubCommand {
    /// Execute arbitrary source code and return output
    #[clap(name = "ecu")]
    Code {
        /// Function to execute
        function:    String,
        /// Input arguments (encoded, as Base64'ed JSON)
        arguments:   String,
        #[clap(short, long, env = "BRANE_WORKDIR", default_value = "/opt/wd")]
        working_dir: PathBuf,
    },
    /// Don't perform any operation and return nothing
    #[clap(name = "no-op")]
    NoOp,
}
