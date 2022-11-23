//  MAIN.rs
//    by Lut99
// 
//  Created:
//    18 Oct 2022, 13:47:17
//  Last edited:
//    22 Nov 2022, 12:01:32
//  Auto updated?
//    Yes
// 
//  Description:
//!   Entrypoint to the `brane-job` service.
// 

use std::path::PathBuf;

use clap::Parser;
use dotenvy::dotenv;
use log::LevelFilter;
use log::{debug, error, info};
use tonic::transport::Server;

use brane_cfg::node::NodeConfig;
use brane_tsk::grpc::JobServiceServer;
use brane_tsk::instance::worker::WorkerServer;


/***** ARGUMENTS *****/
#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    /// Print debug info
    #[clap(long, action, help = "If given, shows additional logging information.", env = "DEBUG")]
    debug           : bool,
    /// Whether to keep containers after execution or not.
    #[clap(long, action, help = "If given, will not remove job containers after removing them.", env = "KEEP_CONTAINERS")]
    keep_containers : bool,

    /// Node environment metadata store.
    #[clap(short, long, default_value = "/node.yml", help = "The path to the node environment configuration. This defines things such as where local services may be found or where to store files, as wel as this service's service address.", env = "NODE_CONFIG_PATH")]
    node_config_path : PathBuf,
}





/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    dotenv().ok();
    let opts = Opts::parse();

    // Configure logger.
    let mut logger = env_logger::builder();
    logger.format_module_path(false);

    if opts.debug {
        logger.filter_level(LevelFilter::Debug).init();
    } else {
        logger.filter_level(LevelFilter::Info).init();
    }
    info!("Initializing brane-job v{}...", env!("CARGO_PKG_VERSION"));

    // Load the config, making sure it's a worker config
    debug!("Loading node.yml file '{}'...", opts.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&opts.node_config_path) {
        Ok(config) => config,
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            std::process::exit(1);
        },
    };
    if !node_config.node.is_worker() { error!("Given NodeConfig file '{}' does not have properties for a worker node.", opts.node_config_path.display()); std::process::exit(1); }

    // Initialize the Xenon thingy
    // debug!("Initializing Xenon...");
    // let xenon_schedulers = Arc::new(DashMap::<String, Arc<RwLock<Scheduler>>>::new());
    // let xenon_endpoint = utilities::ensure_http_schema(&opts.xenon, !opts.debug)?;

    // Start the JobHandler
    let server = WorkerServer::new(
        opts.node_config_path,
        opts.keep_containers,
    );

    // Start gRPC server with callback service.
    debug!("gRPC server ready to serve on '{}'", node_config.node.worker().ports.job);
    if let Err(err) = Server::builder()
        .add_service(JobServiceServer::new(server))
        .serve(node_config.node.worker().ports.job)
        .await
    {
        error!("Failed to start gRPC server: {}", err);
        std::process::exit(1);
    }
}
