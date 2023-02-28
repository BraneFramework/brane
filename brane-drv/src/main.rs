//  MAIN.rs
//    by Lut99
// 
//  Created:
//    30 Sep 2022, 11:59:58
//  Last edited:
//    28 Feb 2023, 16:35:44
//  Auto updated?
//    Yes
// 
//  Description:
//!   Entrypoint to the `brane-drv` service.
// 

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use dotenvy::dotenv;
use log::{debug, error, info, LevelFilter};
use tonic::transport::Server;

use brane_cfg::node::NodeConfig;
use brane_prx::client::ProxyClient;
use specifications::driving::DriverServiceServer;

use brane_drv::planner::InstancePlanner;
use brane_drv::handler::DriverHandler;


/***** ARGUMENTS *****/
/// Defines the arguments that may be given to the service.
#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    /// Print debug info
    #[clap(short, long, action, help = "If given, prints additional logging information.", env = "DEBUG")]
    debug    : bool,
    /// Consumer group id
    #[clap(short, long, default_value = "brane-drv", help = "The group ID of this service's consumer")]
    group_id : String,

    /// Node environment metadata store.
    #[clap(short, long, default_value = "/node.yml", help = "The path to the node environment configuration. This defines things such as where local services may be found or where to store files, as wel as this service's service address.", env = "NODE_CONFIG_PATH")]
    node_config_path : PathBuf,
}





/***** ENTRY POINT *****/
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
    info!("Initializing brane-drv v{}...", env!("CARGO_PKG_VERSION"));

    // Load the config, making sure it's a central config
    debug!("Loading node.yml file '{}'...", opts.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&opts.node_config_path) {
        Ok(config) => config,
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            std::process::exit(1);
        },
    };
    let central: CentralConfig = match node_config.node.try_into_central() {
        Some(central) => central,
        None          => { error!("Given NodeConfig file '{}' does not have properties for a central node.", opts.node_config_path.display()); std::process::exit(1); },
    };

    // Create our side of the planner, and launch its event monitor
    let planner: Arc<InstancePlanner> = match InstancePlanner::new(central.clone()) {
        Ok(planner) => Arc::new(planner),
        Err(err)    => { error!("Failed to create InstancePlanner: {}", err); std::process::exit(1); },
    };
    if let Err(err) = planner.start_event_monitor(&opts.group_id).await { error!("Failed to start InstancePlanner event monitor: {}", err); std::process::exit(1); }

    // Start the DriverHandler
    let handler = DriverHandler::new(
        &opts.node_config_path,
        Arc::new(ProxyClient::new(central.services.prx.address)),
        planner.clone(),
    );

    // Start gRPC server with callback service.
    debug!("gRPC server ready to serve on '{}'", central.services.drv.bind);
    if let Err(err) = Server::builder()
        .add_service(DriverServiceServer::new(handler))
        .serve(central.services.drv.bind)
        .await
    {
        error!("Failed to start gRPC server: {}", err);
        std::process::exit(1);
    }
}
