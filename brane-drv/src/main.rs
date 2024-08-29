//  MAIN.rs
//    by Lut99
//
//  Created:
//    30 Sep 2022, 11:59:58
//  Last edited:
//    08 Feb 2024, 17:08:36
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `brane-drv` service.
//

mod cli;

use std::sync::Arc;
use std::time::Duration;

use brane_cfg::info::Info as _;
use brane_cfg::node::{CentralConfig, NodeConfig};
use brane_drv::handler::DriverHandler;
use brane_prx::client::ProxyClient;
use clap::Parser;
use dotenvy::dotenv;
use error_trace::trace;
use specifications::driving::DriverServiceServer;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tonic::transport::Server;
use tracing::{debug, error, info, warn};

/***** CONSTANTS *****/
/// The default log level for tracing_subscriber. Levels higher than this will be discarded.
const DEFAULT_LOG_LEVEL: tracing::level_filters::LevelFilter = tracing::level_filters::LevelFilter::INFO;
/// The environment variable used by env-filter in tracing subscriber
const LOG_LEVEL_ENV_VAR: &str = "BRANE_DRV_LOG";



/***** ENTRY POINT *****/
#[tokio::main]
async fn main() {
    dotenv().ok();
    let opts = cli::Cli::parse();

    let cli_log_level = opts.logging.log_level(DEFAULT_LOG_LEVEL);
    specifications::tracing::setup_subscriber(LOG_LEVEL_ENV_VAR, cli_log_level);

    info!("Initializing brane-drv v{}...", env!("CARGO_PKG_VERSION"));

    // Load the config, making sure it's a central config
    debug!("Loading node.yml file '{}'...", opts.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&opts.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            std::process::exit(1);
        },
    };
    let central: CentralConfig = match node_config.node.try_into_central() {
        Some(central) => central,
        None => {
            error!("Given NodeConfig file '{}' does not have properties for a central node.", opts.node_config_path.display());
            std::process::exit(1);
        },
    };

    // Start the DriverHandler
    let handler = DriverHandler::new(&opts.node_config_path, Arc::new(ProxyClient::new(central.services.prx.address())));

    // Start gRPC server with callback service.
    debug!("gRPC server ready to serve on '{}'", central.services.drv.bind);
    if let Err(err) = Server::builder()
        .add_service(DriverServiceServer::new(handler))
        .serve_with_shutdown(central.services.drv.bind, async {
            // Register a SIGTERM handler to be Docker-friendly
            let mut handler: Signal = match signal(SignalKind::terminate()) {
                Ok(handler) => handler,
                Err(err) => {
                    error!("{}", trace!(("Failed to register SIGTERM signal handler"), err));
                    warn!("Service will NOT shutdown gracefully on SIGTERM");
                    loop {
                        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                    }
                },
            };

            // Wait until we receive such a signal after which we terminate the server
            handler.recv().await;
            info!("Received SIGTERM, shutting down gracefully...");
        })
        .await
    {
        error!("{}", trace!(("Failed to start gRPC server"), err));
        std::process::exit(1);
    }
}
