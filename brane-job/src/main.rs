//  MAIN.rs
//    by Lut99
//
//  Created:
//    18 Oct 2022, 13:47:17
//  Last edited:
//    14 Jun 2024, 15:14:12
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `brane-job` service.
//

use std::sync::Arc;
use std::time::Duration;

use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, WorkerConfig};
use brane_job::worker::WorkerServer;
use brane_prx::client::ProxyClient;
use clap::Parser;
use dotenvy::dotenv;
use error_trace::trace;
use specifications::working::JobServiceServer;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tonic::transport::Server;
use tracing::{debug, error, info, warn};

/***** CONSTANTS *****/
/// The default log level for tracing_subscriber. Levels higher than this will be discarded.
const DEFAULT_LOG_LEVEL: tracing::level_filters::LevelFilter = tracing::level_filters::LevelFilter::INFO;
/// The environment variable used by env-filter in tracing subscriber
const LOG_LEVEL_ENV_VAR: &str = "BRANE_JOB_LOG";

mod cli;

/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    dotenv().ok();
    let opts = cli::Cli::parse();

    let cli_log_level = opts.logging.log_level(DEFAULT_LOG_LEVEL);
    specifications::tracing::setup_subscriber(LOG_LEVEL_ENV_VAR, cli_log_level);

    info!("Initializing brane-job v{}...", env!("CARGO_PKG_VERSION"));

    // Load the config, making sure it's a worker config
    debug!("Loading node.yml file '{}'...", opts.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&opts.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            std::process::exit(1);
        },
    };
    let worker: WorkerConfig = match node_config.node.try_into_worker() {
        Some(worker) => worker,
        None => {
            error!("Given NodeConfig file '{}' does not have properties for a worker node.", opts.node_config_path.display());
            std::process::exit(1);
        },
    };

    // Initialize the Xenon thingy
    // debug!("Initializing Xenon...");
    // let xenon_schedulers = Arc::new(DashMap::<String, Arc<RwLock<Scheduler>>>::new());
    // let xenon_endpoint = utilities::ensure_http_schema(&opts.xenon, !opts.debug)?;

    // Start the JobHandler
    let server = match WorkerServer::new(opts.node_config_path, opts.keep_containers, Arc::new(ProxyClient::new(worker.services.prx.address()))) {
        Ok(svr) => svr,
        Err(err) => {
            error!("{}", trace!(("Failed to create WorkerServer"), err));
            std::process::exit(1);
        },
    };

    // Start gRPC server with callback service.
    debug!("gRPC server ready to serve on '{}'", worker.services.job.bind);
    if let Err(err) = Server::builder()
        .add_service(JobServiceServer::new(server))
        .serve_with_shutdown(worker.services.job.bind, async {
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
