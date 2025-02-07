//  MAIN.rs
//    by Lut99
//
//  Created:
//    18 Oct 2022, 13:47:17
//  Last edited:
//    07 Feb 2025, 14:16:59
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `brane-job` service.
//

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, WorkerConfig};
use brane_job::worker::WorkerServer;
use brane_prx::client::ProxyClient;
use clap::Parser;
use dotenvy::dotenv;
use error_trace::trace;
use log::{LevelFilter, debug, error, info, warn};
use specifications::working::JobServiceServer;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tonic::transport::Server;


/***** ARGUMENTS *****/
#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    /// Print debug info
    #[clap(long, help = "If given, shows additional logging information.", env = "DEBUG")]
    debug: bool,
    /// Whether to keep containers after execution or not.
    #[clap(long, help = "If given, will not remove job containers after removing them.", env = "KEEP_CONTAINERS")]
    keep_containers: bool,
    /// The token to authenticate ourselves with the checker with.
    #[clap(long, help = "A token to authenticate to the given Checker service with.", env = "CHECKER_DELIB_TOKEN")]
    delib_token: String,

    /// Node environment metadata store.
    #[clap(
        short,
        long,
        default_value = "/node.yml",
        help = "The path to the node environment configuration. This defines things such as where local services may be found or where to store \
                files, as wel as this service's service address.",
        env = "NODE_CONFIG_PATH"
    )]
    node_config_path: PathBuf,
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
    let server = match WorkerServer::new(
        opts.node_config_path,
        opts.keep_containers,
        opts.delib_token,
        Arc::new(ProxyClient::new(worker.services.prx.address())),
    ) {
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
