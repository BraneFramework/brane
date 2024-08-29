//  MAIN.rs
//    by Lut99
//
//  Created:
//    17 Oct 2022, 17:27:16
//  Last edited:
//    25 Nov 2024, 09:48:49
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `brane-plr` service.
//

mod cli;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use brane_cfg::info::Info as _;
use brane_cfg::node::{CentralConfig, NodeConfig};
use brane_plr::context::{Context, Session};
use brane_plr::planner;
use brane_prx::client::ProxyClient;
use clap::Parser;
use dotenvy::dotenv;
use error_trace::trace;
use parking_lot::Mutex;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing::{debug, error, info, warn};
use warp::Filter as _;

/***** CONSTANTS *****/
/// The default log level for tracing_subscriber. Levels higher than this will be discarded.
const DEFAULT_LOG_LEVEL: tracing::level_filters::LevelFilter = tracing::level_filters::LevelFilter::INFO;
/// The environment variable used by env-filter in tracing subscriber
const LOG_LEVEL_ENV_VAR: &str = "BRANE_PLR_LOG";


/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    // Load arguments & environment stuff
    dotenv().ok();
    let opts = cli::Cli::parse();

    let cli_log_level = opts.logging.log_level(DEFAULT_LOG_LEVEL);
    specifications::tracing::setup_subscriber(LOG_LEVEL_ENV_VAR, cli_log_level);

    info!("Initializing brane-plr v{}...", env!("CARGO_PKG_VERSION"));

    // Load the config, making sure it's a central config
    debug!("Loading node.yml file '{}'...", opts.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&opts.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load NodeConfig file: {}", err);
            std::process::exit(1);
        },
    };
    let central_cfg: CentralConfig = match node_config.node.try_into_central() {
        Some(config) => config,
        None => {
            error!("Presented with a non-central `node.yml` file (please adapt it to provide properties for a central node)");
            std::process::exit(1);
        },
    };

    // Create a context for the handler(s)
    let context: Arc<Context> = {
        // Create a client to the relevant proxy thing
        let proxy: ProxyClient = ProxyClient::new(central_cfg.services.prx.address());

        // The state of previously planned workflow snippets per-instance.
        let state: Mutex<HashMap<String, Session>> = Mutex::new(HashMap::new());

        // Build the context
        Arc::new(Context { node_config_path: opts.node_config_path, proxy, state })
    };

    // Next, create the warp server
    let plan = warp::post()
        .and(warp::path("plan"))
        .and(warp::path::end())
        .and(warp::any().map(move || context.clone()))
        .and(warp::body::json())
        .and_then(planner::handle)
        .with(warp::trace::request());
    let paths = plan;

    // Launch it
    let handle = warp::serve(paths).try_bind_with_graceful_shutdown(central_cfg.services.plr.bind, async {
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
    });

    match handle {
        Ok((addr, srv)) => {
            info!("Now serving @ '{addr}'");
            srv.await
        },
        Err(err) => {
            error!("{}", trace!(("Failed to serve at '{}'", central_cfg.services.plr.bind), err));
            std::process::exit(1);
        },
    }
}
