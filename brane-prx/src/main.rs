//  MAIN.rs
//    by Lut99
//
//  Created:
//    23 Nov 2022, 10:52:33
//  Last edited:
//    14 Jun 2024, 15:14:24
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `brane-prx` service.
//

mod cli;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig};
use brane_cfg::proxy::ProxyConfig;
use brane_prx::manage;
use brane_prx::ports::PortAllocator;
use brane_prx::spec::Context;
use clap::Parser;
use dotenvy::dotenv;
use error_trace::trace;
use log::LevelFilter;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing::{debug, error, info, warn};
use warp::Filter;



/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    dotenv().ok();
    let args = cli::Cli::parse();

    // Configure logger.
    let mut logger = env_logger::builder();
    logger.format_module_path(false);

    if args.debug {
        logger.filter_level(LevelFilter::Debug).init();
    } else {
        logger.filter_level(LevelFilter::Info).init();
    }
    info!("Initializing brane-prx v{}...", env!("CARGO_PKG_VERSION"));

    // Load the config, making sure it's a worker config
    debug!("Loading node.yml file '{}'...", args.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&args.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            std::process::exit(1);
        },
    };

    // Load the proxy file
    let proxy_config: ProxyConfig = 'proxy: {
        // Extract the proxy path
        let proxy_path: &Path = match &node_config.node {
            NodeSpecificConfig::Central(node) => match &node.paths.proxy {
                Some(path) => path,
                None => break 'proxy Default::default(),
            },

            NodeSpecificConfig::Worker(node) => match &node.paths.proxy {
                Some(path) => path,
                None => break 'proxy Default::default(),
            },

            NodeSpecificConfig::Proxy(node) => &node.paths.proxy,
        };

        // Start loading the file
        debug!("Loading proxy.yml file '{}'...", proxy_path.display());
        match ProxyConfig::from_path(proxy_path) {
            Ok(config) => config,
            Err(err) => {
                error!("{}", trace!(("Failed to load ProxyConfig file"), err));
                std::process::exit(1);
            },
        }
    };

    // Prepare the context for this node
    debug!("Preparing warp...");
    let context: Arc<Context> = Arc::new(Context {
        node_config_path: args.node_config_path,

        ports:  Mutex::new(PortAllocator::new(*proxy_config.outgoing_range.start(), *proxy_config.outgoing_range.end())),
        proxy:  proxy_config,
        opened: Mutex::new(HashMap::new()),
    });

    // Spawn the incoming ports before we listen for new outgoing port requests
    for (port, address) in &context.proxy.incoming {
        if let Err(err) = manage::new_incoming_path(*port, address.clone(), context.clone()).await {
            error!("Failed to spawn new incoming path: {}", err);
        }
    }

    // Prepare the warp paths for management
    let context = warp::any().map(move || context.clone());
    let filter = warp::post()
        .and(warp::path("outgoing"))
        .and(warp::path("new"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(context.clone())
        .and_then(manage::new_outgoing_path);

    // Extract the proxy address
    let bind_addr: SocketAddr = match node_config.node {
        NodeSpecificConfig::Central(node) => node.services.prx.private().bind,
        NodeSpecificConfig::Worker(node) => node.services.prx.private().bind,
        NodeSpecificConfig::Proxy(node) => node.services.prx.bind,
    };

    // Run the server
    info!("Reading to accept new connections @ '{}'...", bind_addr);
    let handle = warp::serve(filter).try_bind_with_graceful_shutdown(bind_addr, async {
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
            error!("{}", trace!(("Failed to serve at '{bind_addr}'"), err));
            std::process::exit(1);
        },
    }
}
