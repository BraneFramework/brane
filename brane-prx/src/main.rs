//  MAIN.rs
//    by Lut99
// 
//  Created:
//    23 Nov 2022, 10:52:33
//  Last edited:
//    16 Mar 2023, 17:41:25
//  Auto updated?
//    Yes
// 
//  Description:
//!   Entrypoint to the `brane-prx` service.
// 

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use clap::Parser;
use dotenvy::dotenv;
use log::{debug, error, info, LevelFilter};
use warp::Filter;

use brane_cfg::spec::Config as _;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig};
use brane_cfg::proxy::ProxyConfig;

use brane_prx::spec::Context;
use brane_prx::ports::PortAllocator;
use brane_prx::manage;


/***** ARGUMENTS *****/
#[derive(Parser)]
#[clap(name = "Brane proxy service", version = env!("CARGO_PKG_VERSION"), author, about = "A rudimentary, SOCKS-as-a-Service proxy service for outgoing connections from a domain.")]
struct Arguments {
    /// Print debug info
    #[clap(long, action, help = "If given, shows additional logging information.", env = "DEBUG")]
    debug : bool,

    /// Node environment metadata store.
    #[clap(short, long, default_value = "/node.yml", help = "The path to the node environment configuration. This defines things such as where local services may be found or where to store files, as wel as this service's service address.", env = "NODE_CONFIG_PATH")]
    node_config_path : PathBuf,
}





/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    dotenv().ok();
    let args: Arguments = Arguments::parse();

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
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            std::process::exit(1);
        },
    };

    // Load the proxy file
    let proxy_config: ProxyConfig = 'proxy: {
        // Extract the proxy path
        let proxy_path: &Path = match &node_config.node {
            NodeSpecificConfig::Central(node) => match &node.paths.proxy {
                Some(path) => path,
                None       => { break 'proxy Default::default() },
            },

            NodeSpecificConfig::Worker(node) => match &node.paths.proxy {
                Some(path) => path,
                None       => { break 'proxy Default::default() },
            },

            NodeSpecificConfig::Proxy(node) => &node.paths.proxy,
        };

        // Start loading the file
        debug!("Loading proxy.yml file '{}'...", proxy_path.display());
        match ProxyConfig::from_path(proxy_path) {
            Ok(config) => config,
            Err(err)   => {
                error!("Failed to load ProxyConfig file: {}", err);
                std::process::exit(1);
            },
        }
    };

    // Prepare the context for this node
    debug!("Preparing warp...");
    let context: Arc<Context> = Arc::new(Context {
        node_config_path : args.node_config_path,

        ports  : Mutex::new(PortAllocator::new(*proxy_config.outgoing_range.start(), *proxy_config.outgoing_range.end())),
        proxy  : proxy_config,
        opened : Mutex::new(HashMap::new()),
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
        NodeSpecificConfig::Worker(node)  => node.services.prx.private().bind,
        NodeSpecificConfig::Proxy(node)   => node.services.prx.bind,
    };

    // Run the server
    info!("Reading to accept new connections @ '{}'...", bind_addr);
    warp::serve(filter).run(bind_addr).await
}
