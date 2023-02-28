//  MAIN.rs
//    by Lut99
// 
//  Created:
//    23 Nov 2022, 10:52:33
//  Last edited:
//    28 Feb 2023, 16:14:42
//  Auto updated?
//    Yes
// 
//  Description:
//!   Entrypoint to the `brane-prx` service.
// 

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use clap::Parser;
use dotenvy::dotenv;
use log::{debug, error, info, LevelFilter};
use warp::Filter;

use brane_cfg::spec::Config as _;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig};

use brane_prx::spec::Context;
use brane_prx::ports::PortAllocator;
use brane_prx::manage;


/***** ARGUMENTS *****/
#[derive(Parser)]
#[clap(name = "Brane proxy service", version = env!("CARGO_PKG_VERSION"), author, about = "A rudimentary, SOCKS-as-a-Service proxy service for outgoing connections from a domain.")]
struct Arguments {
    /// Print debug info
    #[clap(long, action, help = "If given, shows additional logging information.", env = "DEBUG")]
    debug      : bool,
    /// Defines the port range to allocate new paths in.
    #[clap(short, long, default_value = "4200-4300", help = "The range to allocate new path ports in. Should be given as `<start>-<end>`, where both `<start>` and `<end>` are inclusive, and `<start>` <= `<end>`.")]
    path_range : String,

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

    // Parse the port range
    debug!("Parsing port range...");
    let (start, end): (u16, u16) = {
        // Find the dash
        let dash_pos: usize = match args.path_range.find('-') {
            Some(pos) => pos,
            None      => {
                error!("Given port range '{}' does not have the '-' in it", args.path_range);
                std::process::exit(1);
            },
        };

        // Split it into start and stop
        let start : &str = &args.path_range[..dash_pos];
        let end   : &str = &args.path_range[dash_pos + 1..];

        // Parse both as numbers
        let start: u16 = match u16::from_str(start) {
            Ok(start) => start,
            Err(err)  => { error!("Given port range start '{}' is not a port number: {}", start, err); std::process::exit(1); },
        };
        let end: u16 = match u16::from_str(end) {
            Ok(end)  => end,
            Err(err) => { error!("Given port range end '{}' is not a port number: {}", end, err); std::process::exit(1); },
        };

        // Assert the one is before than the other
        if start > end { error!("Port range start cannot be after port range end ({} > {})", start, end); std::process::exit(1); }
        (start, end)
    };

    // Prepare the context for this node
    debug!("Preparing warp...");
    let context: Arc<Context> = Arc::new(Context {
        node_config_path : args.node_config_path,

        proxy  : node_config.proxy,
        opened : Mutex::new(HashMap::new()),
        ports  : Mutex::new(PortAllocator::new(start, end)),
    });
    let context = warp::any().map(move || context.clone());

    // Prepare the warp paths for management
    let filter = warp::post()
        .and(warp::path("paths"))
        .and(warp::path("new"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(context.clone())
        .and_then(manage::new_path);

    // Extract the proxy address
    let bind_addr: SocketAddr = match node_config.node {
        NodeSpecificConfig::Central(node) => node.services.prx.bind,
        NodeSpecificConfig::Worker(node)  => node.services.prx.bind,
    };

    // Run the server
    info!("Reading to accept new connections @ '{}'...", bind_addr);
    warp::serve(filter).run(bind_addr).await
}
