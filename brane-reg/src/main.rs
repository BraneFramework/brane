//  MAIN.rs
//    by Lut99
// 
//  Created:
//    26 Sep 2022, 15:11:44
//  Last edited:
//    28 Feb 2023, 16:00:22
//  Auto updated?
//    Yes
// 
//  Description:
//!   Entrypoint to the `brane-reg` service.
// 

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use dotenvy::dotenv;
use log::{debug, error, info, LevelFilter};
use rustls::Certificate;
use warp::Filter;

use brane_cfg::spec::Config as _;
use brane_cfg::node::{NodeConfig, WorkerConfig};

use brane_reg::spec::Context;
use brane_reg::server::serve_with_auth;
use brane_reg::health;
use brane_reg::version;
use brane_reg::infra;
use brane_reg::data;


/***** ARGUMENTS *****/
/// Defines the arguments for the `brane-reg` service.
#[derive(Parser)]
struct Args {
    #[clap(long, action, help = "If given, provides additional debug prints on the logger.", env="DEBUG")]
    debug : bool,

    /// Load everything from the node.yml file
    #[clap(short, long, default_value = "/node.yml", help = "The path to the node environment configuration. This defines things such as where local services may be found or where to store files, as wel as this service's service address.", env = "NODE_CONFIG_PATH")]
    node_config_path : PathBuf,
}





/***** ENTYRPOINT *****/
#[tokio::main]
async fn main() {
    // Read the env & CLI args
    dotenv().ok();
    let args = Args::parse();

    // Setup the logger according to the debug flag
    let mut logger = env_logger::builder();
    logger.format_module_path(false);
    if args.debug {
        logger.filter_level(LevelFilter::Debug).init();
    } else {
        logger.filter_level(LevelFilter::Info).init();
    }
    info!("Initializing brane-reg v{}...", env!("CARGO_PKG_VERSION"));

    // Load the config, making sure it's a worker config
    debug!("Loading node.yml file '{}'...", args.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&args.node_config_path) {
        Ok(config) => config,
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            std::process::exit(1);
        },
    };
    if !node_config.node.is_worker() { error!("Given NodeConfig file '{}' does not have properties for a worker node.", args.node_config_path.display()); std::process::exit(1); }



    // Put the path in a context
    let context : Arc<Context> = Arc::new(Context {
        node_config_path : args.node_config_path,
    });
    let context = warp::any().map(move || context.clone());



    // Prepare the filters for the webserver
    let list_assets = warp::get()
        .and(warp::path("data"))
        .and(warp::path("info"))
        .and(warp::path::end())
        .and(context.clone())
        .and_then(data::list);
    let get_asset = warp::get()
        .and(warp::path("data"))
        .and(warp::path("info"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and(context.clone())
        .and_then(data::get);
    let download_asset = warp::get()
        .and(warp::ext::get::<Option<Certificate>>())
        .and(warp::path("data"))
        .and(warp::path("download"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and(context.clone())
        .and_then(data::download_data);
    let download_result = warp::get()
        .and(warp::ext::get::<Option<Certificate>>())
        .and(warp::path("results"))
        .and(warp::path("download"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and(context.clone())
        .and_then(data::download_result);
    let infra_capabilities = warp::get()
        .and(warp::path("infra"))
        .and(warp::path("capabilities"))
        .and(warp::path::end())
        .and(context.clone())
        .and_then(infra::get_capabilities);
    let version = warp::path("version")
        .and(warp::path::end())
        .and_then(version::get);
    let health = warp::path("health")
        .and(warp::path::end())
        .and_then(health::get);
    let filter = list_assets.or(get_asset).or(download_asset).or(download_result).or(infra_capabilities).or(version).or(health);

    // Extract the things we need from the config
    let worker: &WorkerConfig = match node_config.node.try_worker() {
        Some(worker) => worker,
        None         => { error!("Provided with a non-worker `node.yml` (please change it so that it lists the properties of a worker node)"); std::process::exit(1); },
    };

    // Run it
    match serve_with_auth(worker.paths.certs.join("server.pem"), worker.paths.certs.join("server-key.pem"), worker.paths.certs.join("ca.pem"), filter, worker.services.reg.bind).await {
        Ok(_)    => {},
        Err(err) => {
            error!("{}", err);
            std::process::exit(1);
        },
    }
}
