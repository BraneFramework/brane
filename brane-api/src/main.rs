//  MAIN.rs
//    by Lut99
//
//  Created:
//    17 Oct 2022, 15:15:36
//  Last edited:
//    03 Jan 2024, 14:37:08
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `brane-job` service.
//

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use brane_api::errors::ApiError;
use brane_api::schema::{Mutations, Query, Schema};
use brane_api::spec::Context;
use brane_api::{data, health, infra, packages, version};
use brane_cfg::info::Info as _;
use brane_cfg::node::{CentralConfig, NodeConfig};
use brane_prx::client::ProxyClient;
use clap::Parser;
use dotenvy::dotenv;
use error_trace::trace;
use juniper::EmptySubscription;
use log::{LevelFilter, debug, error, info, warn};
use scylla::{Session, SessionBuilder};
use tokio::signal::unix::{Signal, SignalKind, signal};
use warp::Filter;


/***** ARGUMENTS *****/
#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    /// Print debug info
    #[clap(short, long, env = "DEBUG")]
    debug: bool,

    /// Load everything from the node.yml file
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
            error!("Failed to load NodeConfig file: {}", err);
            std::process::exit(1);
        },
    };
    let central: CentralConfig = match node_config.node.try_into_central() {
        Some(central) => central,
        None => {
            error!("Given NodeConfig file '{}' does not have properties for a worker node.", opts.node_config_path.display());
            std::process::exit(1);
        },
    };

    // Configure Scylla.
    debug!("Connecting to scylla...");
    let scylla = match SessionBuilder::new()
        .known_node(central.services.aux_scylla.address.to_string())
        .connection_timeout(Duration::from_secs(3))
        .build()
        .await
    {
        Ok(scylla) => scylla,
        Err(reason) => {
            error!("{}", ApiError::ScyllaConnectError { host: central.services.aux_scylla.address, source: reason });
            std::process::exit(-1);
        },
    };
    debug!("Connected successfully.");

    debug!("Ensuring keyspace & database...");
    if let Err(err) = ensure_db_keyspace(&scylla).await {
        error!("Failed to ensure database keyspace: {}", err)
    };
    if let Err(err) = packages::ensure_db_table(&scylla).await {
        error!("Failed to ensure database table: {}", err)
    };

    // Configure Juniper.
    let node_config_path: PathBuf = opts.node_config_path;
    let scylla = Arc::new(scylla);
    let proxy: Arc<ProxyClient> = Arc::new(ProxyClient::new(central.services.prx.address()));
    let context = warp::any().map(move || Context { node_config_path: node_config_path.clone(), scylla: scylla.clone(), proxy: proxy.clone() });

    let schema = Schema::new(Query {}, Mutations {}, EmptySubscription::new());
    let graphql_filter = juniper_warp::make_graphql_filter(schema, context.clone().boxed());
    let graphql = warp::path("graphql").and(graphql_filter);

    // Configure Warp.
    // Configure the data one
    let list_datasets = warp::path("data").and(warp::path("info")).and(warp::path::end()).and(warp::get()).and(context.clone()).and_then(data::list);
    let get_dataset = warp::path("data")
        .and(warp::path("info"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and(warp::get())
        .and(context.clone())
        .and_then(data::get);
    let data = list_datasets.or(get_dataset);

    // Configure the packages one
    let download_package = warp::path("packages")
        .and(warp::get())
        .and(warp::path::param())
        .and(warp::path::param())
        .and(warp::path::end())
        .and(context.clone())
        .and_then(packages::download);
    let upload_package = warp::path("packages")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::filters::body::stream())
        .and(context.clone())
        .and_then(packages::upload);
    let packages = download_package.or(upload_package);

    // Configure infra
    let list_registries =
        warp::get().and(warp::path("infra")).and(warp::path("registries")).and(warp::path::end()).and(context.clone()).and_then(infra::registries);
    let get_registry = warp::get()
        .and(warp::path("infra"))
        .and(warp::path("registries"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and(context.clone())
        .and_then(infra::get_registry);
    let get_capabilities = warp::get()
        .and(warp::path("infra"))
        .and(warp::path("capabilities"))
        .and(warp::path::param())
        .and(warp::path::end())
        .and(context.clone())
        .and_then(infra::get_capabilities);
    let infra = get_registry.or(list_registries.or(get_capabilities));

    // Configure the health & version
    let health = warp::path("health").and(warp::path::end()).and_then(health::handle);
    let version = warp::path("version").and(warp::path::end()).and_then(version::handle);

    // Construct the final routes
    let routes = data.or(packages.or(infra.or(health.or(version.or(graphql))))).with(warp::log("brane-api"));

    // Run the server
    let handle = warp::serve(routes).try_bind_with_graceful_shutdown(central.services.api.bind, async {
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
            error!("{}", trace!(("Failed to serve at '{}'", central.services.api.bind), err));
            std::process::exit(1);
        },
    }
}

pub async fn ensure_db_keyspace(scylla: &Session) -> Result<scylla::QueryResult, scylla::transport::errors::QueryError> {
    let query = r#"
        CREATE KEYSPACE IF NOT EXISTS brane
        WITH replication = {'class': 'SimpleStrategy', 'replication_factor' : 1};
    "#;

    scylla.query(query, &[]).await
}
