#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
#[macro_use]
extern crate juniper;

/* TIM */
// mod data;
mod health;
/*******/
mod packages;
mod schema;

use anyhow::{Context as _, Result};
// use clap::Parser;
use structopt::StructOpt;
use dotenv::dotenv;
use juniper::EmptySubscription;
use log::LevelFilter;
use schema::{Mutations, Query, Schema};
use scylla::{Session, SessionBuilder};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use warp::Filter;

// #[derive(Parser)]
// #[clap(version = env!("CARGO_PKG_VERSION"))]
// struct Opts {
//     /// Service address
//     #[clap(short, long, default_value = "127.0.0.1:8080", env = "ADDRESS")]
//     address: String,
//     /// Print debug info
//     #[clap(short, long, env = "DEBUG", takes_value = false)]
//     debug: bool,
//     /// Print debug info
//     #[clap(short, long, default_value = "127.0.0.1:5000", env = "REGISTRY")]
//     registry: String,
//     /// Scylla endpoint
//     #[clap(short, long, default_value = "127.0.0.1:9042", env = "SCYLLA")]
//     scylla: String,
// }

#[derive(StructOpt)]
struct Opts {
    #[structopt(short, long, default_value = "127.0.0.1:8080", env = "ADDRESS")]
    address: String,
    /// Print debug info
    #[structopt(short, long, env = "DEBUG", takes_value = false)]
    debug: bool,
    /// Print debug info
    #[structopt(short, long, default_value = "127.0.0.1:5000", env = "REGISTRY")]
    registry: String,
    /// Scylla endpoint
    #[structopt(short, long, default_value = "127.0.0.1:9042", env = "SCYLLA")]
    scylla: String,
}

#[derive(Clone)]
pub struct Context {
    pub registry: String,
    pub scylla: Arc<Session>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let opts = Opts::from_args();

    // Configure logger.
    let mut logger = env_logger::builder();
    logger.format_module_path(false);

    if opts.debug {
        logger.filter_level(LevelFilter::Debug).init();
    } else {
        logger.filter_level(LevelFilter::Info).init();
    }

    // Configure Scylla.
    let scylla = SessionBuilder::new()
        .known_node(&opts.scylla)
        .connection_timeout(Duration::from_secs(3))
        .build()
        .await?;

    ensure_db_keyspace(&scylla).await?;
    packages::ensure_db_table(&scylla).await?;

    let scylla = Arc::new(scylla);
    let registry = opts.registry.clone();

    // Configure Juniper.
    let context = warp::any().map(move || Context {
        registry: registry.clone(),
        scylla: scylla.clone(),
    });

    let schema = Schema::new(Query {}, Mutations {}, EmptySubscription::new());
    let graphql_filter = juniper_warp::make_graphql_filter(schema, context.clone().boxed());
    let graphql = warp::path("graphql").and(graphql_filter);

    // Configure Warp.
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
        .and(warp::filters::body::bytes())
        .and(context.clone())
        .and_then(packages::upload);
    
    /* TIM */
    // Configure the health
    let health = warp::path("health")
        .and(warp::path::end())
        .and_then(health::health);
    /*******/

    let packages = download_package.or(upload_package);
    /* TIM */
    // let routes = graphql.or(packages).with(warp::log("brane-api"));
    let routes = health.or(graphql.or(packages)).with(warp::log("brane-api"));
    /*******/

    let address: SocketAddr = opts.address.clone().parse()?;
    warp::serve(routes).run(address).await;

    Ok(())
}

///
///
///
pub async fn ensure_db_keyspace(scylla: &Session) -> Result<()> {
    let query = r#"
        CREATE KEYSPACE IF NOT EXISTS brane
        WITH replication = {'class': 'SimpleStrategy', 'replication_factor' : 1};
    "#;

    scylla
        .query(query, &[])
        .await
        .map(|_| Ok(()))
        .map_err(|e| anyhow!("{:?}", e))
        .context("Failed to create 'brane' keyspace.")?
}
