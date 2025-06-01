//  MAIN.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:13:06
//  Last edited:
//    01 May 2025, 16:24:27
//  Auto updated?
//    Yes
//
//  Description:
//!   The checker is the entity in the Brane system that is responsible
//!   for consulting a backend reasoner. In XACML terms, it might be
//!   called a Policy Decision Point (PDP).
//

// Declare modules
pub mod apis;
pub mod question;
pub mod reasonerconn;
pub mod stateresolver;
pub mod workflow;

use std::borrow::Cow;
// Imports
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use axum::Router;
use brane_cfg::info::Info;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig};
use brane_chk::apis::{Deliberation, inject_reasoner_api};
use brane_chk::reasonerconn::EFlintHaskellReasonerConnectorWithInterface;
use brane_chk::stateresolver::BraneStateResolver;
use brane_shr::errors::confidentiality::BinaryError;
use clap::Parser;
use enum_debug::EnumDebug as _;
use policy_reasoner::loggers::file::FileLogger;
use policy_reasoner::reasoners::eflint_haskell::reasons::PrefixedHandler;
use policy_reasoner::spec::reasonerconn::ReasonerConnector as _;
use policy_store::auth::jwk::JwkResolver;
use policy_store::auth::jwk::keyresolver::KidResolver;
use policy_store::databases::sqlite::SQLiteDatabase;
use policy_store::servers::axum::AxumServer;
use tracing::{Level, error, info};


/***** ARGUMENTS *****/
#[derive(Debug, Parser)]
struct Arguments {
    /// Whether to enable TRACE-level debug statements.
    #[clap(long)]
    trace: bool,

    /// Node config store.
    #[clap(
        short = 'n',
        long,
        default_value = "./node.yml",
        help = "The path to the node environment configuration. For the checker, this ONLY defines the usecase mapping. The rest is given directly \
                as arguments (but probably via `branectl`).",
        env = "NODE_CONFIG_PATH"
    )]
    node_config_path: PathBuf,

    /// The address of the deliberation API on which to serve.
    #[clap(short = 'a', long, default_value = "127.0.0.1:50053", env = "DELIB_ADDRESS")]
    delib_addr: SocketAddr,
    /// The address of the store API on which to serve.
    #[clap(short = 'A', long, default_value = "127.0.0.1:50054", env = "STORE_ADDRESS")]
    store_addr: SocketAddr,

    /// The path to the deliberation API keystore.
    #[clap(short = 'k', long, default_value = "./delib_keys.json", env = "POLICY_DELIB_KEYS_PATH")]
    delib_keys: PathBuf,
    /// The path to the store API keystore.
    #[clap(short = 'K', long, default_value = "./store_keys.json", env = "POLICY_STORE_KEYS_PATH")]
    store_keys: PathBuf,

    /// The path to the output log file.
    #[clap(short = 'l', long, default_value = "./checker.log", env = "LOG_PATH")]
    log_path: PathBuf,
    /// The path to the database file.
    #[clap(short = 'd', long, default_value = "./policies.db", env = "POLICY_DB_PATH")]
    database_path: PathBuf,
    /// The command of the eFLINT REPL to spawn.
    #[clap(short = 'b', long, default_value = "eflint-repl")]
    backend_cmd: String,
    /// The path to the base policy file to load. This is prefixed to every question and runtime context.
    #[clap(short = 'p', long, default_value = "./policy.eflint", env = "POLICY_FILE")]
    policy: PathBuf,
    /// Any prefix that, when given, reveals certain violations.
    #[clap(short = 'P', long, default_value = "pub-", env = "POLICY_PREFIX")]
    prefix: String,
}



/***** ENTRYPOINT *****/
#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    // Parse the arguments
    let args = Arguments::parse();

    // Setup the logger
    tracing_subscriber::fmt().with_max_level(if args.trace { Level::TRACE } else { Level::DEBUG }).init();
    info!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));

    match run(args).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            error!(err = e.err, "{msg}", msg = e.msg);
            ExitCode::FAILURE
        },
    }
}

async fn run(args: Arguments) -> Result<(), BinaryError> {
    /* Step 1: Prepare the servers */
    // Read the node YAML file.
    let config = NodeConfig::from_path_async(&args.node_config_path).await.map_err(|source| {
        BinaryError::from_error(format!("Failed to lode node config file '{}'", args.node_config_path.display()), Box::new(source))
    })?;

    let node = match config.node {
        NodeSpecificConfig::Worker(cfg) => cfg,
        other => {
            return Err(BinaryError::without_source(format!("Found node.yml for a {}, expected a Worker", other.variant())));
        },
    };

    // Setup the logger
    let logger = FileLogger::new(format!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION")), args.log_path);

    // Setup the reasoner connector
    let reasoner = EFlintHaskellReasonerConnectorWithInterface::new_async(
        shlex::split(&args.backend_cmd).unwrap_or_else(|| vec![args.backend_cmd]),
        args.policy,
        PrefixedHandler::new(Cow::Owned(args.prefix)),
        &logger,
    )
    .await
    .map_err(|err| BinaryError::from_error("Could not setup the reasoner".into(), err))?;

    let reasoner = Arc::new(reasoner);

    // Setup the state resolver
    let resolver = BraneStateResolver::new(node.usecases, &reasoner.reasoner.context().base_policy_hash);

    // Setup the database connection
    let conn = SQLiteDatabase::new_async(&args.database_path, policy_store::databases::sqlite::MIGRATIONS).await.map_err(|source| {
        BinaryError::from_error(format!("Failed to setup connection to SQLiteDatabase '{}'", args.database_path.display()), source)
    })?;
    let conn = Arc::new(conn);

    /* Step 2: Setup the deliberation & store APIs */
    // Deliberation
    let delib = Deliberation::new(args.delib_addr, &args.delib_keys, conn.clone(), resolver, reasoner.clone(), logger)
        .map_err(|source| BinaryError::from_error("Failed to create deliberation API server".to_owned(), source))?;

    // Store
    let resolver = KidResolver::new(&args.store_keys)
        .map_err(|source| BinaryError::from_error(format!("Failed to create KidResolver with file {:?}", args.store_keys.display()), source))?;

    let store = Arc::new(AxumServer::new(args.store_addr, JwkResolver::new("username", resolver), conn));

    // Also inject the reasoner context endpoint
    let paths: Router<()> = inject_reasoner_api(store.clone(), reasoner, AxumServer::routes(store.clone()));



    /* Step 3: Host them concurrently */
    tokio::select! {
        res = delib.serve() => {
            res.map_err(|source| BinaryError::from_error("Failed to host deliberation API".to_owned(), source))?;
            info!("Terminated.");
        },
        res = AxumServer::serve_router(store, paths) => {
            res.map_err(|source| BinaryError::from_error("Failed to host store API".to_owned(), source))?;
            info!("Terminated.")
        }
    }

    Ok(())
}
