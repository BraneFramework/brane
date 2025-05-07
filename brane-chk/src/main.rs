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
use std::sync::Arc;

use axum::Router;
use brane_cfg::info::Info;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig, WorkerConfig};
use brane_chk::apis::{Deliberation, inject_reasoner_api};
use brane_chk::reasonerconn::EFlintHaskellReasonerConnectorWithInterface;
use brane_chk::stateresolver::BraneStateResolver;
use clap::Parser;
use enum_debug::EnumDebug as _;
use error_trace::trace;
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
async fn main() {
    // Parse the arguments
    let args = Arguments::parse();

    // Setup the logger
    tracing_subscriber::fmt().with_max_level(if args.trace { Level::TRACE } else { Level::DEBUG }).init();
    info!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));


    /* Step 1: Prepare the servers */
    // Read the node YAML file.
    let node: WorkerConfig = match NodeConfig::from_path_async(&args.node_config_path).await {
        Ok(node) => match node.node {
            NodeSpecificConfig::Worker(cfg) => cfg,
            other => {
                error!("Found node.yml for a {}, expected a Worker", other.variant());
                std::process::exit(1);
            },
        },
        Err(err) => {
            error!("{}", trace!(("Failed to lode node config file '{}'", args.node_config_path.display()), err));
            std::process::exit(1);
        },
    };

    // Setup the logger
    let logger: FileLogger = FileLogger::new(format!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION")), args.log_path);

    // Setup the reasoner connector
    let reasoner: Arc<EFlintHaskellReasonerConnectorWithInterface> = match EFlintHaskellReasonerConnectorWithInterface::new_async(
        shlex::split(&args.backend_cmd).unwrap_or_else(|| vec![args.backend_cmd]),
        args.policy,
        PrefixedHandler::new(Cow::Owned(args.prefix)),
        &logger,
    )
    .await
    {
        Ok(reasoner) => Arc::new(reasoner),
        Err(err) => {
            error!("{}", trace!(("Failed to create EFlintHaskellReasonerConnectorWithInterface"), err));
            std::process::exit(1);
        },
    };

    // Setup the state resolver
    let resolver: BraneStateResolver = BraneStateResolver::new(node.usecases, &reasoner.reasoner.context().base_policy_hash);

    // Setup the database connection
    let conn: Arc<SQLiteDatabase<_>> = match SQLiteDatabase::new_async(&args.database_path, policy_store::databases::sqlite::MIGRATIONS).await {
        Ok(conn) => Arc::new(conn),
        Err(err) => {
            error!("{}", trace!(("Failed to setup connection to SQLiteDatabase '{}'", args.database_path.display()), err));
            std::process::exit(1);
        },
    };



    /* Step 2: Setup the deliberation & store APIs */
    // Deliberation
    let delib: Deliberation<_, _, _> = match Deliberation::new(args.delib_addr, &args.delib_keys, conn.clone(), resolver, reasoner.clone(), logger) {
        Ok(server) => server,
        Err(err) => {
            error!("{}", trace!(("Failed to create deliberation API server"), err));
            std::process::exit(1);
        },
    };

    // Store
    let resolver: KidResolver = match KidResolver::new(&args.store_keys) {
        Ok(resolver) => resolver,
        Err(err) => {
            error!("{}", trace!(("Failed to create KidResolver with file {:?}", args.store_keys.display()), err));
            std::process::exit(1);
        },
    };
    let store: Arc<AxumServer<_, _>> = Arc::new(AxumServer::new(args.store_addr, JwkResolver::new("username", resolver), conn));

    // Also inject the reasoner context endpoint
    let paths: Router<()> = inject_reasoner_api(store.clone(), reasoner, AxumServer::routes(store.clone()));



    /* Step 3: Host them concurrently */
    tokio::select! {
        res = delib.serve() => match res {
            Ok(_) => info!("Terminated."),
            Err(err) => {
                error!("{}", trace!(("Failed to host deliberation API"), err));
                std::process::exit(1);
            }
        },
        res = AxumServer::serve_router(store, paths) => match res {
            Ok(_) => info!("Terminated."),
            Err(err) => {
                error!("{}", trace!(("Failed to host store API"), err));
                std::process::exit(1);
            }
        },
    }
}
