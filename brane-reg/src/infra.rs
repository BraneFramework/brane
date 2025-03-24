//  INFRA.rs
//    by Lut99
//
//  Created:
//    05 Jan 2023, 11:35:25
//  Last edited:
//    16 Jan 2024, 17:33:30
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines path functions for infrastructure-related querying.
//

use std::collections::HashSet;
use std::sync::Arc;

use brane_cfg::backend::BackendFile;
use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig, WorkerConfig};
use error_trace::trace;
use specifications::package::Capability;
use tracing::{error, info};
use warp::http::HeaderValue;
use warp::hyper::Body;
use warp::reply::Response;
use warp::{Rejection, Reply};

use crate::spec::Context;


/***** LIBRARY *****/
/// Handles a GET on the `/infra/capabilities` path, returning what kind of capabilities this infrastructure supports.
///
/// # Returns
/// The response that can be send back to the client. Contains the set of capabilities supported.
///
/// # Errors
/// This function doesn't usually error.
pub async fn get_capabilities(context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling GET on `/infra/capabilities` (i.e., get domain capabilities)...");

    // Read the node file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            return Err(warp::reject::reject());
        },
    };
    let worker_config: WorkerConfig = if let NodeSpecificConfig::Worker(config) = node_config.node {
        config
    } else {
        panic!("Got a non-worker node config for the registry service");
    };

    // Read the backend file
    let backend: BackendFile = match BackendFile::from_path(worker_config.paths.backend) {
        Ok(backend) => backend,
        Err(err) => {
            error!("{}", trace!(("Failed to load backend file"), err));
            return Err(warp::reject::reject());
        },
    };

    // Serialize the capabilities
    let capabilities: HashSet<Capability> = backend.capabilities.unwrap_or_default();
    let capabilities: String = match serde_json::to_string(&capabilities) {
        Ok(capabilities) => capabilities,
        Err(err) => {
            error!("{}", trace!(("Failed to serialize backend capabilities"), err));
            return Err(warp::reject::reject());
        },
    };
    let capabilities_len: usize = capabilities.len();

    // Construct a response with the body and the content-length header
    let mut response = Response::new(Body::from(capabilities));
    response.headers_mut().insert("Content-Length", HeaderValue::from(capabilities_len));

    // Done
    Ok(response)
}
