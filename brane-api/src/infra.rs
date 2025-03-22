//  INFRA.rs
//    by Lut99
//
//  Created:
//    02 Nov 2022, 16:21:33
//  Last edited:
//    13 Jul 2023, 13:58:57
//  Auto updated?
//    Yes
//
//  Description:
//!   Returns information about the infrastructure.
//

use std::collections::{HashMap, HashSet};

use brane_cfg::info::Info as _;
use brane_cfg::infra::{InfraFile, InfraLocation};
use brane_cfg::node::NodeConfig;
use brane_prx::spec::NewPathRequestTlsOptions;
use log::{debug, error};
use specifications::address::Address;
use specifications::package::Capability;
use warp::hyper::header::HeaderValue;
use warp::hyper::{Body, Response};
use warp::{Rejection, Reply};

pub use crate::errors::InfraError as Error;
use crate::spec::Context;


/***** LIBRARY *****/
/// Lists the registries at each location.
///
/// # Arguments
/// - `context`: The Context that contains stuff we need to run.
///
/// # Returns
/// A response that can be send to client. Specifically, it will contains a map (i.e., `HashMap`) of locations names to addresses where their registries may be found.
///
/// # Errors
/// This function may error (i.e., reject the request) if we failed to load the infrastructure file.
pub async fn registries(context: Context) -> Result<impl Reply, Rejection> {
    debug!("Handling GET on `/infra/registries` (i.e., list all registry endpoints)...");

    // Load the node config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load NodeConfig file: {}", err);
            return Err(warp::reject::custom(Error::SecretError));
        },
    };
    if !node_config.node.is_central() {
        error!("Provided node config file '{}' is not for a central node", context.node_config_path.display());
        return Err(warp::reject::custom(Error::SecretError));
    }

    // Load the infrastructure file
    let infra: InfraFile = match InfraFile::from_path(&node_config.node.central().paths.infra) {
        Ok(infra) => infra,
        Err(source) => {
            error!("{}", Error::InfrastructureOpenError { path: node_config.node.central().paths.infra.clone(), source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };

    // Iterate through all of the regitries
    let mut locations: HashMap<String, Address> = HashMap::new();
    for (name, loc) in infra.into_iter() {
        locations.insert(name, loc.registry);
    }

    // Now serialize this map
    let body: String = match serde_json::to_string(&locations) {
        Ok(body) => body,
        Err(source) => {
            error!("{}", Error::SerializeError { what: "list of all registry endpoints", source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };
    let body_len: usize = body.len();

    // Create the respones around it
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert("Content-Length", HeaderValue::from(body_len));

    // Done
    Ok(response)
}



/// Returns the registry address for the requested location.
///
/// # Arguments
/// - `loc`: The location that the address is asked of.
/// - `context`: The Context that contains stuff we need to run.
///
/// # Returns
/// A response that can be send to client. Specifically, it will contains the address of the registry as plain text.
///
/// # Errors
/// This function may error (i.e., reject the request) if we failed to load the infrastructure file.
pub async fn get_registry(loc: String, context: Context) -> Result<impl Reply, Rejection> {
    debug!("Handling GET on `/infra/registries/{}` (i.e., get location registry address)...", loc);

    // Load the node config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load NodeConfig file: {}", err);
            return Err(warp::reject::custom(Error::SecretError));
        },
    };
    if !node_config.node.is_central() {
        error!("Provided node config file '{}' is not for a central node", context.node_config_path.display());
        return Err(warp::reject::custom(Error::SecretError));
    }

    // Load the infrastructure file
    let infra: InfraFile = match InfraFile::from_path(&node_config.node.central().paths.infra) {
        Ok(infra) => infra,
        Err(source) => {
            error!("{}", Error::InfrastructureOpenError { path: node_config.node.central().paths.infra.clone(), source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };

    // Find the location requested
    let info: &InfraLocation = match infra.get(&loc) {
        Some(info) => info,
        None => {
            return Err(warp::reject::not_found());
        },
    };

    // Create a body with the registry
    let body: String = info.registry.serialize().to_string();
    let body_len: usize = body.len();

    // Create the respones around it
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert("Content-Length", HeaderValue::from(body_len));

    // Done
    Ok(response)
}



/// Returns the capabilities for the requested location.
///
/// # Arguments
/// - `loc`: The location that the capabilities are asked of.
/// - `context`: The Context that contains stuff we need to run.
///
/// # Returns
/// A response that can be send to client. Specifically, it will contain a set of capabilities supported.
///
/// # Errors
/// This function may error (i.e., reject the request) if we failed to load the infrastructure file or contact the requested domain.
pub async fn get_capabilities(loc: String, context: Context) -> Result<impl Reply, Rejection> {
    debug!("Handling GET on `/infra/capabilities/{}` (i.e., get location capabilities)...", loc);

    // Load the node config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load NodeConfig file: {}", err);
            return Err(warp::reject::custom(Error::SecretError));
        },
    };
    if !node_config.node.is_central() {
        error!("Provided node config file '{}' is not for a central node", context.node_config_path.display());
        return Err(warp::reject::custom(Error::SecretError));
    }

    // Load the infrastructure file
    let infra: InfraFile = match InfraFile::from_path(&node_config.node.central().paths.infra) {
        Ok(infra) => infra,
        Err(source) => {
            error!("{}", Error::InfrastructureOpenError { path: node_config.node.central().paths.infra.clone(), source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };

    // Find the location requested
    let info: &InfraLocation = match infra.get(&loc) {
        Some(info) => info,
        None => {
            return Err(warp::reject::not_found());
        },
    };

    // Ask the location about its capabilities
    let reg_addr: String = format!("{}/infra/capabilities", info.registry);
    let res: reqwest::Response = match context.proxy.get(&reg_addr, Some(NewPathRequestTlsOptions { use_client_auth: false, location: loc })).await {
        Ok(res) => match res {
            Ok(res) => res,
            Err(source) => {
                error!("{}", Error::RequestError { address: reg_addr, source });
                return Err(warp::reject::custom(Error::SecretError));
            },
        },
        Err(source) => {
            error!("{}", Error::ProxyError { source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };
    if !res.status().is_success() {
        error!("{}", Error::RequestFailure { address: reg_addr, code: res.status(), message: res.text().await.ok() });
        return Err(warp::reject::custom(Error::SecretError));
    }

    // Parse the body as the proper JSON
    let capabilities: String = match res.text().await {
        Ok(caps) => caps,
        Err(source) => {
            error!("{}", Error::ResponseBodyError { address: reg_addr, source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };
    let capabilities: HashSet<Capability> = match serde_json::from_str(&capabilities) {
        Ok(caps) => caps,
        Err(source) => {
            error!("{}", Error::ResponseParseError { address: reg_addr, raw: capabilities, source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };

    // Create a body with the registry (re-serialize for full correctness)
    let body: String = match serde_json::to_string(&capabilities) {
        Ok(body) => body,
        Err(source) => {
            error!("{}", Error::CapabilitiesSerializeError { source });
            return Err(warp::reject::custom(Error::SecretError));
        },
    };
    let body_len: usize = body.len();

    // Create the respones around it
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert("Content-Length", HeaderValue::from(body_len));

    // Done
    Ok(response)
}
