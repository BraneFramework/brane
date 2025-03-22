//  DATA.rs
//    by Lut99
//
//  Created:
//    26 Sep 2022, 17:20:55
//  Last edited:
//    07 Jun 2023, 16:29:39
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines functions that handle REST-functions to the `/data` path and
//!   nested.
//

use std::collections::HashMap;

use brane_cfg::info::Info as _;
use brane_cfg::infra::InfraFile;
use brane_cfg::node::NodeConfig;
use brane_prx::spec::NewPathRequestTlsOptions;
use log::{debug, error};
use reqwest::StatusCode;
use specifications::data::{AssetInfo, DataInfo};
use warp::http::{HeaderValue, Response};
use warp::hyper::Body;
use warp::{Rejection, Reply};

pub use crate::errors::DataError as Error;
use crate::spec::Context;


/***** HELPER MACROS *****/
/// Quits a path callback with a SecretError.
macro_rules! fail {
    () => {
        return Err(warp::reject::custom(Error::SecretError))
    };
}





/***** LIBRARY *****/
/// Lists the datasets that are known in the instance.
///
/// # Arguments
/// - `context`: The Context that contains stuff we need to run.
///
/// # Returns
/// A response that can be send to client. Specifically, it will contains a map (i.e., `HashMap`) of DataInfo structs that describe all the known datasets and where they live (mapped by their name).
///
/// # Errors
/// This function may error (i.e., reject the request) if we failed to load the infrastructure file.
pub async fn list(context: Context) -> Result<impl Reply, Rejection> {
    debug!("Handling GET on `/data/info` (i.e., list all datasets)...");

    // Load the node config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(source) => {
            error!("Failed to load NodeConfig file: {}", source);
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

    // Iterate through all the locations (each of which have their own registry service)
    let mut datasets: HashMap<String, DataInfo> = HashMap::new();
    for (loc_name, loc) in infra {
        // Run a GET-request on `/data/info` to fetch all datasets in this domain
        let address: String = format!("{}/data/info", loc.registry);
        let res: reqwest::Response =
            match context.proxy.get(&address, Some(NewPathRequestTlsOptions { location: loc_name.clone(), use_client_auth: false })).await {
                Ok(res) => match res {
                    Ok(res) => res,
                    Err(source) => {
                        error!("{} (skipping domain)", Error::RequestError { address, source });
                        continue;
                    },
                },
                Err(source) => {
                    error!("{} (skipping domain)", Error::ProxyError { source });
                    continue;
                },
            };
        if res.status() == StatusCode::NOT_FOUND {
            // Search the next one instead
            continue;
        }

        // Fetch the body
        let body: String = match res.text().await {
            Ok(body) => body,
            Err(source) => {
                error!("{} (skipping domain)", Error::ResponseBodyError { address, source });
                continue;
            },
        };
        let local_sets: HashMap<String, AssetInfo> = match serde_json::from_str(&body) {
            Ok(body) => body,
            Err(source) => {
                debug!("Received body: \"\"\"{}\"\"\"", body);
                error!("{} (skipping domain)", Error::ResponseParseError { address, source });
                continue;
            },
        };

        // Merge that into the existing mapping of DataInfos
        for (n, d) in local_sets {
            if let Some(info) = datasets.get_mut(&n) {
                // Add this location
                info.access.insert(loc_name.clone(), d.access);
            } else {
                datasets.insert(n, d.into_data_info(loc_name.clone()));
            }
        }
    }

    // Now serialize this map
    let body: String = match serde_json::to_string(&datasets) {
        Ok(body) => body,
        Err(source) => {
            error!("{}", Error::SerializeError { what: "list of all datasets", source });
            fail!();
        },
    };
    let body_len: usize = body.len();

    // Create the respones around it
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert("Content-Length", HeaderValue::from(body_len));

    // Done
    Ok(response)
}



/// Retrieves all information about the given dataset.
///
/// # Arguments
/// - `name`: The name of the dataset to query about.
/// - `context`: The Context that contains stuff we need to run.
///
/// # Returns
/// A response that can be send to client. Specifically, it will contains a DataInfo struct that describes everything we know about it.
///
/// # Errors
/// This function may error (i.e., reject the request) if the given name was not known.
pub async fn get(name: String, context: Context) -> Result<impl Reply, Rejection> {
    debug!("Handling GET on `/data/info/{}` (i.e., get dataset info)...", name);

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

    // Iterate through all the locations (each of which have their own registry service)
    let mut dataset: Option<DataInfo> = None;
    for (loc_name, loc) in infra {
        // Run a GET-request on `/data` to fetch the specific dataset we're asked for
        let address: String = format!("{}/data/info/{}", loc.registry, name);
        let res: reqwest::Response =
            match context.proxy.get(&address, Some(NewPathRequestTlsOptions { location: loc_name.clone(), use_client_auth: false })).await {
                Ok(res) => match res {
                    Ok(res) => res,
                    Err(source) => {
                        error!("{} (skipping domain)", Error::RequestError { address, source });
                        continue;
                    },
                },
                Err(source) => {
                    error!("{} (skipping domain)", Error::ProxyError { source });
                    continue;
                },
            };
        if res.status() == StatusCode::NOT_FOUND {
            // Search the next one instead
            continue;
        }

        // Fetch the body
        let body: String = match res.text().await {
            Ok(body) => body,
            Err(source) => {
                error!("{} (skipping domain datasets)", Error::ResponseBodyError { address, source });
                continue;
            },
        };
        let local_set: AssetInfo = match serde_json::from_str(&body) {
            Ok(body) => body,
            Err(source) => {
                debug!("Received body: \"\"\"{}\"\"\"", body);
                error!("{} (skipping domain datasets)", Error::ResponseParseError { address, source });
                continue;
            },
        };

        // Either add or set that as the result
        if let Some(info) = &mut dataset {
            info.access.insert(loc_name, local_set.access);
        } else {
            dataset = Some(local_set.into_data_info(loc_name));
        }
    }

    // If we failed to find it, 404 as well
    if dataset.is_none() {
        return Err(warp::reject::not_found());
    }

    // Now serialize this thing
    let body: String = match serde_json::to_string(&dataset) {
        Ok(body) => body,
        Err(source) => {
            error!("{}", Error::SerializeError { what: "dataset metadata", source });
            fail!();
        },
    };
    let body_len: usize = body.len();

    // Create the respones around it
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert("Content-Length", HeaderValue::from(body_len));

    // Done
    Ok(response)
}
