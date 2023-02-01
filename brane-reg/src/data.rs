//  DATA.rs
//    by Lut99
// 
//  Created:
//    26 Sep 2022, 15:40:40
//  Last edited:
//    01 Feb 2023, 15:40:04
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines functions that handle various REST-functions on the `/data`
//!   path (and children).
// 

use std::path::{Path, PathBuf};
use std::sync::Arc;

use log::{debug, error, info};
use rustls::Certificate;
use tempfile::TempDir;
use tokio::fs as tfs;
use tokio::io::AsyncReadExt;
use warp::{Rejection, Reply};
use warp::http::HeaderValue;
use warp::hyper::{Body, StatusCode};
use warp::hyper::body::{Bytes, Sender};
use warp::reply::{self, Response};
use brane_cfg::certs::extract_client_name;
use brane_cfg::node::NodeConfig;
use brane_cfg::policies::{PolicyFile, UserPolicy};
use brane_shr::fs::archive_async;
use specifications::data::{AccessKind, AssetInfo};
use specifications::profiling::ProfileReport;

pub use crate::errors::DataError as Error;
use crate::errors::AuthorizeError;
use crate::spec::Context;
use crate::store::Store;


/***** HELPER FUNCTIONS *****/
/// Runs the do-be-done data transfer by the checker to assess if we're allowed to do it.
/// 
/// # Arguments
/// - `identity`: The name (or other method of identifying the user) of the person who will download the dataset.
/// - `data`: The name of the dataset they are trying to access.
/// 
/// # Returns
/// Whether permission is given or not.
/// 
/// # Errors
/// This function errors if we failed to ask the checker. Clearly, that should be treated as permission denied.
pub async fn assert_data_permission(node_config: &NodeConfig, identifier: impl AsRef<str>, data: impl AsRef<str>) -> Result<bool, AuthorizeError> {
    let identifier : &str = identifier.as_ref();
    let data       : &str = data.as_ref();

    // We don't have a checker yet to ask ;(

    // Instead, consider a simpler policy model...

    // Load the policy file
    let policies: PolicyFile = match PolicyFile::from_path_async(&node_config.node.worker().paths.policies).await {
        Ok(policies) => policies,
        Err(err)     => { return Err(AuthorizeError::PolicyFileError{ err }); },
    };

    // Match all the rules in-order
    for (i, rule) in policies.users.into_iter().enumerate() {
        // Match on the rule
        match rule {
            UserPolicy::AllowAll => {
                debug!("Allowed downloading of dataset '{}' to '{}' based on rule {} (AllowAll)", data, identifier, i);
                return Ok(true);
            },
            UserPolicy::DenyAll => {
                debug!("Denied downloading of dataset '{}' to '{}' based on rule {} (DenyAll)", data, identifier, i);
                return Ok(false);
            },

            UserPolicy::AllowUserAll { name } => {
                if name == identifier {
                    debug!("Allowed downloading of dataset '{}' to '{}' based on rule {} (AllowUserAll '{}')", data, identifier, i, name);
                    return Ok(true);
                }
            },
            UserPolicy::DenyUserAll { name } => {
                if name == identifier {
                    debug!("Denied downloading of dataset '{}' to '{}' based on rule {} (DenyUserAll '{}')", data, identifier, i, name);
                    return Ok(false);
                }
            },

            UserPolicy::Allow{ name, data: allowed_data } => {
                if name == identifier && data == allowed_data {
                    debug!("Allowed downloading of dataset '{}' to '{}' based on rule {} (Allow '{}' on {:?})", data, identifier, i, name, allowed_data);
                    return Ok(true);
                }
            },
            UserPolicy::Deny{ name, data: denied_data } => {
                if name == identifier && data == denied_data {
                    debug!("Denied downloading of dataset '{}' to '{}' based on rule {} (Deny '{}' on {:?})", data, identifier, i, name, denied_data);
                    return Ok(false);
                }
            },
        }
    }

    // Otherwise, didn't find a rule
    Err(AuthorizeError::NoUserPolicy { user: identifier.into(), data: data.into() })
}

/// Runs the do-be-done intermediate result transfer by the checker to assess if we're allowed to do it.
/// 
/// # Arguments
/// - `identity`: The name (or other method of identifying the user) of the person who will download the intermediate result.
/// - `result`: The name of the intermediate result they are trying to access.
/// 
/// # Returns
/// Whether permission is given or not.
/// 
/// # Errors
/// This function errors if we failed to ask the checker. Clearly, that should be treated as permission denied.
pub async fn assert_result_permission(node_config: &NodeConfig, identifier: impl AsRef<str>, result: impl AsRef<str>) -> Result<bool, AuthorizeError> {
    let identifier : &str = identifier.as_ref();
    let result     : &str = result.as_ref();

    // We don't have a checker yet to ask ;(

    // Instead, consider a simpler policy model...

    // Load the policy file
    let policies: PolicyFile = match PolicyFile::from_path_async(&node_config.node.worker().paths.policies).await {
        Ok(policies) => policies,
        Err(err)     => { return Err(AuthorizeError::PolicyFileError{ err }); },
    };

    // Match all the rules in-order
    for (i, rule) in policies.users.into_iter().enumerate() {
        // Match on the rule
        match rule {
            UserPolicy::AllowAll => {
                debug!("Allowed downloading of dataset '{}' to '{}' based on rule {} (AllowAll)", result, identifier, i);
                return Ok(true);
            },
            UserPolicy::DenyAll => {
                debug!("Denied downloading of dataset '{}' to '{}' based on rule {} (DenyAll)", result, identifier, i);
                return Ok(false);
            },

            UserPolicy::AllowUserAll { name } => {
                if name == identifier {
                    debug!("Allowed downloading of dataset '{}' to '{}' based on rule {} (AllowUserAll '{}')", result, identifier, i, name);
                    return Ok(true);
                }
            },
            UserPolicy::DenyUserAll { name } => {
                if name == identifier {
                    debug!("Denied downloading of dataset '{}' to '{}' based on rule {} (DenyUserAll '{}')", result, identifier, i, name);
                    return Ok(false);
                }
            },

            UserPolicy::Allow{ name, data: allowed_result } => {
                if name == identifier && result == allowed_result {
                    debug!("Allowed downloading of dataset '{}' to '{}' based on rule {} (Allow '{}' on {:?})", result, identifier, i, name, allowed_result);
                    return Ok(true);
                }
            },
            UserPolicy::Deny{ name, data: denied_result } => {
                if name == identifier && result == denied_result {
                    debug!("Denied downloading of dataset '{}' to '{}' based on rule {} (Deny '{}' on {:?})", result, identifier, i, name, denied_result);
                    return Ok(false);
                }
            },
        }
    }

    // Otherwise, didn't find a rule
    Err(AuthorizeError::NoUserPolicy { user: identifier.into(), data: result.into() })
}





/***** LIBRARY *****/
/// Handles a GET on the main `/data` path, returning a JSON with the datasets known to this registry.
/// 
/// # Arguments
/// - `context`: The context that carries options and some shared structures between the warp paths.
/// 
/// # Returns
/// The response that can be send back to the client. Contains a JSON-encoded list (`Vec`) of AssetInfo structs.
/// 
/// # Errors
/// This function may error (i.e., reject) if we could not serialize the given store.
pub async fn list(context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling GET on `/data/info` (i.e., list all datasets)...");

    // Load the config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            return Err(warp::reject::reject());
        },
    };
    if !node_config.node.is_worker() { error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display()); return Err(warp::reject::reject()); }

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file(format!("brane-reg /data/info"), format!("brane-reg_{}_info", node_config.node.worker().location_id));
    let _guard = report.time("Total");

    // Load the store
    debug!("Loading data ('{}') and results ('{}')...", node_config.node.worker().paths.data.display(), node_config.node.worker().paths.results.display());
    let store: Store = match Store::from_dirs(&node_config.node.worker().paths.data, &node_config.node.worker().paths.results).await {
        Ok(store) => store,
        Err(err)  => {
            error!("Failed to load the store: {}", err);
            return Err(warp::reject::reject());
        }
    };

    // Simply parse to a string
    debug!("Writing list of datasets as response...");
    let body: String = match serde_json::to_string(&store.datasets) {
        Ok(body) => body,
        Err(err) => {
            return Err(warp::reject::custom(Error::StoreSerializeError { err }));
        }
    };
    let body_len: usize = body.len();

    // Construct a response with the body and the content-length header
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        "Content-Length",
        HeaderValue::from(body_len),
    );

    // Done
    Ok(response)
}



/// Handles a GET on a specific datasets in a child-path of the `/data`-path, returning a JSON with more information about this dataset.
/// 
/// # Arguments
/// - `name`: The name of the dataset to retrieve the metadata for.
/// - `context`: The context that carries options and some shared structures between the warp paths.
/// 
/// # Returns
/// The response that can be send back to the client. Contains a JSON-encoded AssetInfo struct with the metadata.
/// 
/// # Errors
/// This function may error (i.e., reject) if we didn't know the given name or we failred to serialize the relevant AssetInfo.
pub async fn get(name: String, context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling GET on `/data/info/{}` (i.e., get dataset metdata)...", name);

    // Load the config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            return Err(warp::reject::reject());
        },
    };
    if !node_config.node.is_worker() { error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display()); return Err(warp::reject::reject()); }

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file(format!("brane-reg /data/info/{}", name), format!("brane-reg_{}_info-{}", node_config.node.worker().location_id, name));
    let _guard = report.time("Total");

    // Load the store
    debug!("Loading data ('{}') and results ('{}')...", node_config.node.worker().paths.data.display(), node_config.node.worker().paths.results.display());
    let store: Store = match Store::from_dirs(&node_config.node.worker().paths.data, &node_config.node.worker().paths.results).await {
        Ok(store) => store,
        Err(err)  => {
            error!("Failed to load the store: {}", err);
            return Err(warp::reject::reject());
        }
    };

    // Attempt to resolve the name in the given store
    let info: &AssetInfo = match store.get_data(&name) {
        Some(info) => info,
        None       => {
            error!("Unknown dataset '{}'", name);
            return Err(warp::reject::not_found());
        },
    };

    // Serialize it (or at least, try so)
    debug!("Dataset found, returning results");
    let body: String = match serde_json::to_string(info) {
        Ok(body) => body,
        Err(err) => {
            return Err(warp::reject::custom(Error::AssetSerializeError { name, err }));
        },
    };
    let body_len: usize = body.len();

    // Construct a response with the body and the content-length header
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        "Content-Length",
        HeaderValue::from(body_len),
    );

    // Done
    Ok(response)
}



/// Handles a GET that downloads an entire dataset. This basically emulates a data transfer.
/// 
/// # Arguments
/// - `cert`: The client certificate by which we may extract some identity. Only clients that are authenticated by the local store may connect.
/// - `name`: The name of the dataset to download.
/// - `context`: The context that carries options and some shared structures between the warp paths.
/// 
/// # Returns
/// The response that can be sent back to the client. Contains a raw binary of the dataset, which is packaged as an archive before sending.
/// 
/// # Errors
/// This function may error (i.e., reject) if we didn't know the given name or we failed to serialize the relevant AssetInfo.
pub async fn download_data(cert: Option<Certificate>, name: String, context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling GET on `/data/download/{}` (i.e., download dataset)...", name);

    // Load the config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            return Err(warp::reject::reject());
        },
    };
    if !node_config.node.is_worker() { error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display()); return Err(warp::reject::reject()); }

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file(format!("brane-reg /data/download/{}", name), format!("brane-reg_{}_download-{}", node_config.node.worker().location_id, name));

    // Load the store
    debug!("Loading data ('{}') and results ('{}')...", node_config.node.worker().paths.data.display(), node_config.node.worker().paths.results.display());
    let loading = report.time("Disk loading");
    let store: Store = match Store::from_dirs(&node_config.node.worker().paths.data, &node_config.node.worker().paths.results).await {
        Ok(store) => store,
        Err(err)  => {
            error!("Failed to load the store: {}", err);
            return Err(warp::reject::reject());
        }
    };

    // Attempt to resolve the name in the given store
    let info: &AssetInfo = match store.get_data(&name) {
        Some(info) => info,
        None       => {
            error!("Unknown dataset '{}'", name);
            return Err(warp::reject::not_found());
        },
    };
    loading.stop();

    // Attempt to parse the certificate to get the client's name (which tracks because it's already authenticated)
    let auth = report.time("Authorization");
    let cert: Certificate = match cert { Some(cert) => cert, None => { error!("Client did not specify a certificate (client unauthenticated)"); return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN)); } };
    let client_name: String = match extract_client_name(cert) {
        Ok(name) => name,
        Err(err) => {
            error!("{} (client unauthenticated)", err);
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
    };

    // Before we continue, assert that this dataset may be downloaded by this person (uh-oh, how we gon' do that)
    match assert_data_permission(&node_config, &client_name, &info.name).await {
        Ok(true)  => {
            info!("Checker authorized download of dataset '{}' by '{}'", info.name, client_name);
        },

        Ok(false) => {
            info!("Checker denied download of dataset '{}' by '{}'", info.name, client_name);
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
        Err(err) => {
            error!("Failed to consult the checker: {}", err);
            return Err(warp::reject::reject());
        },
    }
    auth.stop();

    // Access the dataset in the way it likes to be accessed
    match &info.access {
        AccessKind::File { path } => {
            debug!("Accessing file '{}' @ '{}' as AccessKind::File...", name, path.display());
            let path: PathBuf = node_config.node.worker().paths.data.join(&name).join(path);
            debug!("File can be found under: '{}'", path.display());

            // First, get a temporary directory
            let arch = report.time("Archiving (file)");
            let tmpdir: TempDir = match TempDir::new() {
                Ok(tmpdir) => tmpdir,
                Err(err)   => {
                    let err = Error::TempDirCreateError{ err };
                    error!("{}", err);
                    return Err(warp::reject::custom(err));
                }
            };

            // Next, create an archive in the temporary directory
            let tar_path: PathBuf = tmpdir.path().join("data.tar.gz");
            if let Err(err) = archive_async(&path, &tar_path, true).await {
                let err = Error::DataArchiveError{ err };
                error!("{}", err);
                return Err(warp::reject::custom(err));
            }
            arch.stop();

            // Now we send the tarball as a file in the reply
            debug!("Sending back reply with compressed archive...");
            let (mut body_sender, body): (Sender, Body) = Body::channel();

            // Spawn a future that reads the file chunk-by-chunk (in case of large files)
            tokio::spawn(async move {
                let _upload = report.time("Uploading (file)");

                // We move the temporary directory here just to keep it in scope
                let _tmpdir: TempDir = tmpdir;

                // Open the archive file to read
                let mut handle: tfs::File = match tfs::File::open(&tar_path).await {
                    Ok(handle) => handle,
                    Err(err)   => {
                        let err = Error::TarOpenError{ path: tar_path, err };
                        error!("{}", err);
                        return Err(warp::reject::custom(err));
                    },
                };

                // Read it chunk-by-chunk
                // (The size of the buffer, like most of the code but edited for not that library cuz it crashes during compilation, has been pulled from https://docs.rs/stream-body/latest/stream_body/)
                let mut buf: [u8; 1024 * 16] = [0; 1024 * 16];
                loop {
                    // Read the chunk
                    let bytes: usize = match handle.read(&mut buf).await {
                        Ok(bytes) => bytes,
                        Err(err)  => {
                            error!("{}", Error::TarReadError{ path: tar_path, err });
                            break;
                        },
                    };
                    if bytes == 0 { break; }

                    // Send that with the body
                    if let Err(err) = body_sender.send_data(Bytes::copy_from_slice(&buf[..bytes])).await {
                        error!("{}", Error::TarSendError{ err });
                    }
                }

                // Done
                Ok(())
            });

            // We use the handle as a stream.
            Ok(reply::with_status(Response::new(body), StatusCode::OK))
        },
    }
}

/// Handles a GET that downloads an intermediate result. This basically emulates a data transfer.
/// 
/// # Arguments
/// - `cert`: The client certificate by which we may extract some identity. Only clients that are authenticated by the local store may connect.
/// - `name`: The name of the intermediate result to download.
/// - `context`: The context that carries options and some shared structures between the warp paths.
/// 
/// # Returns
/// The response that can be sent back to the client. Contains a raw binary of the result, which is packaged as an archive before sending.
/// 
/// # Errors
/// This function may error (i.e., reject) if we didn't know the given name or we failed to serialize the relevant AssetInfo.
pub async fn download_result(cert: Option<Certificate>, name: String, context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling GET on `/results/download/{}` (i.e., download intermediate result)...", name);

    // Load the config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err)   => {
            error!("Failed to load NodeConfig file: {}", err);
            return Err(warp::reject::reject());
        },
    };
    if !node_config.node.is_worker() { error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display()); return Err(warp::reject::reject()); }

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file(format!("brane-reg /results/download/{}", name), format!("brane-reg_{}_download-{}", node_config.node.worker().location_id, name));

    // Load the store
    debug!("Loading data ('{}') and results ('{}')...", node_config.node.worker().paths.data.display(), node_config.node.worker().paths.results.display());
    let loading = report.time("Disk loading");
    let store: Store = match Store::from_dirs(&node_config.node.worker().paths.data, &node_config.node.worker().paths.results).await {
        Ok(store) => store,
        Err(err)  => {
            error!("Failed to load the store: {}", err);
            return Err(warp::reject::reject());
        }
    };

    // Attempt to resolve the name in the given store
    let path: &Path = match store.get_result(&name) {
        Some(path) => path,
        None       => {
            error!("Unknown intermediate result '{}'", name);
            return Err(warp::reject::not_found());
        },
    };
    loading.stop();

    // Attempt to parse the certificate to get the client's name (which tracks because it's already authenticated)
    let auth = report.time("Authorization");
    let cert: Certificate = match cert { Some(cert) => cert, None => { error!("Client did not specify a certificate (client unauthenticated)"); return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN)); } };
    let client_name: String = match extract_client_name(cert) {
        Ok(name) => name,
        Err(err) => {
            error!("{} (client unauthenticated)", err);
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
    };

    // Before we continue, assert that this dataset may be downloaded by this person (uh-oh, how we gon' do that)
    match assert_result_permission(&node_config, &client_name, &name).await {
        Ok(true)  => {
            info!("Checker authorized download of intermediate result '{}' by '{}'", name, client_name);
        },

        Ok(false) => {
            info!("Checker denied download of intermediate result '{}' by '{}'", name, client_name);
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
        Err(err) => {
            error!("Failed to consult the checker: {}", err);
            return Err(warp::reject::reject());
        },
    }
    auth.stop();

    // Start the upload; first, get a temporary directory
    let arch = report.time("Archiving (file)");
    let tmpdir: TempDir = match TempDir::new() {
        Ok(tmpdir) => tmpdir,
        Err(err)   => {
            let err = Error::TempDirCreateError{ err };
            error!("{}", err);
            return Err(warp::reject::custom(err));
        }
    };

    // Next, create an archive in the temporary directory
    let tar_path: PathBuf = tmpdir.path().join("data.tar.gz");
    if let Err(err) = archive_async(&path, &tar_path, true).await {
        let err = Error::DataArchiveError{ err };
        error!("{}", err);
        return Err(warp::reject::custom(err));
    }
    arch.stop();

    // Now we send the tarball as a file in the reply
    debug!("Sending back reply with compressed archive...");
    let (mut body_sender, body): (Sender, Body) = Body::channel();

    // Spawn a future that reads the file chunk-by-chunk (in case of large files)
    tokio::spawn(async move {
        let _upload = report.time("Uploading (file)");

        // We move the temporary directory here just to keep it in scope
        let _tmpdir: TempDir = tmpdir;

        // Open the archive file to read
        let mut handle: tfs::File = match tfs::File::open(&tar_path).await {
            Ok(handle) => handle,
            Err(err)   => {
                let err = Error::TarOpenError{ path: tar_path, err };
                error!("{}", err);
                return Err(warp::reject::custom(err));
            },
        };

        // Read it chunk-by-chunk
        // (The size of the buffer, like most of the code but edited for not that library cuz it crashes during compilation, has been pulled from https://docs.rs/stream-body/latest/stream_body/)
        let mut buf: [u8; 1024 * 16] = [0; 1024 * 16];
        loop {
            // Read the chunk
            let bytes: usize = match handle.read(&mut buf).await {
                Ok(bytes) => bytes,
                Err(err)  => {
                    error!("{}", Error::TarReadError{ path: tar_path, err });
                    break;
                },
            };
            if bytes == 0 { break; }

            // Send that with the body
            if let Err(err) = body_sender.send_data(Bytes::copy_from_slice(&buf[..bytes])).await {
                error!("{}", Error::TarSendError{ err });
            }
        }

        // Done
        Ok(())
    });

    // We use the handle as a stream.
    Ok(reply::with_status(Response::new(body), StatusCode::OK))
}
