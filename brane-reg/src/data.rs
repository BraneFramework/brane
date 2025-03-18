//  DATA.rs
//    by Lut99
//
//  Created:
//    26 Sep 2022, 15:40:40
//  Last edited:
//    07 Feb 2024, 14:19:12
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines functions that handle various REST-functions on the `/data`
//!   path (and children).
//

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use brane_ast::Workflow;
use brane_ast::ast::Edge;
use brane_ast::func_id::FunctionId;
use brane_cfg::certs::extract_client_name;
use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig, WorkerConfig};
use brane_exe::pc::ProgramCounter;
use brane_shr::formatters::BlockFormatter;
use brane_shr::fs::archive_async;
use brane_tsk::errors::AuthorizeError;
use deliberation::spec::Verdict;
use enum_debug::EnumDebug as _;
use error_trace::{ErrorTrace as _, trace};
use log::{debug, error, info};
use reqwest::header;
use rustls::Certificate;
use serde::{Deserialize, Serialize};
use specifications::checking::DELIBERATION_API_TRANSFER_DATA;
use specifications::data::{AccessKind, AssetInfo, DataName};
use specifications::profiling::ProfileReport;
use specifications::registering::DownloadAssetRequest;
use tempfile::TempDir;
use tokio::fs as tfs;
use tokio::io::AsyncReadExt;
use warp::http::HeaderValue;
use warp::hyper::body::{Bytes, Sender};
use warp::hyper::{Body, StatusCode};
use warp::reply::{self, Response};
use warp::{Rejection, Reply};

// use crate::errors::AuthorizeError;
pub use crate::errors::DataError as Error;
use crate::spec::Context;
use crate::store::Store;


/***** HELPER FUNCTIONS *****/
/// Runs the do-be-done data transfer by the checker to assess if we're allowed to do it.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains if and where we should proxy the request through and where we may find the checker.
/// - `use_case`: A string denoting which use-case (registry) we're using.
/// - `workflow`: The workflow to check.
/// - `client_name`: The name as which the client is authenticated. Will be matched with the indicated task.
/// - `data_name`: The name of the dataset they are trying to access.
/// - `call`: A program counter that identifies for which call in the workflow we're doing this request (if any).
///
/// # Returns
/// Whether permission is given or not. It is given as an [`Option`] that, when [`None`], means permission is given; else, it carries a list of reasons why not (if shared by the checker).
///
/// # Errors
/// This function errors if we failed to ask the checker. Clearly, that should be treated as permission denied.
pub async fn assert_asset_permission(
    worker_cfg: &WorkerConfig,
    use_case: &str,
    workflow: &Workflow,
    client_name: &str,
    data_name: DataName,
    call: Option<ProgramCounter>,
) -> Result<Option<Vec<String>>, AuthorizeError> {
    info!(
        "Checking data access of '{}'{} permission with checker '{}'...",
        data_name,
        if let Some(call) = call { format!(" (in the context of {})", call) } else { String::new() },
        worker_cfg.services.chk.address
    );

    // Check if the authenticated name checks out
    if let Some(pc) = call {
        // Extract the parts of the node we're interested in
        let (at, input): (&String, &HashMap<DataName, _>) = if pc.func_id.is_main() {
            match workflow.graph.get(pc.edge_idx) {
                Some(Edge::Node { task: _, locs: _, at, input, result: _, metadata: _, next: _ }) => {
                    if let Some(at) = at {
                        (at, input)
                    } else {
                        return Err(AuthorizeError::MissingLocation { pc });
                    }
                },

                Some(edge) => return Err(AuthorizeError::AuthorizationWrongEdge { pc, got: edge.variant().to_string() }),
                None => return Err(AuthorizeError::IllegalEdgeIdx { func: pc.func_id, got: pc.edge_idx, max: workflow.graph.len() }),
            }
        } else {
            match workflow.funcs.get(&pc.func_id.id()) {
                Some(edges) => match edges.get(pc.edge_idx) {
                    Some(Edge::Node { task: _, locs: _, at, input, result: _, metadata: _, next: _ }) => {
                        if let Some(at) = at {
                            (at, input)
                        } else {
                            return Err(AuthorizeError::MissingLocation { pc });
                        }
                    },

                    Some(edge) => return Err(AuthorizeError::AuthorizationWrongEdge { pc, got: edge.variant().to_string() }),
                    None => return Err(AuthorizeError::IllegalEdgeIdx { func: pc.func_id, got: pc.edge_idx, max: edges.len() }),
                },

                None => return Err(AuthorizeError::IllegalFuncId { got: pc.func_id }),
            }
        };

        // Assert that they match with the request
        if client_name != at {
            return Err(AuthorizeError::AuthorizationUserMismatch {
                who: format!("task {pc} executor"),
                authenticated: client_name.into(),
                workflow: at.clone(),
            });
        }
        if !input.contains_key(&data_name) {
            return Err(AuthorizeError::AuthorizationDataMismatch { pc, data_name });
        }
    } else {
        // Authenticate the scientist
        match &*workflow.user {
            Some(user) => {
                if client_name != user {
                    return Err(AuthorizeError::AuthorizationUserMismatch {
                        who: "end user".into(),
                        authenticated: client_name.into(),
                        workflow: user.clone(),
                    });
                }
            },

            None => return Err(AuthorizeError::NoWorkflowUser { workflow: serde_json::to_string_pretty(workflow).unwrap() }),
        }
    }

    // Alrighty tighty, let's begin by building the request for the checker
    debug!("Constructing checker request...");
    let body: AccessDataRequest =
        AccessDataRequest { use_case: use_case.into(), workflow: workflow.clone(), data_id: data_name.name().into(), task_id: call };

    // Next, generate a JWT to inject in the request
    let jwt: String = match specifications::policy::generate_policy_token(
        if let Some(user) = &*workflow.user { user.as_str() } else { "UNKNOWN" },
        &worker_cfg.name,
        Duration::from_secs(60),
        &worker_cfg.paths.policy_deliberation_secret,
    ) {
        Ok(token) => token,
        Err(err) => return Err(AuthorizeError::TokenGenerate { secret: worker_cfg.paths.policy_deliberation_secret.clone(), err }),
    };

    // Prepare the request to send
    let client: reqwest::Client = match reqwest::Client::builder().build() {
        Ok(client) => client,
        Err(err) => return Err(AuthorizeError::ClientBuild { err }),
    };
    let addr: String = format!("{}/{}", worker_cfg.services.chk.address, DELIBERATION_API_TRANSFER_DATA.1);
    let req: reqwest::Request =
        match client.request(DELIBERATION_API_TRANSFER_DATA.0, &addr).header(header::AUTHORIZATION, format!("Bearer {jwt}")).json(&body).build() {
            Ok(req) => req,
            Err(err) => return Err(AuthorizeError::ExecuteRequestBuild { addr, err }),
        };

    // Send it
    debug!("Sending request to '{addr}'...");
    let res: reqwest::Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => {
            return Err(AuthorizeError::ExecuteRequestSend { addr, err });
        },
    };

    // Match on the status code to find if it's OK
    debug!("Waiting for checker response...");
    if !res.status().is_success() {
        return Err(AuthorizeError::ExecuteRequestFailure { addr, code: res.status(), err: res.text().await.ok() });
    }
    let res: String = match res.text().await {
        Ok(res) => res,
        Err(err) => return Err(AuthorizeError::ExecuteBodyDownload { addr, err }),
    };
    let res: Verdict = match serde_json::from_str(&res) {
        Ok(res) => res,
        Err(err) => return Err(AuthorizeError::ExecuteBodyDeserialize { addr, raw: res, err }),
    };

    // Now match the checker's response
    match res {
        Verdict::Allow(_) => {
            info!(
                "Checker ALLOWED data access of '{}'{}",
                data_name,
                if let Some(call) = call { format!(" (in the context of {})", call) } else { String::new() },
            );
            Ok(None)
        },

        Verdict::Deny(verdict) => {
            info!(
                "Checker DENIED data access of '{}'{}",
                data_name,
                if let Some(call) = call { format!(" (in the context of {})", call) } else { String::new() },
            );
            Ok(Some(verdict.reasons_for_denial.unwrap_or_else(Vec::new)))
        },
    }
}





/***** HELPER STRUCTURES *****/
/// Manual copy of the [policy-reasoner](https://github.com/braneframework/policy-reasoner)'s `AccessDataRequest`-struct.
///
/// This is necessary because, when we pull the dependency directly, we get conflicts because that repository depends on the git version of this repository, meaning its notion of a Workflow is always (practically) outdated.
#[derive(Serialize, Deserialize)]
pub struct AccessDataRequest {
    /// Some identifier that allows the policy reasoner to assume a different context.
    ///
    /// Note that not any identifier is accepted. Which are depends on which plugins used.
    pub use_case: String,
    /// The workflow given as context.
    pub workflow: Workflow,
    /// Identifier for the requested dataset
    pub data_id:  String,
    /// Structured as follows:
    /// - `0`: Pointer to the particular function, where there are two cases:
    ///   - `usize::MAX` means main function (workflow.graph)
    ///   - otherwise, index into function table (workflow.funcs[...])
    /// - `1`: Pointer to the instruction (Edge) within the function indicated by `0`.
    /// - Empty if the requested dataset is the result of the workflow
    pub task_id:  Option<ProgramCounter>,
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
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            return Err(warp::reject::reject());
        },
    };
    if !node_config.node.is_worker() {
        error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display());
        return Err(warp::reject::reject());
    }

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file("brane-reg /data/info", format!("brane-reg_{}_info", node_config.node.worker().name));
    let _guard = report.time("Total");

    // Load the store
    debug!(
        "Loading data ('{}') and results ('{}')...",
        node_config.node.worker().paths.data.display(),
        node_config.node.worker().paths.results.display()
    );
    let store: Store = match Store::from_dirs(&node_config.node.worker().paths.data, &node_config.node.worker().paths.results).await {
        Ok(store) => store,
        Err(err) => {
            error!("{}", trace!(("Failed to load the store"), err));
            return Err(warp::reject::reject());
        },
    };

    // Simply parse to a string
    debug!("Writing list of datasets as response...");
    let body: String = match serde_json::to_string(&store.datasets) {
        Ok(body) => body,
        Err(err) => {
            return Err(warp::reject::custom(Error::StoreSerializeError { err }));
        },
    };
    let body_len: usize = body.len();

    // Construct a response with the body and the content-length header
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert("Content-Length", HeaderValue::from(body_len));

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
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            return Err(warp::reject::reject());
        },
    };
    if !node_config.node.is_worker() {
        error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display());
        return Err(warp::reject::reject());
    }

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file(
        format!("brane-reg /data/info/{name}"),
        format!("brane-reg_{}_info-{}", node_config.node.worker().name, name),
    );
    let _guard = report.time("Total");

    // Load the store
    debug!(
        "Loading data ('{}') and results ('{}')...",
        node_config.node.worker().paths.data.display(),
        node_config.node.worker().paths.results.display()
    );
    let store: Store = match Store::from_dirs(&node_config.node.worker().paths.data, &node_config.node.worker().paths.results).await {
        Ok(store) => store,
        Err(err) => {
            error!("{}", trace!(("Failed to load the store"), err));
            return Err(warp::reject::reject());
        },
    };

    // Attempt to resolve the name in the given store
    let info: &AssetInfo = match store.get_data(&name) {
        Some(info) => info,
        None => {
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
    response.headers_mut().insert("Content-Length", HeaderValue::from(body_len));

    // Done
    Ok(response)
}



/// Handles a GET that downloads an entire dataset. This basically emulates a data transfer.
///
/// # Arguments
/// - `cert`: The client certificate by which we may extract some identity. Only clients that are authenticated by the local store may connect.
/// - `name`: The name of the dataset to download.
/// - `body`: The body given with the request.
/// - `context`: The context that carries options and some shared structures between the warp paths.
///
/// # Returns
/// The response that can be sent back to the client. Contains a raw binary of the dataset, which is packaged as an archive before sending.
///
/// # Errors
/// This function may error (i.e., reject) if we didn't know the given name or we failed to serialize the relevant AssetInfo.
pub async fn download_data(
    cert: Option<Certificate>,
    name: String,
    body: DownloadAssetRequest,
    context: Arc<Context>,
) -> Result<impl Reply, Rejection> {
    let DownloadAssetRequest { use_case, workflow, task: _ } = body;
    info!("Handling GET on `/data/download/{}` (i.e., download dataset)...", name);

    // Parse if a valid workflow is given
    debug!("Parsing workflow in request body...\n\nWorkflow:\n{}\n", BlockFormatter::new(serde_json::to_string_pretty(&workflow).unwrap()));
    let workflow: Workflow = match serde_json::from_value(workflow) {
        Ok(wf) => wf,
        Err(err) => {
            debug!("{}", trace!(("Given request has an invalid workflow"), err));
            return Ok(warp::reply::with_status(Response::new("Invalid workflow".to_string().into()), StatusCode::BAD_REQUEST));
        },
    };

    // Load the config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            return Err(warp::reject::reject());
        },
    };
    let worker_config: WorkerConfig = if let NodeSpecificConfig::Worker(worker) = node_config.node {
        worker
    } else {
        error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display());
        return Err(warp::reject::reject());
    };

    // Start profiling (F first function, but now we can use the location)
    let report =
        ProfileReport::auto_reporting_file(format!("brane-reg /data/download/{name}"), format!("brane-reg_{}_download-{}", worker_config.name, name));

    // Load the store
    debug!("Loading data ('{}') and results ('{}')...", worker_config.paths.data.display(), worker_config.paths.results.display());
    let loading = report.time("Disk loading");
    let store: Store = match Store::from_dirs(&worker_config.paths.data, &worker_config.paths.results).await {
        Ok(store) => store,
        Err(err) => {
            error!("{}", trace!(("Failed to load the store"), err));
            return Err(warp::reject::reject());
        },
    };

    // Attempt to resolve the name in the given store
    let info: &AssetInfo = match store.get_data(&name) {
        Some(info) => info,
        None => {
            error!("Unknown dataset '{}'", name);
            return Err(warp::reject::not_found());
        },
    };
    loading.stop();

    // Attempt to parse the certificate to get the client's name (which tracks because it's already authenticated)
    let auth = report.time("Authorization");
    let cert: Certificate = match cert {
        Some(cert) => cert,
        None => {
            error!("Client did not specify a certificate (client unauthenticated)");
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
    };
    let client_name: String = match extract_client_name(cert) {
        Ok(name) => name,
        Err(err) => {
            error!("{} (client unauthenticated)", err);
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
    };

    // Before we continue, assert that this dataset may be downloaded by this person (uh-oh, how we gon' do that)
    match assert_asset_permission(
        &worker_config,
        &use_case,
        &workflow,
        &client_name,
        DataName::Data(name.clone()),
        body.task.map(|t| ProgramCounter::new(if let Some(id) = t.0 { FunctionId::Func(id as usize) } else { FunctionId::Main }, t.1 as usize)),
    )
    .await
    {
        Ok(None) => {
            info!("Checker authorized download of dataset '{}' by '{}'", info.name, client_name);
        },

        Ok(Some(reasons)) => {
            info!("Checker denied download of dataset '{}' by '{}'", info.name, client_name);
            if !reasons.is_empty() {
                debug!("Reasons:\n{}\n", reasons.into_iter().map(|r| format!(" - {r}")).collect::<Vec<String>>().join("\n"));
            }
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
        Err(err) => {
            error!("{}", trace!(("Failed to consult the checker"), err));
            return Err(warp::reject::reject());
        },
    }
    auth.stop();

    // Access the dataset in the way it likes to be accessed
    match &info.access {
        AccessKind::File { path } => {
            debug!("Accessing file '{}' @ '{}' as AccessKind::File...", name, path.display());
            let path: PathBuf = worker_config.paths.data.join(&name).join(path);
            debug!("File can be found under: '{}'", path.display());

            // First, get a temporary directory
            let arch = report.time("Archiving (file)");
            let tmpdir: TempDir = match TempDir::new() {
                Ok(tmpdir) => tmpdir,
                Err(err) => {
                    let err = Error::TempDirCreateError { err };
                    error!("{}", err.trace());
                    return Err(warp::reject::custom(err));
                },
            };

            // Next, create an archive in the temporary directory
            let tar_path: PathBuf = tmpdir.path().join("data.tar.gz");
            if let Err(err) = archive_async(&path, &tar_path, true).await {
                let err = Error::DataArchiveError { err };
                error!("{}", err.trace());
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
                    Err(err) => {
                        let err = Error::TarOpenError { path: tar_path, err };
                        error!("{}", err.trace());
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
                        Err(err) => {
                            error!("{}", Error::TarReadError { path: tar_path, err }.trace());
                            break;
                        },
                    };
                    if bytes == 0 {
                        break;
                    }

                    // Send that with the body
                    if let Err(err) = body_sender.send_data(Bytes::copy_from_slice(&buf[..bytes])).await {
                        error!("{}", Error::TarSendError { err }.trace());
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
/// - `body`: The body given with the request.
/// - `context`: The context that carries options and some shared structures between the warp paths.
///
/// # Returns
/// The response that can be sent back to the client. Contains a raw binary of the result, which is packaged as an archive before sending.
///
/// # Errors
/// This function may error (i.e., reject) if we didn't know the given name or we failed to serialize the relevant AssetInfo.
pub async fn download_result(
    cert: Option<Certificate>,
    name: String,
    body: DownloadAssetRequest,
    context: Arc<Context>,
) -> Result<impl Reply, Rejection> {
    let DownloadAssetRequest { use_case, workflow, task: _ } = body;
    info!("Handling GET on `/results/download/{}` (i.e., download intermediate result)...", name);

    // Parse if a valid workflow is given
    debug!("Parsing workflow in request body...\n\nWorkflow:\n{}\n", BlockFormatter::new(serde_json::to_string_pretty(&workflow).unwrap()));
    let workflow: Workflow = match serde_json::from_value(workflow) {
        Ok(wf) => wf,
        Err(err) => {
            debug!("{}", trace!(("Given request has an invalid workflow"), err));
            return Ok(warp::reply::with_status(Response::new("Invalid workflow".to_string().into()), StatusCode::BAD_REQUEST));
        },
    };

    // Load the config file
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            return Err(warp::reject::reject());
        },
    };
    let worker_config: WorkerConfig = if let NodeSpecificConfig::Worker(worker) = node_config.node {
        worker
    } else {
        error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display());
        return Err(warp::reject::reject());
    };

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file(
        format!("brane-reg /results/download/{name}"),
        format!("brane-reg_{}_download-{}", worker_config.name, name),
    );

    // Load the store
    debug!("Loading data ('{}') and results ('{}')...", worker_config.paths.data.display(), worker_config.paths.results.display());
    let loading = report.time("Disk loading");
    let store: Store = match Store::from_dirs(&worker_config.paths.data, &worker_config.paths.results).await {
        Ok(store) => store,
        Err(err) => {
            error!("{}", trace!(("Failed to load the store"), err));
            return Err(warp::reject::reject());
        },
    };

    // Attempt to resolve the name in the given store
    let path: &Path = match store.get_result(&name) {
        Some(path) => path,
        None => {
            error!("Unknown intermediate result '{}'", name);
            return Err(warp::reject::not_found());
        },
    };
    loading.stop();

    // Attempt to parse the certificate to get the client's name (which tracks because it's already authenticated)
    let auth = report.time("Authorization");
    let cert: Certificate = match cert {
        Some(cert) => cert,
        None => {
            error!("Client did not specify a certificate (client unauthenticated)");
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
    };
    let client_name: String = match extract_client_name(cert) {
        Ok(name) => name,
        Err(err) => {
            error!("{} (client unauthenticated)", err);
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
    };

    // Before we continue, assert that this dataset may be downloaded by this person (uh-oh, how we gon' do that)
    match assert_asset_permission(
        &worker_config,
        &use_case,
        &workflow,
        &client_name,
        DataName::IntermediateResult(name.clone()),
        body.task.map(|t| ProgramCounter::new(if let Some(id) = t.0 { FunctionId::Func(id as usize) } else { FunctionId::Main }, t.1 as usize)),
    )
    .await
    {
        Ok(None) => {
            info!("Checker authorized download of intermediate result '{}' by '{}'", name, client_name);
        },

        Ok(Some(reasons)) => {
            info!("Checker denied download of intermediate result '{}' by '{}'", name, client_name);
            if !reasons.is_empty() {
                debug!("Reasons:\n{}\n", reasons.into_iter().map(|r| format!(" - {r}")).collect::<Vec<String>>().join("\n"));
            }
            return Ok(reply::with_status(Response::new(Body::empty()), StatusCode::FORBIDDEN));
        },
        Err(err) => {
            error!("{}", trace!(("Failed to consult the checker"), err));
            return Err(warp::reject::reject());
        },
    }
    auth.stop();

    // Start the upload; first, get a temporary directory
    let arch = report.time("Archiving (file)");
    let tmpdir: TempDir = match TempDir::new() {
        Ok(tmpdir) => tmpdir,
        Err(err) => {
            let err = Error::TempDirCreateError { err };
            error!("{}", err.trace());
            return Err(warp::reject::custom(err));
        },
    };

    // Next, create an archive in the temporary directory
    let tar_path: PathBuf = tmpdir.path().join("data.tar.gz");
    if let Err(err) = archive_async(&path, &tar_path, true).await {
        let err = Error::DataArchiveError { err };
        error!("{}", err.trace());
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
            Err(err) => {
                let err = Error::TarOpenError { path: tar_path, err };
                error!("{}", err.trace());
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
                Err(err) => {
                    error!("{}", Error::TarReadError { path: tar_path, err }.trace());
                    break;
                },
            };
            if bytes == 0 {
                break;
            }

            // Send that with the body
            if let Err(err) = body_sender.send_data(Bytes::copy_from_slice(&buf[..bytes])).await {
                error!("{}", Error::TarSendError { err }.trace());
            }
        }

        // Done
        Ok(())
    });

    // We use the handle as a stream.
    Ok(reply::with_status(Response::new(body), StatusCode::OK))
}
