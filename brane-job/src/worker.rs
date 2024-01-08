//  WORKER.rs
//    by Lut99
//
//  Created:
//    31 Oct 2022, 11:21:14
//  Last edited:
//    08 Jan 2024, 18:46:08
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the worker side of the communication. This is the other
//!   side for all sorts of things, from execution to preprocessing to
//!   execution to publicizing/committing.
//

use std::collections::{HashMap, HashSet};
// use std::error;
use std::ffi::OsStr;
// use std::fmt::{Display, Formatter, Result as FResult};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bollard::API_DEFAULT_VERSION;
use brane_ast::ast::{ComputeTaskDef, DataName, TaskDef};
use brane_ast::locations::Location;
use brane_ast::Workflow;
use brane_cfg::backend::{BackendFile, Credentials};
use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, WorkerConfig};
use brane_exe::FullValue;
use brane_prx::client::ProxyClient;
use brane_prx::spec::NewPathRequestTlsOptions;
use brane_shr::formatters::BlockFormatter;
use brane_shr::fs::{copy_dir_recursively_async, unarchive_async};
use brane_tsk::docker::{self, ClientVersion, DockerOptions, ExecuteInfo, ImageSource, Network};
use brane_tsk::errors::{AuthorizeError, CommitError, ExecuteError, PreprocessError};
use brane_tsk::spec::JobStatus;
use brane_tsk::tools::decode_base64;
use chrono::Utc;
// use deliberation::spec::ExecuteTaskRequest;
use enum_debug::EnumDebug as _;
use futures_util::StreamExt;
use hyper::body::Bytes;
// use kube::config::Kubeconfig;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json_any_key::json_to_map;
// use brane_tsk::k8s::{self, K8sOptions};
use specifications::container::{Image, VolumeBind};
use specifications::data::{AccessKind, AssetInfo};
use specifications::package::{Capability, PackageIndex, PackageInfo, PackageKind};
use specifications::profiling::{ProfileReport, ProfileScopeHandle};
use specifications::version::Version;
use specifications::working::{
    CommitReply, CommitRequest, ExecuteReply, ExecuteRequest, JobService, PreprocessKind, PreprocessReply, PreprocessRequest, TaskStatus,
    TransferRegistryTar,
};
use tokio::fs as tfs;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{self, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};


/***** CONSTANTS *****/
/// Path to the temporary folder.
pub const TEMPORARY_DIR: &str = "/tmp";





/***** HELPER MACROS *****/
/// Translates the given error into a log message, updates the client _and_ returns it.
macro_rules! err {
    ($tx:ident, $err:expr) => {
        err!($tx, JobStatus::CreationFailed, $err)
    };

    ($tx:ident,JobStatus:: $status:ident, $err:expr) => {{
        let err = $err;
        log::error!("{}", err);
        if let Err(err) = update_client(&$tx, JobStatus::$status(format!("{}", err))).await {
            log::error!("{}", err);
        }
        Err(err)
    }};
}





/***** HELPER FUNCTIONS *****/
/// Updates the client with a status update.
///
/// # Arguments
/// - `tx`: The channel to update the client on.
/// - `status`: The status to update the client with.
///
/// # Errors
/// This function may error if we failed to update the client.
async fn update_client(tx: &Sender<Result<ExecuteReply, Status>>, status: JobStatus) -> Result<(), ExecuteError> {
    // Convert the JobStatus into a code and (possible) value
    let (status, value): (TaskStatus, Option<String>) = status.into();

    // Put that in an ExecuteReply
    let reply: ExecuteReply = ExecuteReply { status: status as i32, value };

    // Send it over the wire
    debug!("Updating client on '{:?}'...", status);
    if let Err(err) = tx.send(Ok(reply)).await {
        return Err(ExecuteError::ClientUpdateError { status, err });
    }

    // Done
    Ok(())
}





/***** ERRORS *****/
// /// Defines errors that occur when preprocessing transfer tarballs through Kubernetes.
// #[derive(Debug)]
// pub enum PreprocessTransferTarK8sError {
//     /// Failed to load the Kubernetes config file.
//     LoadConfig{ err: k8s::ConfigError },
// }
// impl Display for PreprocessTransferTarK8sError {
//     fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
//         use PreprocessTransferTarK8sError::*;
//         match self {
//             LoadConfig{ .. } => write!(f, "Failed to load Kubernetes client config file"),
//         }
//     }
// }
// impl error::Error for PreprocessTransferTarK8sError {
//     fn source(&self) -> Option<&(dyn error::Error + 'static)> {
//         use PreprocessTransferTarK8sError::*;
//         match self {
//             LoadConfig { err } => Some(err),
//         }
//     }
// }





/***** HELPER STRUCTURES *****/
/// Manual copy of the [policy-reasoner](https://github.com/epi-project/policy-reasoner)'s `ExecuteRequest`-struct.
///
/// This is necessary because, when we pull the dependency directly, we get conflicts because that repository depends on the git version of this repository, meaning its notion of a Workflow is always (practically) outdated.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyExecuteRequest {
    /// The workflow that is being examined.
    pub workflow: Workflow,
    /// The ID (i.e., program counter) of the call that we want to authorize.
    pub task_id:  (usize, usize),
}





/***** AUXILLARY STRUCTURES *****/
/// Helper structure for grouping together task-dependent "constants", but that are not part of the task itself.
#[derive(Clone, Debug)]
pub struct ControlNodeInfo {
    /// The address of the API service.
    pub api_endpoint: String,
}
impl ControlNodeInfo {
    /// Constructor for the ControlNodeInfo.
    ///
    /// # Arguments
    /// - `api_endpoint`: The address of the API service.
    ///
    /// # Returns
    /// A new ControlNodeInfo instance.
    #[inline]
    pub fn new(api_endpoint: impl Into<String>) -> Self { Self { api_endpoint: api_endpoint.into() } }
}

/// Helper structure for grouping together task information.
#[derive(Clone, Debug)]
pub struct TaskInfo {
    /// The name of the task to execute.
    pub name: String,
    /// The identifier of the call to the task we're executing.
    pub pc:   (usize, usize),

    /// The name of the task's parent package.
    pub package_name: String,
    /// The version of the task's parent package.
    pub package_version: Version,
    /// The kind of the task to execute.
    pub kind: Option<PackageKind>,
    /// The image name of the package where the task is from. Note: won't be populated until later.
    pub image: Option<Image>,

    /// The input datasets/results to this task, if any.
    pub input:  HashMap<DataName, AccessKind>,
    /// If this call returns an intermediate result, its name is defined here.
    pub result: Option<String>,

    /// The input arguments to the task. Still need to be resolved before running.
    pub args: HashMap<String, FullValue>,
    /// The requirements for this task.
    pub requirements: HashSet<Capability>,
}
impl TaskInfo {
    /// Constructor for the TaskInfo.
    ///
    /// # Arguments
    /// - `name`: The name of the task to execute.
    /// - `pc`: The identifier of the call to the task we're executing.
    /// - `package_name`: The name of the task's parent package.
    /// - `package_version`: The version of the task's parent package.
    /// - `input`: The input datasets/results to this task, if any.
    /// - `result`: If this call returns an intermediate result, its name is defined here.
    /// - `args`: The input arguments to the task. Still need to be resolved before running.
    /// - `requirements`: The list of required capabilities for this task.
    ///
    /// # Returns
    /// A new TaskInfo instance.
    #[inline]
    pub fn new(
        name: impl Into<String>,
        pc: (usize, usize),
        package_name: impl Into<String>,
        package_version: impl Into<Version>,
        input: HashMap<DataName, AccessKind>,
        result: Option<String>,
        args: HashMap<String, FullValue>,
        requirements: HashSet<Capability>,
    ) -> Self {
        Self {
            name: name.into(),
            pc,

            package_name: package_name.into(),
            package_version: package_version.into(),
            kind: None,
            image: None,

            input,
            result,

            args,
            requirements,
        }
    }
}





/***** PLANNING FUNCTIONS *****/
/// Function that preprocesses the given tar by downloading it to the local machine and extracting it.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains the path where we may find certificates and where to download data & result files to.
/// - `proxy`: The proxy client we use to proxy the data transfer.
/// - `location`: The location to download the tarball from.
/// - `address`: The address to download the tarball from.
/// - `data_name`: The type of the data (i.e., Data or IntermediateResult) combined with its identifier.
/// - `prof`: A ProfileScope to provide more detailled information about the time it takes to preprocess a TAR-file.
///
/// # Returns
/// The AccessKind to access the extracted data.
///
/// # Errors
/// This function can error for literally a million reasons - but they mostly relate to IO (file access, request success etc).
async fn preprocess_transfer_tar_local(
    worker_cfg: &WorkerConfig,
    proxy: Arc<ProxyClient>,
    location: Location,
    address: impl AsRef<str>,
    data_name: DataName,
    prof: ProfileScopeHandle<'_>,
) -> Result<AccessKind, PreprocessError> {
    debug!("Preprocessing by executing a data transfer");
    let address: &str = address.as_ref();
    debug!("Downloading from {} ({}) to local machine", location, address);



    // Prepare the folder where we will download the data to
    debug!("Preparing filesystem...");
    let pre = prof.time("Filesystem preparation");
    let tar_path: PathBuf = PathBuf::from("/tmp/tars");
    if !tar_path.is_dir() {
        if tar_path.exists() {
            return Err(PreprocessError::DirNotADirError { what: "temporary tarball", path: tar_path });
        }
        if let Err(err) = tfs::create_dir_all(&tar_path).await {
            return Err(PreprocessError::DirCreateError { what: "temporary tarball", path: tar_path, err });
        }
    }

    // Make sure the data folder is there
    let temp_data_path: &Path = &worker_cfg.paths.temp_data;
    if temp_data_path.exists() && !temp_data_path.is_dir() {
        return Err(PreprocessError::DirNotADirError { what: "temporary data", path: temp_data_path.into() });
    } else if !temp_data_path.exists() {
        return Err(PreprocessError::DirNotExistsError { what: "temporary data", path: temp_data_path.into() });
    }

    // Also make sure the results folder is there
    let temp_results_path: &Path = &worker_cfg.paths.temp_results;
    if temp_results_path.exists() && !temp_results_path.is_dir() {
        return Err(PreprocessError::DirNotADirError { what: "temporary results", path: temp_results_path.into() });
    } else if !temp_results_path.exists() {
        return Err(PreprocessError::DirNotExistsError { what: "temporary results", path: temp_results_path.into() });
    }

    // Also compute the final file path
    let (tar_path, data_path): (PathBuf, PathBuf) = match &data_name {
        DataName::Data(name) => {
            // Make sure the data path exists but is clean
            let data_path: PathBuf = temp_data_path.join(name);
            if data_path.exists() {
                if !data_path.is_dir() {
                    return Err(PreprocessError::DirNotADirError { what: "temporary data", path: data_path });
                }
                if let Err(err) = tfs::remove_dir_all(&data_path).await {
                    return Err(PreprocessError::DirRemoveError { what: "temporary data", path: data_path, err });
                }
            }

            // Add the name of the file as the final result path
            (tar_path.join(format!("data_{name}.tar.gz")), data_path)
        },

        DataName::IntermediateResult(name) => {
            // Make sure the result path exists
            let res_path: PathBuf = temp_results_path.join(name);
            if res_path.exists() {
                if !res_path.is_dir() {
                    return Err(PreprocessError::DirNotADirError { what: "temporary result", path: res_path });
                }
                if let Err(err) = tfs::remove_dir_all(&res_path).await {
                    return Err(PreprocessError::DirRemoveError { what: "temporary result", path: res_path, err });
                }
            }

            // Add the name of the file as the final result path
            (tar_path.join(format!("res_{name}.tar.gz")), res_path)
        },
    };
    pre.stop();



    // Send a reqwest
    debug!("Sending download request...");
    let download = prof.time("Downloading");
    let res = match proxy.get(address, Some(NewPathRequestTlsOptions { location: location.clone(), use_client_auth: true })).await {
        Ok(result) => match result {
            Ok(res) => res,
            Err(err) => {
                return Err(PreprocessError::DownloadRequestError { address: address.into(), err });
            },
        },
        Err(err) => {
            return Err(PreprocessError::ProxyError { err: Box::new(err) });
        },
    };
    if !res.status().is_success() {
        return Err(PreprocessError::DownloadRequestFailure { address: address.into(), code: res.status(), message: res.text().await.ok() });
    }



    // With the request success, download it in parts
    debug!("Downloading file to '{}'...", tar_path.display());
    {
        let mut handle: tfs::File = match tfs::File::create(&tar_path).await {
            Ok(handle) => handle,
            Err(err) => {
                return Err(PreprocessError::TarCreateError { path: tar_path, err });
            },
        };
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            // Unwrap the chunk
            let mut chunk: Bytes = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    return Err(PreprocessError::DownloadStreamError { address: address.into(), err });
                },
            };

            // Write it to the file
            if let Err(err) = handle.write_all_buf(&mut chunk).await {
                return Err(PreprocessError::TarWriteError { path: tar_path, err });
            }
        }
    }
    download.stop();



    // It took a while, but we now have the tar file; extract it
    debug!("Unpacking '{}' to '{}'...", tar_path.display(), data_path.display());
    if let Err(err) = prof.time_fut("unarchiving", unarchive_async(tar_path, &data_path)).await {
        return Err(PreprocessError::DataExtractError { err });
    }



    // Done; send back the reply
    Ok(AccessKind::File { path: data_path })
}

// /// Function that preprocesses the given tar by downloading it to the backend Kubernetes cluster and preparing it as a mountable volume.
// ///
// /// # Arguments
// /// - `kinfo`: The [`K8sOptions`] that describe the remote Kubernetes cluster and how to connect to it.
// /// - `location`: The location to download the tarball from.
// /// - `address`: The address to download the tarball from.
// /// - `prof`: A ProfileScope to provide more detailled information about the time it takes to preprocess a TAR-file.
// ///
// /// # Returns
// /// The AccessKind to access the extracted data.
// ///
// /// # Errors
// /// This function can error for literally a million reasons - but they mostly relate to IO (file access, request success etc).
// async fn preprocess_transfer_tar_k8s(kinfo: K8sOptions, location: Location, address: impl AsRef<str>, prof: ProfileScopeHandle<'_>) -> Result<AccessKind, PreprocessError> {
//     debug!("Preprocessing by executing a data transfer");
//     let address: &str  = address.as_ref();
//     debug!("Downloading from {} ({}) to Kubernetes cluster", location, address);



//     // Done
//     Ok(())
// }

/// Function that preprocesses by downloading the given tar and extracting it.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains the path where we may find certificates and where to download data & result files to.
/// - `proxy`: The proxy client we use to proxy the data transfer.
/// - `location`: The location to download the tarball from.
/// - `address`: The address to download the tarball from.
/// - `data_name`: The type of the data (i.e., Data or IntermediateResult) combined with its identifier.
/// - `prof`: A ProfileScope to provide more detailled information about the time it takes to preprocess a TAR-file.
///
/// # Returns
/// The AccessKind to access the extracted data.
///
/// # Errors
/// This function can error for literally a million reasons - but they mostly relate to IO (file access, request success etc).
pub async fn preprocess_transfer_tar(
    worker_cfg: &WorkerConfig,
    proxy: Arc<ProxyClient>,
    location: Location,
    address: impl AsRef<str>,
    data_name: DataName,
    prof: ProfileScopeHandle<'_>,
) -> Result<AccessKind, PreprocessError> {
    debug!("Preprocessing tar...");

    // Load the local backend file
    let backend: BackendFile = match BackendFile::from_path_async(&worker_cfg.paths.backend).await {
        Ok(backend) => backend,
        Err(err) => {
            return Err(PreprocessError::BackendFileError { err });
        },
    };

    // Now match the credential type
    match backend.method {
        Credentials::Local { .. } => {
            // Download the container locally
            preprocess_transfer_tar_local(worker_cfg, proxy, location, address, data_name, prof).await
        },

        Credentials::Ssh { .. } => Err(PreprocessError::UnsupportedBackend { what: "SSH" }),

        Credentials::Kubernetes { registry_address: _, config: _ } => {
            Err(PreprocessError::UnsupportedBackend { what: "Kubernetes" })

            // // Prepare the Kubernetes options
            // let kinfo: K8sOptions = K8sOptions { registry_address, config };

            // // Call the function
            // preprocess_transfer_tar_k8s(kinfo, location, address, prof).await
        },
        Credentials::Slurm { .. } => Err(PreprocessError::UnsupportedBackend { what: "SSH" }),
    }
}





/***** EXECUTION FUNCTIONS *****/
/// Runs the given (call to a) task in the given workflow by the checker to see if it's authorized.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains if and where we should proxy the request through and where we may find the checker.
/// - `workflow`: The workflow to check.
/// - `call`: A program counter that identifies which call in the workflow we'll be checkin'.
///
/// # Returns
/// Whether the workflow has been accepted or not.
///
/// # Errors
/// This function errors if we failed to reach the checker, or the checker itself crashed.
async fn assert_task_permission(worker_cfg: &WorkerConfig, workflow: &Workflow, call: (usize, usize)) -> Result<bool, AuthorizeError> {
    info!("Checking task '{}:{}' execution permission with checker '{}'...", call.0, call.1, worker_cfg.services.chk.address);

    // Alrighty tighty, let's begin by building the request for the checker
    debug!("Constructing checker request...");
    let body: PolicyExecuteRequest = PolicyExecuteRequest { workflow: workflow.clone(), task_id: call };

    // Prepare the request to send
    debug!("Building request...");
    let client: reqwest::Client = match reqwest::Client::builder().build() {
        Ok(client) => client,
        Err(err) => return Err(AuthorizeError::ClientBuild { err }),
    };
    let req: reqwest::Request = match client.request(reqwest::Method::POST, worker_cfg.services.chk.address.to_string()).json(&body).build() {
        Ok(req) => req,
        Err(err) => return Err(AuthorizeError::ExecuteRequestBuild { addr: worker_cfg.services.chk.address.clone(), err }),
    };

    // Send it
    debug!("Sending request to '{}'...", worker_cfg.services.chk.address);
    let res: reqwest::Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => {
            return Err(AuthorizeError::ExecuteRequestSend { addr: worker_cfg.services.chk.address.clone(), err });
        },
    };

    // Match on the status code to find if it's OK
    debug!("Waiting for response response...");
    let allowed: bool = match res.status() {
        reqwest::StatusCode::OK => true,
        reqwest::StatusCode::FORBIDDEN => false,
        code => {
            return Err(AuthorizeError::ExecuteRequestFailure { addr: worker_cfg.services.chk.address.clone(), code, err: res.text().await.ok() });
        },
    };

    // Print what it told us
    println!("Verdict: {}", if allowed { "allowed" } else { "denied" });
    println!("{:?}", res.text().await);
    Ok(false)
}



/// Returns the path of a cached container file if it is cached.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains if and where we should proxy the request through and where we may download package images to.
/// - `image`: The image name of the image we want to have.
///
/// # Returns
/// The path to the file if it exists (and is thus cached), or `None` otherwise. Note that the existance of the image file itself does not mean the hash and ID cache files are there too.
#[inline]
fn get_cached_container(worker_cfg: &WorkerConfig, image: &Image) -> Option<PathBuf> {
    // Generate the path
    let image_path: PathBuf = worker_cfg.paths.packages.join(format!("{}-{}.tar", image.name, image.version.as_ref().unwrap_or(&"latest".into())));

    // Whether we return it determines if it exists
    if image_path.exists() { Some(image_path) } else { None }
}

/// Downloads a container to the local registry.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains if and where we should proxy the request through and where we may download package images to.
/// - `proxy`: The proxy client we use to proxy the data transfer.
/// - `endpoint`: The address where to download the container from.
/// - `image`: The image name (including digest, for caching) to download.
///
/// # Returns
/// The path of the downloaded image file combined with the hash of the image. It's very good practise to use this one, since the actual path is subject to change.
///
/// The given Image is also updated with any new digests if none are given.
///
/// # Errors
/// This function may error if we failed to reach the remote host, download the file or write the file.
async fn get_container(
    worker_cfg: &WorkerConfig,
    proxy: Arc<ProxyClient>,
    endpoint: impl AsRef<str>,
    image: &Image,
) -> Result<PathBuf, ExecuteError> {
    let endpoint: &str = endpoint.as_ref();
    debug!("Downloading image '{}' from '{}'...", image, endpoint);

    // Send a GET-request to the correct location
    let address: String = format!("{}/packages/{}/{}", endpoint, image.name, image.version.as_ref().unwrap_or(&"latest".into()));
    debug!("Performing request to '{}'...", address);
    let res = match proxy.get(&address, None).await {
        Ok(result) => match result {
            Ok(res) => res,
            Err(err) => {
                return Err(ExecuteError::DownloadRequestError { address, err });
            },
        },
        Err(err) => {
            return Err(ExecuteError::ProxyError { err: Box::new(err) });
        },
    };
    if !res.status().is_success() {
        return Err(ExecuteError::DownloadRequestFailure { address, code: res.status(), message: res.text().await.ok() });
    }

    // With the request success, download it in parts
    let image_path: PathBuf = worker_cfg.paths.packages.join(format!("{}-{}.tar", image.name, image.version.as_ref().unwrap_or(&"latest".into())));
    debug!("Writing request stream to '{}'...", image_path.display());
    {
        let mut handle: tfs::File = match tfs::File::create(&image_path).await {
            Ok(handle) => handle,
            Err(err) => {
                return Err(ExecuteError::ImageCreateError { path: image_path, err });
            },
        };
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            // Unwrap the chunk
            let mut chunk: Bytes = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    return Err(ExecuteError::DownloadStreamError { address, err });
                },
            };

            // Write it to the file
            if let Err(err) = handle.write_all_buf(&mut chunk).await {
                return Err(ExecuteError::ImageWriteError { path: image_path, err });
            }
        }
    }

    // That's OK - now return
    Ok(image_path)
}

/// Returns the hash and identifier of the given image file.
///
/// The hash is meant to represent some cryptographically secure footprint, whereas the identifier is the Docker ID of the image we can use to refer to this unique instance in the Docker daemon.
///
/// Note that the ID itself is _not_ cryptographically secure, since it is not computed but read from the image file. It may thus be tempered with by the sender.
///
/// # Arguments
/// - `node_config`: The configuration for this node's environment. For us, contains the location to the `backend` file that determines if we need to compute a hash or not.
/// - `image_path`: The path to the image file to compute the hash and ID of.
/// - `prof`: A ProfileScope to provide more detailled information about the time it takes to retrieve the container identifiers.
///
/// # Returns
/// The ID and hash of this container, respectively. Note that the hash may be empty, in which case the system admin disabled container security.
///
/// Also note that, for performance reasons, the function generates cache files alongside the image file if they are not present already.
///
/// # Errors
/// This function errors if we failed to read the given image file or any other associated cache file.
async fn get_container_ids(
    worker_cfg: &WorkerConfig,
    image_path: impl AsRef<Path>,
    prof: ProfileScopeHandle<'_>,
) -> Result<(String, Option<String>), ExecuteError> {
    let image_path: &Path = image_path.as_ref();
    debug!("Computing ID and hash for '{}'...", image_path.display());

    // Open the backend file
    let disk = prof.time("File loading");
    let backend: BackendFile = match BackendFile::from_path(&worker_cfg.paths.backend) {
        Ok(backend) => backend,
        Err(err) => {
            return Err(ExecuteError::BackendFileError { path: worker_cfg.paths.backend.clone(), err });
        },
    };
    disk.stop();

    // Get the directory of the image
    let dir: &Path = image_path.parent().unwrap_or(image_path);
    let file_name: &OsStr = image_path.file_stem().unwrap_or_else(|| OsStr::new(""));

    // Check the image ID
    let id: String = {
        // Check if the cache file exists
        let cache_file: PathBuf = dir.join(format!("{}-id.sha256", file_name.to_string_lossy()));
        if cache_file.exists() {
            // Attempt to read it
            let _cache = prof.time("ID cache file reading");
            match tfs::read_to_string(&cache_file).await {
                Ok(id) => id,
                Err(err) => {
                    return Err(ExecuteError::IdReadError { path: cache_file, err });
                },
            }
        } else {
            // Get the ID from the image
            let _ext = prof.time("ID extraction");
            let id: String = match docker::get_digest(image_path).await {
                Ok(id) => id,
                Err(err) => {
                    return Err(ExecuteError::DigestError { path: image_path.into(), err });
                },
            };

            // Write it to the cache file
            if let Err(err) = tfs::write(&cache_file, &id).await {
                return Err(ExecuteError::IdWriteError { path: cache_file, err });
            }

            // Return the ID
            id
        }
    };

    // Check the image hash
    let hash: Option<String> = if backend.hash_containers() {
        // Check if the hash file exists
        let cache_file: PathBuf = dir.join(format!("{}-hash.sha256", file_name.to_string_lossy()));
        if cache_file.exists() {
            // Attempt to read it
            let _cache = prof.time("Hash cache file reading");
            match tfs::read_to_string(&cache_file).await {
                Ok(hash) => Some(hash),
                Err(err) => {
                    return Err(ExecuteError::HashReadError { path: cache_file, err });
                },
            }
        } else {
            // Compute the hash
            let _ext = prof.time("Hash computation");
            let hash: String = match docker::hash_container(image_path).await {
                Ok(hash) => hash,
                Err(err) => {
                    return Err(ExecuteError::HashError { err });
                },
            };

            // Write it to the cache file
            if let Err(err) = tfs::write(&cache_file, &hash).await {
                return Err(ExecuteError::HashWriteError { path: cache_file, err });
            }

            // Return the hash
            Some(hash)
        }
    } else {
        None
    };

    // Done
    Ok((id, hash))
}

/// Ensures the given image exists, either by finding it in the local cache or by downloading it from the central node.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains if and where we should proxy the request through and where we may download package images to.
/// - `proxy`: The proxy client we use to proxy the data transfer.
/// - `endpoint`: The address where to download the container from.
/// - `image`: The image name (including digest, for caching) to download.
/// - `prof`: A ProfileScope to provide more detailled information about the time it takes to ensure a container exists.
///
/// # Returns
/// The path of the downloaded image file combined with the ID of the image and the hash of the image, respectively.
///
/// It's very good practise to use this path, since the cached path might be changed in this function.
///
/// The ID may be used to communicate the container to Docker, but it is not cryptographically secure (it is provided by the remote party as-is). Use the hash instead for policies.
///
/// Also note that if the hash is missing (`None`), then the system administrator disabled container security and no consulting of the checker on this respect should occur.
///
/// # Errors
/// This function may error if we failed to reach the remote host, download the file or write the file. If it is cached, then we may fail if we failed to read any of the cached files.
async fn ensure_container(
    worker_cfg: &WorkerConfig,
    proxy: Arc<ProxyClient>,
    endpoint: impl AsRef<str>,
    image: &Image,
    prof: ProfileScopeHandle<'_>,
) -> Result<(PathBuf, String, Option<String>), ExecuteError> {
    // Download the file if we don't have it locally already
    let image_path: PathBuf = match prof.time_func("cache checking", || get_cached_container(worker_cfg, image)) {
        Some(path) => path,
        None => prof.time_fut("container downloading", get_container(worker_cfg, proxy, endpoint, image)).await?,
    };

    // Compute the ID and hash for it
    let (id, hash): (String, Option<String>) =
        prof.nest_fut("container ID & hash computation", |scope| get_container_ids(worker_cfg, &image_path, scope)).await?;

    // Done, return
    Ok((image_path, id, hash))
}



/// Runs the given task on a local backend.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains the location ID of this location and where to find data & intermediate results.
/// - `dinfo`: Information that determines where and how to connect to the local Docker deamon.
/// - `tx`: The transmission channel over which we should update the client of our progress.
/// - `container_path`: The path of the downloaded container that we should execute.
/// - `tinfo`: The TaskInfo that describes the task itself to execute.
/// - `keep_container`: Whether to keep the container after execution or not.
/// - `prof`: A ProfileScope to provide more detailled information about the time it takes to execute a local task.
///
/// # Returns
/// The return value of the task when it completes..
///
/// # Errors
/// This function errors if the task fails for whatever reason or we didn't even manage to launch it.
async fn execute_task_local(
    worker_cfg: &WorkerConfig,
    dinfo: DockerOptions,
    tx: &Sender<Result<ExecuteReply, Status>>,
    container_path: impl AsRef<Path>,
    tinfo: TaskInfo,
    keep_container: bool,
    prof: ProfileScopeHandle<'_>,
) -> Result<FullValue, JobStatus> {
    let container_path: &Path = container_path.as_ref();
    let mut tinfo: TaskInfo = tinfo;
    let image: Image = tinfo.image.clone().unwrap();
    debug!("Spawning container '{}' as a local container...", image);

    // First, we preprocess the arguments
    let binds: Vec<VolumeBind> = match prof
        .time_fut(
            "preprocessing",
            docker::preprocess_args(&mut tinfo.args, &tinfo.input, &tinfo.result, Some(&worker_cfg.paths.data), &worker_cfg.paths.results),
        )
        .await
    {
        Ok(binds) => binds,
        Err(err) => {
            return Err(JobStatus::CreationFailed(format!("Failed to preprocess arguments: {err}")));
        },
    };

    // Serialize them next
    let ser = prof.time("Serialization");
    let params: String = match serde_json::to_string(&tinfo.args) {
        Ok(params) => params,
        Err(err) => {
            return Err(JobStatus::CreationFailed(format!("Failed to serialize arguments: {err}")));
        },
    };
    ser.stop();

    // Prepare the ExecuteInfo
    let info: ExecuteInfo = ExecuteInfo::new(
        &tinfo.name,
        image,
        ImageSource::Path(container_path.into()),
        vec![
            "-d".into(),
            "--application-id".into(),
            "unspecified".into(),
            "--location-id".into(),
            worker_cfg.name.clone(),
            "--job-id".into(),
            "unspecified".into(),
            tinfo.kind.unwrap().into(),
            tinfo.name.clone(),
            STANDARD.encode(params),
        ],
        binds,
        tinfo.requirements,
        Network::None,
    );

    // Now we can launch the container...
    let exec = prof.nest("execution");
    let total = prof.time("Total");
    let name: String = match exec.time_fut("spawn overhead", docker::launch(&dinfo, info)).await {
        Ok(name) => name,
        Err(err) => {
            return Err(JobStatus::CreationFailed(format!("Failed to spawn container: {err}")));
        },
    };
    if let Err(err) = update_client(tx, JobStatus::Created).await {
        error!("{}", err);
    }
    if let Err(err) = update_client(tx, JobStatus::Started).await {
        error!("{}", err);
    }

    // ...and wait for it to complete
    let (code, stdout, stderr): (i32, String, String) = match exec.time_fut("join overhead", docker::join(dinfo, name, keep_container)).await {
        Ok(name) => name,
        Err(err) => {
            return Err(JobStatus::CompletionFailed(format!("Failed to join container: {err}")));
        },
    };
    total.stop();
    exec.finish();

    // Let the client know it was done
    debug!("Container return code: {}", code);
    debug!("Container stdout/stderr:\n\nstdout:\n{}\n\nstderr:\n{}\n", BlockFormatter::new(&stdout), BlockFormatter::new(&stderr));
    if let Err(err) = update_client(tx, JobStatus::Completed).await {
        error!("{}", err);
    }

    // If the return code is no bueno, error and show stderr
    if code != 0 {
        return Err(JobStatus::Failed(code, stdout, stderr));
    }

    // Otherwise, decode the output of branelet to the value returned
    let decode = prof.time("Decode");
    let output = stdout.lines().last().unwrap_or_default().to_string();
    let raw: String = match decode_base64(output) {
        Ok(raw) => raw,
        Err(err) => {
            return Err(JobStatus::DecodingFailed(format!("Failed to decode output ase base64: {err}")));
        },
    };
    let value: FullValue = match serde_json::from_str::<Option<FullValue>>(&raw) {
        Ok(value) => value.unwrap_or(FullValue::Void),
        Err(err) => {
            return Err(JobStatus::DecodingFailed(format!("Failed to decode output as JSON: {err}")));
        },
    };
    decode.stop();

    // Done
    debug!("Task '{}' returned value: '{:?}'", tinfo.name, value);
    Ok(value)
}

// /// Runs the given task on a Kubernetes backend.
// ///
// /// # Arguments
// /// - `worker_cfg`: The configuration for this node's environment. For us, contains the location ID of this location and where to find data & intermediate results.
// /// - `kinfo`: Information that determines where and how to connect to the Kubernetes cluster.
// /// - `tx`: The transmission channel over which we should update the client of our progress.
// /// - `container_path`: The path of the downloaded container that we should execute.
// /// - `tinfo`: The TaskInfo that describes the task itself to execute.
// /// - `prof`: A ProfileScope to provide more detailled information about the time it takes to execute a local task.
// ///
// /// # Returns
// /// The return value of the task when it completes..
// ///
// /// # Errors
// /// This function errors if the task fails for whatever reason or we didn't even manage to launch it.
// async fn execute_task_k8s(worker_cfg: &WorkerConfig, kinfo: K8sOptions, tx: &Sender<Result<ExecuteReply, Status>>, container_path: impl AsRef<Path>, tinfo: TaskInfo, prof: ProfileScopeHandle<'_>) -> Result<FullValue, JobStatus> {
//     let container_path : &Path    = container_path.as_ref();
//     let mut tinfo      : TaskInfo = tinfo;
//     let image          : Image    = tinfo.image.clone().unwrap();
//     debug!("Spawning container '{}' as a Kubernetes container...", image);

//     // First, let's read the Kubernetes file
//     let config: k8s::Config = match k8s::read_config(&kinfo.config).await {
//         Ok(config) => config,
//         Err(err)   => { return Err(JobStatus::CreationFailed(format!("Failed to parse Kubernetes configuration file: {err}"))); },
//     };



//     // Let us preprocess the arguments
//     let binds: Vec<VolumeBind> = match prof.time_fut("preprocessing", docker::preprocess_args(&mut tinfo.args, &tinfo.input, &tinfo.result, Some(&worker_cfg.paths.data), &worker_cfg.paths.results)).await {
//         Ok(binds) => binds,
//         Err(err)  => { return Err(JobStatus::CreationFailed(format!("Failed to preprocess arguments: {err}"))); },
//     };

//     // Serialize them next
//     let ser = prof.time("Serialization");
//     let params: String = match serde_json::to_string(&tinfo.args) {
//         Ok(params) => params,
//         Err(err)   => { return Err(JobStatus::CreationFailed(format!("Failed to serialize arguments: {err}"))); },
//     };
//     ser.stop();

//     // Prepare the ExecuteInfo
//     let info: ExecuteInfo = ExecuteInfo::new(
//         &tinfo.name,
//         image,
//         ImageSource::Path(container_path.into()),
//         vec![
//             "-d".into(),
//             "--application-id".into(),
//             "unspecified".into(),
//             "--location-id".into(),
//             worker_cfg.name.clone(),
//             "--job-id".into(),
//             "unspecified".into(),
//             tinfo.kind.unwrap().into(),
//             tinfo.name.clone(),
//             base64::encode(params),
//         ],
//         binds,
//         tinfo.requirements,
//         Network::None,
//     );

//     // Now we can launch the container...
//     let exec = prof.nest("execution");
//     let total = prof.time("Total");
//     let name: String = match exec.time_fut("spawn overhead", docker::launch(&dinfo, info)).await {
//         Ok(name) => name,
//         Err(err) => { return Err(JobStatus::CreationFailed(format!("Failed to spawn container: {err}"))); },
//     };
//     if let Err(err) = update_client(tx, JobStatus::Created).await { error!("{}", err); }
//     if let Err(err) = update_client(tx, JobStatus::Started).await { error!("{}", err); }

//     // ...and wait for it to complete
//     let (code, stdout, stderr): (i32, String, String) = match exec.time_fut("join overhead", docker::join(dinfo, name, keep_container)).await {
//         Ok(name) => name,
//         Err(err) => { return Err(JobStatus::CompletionFailed(format!("Failed to join container: {err}"))); },
//     };
//     total.stop();
//     exec.finish();

//     // Let the client know it was done
//     debug!("Container return code: {}", code);
//     debug!("Container stdout/stderr:\n\nstdout:\n{}\n\nstderr:\n{}\n", BlockFormatter::new(&stdout), BlockFormatter::new(&stderr));
//     if let Err(err) = update_client(tx, JobStatus::Completed).await { error!("{}", err); }

//     // If the return code is no bueno, error and show stderr
//     if code != 0 {
//         return Err(JobStatus::Failed(code, stdout, stderr));
//     }

//     // Otherwise, decode the output of branelet to the value returned
//     let decode = prof.time("Decode");
//     let output = stdout.lines().last().unwrap_or_default().to_string();
//     let raw: String = match decode_base64(output) {
//         Ok(raw)  => raw,
//         Err(err) => { return Err(JobStatus::DecodingFailed(format!("Failed to decode output ase base64: {err}"))); },
//     };
//     let value: FullValue = match serde_json::from_str::<Option<FullValue>>(&raw) {
//         Ok(value) => value.unwrap_or(FullValue::Void),
//         Err(err)  => { return Err(JobStatus::DecodingFailed(format!("Failed to decode output as JSON: {err}"))); },
//     };
//     decode.stop();

//     // Done
//     debug!("Task '{}' returned value: '{:?}'", tinfo.name, value);
//     Ok(value)
// }



/// Runs the given task on the backend.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains the location ID of this location and where to find data & intermediate results.
/// - `proxy`: The proxy client we use to proxy the data transfer.
/// - `tx`: The channel to transmit stuff back to the client on.
/// - `workflow`: The Workflow that we're executing. Useful for communicating with the eFLINT backend.
/// - `cinfo`: The ControlNodeInfo that specifies where to find services over at the control node.
/// - `tinfo`: The TaskInfo that describes the task itself to execute.
/// - `keep_container`: Whether to keep the container after execution or not.
/// - `prof`: A ProfileScope to provide more detailled information about the time it takes to execute a task.
///
/// # Returns
/// Nothing directly, although it does communicate updates, results and errors back to the client via the given `tx`.
///
/// # Errors
/// This fnction may error for many many reasons, but chief among those are unavailable backends or a crashing task.
#[allow(clippy::too_many_arguments)]
async fn execute_task(
    worker_cfg: &WorkerConfig,
    proxy: Arc<ProxyClient>,
    tx: Sender<Result<ExecuteReply, Status>>,
    workflow: Workflow,
    cinfo: ControlNodeInfo,
    tinfo: TaskInfo,
    keep_container: bool,
    prof: ProfileScopeHandle<'_>,
) -> Result<(), ExecuteError> {
    let mut tinfo = tinfo;

    // We update the user first on that the job has been received
    info!("Starting execution of task '{}'", tinfo.name);
    if let Err(err) = update_client(&tx, JobStatus::Received).await {
        error!("{}", err);
    }



    /* CALL PREPARATION */
    // Next, query the API for a package index.
    let idx = prof.time("Index retrieval");
    let index: PackageIndex = match proxy.get_package_index(&format!("{}/graphql", cinfo.api_endpoint)).await {
        Ok(result) => match result {
            Ok(index) => index,
            Err(err) => {
                return err!(tx, ExecuteError::PackageIndexError { endpoint: cinfo.api_endpoint.clone(), err });
            },
        },
        Err(err) => {
            return err!(tx, ExecuteError::ProxyError { err: Box::new(err) });
        },
    };

    // Get the info
    let info: &PackageInfo = match index.get(&tinfo.package_name, Some(&tinfo.package_version)) {
        Some(info) => info,
        None => {
            return err!(tx, ExecuteError::UnknownPackage { name: tinfo.package_name.clone(), version: tinfo.package_version });
        },
    };
    idx.stop();

    // Deduce the image name from that
    tinfo.kind = Some(info.kind);
    tinfo.image = Some(Image::new(&tinfo.package_name, Some(tinfo.package_version), info.digest.clone()));

    // Now load the credentials file to get things going
    let disk = prof.time("File loading");
    let creds: BackendFile = match BackendFile::from_path(&worker_cfg.paths.backend) {
        Ok(creds) => creds,
        Err(err) => {
            return err!(tx, ExecuteError::BackendFileError { path: worker_cfg.paths.backend.clone(), err });
        },
    };
    disk.stop();

    // Download the container from the central node
    let (container_path, container_id, container_hash): (PathBuf, String, Option<String>) = prof
        .nest_fut(format!("container {:?} downloading", tinfo.image.as_ref()), |scope| {
            ensure_container(worker_cfg, proxy, &cinfo.api_endpoint, tinfo.image.as_ref().unwrap(), scope)
        })
        .await?;
    tinfo.image.as_mut().unwrap().digest = Some(container_id);



    /* AUTHORIZATION */
    // We only do the container security thing if the user told us to; otherwise, the hash will be empty
    if let Some(_container_hash) = container_hash {
        let _auth = prof.time("Authorization");

        // First: make sure that the workflow is allowed by the checker
        match assert_task_permission(worker_cfg, &workflow, tinfo.pc).await {
            Ok(true) => {
                debug!("Checker accepted incoming workflow");
                if let Err(err) = update_client(&tx, JobStatus::Authorized).await {
                    error!("{}", err);
                }
            },
            Ok(false) => {
                debug!("Checker rejected incoming workflow");
                if let Err(err) = update_client(&tx, JobStatus::Denied).await {
                    error!("{}", err);
                }
                return Err(ExecuteError::AuthorizationFailure { checker: worker_cfg.services.reg.address.clone() });
            },

            Err(err) => {
                return err!(tx, JobStatus::AuthorizationFailed, ExecuteError::AuthorizationError {
                    checker: worker_cfg.services.reg.address.clone(),
                    err
                });
            },
        }
    }



    /* SCHEDULE */
    // Match on the specific type to find the specific backend
    let value: FullValue = match creds.method {
        Credentials::Local { path, version } => {
            // Prepare the DockerInfo
            let dinfo: DockerOptions = DockerOptions {
                socket:  path.unwrap_or_else(|| PathBuf::from("/var/run/docker.sock")),
                version: ClientVersion(
                    version
                        .map(|(major, minor)| bollard::ClientVersion { major_version: major, minor_version: minor })
                        .unwrap_or(*API_DEFAULT_VERSION),
                ),
            };

            // Do the call
            match prof
                .nest_fut("execution (local)", |scope| execute_task_local(worker_cfg, dinfo, &tx, container_path, tinfo, keep_container, scope))
                .await
            {
                Ok(value) => value,
                Err(status) => {
                    error!("Job failed with status: {:?}", status);
                    if let Err(err) = update_client(&tx, status).await {
                        error!("{}", err);
                    }
                    return Ok(());
                },
            }
        },

        Credentials::Ssh { .. } => {
            error!("SSH backend is not yet supported");
            if let Err(err) = update_client(&tx, JobStatus::CreationFailed("SSH backend is not yet supported".into())).await {
                error!("{}", err);
            }
            return Ok(());
        },

        Credentials::Kubernetes { registry_address: _, config: _ } => {
            error!("Kubernetes backend is not yet supported");
            if let Err(err) = update_client(&tx, JobStatus::CreationFailed("Kubernetes backend is not yet supported".into())).await {
                error!("{}", err);
            }
            return Ok(());

            // // Prepare the options for the Kubernetes client
            // let kinfo: K8sOptions = K8sOptions {
            //     registry_address,
            //     config,
            // };

            // // Prepare the options we want to pass to Kubernetes
            // match prof.nest_fut("execution (k8s)", |scope| execute_task_k8s(worker_cfg, kinfo, &tx, container_path, tinfo, scope)).await {
            //     Ok(value)   => value,
            //     Err(status) => {
            //         error!("Job failed with status: {:?}", status);
            //         if let Err(err) = update_client(&tx, status).await { error!("{}", err); }
            //         return Ok(());
            //     }
            // }
        },
        Credentials::Slurm { .. } => {
            error!("Slurm backend is not yet supported");
            if let Err(err) = update_client(&tx, JobStatus::CreationFailed("Slurm backend is not yet supported".into())).await {
                error!("{}", err);
            }
            return Ok(());
        },
    };
    debug!("Job completed");



    /* RETURN */
    // Alright, we are done; the rest is up to the little branelet itself.
    if let Err(err) = update_client(&tx, JobStatus::Finished(value)).await {
        error!("{}", err);
    }
    Ok(())
}



/// Commits the given intermediate result.
///
/// # Arguments
/// - `worker_cfg`: The configuration for this node's environment. For us, contains where to read intermediate results from and data to.
/// - `results_path`: Path to the shared data results directory. This is where the results live.
/// - `name`: The name of the intermediate result to promote.
/// - `data_name`: The name of the intermediate result to promote it as.
/// - `prof`: A ProfileScope to provide more detailled information about the time it takes to commit a result.
///
/// # Errors
/// This function may error for many many reasons, but chief among those are unavailable registries and such.
async fn commit_result(
    worker_cfg: &WorkerConfig,
    name: impl AsRef<str>,
    data_name: impl AsRef<str>,
    prof: ProfileScopeHandle<'_>,
) -> Result<(), CommitError> {
    let name: &str = name.as_ref();
    let data_name: &str = data_name.as_ref();
    debug!("Commit intermediate result '{}' as '{}'...", name, data_name);



    // Step 1: Check if the dataset already exists (locally)
    let data_path: &Path = &worker_cfg.paths.data;
    let info: Option<AssetInfo> = {
        let _reg = prof.time("Local registry scan");

        // Get the entries in the dataset directory
        let mut entries: tfs::ReadDir = match tfs::read_dir(data_path).await {
            Ok(entries) => entries,
            Err(err) => {
                return Err(CommitError::DirReadError { path: data_path.into(), err });
            },
        };

        // Iterate through them
        let mut found_info: Option<AssetInfo> = None;
        let mut i: usize = 0;
        #[allow(irrefutable_let_patterns)]
        while let entry = entries.next_entry().await {
            // Unwrap it
            let entry: tfs::DirEntry = match entry {
                Ok(Some(entry)) => entry,
                Ok(None) => {
                    break;
                },
                Err(err) => {
                    return Err(CommitError::DirEntryReadError { path: data_path.into(), i, err });
                },
            };

            // Match on directory or not
            let entry_path: PathBuf = entry.path();
            if entry_path.is_dir() {
                // Try to find the data.yml
                let info_path: PathBuf = entry_path.join("data.yml");
                if !info_path.exists() {
                    warn!("Directory '{}' is in the data folder, but does not have a `data.yml` file", entry_path.display());
                    continue;
                }
                if !info_path.is_file() {
                    warn!("Directory '{}' is in the data folder, but the nested `data.yml` file is not a file", entry_path.display());
                    continue;
                }

                // Load it
                let mut info: AssetInfo = match AssetInfo::from_path(&info_path) {
                    Ok(info) => info,
                    Err(err) => {
                        return Err(CommitError::AssetInfoReadError { path: info_path, err });
                    },
                };

                // Canonicalize the assetinfo's path
                match &mut info.access {
                    AccessKind::File { path } => {
                        if path.is_relative() {
                            *path = entry_path.join(&path);
                        }
                    },
                }

                // Keep it if it has the target name
                if info.name == data_name {
                    found_info = Some(info);
                    break;
                }
            }

            // Continue
            i += 1;
        }

        // Done, return the option
        found_info
    };



    // Step 2: Match on whether it already exists or not and copy the file
    let copy = prof.time("Data copying");
    let results_path: &Path = &worker_cfg.paths.results;
    if let Some(info) = info {
        debug!("Dataset '{}' already exists; overwriting file...", data_name);

        // Copy the source to the target destination (file, in this case)
        match &info.access {
            AccessKind::File { path: data_path } => {
                // Remove the old directory first (or file)
                if data_path.is_file() {
                    if let Err(err) = tfs::remove_file(&data_path).await {
                        return Err(CommitError::FileRemoveError { path: data_path.clone(), err });
                    }
                } else if data_path.is_dir() {
                    if let Err(err) = tfs::remove_dir_all(&data_path).await {
                        return Err(CommitError::DirRemoveError { path: data_path.clone(), err });
                    }
                } else if data_path.exists() {
                    return Err(CommitError::PathNotFileNotDir { path: data_path.clone() });
                } else {
                    // Nothing to remove
                    warn!("Previous dataset '{}' is marked as existing, but its data doesn't exist", data_path.display());
                }

                // Simply copy the one directory over the other and it's updated
                if let Err(err) = copy_dir_recursively_async(results_path.join(name), data_path).await {
                    return Err(CommitError::DataCopyError { err });
                };
            },
        }
    } else {
        debug!("Dataset '{}' doesn't exist; creating new entry...", data_name);

        // Prepare the package directory by creating it if it doesn't exist yet
        let dir: PathBuf = data_path.join(data_name);
        if !dir.is_dir() {
            if dir.exists() {
                return Err(CommitError::DataDirNotADir { path: dir });
            }
            if let Err(err) = tfs::create_dir_all(&dir).await {
                return Err(CommitError::DataDirCreateError { path: dir, err });
            }
        }

        // Copy the directory first, to not have the registry use it yet while copying
        if let Err(err) = copy_dir_recursively_async(results_path.join(name), dir.join("data")).await {
            return Err(CommitError::DataCopyError { err });
        };

        // Create a new AssetInfo struct
        let info: AssetInfo = AssetInfo {
            name: data_name.into(),
            owners: None,      // TODO: Merge parent datasets??
            description: None, // TODO: Add parents & algorithm in description??
            created: Utc::now(),

            access: AccessKind::File { path: dir.join("data") },
        };

        // Now write that
        let info_path: PathBuf = dir.join("data.yml");
        let mut handle: tfs::File = match tfs::File::create(&info_path).await {
            Ok(handle) => handle,
            Err(err) => {
                return Err(CommitError::DataInfoCreateError { path: info_path, err });
            },
        };
        let sinfo: String = match serde_yaml::to_string(&info) {
            Ok(sinfo) => sinfo,
            Err(err) => {
                return Err(CommitError::DataInfoSerializeError { err });
            },
        };
        if let Err(err) = handle.write_all(sinfo.as_bytes()).await {
            return Err(CommitError::DataInfoWriteError { path: info_path, err });
        }
    }
    copy.stop();



    // Step 3: Enjoy
    Ok(())
}





/***** LIBRARY *****/
/// Defines a server for incoming worker requests.
#[derive(Clone, Debug)]
pub struct WorkerServer {
    /// The path to the node config file that we store.
    node_config_path: PathBuf,
    /// Whether to remove containers after execution or not (but negated).
    keep_containers:  bool,

    /// The proxy client to connect to the proxy service with.
    proxy: Arc<ProxyClient>,
}

impl WorkerServer {
    /// Constructor for the JobHandler.
    ///
    /// # Arguments
    /// - `node_config_path`: The path to the `node.yml` file that describes this node's environment.
    /// - `keep_containers`: If true, then we will not remove containers after execution (useful for debugging).
    /// - `proxy`: The proxy client to connect to the proxy service with.
    ///
    /// # Returns
    /// A new JobHandler instance.
    #[inline]
    pub fn new(node_config_path: impl Into<PathBuf>, keep_containers: bool, proxy: Arc<ProxyClient>) -> Self {
        Self { node_config_path: node_config_path.into(), keep_containers, proxy }
    }
}

#[tonic::async_trait]
impl JobService for WorkerServer {
    type ExecuteStream = ReceiverStream<Result<ExecuteReply, Status>>;

    async fn preprocess(&self, request: Request<PreprocessRequest>) -> Result<Response<PreprocessReply>, Status> {
        let request = request.into_inner();
        debug!("Receiving preprocess request");

        // Load the location ID from the node config
        let location_id: String = match NodeConfig::from_path(&self.node_config_path) {
            Ok(node_config) => match node_config.node.try_into_worker() {
                Some(node) => node.name,
                None => {
                    error!("Provided a non-worker `node.yml` file; please change to include worker services");
                    return Err(Status::internal("An internal error occurred"));
                },
            },
            Err(err) => {
                error!("Could not load `node.yml` file '{}': {}", self.node_config_path.display(), err);
                return Err(Status::internal("An internal error occurred"));
            },
        };

        // Do the profiling (F the first function)
        let report = ProfileReport::auto_reporting_file("brane-job WorkerServer::preprocess", format!("brane-job_{location_id}_preprocess"));
        let _total = report.time("Total");

        // Fetch the data kind
        let data_name: DataName = match request.data {
            Some(name) => name.into(),
            None => {
                debug!("Incoming request has invalid data name (dropping it)");
                return Err(Status::invalid_argument("Unknown data name"));
            },
        };

        // Parse the preprocess kind
        match request.kind {
            Some(PreprocessKind::TransferRegistryTar(TransferRegistryTar { location, address })) => {
                // Load the node config file
                let disk = report.time("File loading");
                let node_config: NodeConfig = match NodeConfig::from_path(&self.node_config_path) {
                    Ok(config) => config,
                    Err(err) => {
                        error!("{}", err);
                        return Err(Status::internal("An internal error occurred"));
                    },
                };
                let worker: WorkerConfig = match node_config.node.try_into_worker() {
                    Some(worker) => worker,
                    None => {
                        error!("Provided a non-worker `node.yml`; please provide one for a worker node");
                        return Err(Status::internal("An internal error occurred"));
                    },
                };
                disk.stop();

                // Run the function that way
                let access: AccessKind = match report
                    .nest_fut("TransferTar preprocessing", |scope| {
                        preprocess_transfer_tar(&worker, self.proxy.clone(), location, address, data_name, scope)
                    })
                    .await
                {
                    Ok(access) => access,
                    Err(err) => {
                        error!("{}", err);
                        return Err(Status::internal("An internal error occurred"));
                    },
                };

                // Serialize the accesskind and return the reply
                let ser = report.time("Serialization");
                let saccess: String = match serde_json::to_string(&access) {
                    Ok(saccess) => saccess,
                    Err(err) => {
                        error!("{}", PreprocessError::AccessKindSerializeError { err });
                        return Err(Status::internal("An internal error occurred"));
                    },
                };
                ser.stop();

                // Done
                debug!("File transfer complete.");
                Ok(Response::new(PreprocessReply { access: saccess }))
            },

            None => {
                debug!("Incoming request has invalid preprocess kind (dropping it)");
                Err(Status::invalid_argument("Unknown preprocesskind"))
            },
        }
    }

    async fn execute(&self, request: Request<ExecuteRequest>) -> Result<Response<Self::ExecuteStream>, Status> {
        let request = request.into_inner();
        debug!("Receiving execute request");

        // Load the location ID from the node config
        let location_id: String = match NodeConfig::from_path(&self.node_config_path) {
            Ok(node_config) => match node_config.node.try_into_worker() {
                Some(node) => node.name,
                None => {
                    error!("Provided a non-worker `node.yml` file; please change to include worker services");
                    return Err(Status::internal("An internal error occurred"));
                },
            },
            Err(err) => {
                error!("Could not load `node.yml` file '{}': {}", self.node_config_path.display(), err);
                return Err(Status::internal("An internal error occurred"));
            },
        };

        // Do the profiling
        let report = ProfileReport::auto_reporting_file("brane-job WorkerServer::execute", format!("brane-job_{location_id}_execute"));
        let overhead = report.nest("handler overhead");
        let total = overhead.time("Total");

        // Prepare gRPC stream between client and (this) job delegate.
        let (tx, rx) = mpsc::channel::<Result<ExecuteReply, Status>>(10);

        // Attempt to parse the workflow
        let par = overhead.time("Parsing");
        let workflow: Workflow = match serde_json::from_str(&request.workflow) {
            Ok(workflow) => workflow,
            Err(err) => {
                error!("Failed to deserialize workflow: {}", err);
                debug!(
                    "Workflow:\n{}\n{}\n{}\n",
                    (0..80).map(|_| '-').collect::<String>(),
                    request.workflow,
                    (0..80).map(|_| '-').collect::<String>()
                );
                if let Err(err) = tx.send(Err(Status::invalid_argument(format!("Failed to deserialize workflow: {err}")))).await {
                    error!("{}", err);
                }
                return Ok(Response::new(ReceiverStream::new(rx)));
            },
        };

        // Fetch the task ID
        if request.task_def as usize >= workflow.table.tasks.len() {
            error!("Given task ID '{}' is out-of-bounds for workflow with {} tasks", request.task_def, workflow.table.tasks.len());
            if let Err(err) = tx
                .send(Err(Status::invalid_argument(format!(
                    "Given task ID '{}' is out-of-bounds for workflow with {} tasks",
                    request.task_def,
                    workflow.table.tasks.len()
                ))))
                .await
            {
                error!("{}", err);
            }
            return Ok(Response::new(ReceiverStream::new(rx)));
        }
        let task: &ComputeTaskDef = match &workflow.table.tasks[request.task_def as usize] {
            TaskDef::Compute(def) => def,
            _ => {
                error!("A task of type '{}' is not yet supported", workflow.table.tasks[request.task_def as usize].variant());
                if let Err(err) = tx
                    .send(Err(Status::invalid_argument(format!(
                        "A task of type '{}' is not yet supported",
                        workflow.table.tasks[request.task_def as usize].variant()
                    ))))
                    .await
                {
                    error!("{}", err);
                }
                return Ok(Response::new(ReceiverStream::new(rx)));
            },
        };

        // Attempt to parse the input
        let input: HashMap<DataName, AccessKind> = match json_to_map(&request.input) {
            Ok(input) => input,
            Err(err) => {
                error!("Failed to deserialize input '{}': {}", request.input, err);
                if let Err(err) = tx.send(Err(Status::invalid_argument(format!("Failed to deserialize input '{}': {}", request.input, err)))).await {
                    error!("{}", err);
                }
                return Ok(Response::new(ReceiverStream::new(rx)));
            },
        };

        // Attempt to parse the arguments
        let args: HashMap<String, FullValue> = match serde_json::from_str(&request.args) {
            Ok(args) => args,
            Err(err) => {
                error!("Failed to deserialize arguments '{}': {}", request.args, err);
                if let Err(err) = tx.send(Err(Status::invalid_argument(format!("Failed to deserialize arguments '{}': {}", request.args, err)))).await
                {
                    error!("{}", err);
                }
                return Ok(Response::new(ReceiverStream::new(rx)));
            },
        };
        par.stop();

        // Load the node config file
        let disk = overhead.time("File loading");
        let node_config: NodeConfig = match NodeConfig::from_path(&self.node_config_path) {
            Ok(config) => config,
            Err(err) => {
                error!("{}", err);
                return Err(Status::internal("An internal error occurred"));
            },
        };
        let worker: WorkerConfig = match node_config.node.try_into_worker() {
            Some(worker) => worker,
            None => {
                error!("Provided a non-worker `node.yml`; please provide one for a worker node");
                return Err(Status::internal("An internal error occurred"));
            },
        };
        disk.stop();

        // Collect some request data into ControlNodeInfo's and TaskInfo's.
        let cinfo: ControlNodeInfo = ControlNodeInfo::new(request.api);
        let tinfo: TaskInfo = TaskInfo::new(
            task.function.name.clone(),
            (request.call_fn as usize, request.call_edge as usize),
            task.package.clone(),
            task.version,
            input,
            request.result,
            args,
            task.requirements.clone(),
        );
        total.stop();
        overhead.finish();

        // Now move the rest to a separate task so we can return the start of the stream
        let keep_containers: bool = self.keep_containers;
        let proxy: Arc<ProxyClient> = self.proxy.clone();
        tokio::spawn(async move {
            let worker: WorkerConfig = worker;
            report.nest_fut("execution", |scope| execute_task(&worker, proxy, tx, workflow, cinfo, tinfo, keep_containers, scope)).await
        });

        // Return the stream so the user can get updates
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn commit(&self, request: Request<CommitRequest>) -> Result<Response<CommitReply>, Status> {
        let request = request.into_inner();
        debug!("Receiving commit request");

        // Load the location ID from the node config
        let location_id: String = match NodeConfig::from_path(&self.node_config_path) {
            Ok(node_config) => match node_config.node.try_into_worker() {
                Some(node) => node.name,
                None => {
                    error!("Provided a non-worker `node.yml` file; please change to include worker services");
                    return Err(Status::internal("An internal error occurred"));
                },
            },
            Err(err) => {
                error!("Could not load `node.yml` file '{}': {}", self.node_config_path.display(), err);
                return Err(Status::internal("An internal error occurred"));
            },
        };

        // Do the profiling
        let report = ProfileReport::auto_reporting_file("brane-job WorkerServer::commit", format!("brane-job_{location_id}_commit"));
        let _guard = report.time("Total");

        // Load the node config file
        let disk = report.time("File loading");
        let node_config: NodeConfig = match NodeConfig::from_path(&self.node_config_path) {
            Ok(config) => config,
            Err(err) => {
                error!("{}", err);
                return Err(Status::internal("An internal error occurred"));
            },
        };
        let worker: WorkerConfig = match node_config.node.try_into_worker() {
            Some(worker) => worker,
            None => {
                error!("Provided a non-worker `node.yml`; please provide one for a worker node");
                return Err(Status::internal("An internal error occurred"));
            },
        };
        disk.stop();

        // Run the function
        if let Err(err) = report.nest_fut("committing", |scope| commit_result(&worker, &request.result_name, &request.data_name, scope)).await {
            error!("{}", err);
            return Err(Status::internal("An internal error occurred"));
        }

        // Be done without any error
        Ok(Response::new(CommitReply {}))
    }
}
