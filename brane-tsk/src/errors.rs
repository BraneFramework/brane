//  ERRORS.rs
//    by Lut99
//
//  Created:
//    24 Oct 2022, 15:27:26
//  Last edited:
//    02 May 2025, 11:43:11
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines errors that occur in the `brane-tsk` crate.
//

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult, Write};
use std::path::PathBuf;

use bollard::ClientVersion;
use bollard::secret::{BuildInfo, CreateImageInfo};
use brane_shr::formatters::{BlockFormatter, Capitalizeable};
use enum_debug::EnumDebug as _;
use reqwest::StatusCode;
use serde_json::Value;
use specifications::address::Address;
use specifications::container::Image;
use specifications::data::DataName;
use specifications::driving::ExecuteReply;
use specifications::package::Capability;
use specifications::pc::ProgramCounter;
use specifications::version::Version;
use specifications::wir::Workflow;
use specifications::wir::func_id::FunctionId;
use specifications::wir::locations::{Location, Locations};
// The TaskReply is here for legacy reasons; bad name
use specifications::working::{ExecuteReply as TaskReply, TaskStatus};
use tonic::Status;

/***** CONSTANTS *****/
const BLOCK_SEPARATOR: &str = "--------------------------------------------------------------------------------";

/***** AUXILLARY *****/
/// Turns a [`String`] into something that [`Error`]s.
// FIXME: either use enumerated errors or use something like anyhow
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StringError(pub String);
impl Display for StringError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", self.0) }
}

impl Error for StringError {}

/***** LIBRARY *****/
/// Defines a kind of combination of all the possible errors that may occur in the process.
#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    /// Something went wrong while planning.
    #[error("Failed to plan workflow")]
    PlanError { source: PlanError },
    /// Something went wrong while executing.
    #[error("Failed to execute workflow")]
    ExecError { source: brane_exe::errors::VmError },
}

/// Defines common errors that occur when trying to plan a workflow.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// Failed to load the infrastructure file.
    #[error("Failed to load infrastructure file")]
    InfraFileLoadError { source: brane_cfg::infra::Error },

    /// The user didn't specify the location (specifically enough).
    #[error("Ambigious location for task '{}': {}", name, if let Locations::Restricted(locs) = locs { format!("possible locations are {}, but you need to reduce that to only 1 (use On-structs for that)", locs.join(", ")) } else { "all locations are possible, but you need to reduce that to only 1 (use On-structs for that)".into() })]
    AmbigiousLocationError { name: String, locs: Locations },
    /// Failed to send a request to the API service.
    #[error("Failed to send GET-request to '{address}'")]
    RequestError { address: String, source: reqwest::Error },
    /// The request failed with a non-OK status code
    #[error("GET-request to '{}' failed with {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(err) = err { format!("\n\nResponse:\n{}\n", BlockFormatter::new(err)) } else { String::new() })]
    RequestFailure { address: String, code: reqwest::StatusCode, err: Option<String> },
    /// Failed to get the body of a request.
    #[error("Failed to get the body of response from '{address}' as UTF-8 text")]
    RequestBodyError { address: String, source: reqwest::Error },
    /// Failed to parse the body of the request as valid JSON
    #[error("Failed to parse response '{raw}' from '{address}' as valid JSON")]
    RequestParseError { address: String, raw: String, source: serde_json::Error },
    /// The planned domain does not support the task.
    #[error("Location '{loc}' only supports capabilities {got:?}, whereas task '{task}' requires capabilities {expected:?}")]
    UnsupportedCapabilities { task: String, loc: String, expected: HashSet<Capability>, got: HashSet<Capability> },
    /// The given dataset was unknown to us.
    #[error("Unknown dataset '{name}'")]
    UnknownDataset { name: String },
    /// The given intermediate result was unknown to us.
    #[error("Unknown intermediate result '{name}'")]
    UnknownIntermediateResult { name: String },
    /// We failed to insert one of the dataset in the runtime set.
    #[error("Failed to plan dataset")]
    DataPlanError { source: specifications::data::RuntimeDataIndexError },
    /// We can't access a dataset in the local instance.
    #[error("Dataset '{}' is unavailable{}", name, if !locs.is_empty() { format!( "; however, locations {} do (try to get download permission to those datasets)", locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")) } else { String::new() })]
    DatasetUnavailable { name: String, locs: Vec<String> },
    /// We can't access an intermediate result in the local instance.
    #[error("Intermediate result '{}' is unavailable{}", name, if !locs.is_empty() { format!( "; however, locations {} do (try to get download permission to those datasets)", locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")) } else { String::new() })]
    IntermediateResultUnavailable { name: String, locs: Vec<String> },

    // Instance-only
    /// Failed to serialize the internal workflow.
    #[error("Failed to serialize workflow '{id}'")]
    WorkflowSerialize { id: String, source: serde_json::Error },
    /// Failed to serialize the [`PlanningRequest`](specifications::planning::PlanningRequest).
    #[error("Failed to serialize planning request for workflow '{id}'")]
    PlanningRequestSerialize { id: String, source: serde_json::Error },
    /// Failed to create a request to plan at the planner.
    #[error("Failed to create request to plan workflow '{id}' for '{url}'")]
    PlanningRequest { id: String, url: String, source: reqwest::Error },
    /// Failed to send a request to plan at the planner.
    #[error("Failed to send request to plan workflow '{id}' to '{url}'")]
    PlanningRequestSend { id: String, url: String, source: reqwest::Error },
    /// The server failed to plan.
    #[error("Planner failed to plan workflow '{}' (server at '{url}' returned {} ({})){}", id, code.as_u16(), code.canonical_reason().unwrap_or("???"), if let Some(res) = response { format!("\n\nResponse:\n{}\n", BlockFormatter::new(res)) } else { String::new() })]
    PlanningFailure { id: String, url: String, code: StatusCode, response: Option<String> },
    /// Failed to download the server's response.
    #[error("Failed to download response from '{url}' for workflow '{id}'")]
    PlanningResponseDownload { id: String, url: String, source: reqwest::Error },
    /// failed to parse the server's response.
    #[error("Failed to parse response from '{}' to planning workflow '{}'\n\nResponse:\n{}\n", url, id, BlockFormatter::new(raw))]
    PlanningResponseParse { id: String, url: String, raw: String, source: serde_json::Error },
    /// Failed to parse the server's returned plan.
    #[error("Failed to parse plan returned by '{}' to plan workflow '{}'\n\nPlan:\n{}\n", url, id, BlockFormatter::new(format!("{:?}", raw)))]
    PlanningPlanParse { id: String, url: String, raw: Value, source: serde_json::Error },

    /// Failed to a checker to validate the workflow
    #[error("Failed to create gRPC connection to `brane-job` service at '{endpoint}'")]
    GrpcConnectError { endpoint: Address, source: specifications::working::JobServiceError },
    /// Failed to connect to the proxy service
    #[error("Failed to use `brane-prx` service")]
    ProxyError { source: Box<dyn 'static + Send + Error> },
    /// Failed to submit the gRPC request to validate a workflow.
    #[error("Failed to send {what} over gRPC connection to `brane-job` service at '{endpoint}'")]
    GrpcRequestError { what: &'static str, endpoint: Address, source: tonic::Status },
    /// One of the checkers denied everything :/
    #[error("Checker of domain '{domain}' denied plan{}", if !reasons.is_empty() { format!( "\n\nReasons:\n{}", reasons.iter().fold(String::new(), |mut output, r| { let _ = writeln!(output, "  - {r}"); output })) } else { String::new() })]
    CheckerDenied { domain: Location, reasons: Vec<String> },
}

/// Defines common errors that occur when trying to preprocess datasets.
#[derive(Debug, thiserror::Error)]
pub enum PreprocessError {
    /// The dataset was _still_ unavailable after preprocessing
    #[error("{} '{}' is not available locally", name.variant(), name.name())]
    UnavailableData { name: DataName },

    // Instance only (client-side)
    /// Failed to load the node config file.
    #[error("Failed to load node config file '{}'", path.display())]
    NodeConfigReadError { path: PathBuf, source: brane_cfg::info::YamlError },
    /// Failed to load the infra file.
    #[error("Failed to load infrastructure file '{}'", path.display())]
    InfraReadError { path: PathBuf, source: brane_cfg::infra::Error },
    /// The given location was unknown.
    #[error("Unknown location '{loc}'")]
    UnknownLocationError { loc: Location },
    /// Failed to connect to a proxy.
    #[error("Failed to prepare proxy service")]
    ProxyError { source: Box<dyn 'static + Send + Sync + Error> },
    /// Failed to connect to a delegate node with gRPC
    #[error("Failed to start gRPC connection with delegate node '{endpoint}'")]
    GrpcConnectError { endpoint: String, source: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    #[error("Failed to send {what} request to delegate node '{endpoint}'")]
    GrpcRequestError { what: &'static str, endpoint: String, source: tonic::Status },
    /// Failed to re-serialize the access kind.
    #[error("Failed to parse access kind '{raw}' sent by remote delegate '{endpoint}'")]
    AccessKindParseError { endpoint: String, raw: String, source: serde_json::Error },

    /// Failed to open/read a given file.
    #[error("Failed to read {} file '{}'", what, path.display())]
    FileReadError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to parse an identity file.
    #[error("Failed to parse identity file '{}'", path.display())]
    IdentityFileError { path: PathBuf, source: reqwest::Error },
    /// Failed to parse a certificate.
    #[error("Failed to parse certificate '{}'", path.display())]
    CertificateError { path: PathBuf, source: reqwest::Error },
    /// Failed to resolve a location identifier to a registry address.
    #[error("Failed to resolve location ID '{id}' to a local registry address")]
    LocationResolve { id: String, source: crate::caches::DomainRegistryCacheError },
    /// A directory was not a directory but a file.
    #[error("{} directory '{}' is not a directory", what.capitalize(), path.display())]
    DirNotADirError { what: &'static str, path: PathBuf },
    /// A directory what not a directory because it didn't exist.
    #[error("{} directory '{}' doesn't exist", what.capitalize(), path.display())]
    DirNotExistsError { what: &'static str, path: PathBuf },
    /// A directory could not be removed.
    #[error("Failed to remove {} directory '{}'", what, path.display())]
    DirRemoveError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// A directory could not be created.
    #[error("Failed to create {} directory '{}'", what, path.display())]
    DirCreateError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to create a reqwest proxy object.
    #[error("Failed to create proxy to '{address}'")]
    ProxyCreateError { address: Address, source: reqwest::Error },
    /// Failed to create a reqwest client.
    #[error("Failed to create HTTP-client")]
    ClientCreateError { source: reqwest::Error },
    /// Failed to send a GET-request to fetch the data.
    #[error("Failed to send GET download request to '{address}'")]
    DownloadRequestError { address: String, source: reqwest::Error },
    /// The given download request failed with a non-success status code.
    #[error("GET download request to '{}' failed with status code {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(message) = message { format!(": {message}") } else { String::new() })]
    DownloadRequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to reach the next chunk of data.
    #[error("Failed to get next chunk in download stream from '{address}'")]
    DownloadStreamError { address: String, source: reqwest::Error },
    /// Failed to create the file to which we write the download stream.
    #[error("Failed to create tarball file '{}'", path.display())]
    TarCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to (re-)open the file to which we've written the download stream.
    #[error("Failed to re-open tarball file '{}'", path.display())]
    TarOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    #[error("Failed to write to tarball file '{}'", path.display())]
    TarWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to extract the downloaded tar.
    #[error("Failed to extract dataset")]
    DataExtractError { source: brane_shr::fs::Error },
    /// Failed to serialize the preprocessrequest.
    #[error("Failed to serialize the given AccessKind")]
    AccessKindSerializeError { source: serde_json::Error },

    /// Failed to parse the backend file.
    #[error("Failed to load backend file")]
    BackendFileError { source: brane_cfg::backend::Error },
    /// The given backend type is not (yet) supported.
    #[error("Backend type '{what}' is not (yet) supported")]
    UnsupportedBackend { what: &'static str },
}

/// Defines common errors that occur when trying to execute tasks.
///
/// Note: we've boxed `Image` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    // General errors
    /// We encountered a package call that we didn't know.
    #[error("Unknown package '{name}' (or it does not have version {version})")]
    UnknownPackage { name: String, version: Version },
    /// We encountered a dataset/result that we didn't know.
    #[error("Unknown {} '{}'", name.variant(), name.name())]
    UnknownData { name: DataName },
    /// Failed to serialize task's input arguments
    #[error("Failed to serialize input arguments")]
    ArgsEncodeError { source: serde_json::Error },
    /// The external call failed with a nonzero exit code and some stdout/stderr
    #[error(
        "Task '{}' (image '{}') failed with exit code {}\n\n{}\n\n{}\n\n",
        name,
        image,
        code,
        BlockFormatter::new(stdout),
        BlockFormatter::new(stderr)
    )]
    ExternalCallFailed { name: String, image: Box<Image>, code: i32, stdout: String, stderr: String },
    /// Failed to decode the branelet output from base64 to raw bytes
    #[error("Failed to decode the following task output as valid Base64:\n{}\n\n", BlockFormatter::new(raw))]
    Base64DecodeError { raw: String, source: base64::DecodeError },
    /// Failed to decode the branelet output from raw bytes to an UTF-8 string
    #[error("Failed to decode the following task output as valid UTF-8:\n{}\n\n", BlockFormatter::new(raw))]
    Utf8DecodeError { raw: String, source: std::string::FromUtf8Error },
    /// Failed to decode the branelet output from an UTF-8 string to a FullValue
    #[error("Failed to decode the following task output as valid JSON:\n{}\n\n", BlockFormatter::new(raw))]
    JsonDecodeError { raw: String, source: serde_json::Error },

    // Docker errors
    /// Failed to create a new volume bind
    #[error("Failed to create VolumeBind")]
    VolumeBindError { source: specifications::container::VolumeBindError },
    /// The generated path of a result is not a directory
    #[error("Result directory '{}' exists but is not a directory", path.display())]
    ResultDirNotADir { path: PathBuf },
    /// Could not remove the old result directory
    #[error("Failed to remove existing result directory '{}'", path.display())]
    ResultDirRemoveError { path: PathBuf, source: std::io::Error },
    /// Could not create the new result directory
    #[error("Failed to create result directory '{}'", path.display())]
    ResultDirCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to run the task as a local Docker container
    #[error("Failed to execute task '{name}' (image '{image}') as a Docker container")]
    DockerError { name: String, image: Box<Image>, source: DockerError },

    // Instance-only (client side)
    /// The given job status was missing a string while we expected one
    #[error("Incoming status update {status:?} is missing mandatory `value` field")]
    StatusEmptyStringError { status: TaskStatus },
    /// Failed to parse the given value as a FullValue
    #[error("Failed to parse '{raw}' as a FullValue in incoming status update {status:?}")]
    StatusValueParseError { status: TaskStatus, raw: String, source: serde_json::Error },
    /// Failed to parse the given value as a return code/stdout/stderr triplet.
    #[error("Failed to parse '{raw}' as a return code/stdout/stderr triplet in incoming status update {status:?}")]
    StatusTripletParseError { status: TaskStatus, raw: String, source: serde_json::Error },
    /// Failed to update the client of a status change.
    #[error("Failed to update client of status {status:?}")]
    ClientUpdateError { status: TaskStatus, source: tokio::sync::mpsc::error::SendError<Result<TaskReply, Status>> },
    /// Failed to load the node config file.
    #[error("Failed to load node config file '{}'", path.display())]
    NodeConfigReadError { path: PathBuf, source: brane_cfg::info::YamlError },
    /// Failed to load the infra file.
    #[error("Failed to load infrastructure file '{}'", path.display())]
    InfraReadError { path: PathBuf, source: brane_cfg::infra::Error },
    /// The given location was unknown.
    #[error("Unknown location '{loc}'")]
    UnknownLocationError { loc: Location },
    /// Failed to prepare the proxy service.
    #[error("Failed to prepare proxy service")]
    ProxyError { source: Box<dyn 'static + Send + Sync + Error> },
    /// Failed to connect to a delegate node with gRPC
    #[error("Failed to start gRPC connection with delegate node '{endpoint}'")]
    GrpcConnectError { endpoint: String, source: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    #[error("Failed to send {what} request to delegate node '{endpoint}'")]
    GrpcRequestError { what: &'static str, endpoint: String, source: tonic::Status },
    /// Preprocessing failed with the following error.
    #[error("Remote delegate '{endpoint}' returned status '{status:?}' while executing task '{name}'")]
    ExecuteError { endpoint: String, name: String, status: TaskStatus, source: StringError },

    // Instance-only (worker side)
    /// Failed to load the digest cache file
    #[error("Failed to read cached digest in '{}'", path.display())]
    DigestReadError { path: PathBuf, source: std::io::Error },
    /// Failed to fetch the digest of an already existing image.
    #[error("Failed to read digest of image '{}'", path.display())]
    DigestError { path: PathBuf, source: DockerError },
    /// Failed to create a reqwest proxy object.
    #[error("Failed to create proxy to '{address}'")]
    ProxyCreateError { address: Address, source: reqwest::Error },
    /// Failed to create a reqwest client.
    #[error("Failed to create HTTP-client")]
    ClientCreateError { source: reqwest::Error },
    /// Failed to send a GET-request to fetch the data.
    #[error("Failed to send GET download request to '{address}'")]
    DownloadRequestError { address: String, source: reqwest::Error },
    /// The given download request failed with a non-success status code.
    #[error("GET download request to '{}' failed with status code {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(message) = message { format!(": {message}") } else { String::new() })]
    DownloadRequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to reach the next chunk of data.
    #[error("Failed to get next chunk in download stream from '{address}'")]
    DownloadStreamError { address: String, source: reqwest::Error },
    /// Failed to create the file to which we write the download stream.
    #[error("Failed to create tarball file '{}'", path.display())]
    ImageCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    #[error("Failed to write to tarball file '{}'", path.display())]
    ImageWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to write to the file where we write the container ID.
    #[error("Failed to write image ID to file '{}'", path.display())]
    IdWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to read from the file where we cached the container ID.
    #[error("Failed to read image from file '{}'", path.display())]
    IdReadError { path: PathBuf, source: std::io::Error },
    /// Failed to hash the given container.
    #[error("Failed to hash image")]
    HashError { source: DockerError },
    /// Failed to write to the file where we write the container hash.
    #[error("Failed to write image hash to file '{}'", path.display())]
    HashWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to read to the file where we cached the container hash.
    #[error("Failed to read image hash from file '{}'", path.display())]
    HashReadError { path: PathBuf, source: std::io::Error },

    /// The checker rejected the workflow.
    #[error("Checker rejected workflow")]
    AuthorizationFailure { checker: Address },
    /// The checker failed to check workflow authorization.
    #[error("Checker failed to authorize workflow")]
    AuthorizationError { checker: Address, source: AuthorizeError },
    /// Failed to get an up-to-date package index.
    #[error("Failed to get PackageIndex from '{endpoint}'")]
    PackageIndexError { endpoint: String, source: ApiError },
    /// Failed to load the backend file.
    #[error("Failed to load backend file '{}'", path.display())]
    BackendFileError { path: PathBuf, source: brane_cfg::backend::Error },
}

/// A special case of the execute error, this relates to authorization errors in the backend eFLINT reasoner (or other reasoners).
#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    /// Failed to generate a new JWT for a request.
    #[error("Failed to generate new JWT using secret '{}'", secret.display())]
    TokenGenerate { secret: PathBuf, source: specifications::policy::Error },
    /// Failed to build a `reqwest::Client`.
    #[error("Failed to build HTTP client")]
    ClientBuild { source: reqwest::Error },
    /// Failed to build a request to the policy reasoner.
    #[error("Failed to build an ExecuteRequest destined for the checker at '{addr}'")]
    ExecuteRequestBuild { addr: String, source: reqwest::Error },
    /// Failed to send a request to the policy reasoner.
    #[error("Failed to send ExecuteRequest to checker '{addr}'")]
    ExecuteRequestSend { addr: String, source: reqwest::Error },
    /// Request did not succeed
    #[error("ExecuteRequest to checker '{}' failed with status code {} ({}){}", addr, code, code.canonical_reason().unwrap_or("???"), if let Some(err) = err { format!("\n\nResponse:\n{}\n{}\n{}\n", (0..80).map(|_| '-').collect::<String>(), err, (0..80).map(|_| '-').collect::<String>()) } else { String::new() })]
    ExecuteRequestFailure { addr: String, code: StatusCode, err: Option<String> },
    /// Failed to download the body of an execute request response.
    #[error("Failed to download response body from '{addr}'")]
    ExecuteBodyDownload { addr: String, source: reqwest::Error },
    /// Failed to deserialize the body of an execute request response.
    #[error("Failed to deserialize response body received from '{}' as valid JSON\n\nResponse:\n{}\n", addr, BlockFormatter::new(raw))]
    ExecuteBodyDeserialize { addr: String, raw: String, source: serde_json::Error },

    /// The data to authorize is not input to the task given as context.
    #[error("Dataset '{data_name}' is not an input to task {pc}")]
    AuthorizationDataMismatch { pc: ProgramCounter, data_name: DataName },
    /// The user to authorize does not execute the given task.
    #[error("Authorized user '{}' does not match '{}' user in workflow\n\nWorkflow:\n{:#?}\n", authenticated, who, workflow)]
    AuthorizationUserMismatch { who: String, authenticated: String, workflow: Workflow },
    /// An edge was referenced to be executed which wasn't an [`Edge::Node`](specifications::wir::Edge).
    #[error("Edge {pc} in workflow is not an Edge::Node but an Edge::{got}")]
    AuthorizationWrongEdge { pc: ProgramCounter, got: String },
    /// An edge index given was out-of-bounds for the given function.
    #[error("Edge index {got} is out-of-bounds for function {func} with {max} edges")]
    IllegalEdgeIdx { func: FunctionId, got: usize, max: usize },
    /// A given function does not exist
    #[error("Function {got} does not exist in given workflow")]
    IllegalFuncId { got: FunctionId },
    /// There was a node in a workflow with no `at`-specified.
    #[error("Node call at {pc} has no location planned")]
    MissingLocation { pc: ProgramCounter },
    /// The workflow has no end user specified.
    #[error("Given workflow has no end user specified\n\nWorkflow:\n{}\n", BlockFormatter::new(workflow))]
    NoWorkflowUser { workflow: String },
}

/// Defines common errors that occur when trying to write to stdout.
#[derive(Debug, thiserror::Error)]
pub enum StdoutError {
    /// Failed to write to the gRPC channel to feedback stdout back to the client.
    #[error("Failed to write on gRPC channel back to client")]
    TxWriteError { source: tokio::sync::mpsc::error::SendError<Result<ExecuteReply, Status>> },
}

/// Defines common errors that occur when trying to commit an intermediate result.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    // Docker-local errors
    /// The given dataset was unavailable locally
    #[error("Dataset '{}' is unavailable{}", name, if !locs.is_empty() { format!( "; however, locations {} do (try to get download permission to those datasets)", locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")) } else { String::new() })]
    UnavailableDataError { name: String, locs: Vec<String> },
    /// The generated path of a data is not a directory
    #[error("Dataset directory '{}' exists but is not a directory", path.display())]
    DataDirNotADir { path: PathBuf },
    /// Could not create the new data directory
    #[error("Failed to create dataset directory '{}'", path.display())]
    DataDirCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to create a new DataInfo file.
    #[error("Failed to create new data info file '{}'", path.display())]
    DataInfoCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to serialize a new DataInfo file.
    #[error("Failed to serialize DataInfo struct")]
    DataInfoSerializeError { source: serde_yaml::Error },
    /// Failed to write the DataInfo the the created file.
    #[error("Failed to write DataInfo to '{}'", path.display())]
    DataInfoWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to read the given directory.
    #[error("Failed to read directory '{}'", path.display())]
    DirReadError { path: PathBuf, source: std::io::Error },
    /// Failed to read the given directory entry.
    #[error("Failed to read entry {} in directory '{}'", i, path.display())]
    DirEntryReadError { path: PathBuf, i: usize, source: std::io::Error },
    /// Failed to copy the data
    #[error("Failed to copy data directory")]
    DataCopyError { source: brane_shr::fs::Error },

    // Instance-only (client side)
    /// Failed to load the node config file.
    #[error("Failed to load node config file '{}'", path.display())]
    NodeConfigReadError { path: PathBuf, source: brane_cfg::info::YamlError },
    /// Failed to load the infra file.
    #[error("Failed to load infrastructure file '{}'", path.display())]
    InfraReadError { path: PathBuf, source: brane_cfg::infra::Error },
    /// The given location was unknown.
    #[error("Unknown location '{loc}'")]
    UnknownLocationError { loc: Location },
    /// Failed to prepare the proxy service.
    #[error("Failed to prepare proxy service")]
    ProxyError { source: Box<dyn 'static + Send + Sync + Error> },
    /// Failed to connect to a delegate node with gRPC
    #[error("Failed to start gRPC connection with delegate node '{endpoint}'")]
    GrpcConnectError { endpoint: String, source: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    #[error("Failed to send {what} request to delegate node '{endpoint}'")]
    GrpcRequestError { what: &'static str, endpoint: String, source: tonic::Status },

    // Instance-only (worker side)
    /// Failed to read the AssetInfo file.
    #[error("Failed to load asset info file '{}'", path.display())]
    AssetInfoReadError { path: PathBuf, source: specifications::data::AssetInfoError },
    /// Failed to remove a file.
    #[error("Failed to remove file '{}'", path.display())]
    FileRemoveError { path: PathBuf, source: std::io::Error },
    /// Failed to remove a directory.
    #[error("Failed to remove directory '{}'", path.display())]
    DirRemoveError { path: PathBuf, source: std::io::Error },
    /// A given path is neither a file nor a directory.
    #[error("Given path '{}' neither points to a file nor a directory", path.display())]
    PathNotFileNotDir { path: PathBuf },
}

/// Collects errors that relate to the AppId or TaskId (actually only parser errors).
#[derive(Debug, thiserror::Error)]
pub enum IdError {
    /// Failed to parse the AppId from a string.
    #[error("Failed to parse {what} from '{raw}'")]
    ParseError { what: &'static str, raw: String, source: uuid::Error },
}

/// Collects errors that relate to Docker.
///
/// Note: we've boxed `Image` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    /// We failed to connect to the local Docker daemon.
    #[error("Failed to connect to the local Docker daemon through socket '{}' and with client version {}", path.display(), version)]
    ConnectionError { path: PathBuf, version: ClientVersion, source: bollard::errors::Error },

    /// Failed to wait for the container with the given name.
    #[error("Failed to wait for Docker container with name '{name}'")]
    WaitError { name: String, source: bollard::errors::Error },
    /// Failed to read the logs of a container.
    #[error("Failed to get logs of Docker container with name '{name}'")]
    LogsError { name: String, source: bollard::errors::Error },

    /// Failed to inspect the given container.
    #[error("Failed to inspect Docker container with name '{name}'")]
    InspectContainerError { name: String, source: bollard::errors::Error },
    /// The given container was not attached to any networks.
    #[error("Docker container with name '{name}' is not connected to any networks")]
    ContainerNoNetwork { name: String },

    /// Could not create and/or start the given container.
    #[error("Could not create Docker container with name '{name}' (image: {image})")]
    CreateContainerError { name: String, image: Box<Image>, source: bollard::errors::Error },
    /// Fialed to start the given container.
    #[error("Could not start Docker container with name '{name}' (image: {image})")]
    StartError { name: String, image: Box<Image>, source: bollard::errors::Error },

    /// An executing container had no execution state (it wasn't started?)
    #[error("Docker container with name '{name}' has no execution state (has it been started?)")]
    ContainerNoState { name: String },
    /// An executing container had no return code.
    #[error("Docker container with name '{name}' has no return code (did you wait before completing?)")]
    ContainerNoExitCode { name: String },

    /// Failed to remove the given container.
    #[error("Fialed to remove Docker container with name '{name}'")]
    ContainerRemoveError { name: String, source: bollard::errors::Error },

    /// Failed to open the given image file.
    #[error("Failed to open image file '{}'", path.display())]
    ImageFileOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to import the given image file.
    #[error("Failed to import image file '{}' into Docker engine", path.display())]
    ImageImportError { path: PathBuf, source: bollard::errors::Error },
    /// Failed to find the digest after importing the given image.
    #[error("Failed to read digest after importing image '{}'\n\nReturned infos:\n{BLOCK_SEPARATOR}\n{}{BLOCK_SEPARATOR}\n",
        path.display(),
        infos.iter().fold(String::new(), |mut acc, line| { writeln!(acc, "{line:?}").expect("Writing to string"); acc }),
    )]
    ImageImportFindId { path: PathBuf, infos: Vec<BuildInfo> },
    /// Failed to create the given image file.
    #[error("Failed to create image file '{}'", path.display())]
    ImageFileCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to download a piece of the image from the Docker client.
    #[error("Failed to export image '{name}'")]
    ImageExportError { name: String, source: bollard::errors::Error },
    /// Failed to write a chunk of the exported image.
    #[error("Failed to write to image file '{}'", path.display())]
    ImageFileWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to shutdown the given file.
    #[error("Failed to shut image file '{}' down", path.display())]
    ImageFileShutdownError { path: PathBuf, source: std::io::Error },

    /// Failed to pull the given image file.
    #[error("Failed to pull image '{source}' into Docker engine")]
    ImagePullError { image_source: String, source: bollard::errors::Error },
    /// Failed to find the digest after pulling the given image.
    #[error("Failed to read digest after pulling image '{}'\n\nReturned infos:\n{BLOCK_SEPARATOR}\n{}{BLOCK_SEPARATOR}\n",
        image_source,
        infos.iter().fold(String::new(), |mut acc, line| { writeln!(acc, "{line:?}").expect("Writing to string"); acc }),
    )]
    ImagePullFindId { image_source: String, infos: Vec<CreateImageInfo> },
    /// Failed to appropriately tag the pulled image.
    #[error("Failed to tag pulled image '{source}' as '{image}'")]
    ImageTagError { image: Box<Image>, image_source: String, source: bollard::errors::Error },

    /// Failed to inspect a certain image.
    #[error("Failed to inspect image '{}'{}", image.name(), if let Some(digest) = image.digest() { format!(" ({digest})") } else { String::new() })]
    ImageInspectError { image: Box<Image>, source: bollard::errors::Error },
    /// Failed to remove a certain image.
    #[error("Failed to remove image '{}' (id: {}) from Docker engine", image.name(), id)]
    ImageRemoveError { image: Box<Image>, id: String, source: bollard::errors::Error },

    /// Failed to list the images in a docker instance.
    #[error("Could not list images")]
    ImageList { source: bollard::errors::Error },

    /// Could not open the given image.tar.
    #[error("Could not open given Docker image file '{}'", path.display())]
    ImageTarOpenError { path: PathBuf, source: std::io::Error },
    /// Could not read from the given image.tar.
    #[error("Could not read given Docker image file '{}'", path.display())]
    ImageTarReadError { path: PathBuf, source: std::io::Error },
    /// Could not get the list of entries from the given image.tar.
    #[error("Could not get file entries in Docker image file '{}'", path.display())]
    ImageTarEntriesError { path: PathBuf, source: std::io::Error },
    /// COuld not read a single entry from the given image.tar.
    #[error("Could not get file entry from Docker image file '{}'", path.display())]
    ImageTarEntryError { path: PathBuf, source: std::io::Error },
    /// Could not get path from entry
    #[error("Given Docker image file '{}' contains illegal path entry", path.display())]
    ImageTarIllegalPath { path: PathBuf, source: std::io::Error },
    /// Could not read the manifest.json file
    #[error("Failed to read '{}' in Docker image file '{}'", entry.display(), path.display())]
    ImageTarManifestReadError { path: PathBuf, entry: PathBuf, source: std::io::Error },
    /// Could not parse the manifest.json file
    #[error("Could not parse '{}' in Docker image file '{}'", entry.display(), path.display())]
    ImageTarManifestParseError { path: PathBuf, entry: PathBuf, source: serde_json::Error },
    /// Incorrect number of items found in the toplevel list of the manifest.json file
    #[error("Got incorrect number of entries in '{}' in Docker image file '{}': got {}, expected 1", entry.display(), path.display(), got)]
    ImageTarIllegalManifestNum { path: PathBuf, entry: PathBuf, got: usize },
    /// Could not find the expected part of the config digest
    #[error("Found image digest '{}' in '{}' in Docker image file '{}' is illegal: does not start with '{}'", digest, entry.display(), path.display(), crate::docker::MANIFEST_CONFIG_PREFIX)]
    ImageTarIllegalDigest { path: PathBuf, entry: PathBuf, digest: String },
    /// Could not find the manifest.json file in the given image.tar.
    #[error("Could not find manifest.json in given Docker image file '{}'", path.display())]
    ImageTarNoManifest { path: PathBuf },
}

/// Collects errors that relate to local index interaction.
#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    /// There was an error reading entries from a package's directory
    #[error("Could not read package directory '{}'", path.display())]
    PackageDirReadError { path: PathBuf, source: std::io::Error },
    /// Found a version entry who's path could not be split into a filename
    #[error("Could not get the version directory from '{}'", path.display())]
    UnreadableVersionEntry { path: PathBuf },
    /// The name of version directory in a package's dir is not a valid version
    #[error("Entry '{version}' for package '{package}' is not a valid version")]
    IllegalVersionEntry { package: String, version: String, source: specifications::version::ParseError },
    /// The given package has no versions registered to it
    #[error("Package '{package}' does not have any registered versions")]
    NoVersions { package: String },

    /// There was an error reading entries from the packages directory
    #[error("Could not read from Brane packages directory '{}'", path.display())]
    PackagesDirReadError { path: PathBuf, source: std::io::Error },
    /// We tried to load a package YML but failed
    #[error("Could not read '{}' for package '{}'", path.display(), package)]
    InvalidPackageYml { package: String, path: PathBuf, source: specifications::package::PackageInfoError },
    /// We tried to load a Package Index from a JSON value with PackageInfos but we failed
    #[error("Could not create PackageIndex")]
    PackageIndexError { source: specifications::package::PackageIndexError },

    /// Failed to read the datasets folder
    #[error("Failed to read datasets folder '{}'", path.display())]
    DatasetsReadError { path: PathBuf, source: std::io::Error },
    /// Failed to open a data.yml file.
    #[error("Failed to open data info file '{}'", path.display())]
    DataInfoOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to read/parse a data.yml file.
    #[error("Failed to read/parse data info file '{}'", path.display())]
    DataInfoReadError { path: PathBuf, source: serde_yaml::Error },
    /// Failed to create a new DataIndex from the infos locally read.
    #[error("Failed to create data index from local datasets")]
    DataIndexError { source: specifications::data::DataIndexError },
}

/// Collects errors that relate to API interaction.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Failed to send a GraphQL request.
    #[error("Failed to post request to '{address}'")]
    RequestError { address: String, source: reqwest::Error },
    /// Failed to get the body of a response.
    #[error("Failed to get body from response from '{address}'")]
    ResponseBodyError { address: String, source: reqwest::Error },
    /// Failed to parse the response from the server.
    #[error("Failed to parse response \"\"\"{raw}\"\"\" from '{address}' as JSON")]
    ResponseJsonParseError { address: String, raw: String, source: serde_json::Error },
    /// The remote failed to produce even a single result (not even 'no packages').
    #[error("'{address}' responded without a body (not even that no packages are available)")]
    NoResponse { address: String },

    /// Failed to parse the package kind in a package info.
    #[error("Failed to parse '{raw}' as package kind in package {index} returned by '{address}'")]
    PackageKindParseError { address: String, index: usize, raw: String, source: specifications::package::PackageKindError },
    /// Failed to parse the package's version in a package info.
    #[error("Failed to parse '{raw}' as version in package {index} returned by '{address}'")]
    VersionParseError { address: String, index: usize, raw: String, source: specifications::version::ParseError },
    /// Failed to create a package index from the given infos.
    #[error("Failed to create a package index from the package infos given by '{address}'")]
    PackageIndexError { address: String, source: specifications::package::PackageIndexError },

    /// Failed to create a data index from the given infos.
    #[error("Failed to create a data index from the data infos given by '{address}'")]
    DataIndexError { address: String, source: specifications::data::DataIndexError },
}

/// Errors that relate to parsing Docker client version numbers.
#[derive(Debug, thiserror::Error)]
pub enum ClientVersionParseError {
    /// Missing a dot in the version number
    #[error("Missing '.' in Docket client version number '{raw}'")]
    MissingDot { raw: String },
    /// The given major version was not a valid usize
    #[error("'{raw}' is not a valid Docket client version major number")]
    IllegalMajorNumber { raw: String, source: std::num::ParseIntError },
    /// The given major version was not a valid usize
    #[error("'{raw}' is not a valid Docket client version minor number")]
    IllegalMinorNumber { raw: String, source: std::num::ParseIntError },
}
