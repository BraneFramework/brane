//  ERRORS.rs
//    by Lut99
//
//  Created:
//    24 Oct 2022, 15:27:26
//  Last edited:
//    08 Feb 2024, 16:47:05
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
use brane_ast::Workflow;
use brane_ast::func_id::FunctionId;
use brane_ast::locations::{Location, Locations};
use brane_exe::pc::ProgramCounter;
use brane_shr::formatters::{BlockFormatter, Capitalizeable};
use enum_debug::EnumDebug as _;
use reqwest::StatusCode;
use serde_json::Value;
use specifications::address::Address;
use specifications::container::Image;
use specifications::data::DataName;
use specifications::driving::ExecuteReply;
use specifications::package::Capability;
use specifications::version::Version;
// The TaskReply is here for legacy reasons; bad name
use specifications::working::{ExecuteReply as TaskReply, TaskStatus};
use tonic::Status;


/***** AUXILLARY *****/
/// Turns a [`String`] into something that [`Error`]s.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StringError(pub String);
impl Display for StringError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", self.0) }
}
impl Error for StringError {}





/***** LIBRARY *****/
/// Defines a kind of combination of all the possible errors that may occur in the process.
#[derive(Debug)]
pub enum TaskError {
    /// Something went wrong while planning.
    PlanError { err: PlanError },
    /// Something went wrong while executing.
    ExecError { err: brane_exe::errors::VmError },
}
impl Display for TaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use TaskError::*;
        match self {
            PlanError { .. } => write!(f, "Failed to plan workflow"),
            ExecError { .. } => write!(f, "Failed to execute workflow"),
        }
    }
}
impl Error for TaskError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use TaskError::*;
        match self {
            PlanError { err } => Some(err),
            ExecError { err } => Some(err),
        }
    }
}





/// Defines common errors that occur when trying to plan a workflow.
#[derive(Debug)]
pub enum PlanError {
    /// Failed to load the infrastructure file.
    InfraFileLoadError { err: brane_cfg::infra::Error },

    /// The user didn't specify the location (specifically enough).
    AmbigiousLocationError { name: String, locs: Locations },
    /// Failed to send a request to the API service.
    RequestError { address: String, err: reqwest::Error },
    /// The request failed with a non-OK status code
    RequestFailure { address: String, code: reqwest::StatusCode, err: Option<String> },
    /// Failed to get the body of a request.
    RequestBodyError { address: String, err: reqwest::Error },
    /// Failed to parse the body of the request as valid JSON
    RequestParseError { address: String, raw: String, err: serde_json::Error },
    /// The planned domain does not support the task.
    UnsupportedCapabilities { task: String, loc: String, expected: HashSet<Capability>, got: HashSet<Capability> },
    /// The given dataset was unknown to us.
    UnknownDataset { name: String },
    /// The given intermediate result was unknown to us.
    UnknownIntermediateResult { name: String },
    /// We failed to insert one of the dataset in the runtime set.
    DataPlanError { err: specifications::data::RuntimeDataIndexError },
    /// We can't access a dataset in the local instance.
    DatasetUnavailable { name: String, locs: Vec<String> },
    /// We can't access an intermediate result in the local instance.
    IntermediateResultUnavailable { name: String, locs: Vec<String> },

    // Instance-only
    /// Failed to serialize the internal workflow.
    WorkflowSerialize { id: String, err: serde_json::Error },
    /// Failed to serialize the [`PlanningRequest`](specifications::planning::PlanningRequest).
    PlanningRequestSerialize { id: String, err: serde_json::Error },
    /// Failed to create a request to plan at the planner.
    PlanningRequest { id: String, url: String, err: reqwest::Error },
    /// Failed to send a request to plan at the planner.
    PlanningRequestSend { id: String, url: String, err: reqwest::Error },
    /// The server failed to plan.
    PlanningFailure { id: String, url: String, code: StatusCode, response: Option<String> },
    /// Failed to download the server's response.
    PlanningResponseDownload { id: String, url: String, err: reqwest::Error },
    /// failed to parse the server's response.
    PlanningResponseParse { id: String, url: String, raw: String, err: serde_json::Error },
    /// Failed to parse the server's returned plan.
    PlanningPlanParse { id: String, url: String, raw: Value, err: serde_json::Error },

    /// Failed to a checker to validate the workflow
    GrpcConnectError { endpoint: Address, err: specifications::working::JobServiceError },
    /// Failed to connect to the proxy service
    ProxyError { err: Box<dyn 'static + Send + Error> },
    /// Failed to submit the gRPC request to validate a workflow.
    GrpcRequestError { what: &'static str, endpoint: Address, err: tonic::Status },
    /// One of the checkers denied everything :/
    CheckerDenied { domain: Location, reasons: Vec<String> },
}
impl Display for PlanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PlanError::*;
        match self {
            InfraFileLoadError { .. } => write!(f, "Failed to load infrastructure file"),

            AmbigiousLocationError { name, locs } => write!(
                f,
                "Ambigious location for task '{}': {}",
                name,
                if let Locations::Restricted(locs) = locs {
                    format!("possible locations are {}, but you need to reduce that to only 1 (use On-structs for that)", locs.join(", "))
                } else {
                    "all locations are possible, but you need to reduce that to only 1 (use On-structs for that)".into()
                }
            ),
            RequestError { address, .. } => write!(f, "Failed to send GET-request to '{address}'"),
            RequestFailure { address, code, err } => write!(
                f,
                "GET-request to '{}' failed with {} ({}){}",
                address,
                code,
                code.canonical_reason().unwrap_or("???"),
                if let Some(err) = err { format!("\n\nResponse:\n{}\n", BlockFormatter::new(err)) } else { String::new() }
            ),
            RequestBodyError { address, .. } => write!(f, "Failed to get the body of response from '{address}' as UTF-8 text"),
            RequestParseError { address, raw, .. } => write!(f, "Failed to parse response '{raw}' from '{address}' as valid JSON"),
            UnsupportedCapabilities { task, loc, expected, got } => {
                write!(f, "Location '{loc}' only supports capabilities {got:?}, whereas task '{task}' requires capabilities {expected:?}")
            },
            UnknownDataset { name } => write!(f, "Unknown dataset '{name}'"),
            UnknownIntermediateResult { name } => write!(f, "Unknown intermediate result '{name}'"),
            DataPlanError { .. } => write!(f, "Failed to plan dataset"),
            DatasetUnavailable { name, locs } => write!(
                f,
                "Dataset '{}' is unavailable{}",
                name,
                if !locs.is_empty() {
                    format!(
                        "; however, locations {} do (try to get download permission to those datasets)",
                        locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")
                    )
                } else {
                    String::new()
                }
            ),
            IntermediateResultUnavailable { name, locs } => write!(
                f,
                "Intermediate result '{}' is unavailable{}",
                name,
                if !locs.is_empty() {
                    format!(
                        "; however, locations {} do (try to get download permission to those datasets)",
                        locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")
                    )
                } else {
                    String::new()
                }
            ),

            WorkflowSerialize { id, .. } => write!(f, "Failed to serialize workflow '{id}'"),
            PlanningRequestSerialize { id, .. } => write!(f, "Failed to serialize planning request for workflow '{id}'"),
            PlanningRequest { id, url, .. } => write!(f, "Failed to create request to plan workflow '{id}' for '{url}'"),
            PlanningRequestSend { id, url, .. } => write!(f, "Failed to send request to plan workflow '{id}' to '{url}'"),
            PlanningFailure { id, url, code, response } => write!(
                f,
                "Planner failed to plan workflow '{}' (server at '{url}' returned {} ({})){}",
                id,
                code.as_u16(),
                code.canonical_reason().unwrap_or("???"),
                if let Some(res) = response { format!("\n\nResponse:\n{}\n", BlockFormatter::new(res)) } else { String::new() }
            ),
            PlanningResponseDownload { id, url, .. } => write!(f, "Failed to download response from '{url}' for workflow '{id}'"),
            PlanningResponseParse { id, url, raw, .. } => {
                write!(f, "Failed to parse response from '{}' to planning workflow '{}'\n\nResponse:\n{}\n", url, id, BlockFormatter::new(raw))
            },
            PlanningPlanParse { id, url, raw, .. } => write!(
                f,
                "Failed to parse plan returned by '{}' to plan workflow '{}'\n\nPlan:\n{}\n",
                url,
                id,
                BlockFormatter::new(format!("{:?}", raw))
            ),

            GrpcConnectError { endpoint, .. } => write!(f, "Failed to create gRPC connection to `brane-job` service at '{endpoint}'"),
            ProxyError { .. } => write!(f, "Failed to use `brane-prx` service"),
            GrpcRequestError { what, endpoint, .. } => write!(f, "Failed to send {what} over gRPC connection to `brane-job` service at '{endpoint}'"),
            CheckerDenied { domain, reasons } => write!(
                f,
                "Checker of domain '{domain}' denied plan{}",
                if !reasons.is_empty() {
                    format!(
                        "\n\nReasons:\n{}",
                        reasons.iter().fold(String::new(), |mut output, r| {
                            let _ = writeln!(output, "  - {r}");
                            output
                        })
                    )
                } else {
                    String::new()
                }
            ),
        }
    }
}
impl Error for PlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use PlanError::*;
        match self {
            InfraFileLoadError { err } => Some(err),

            AmbigiousLocationError { .. } => None,
            RequestError { err, .. } => Some(err),
            RequestFailure { .. } => None,
            RequestBodyError { err, .. } => Some(err),
            RequestParseError { err, .. } => Some(err),
            UnsupportedCapabilities { .. } => None,
            UnknownDataset { .. } => None,
            UnknownIntermediateResult { .. } => None,
            DataPlanError { err } => Some(err),
            DatasetUnavailable { .. } => None,
            IntermediateResultUnavailable { .. } => None,

            WorkflowSerialize { err, .. } => Some(err),
            PlanningRequestSerialize { err, .. } => Some(err),
            PlanningRequest { err, .. } => Some(err),
            PlanningRequestSend { err, .. } => Some(err),
            PlanningFailure { .. } => None,
            PlanningResponseDownload { err, .. } => Some(err),
            PlanningResponseParse { err, .. } => Some(err),
            PlanningPlanParse { err, .. } => Some(err),

            GrpcConnectError { err, .. } => Some(err),
            ProxyError { err } => Some(&**err),
            GrpcRequestError { err, .. } => Some(err),
            CheckerDenied { .. } => None,
        }
    }
}



/// Defines common errors that occur when trying to preprocess datasets.
#[derive(Debug)]
pub enum PreprocessError {
    /// The dataset was _still_ unavailable after preprocessing
    UnavailableData { name: DataName },

    // Instance only (client-side)
    /// Failed to load the node config file.
    NodeConfigReadError { path: PathBuf, err: brane_cfg::info::YamlError },
    /// Failed to load the infra file.
    InfraReadError { path: PathBuf, err: brane_cfg::infra::Error },
    /// The given location was unknown.
    UnknownLocationError { loc: Location },
    /// Failed to connect to a proxy.
    ProxyError { err: Box<dyn 'static + Send + Sync + Error> },
    /// Failed to connect to a delegate node with gRPC
    GrpcConnectError { endpoint: Address, err: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    GrpcRequestError { what: &'static str, endpoint: Address, err: tonic::Status },
    /// Failed to re-serialize the access kind.
    AccessKindParseError { endpoint: Address, raw: String, err: serde_json::Error },

    // Instance only (worker-side)
    // /// Failed to load the keypair.
    // KeypairLoadError{ err: brane_cfg::certs::Error },
    // /// Failed to load the certificate root store.
    // StoreLoadError{ err: brane_cfg::certs::Error },
    // /// The given certificate file was empty.
    // EmptyCertFile{ path: PathBuf },
    // /// Failed to parse the given key/cert pair as an IdentityFile.
    // IdentityFileError{ certfile: PathBuf, keyfile: PathBuf, err: reqwest::Error },
    // /// Failed to load the given certificate as PEM root certificate.
    // RootError{ cafile: PathBuf, err: reqwest::Error },
    /// Failed to open/read a given file.
    FileReadError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to parse an identity file.
    IdentityFileError { path: PathBuf, err: reqwest::Error },
    /// Failed to parse a certificate.
    CertificateError { path: PathBuf, err: reqwest::Error },
    /// Failed to resolve a location identifier to a registry address.
    LocationResolve { id: String, err: crate::caches::DomainRegistryCacheError },
    /// A directory was not a directory but a file.
    DirNotADirError { what: &'static str, path: PathBuf },
    /// A directory what not a directory because it didn't exist.
    DirNotExistsError { what: &'static str, path: PathBuf },
    /// A directory could not be removed.
    DirRemoveError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// A directory could not be created.
    DirCreateError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to create a reqwest proxy object.
    ProxyCreateError { address: Address, err: reqwest::Error },
    /// Failed to create a reqwest client.
    ClientCreateError { err: reqwest::Error },
    /// Failed to send a GET-request to fetch the data.
    DownloadRequestError { address: String, err: reqwest::Error },
    /// The given download request failed with a non-success status code.
    DownloadRequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to reach the next chunk of data.
    DownloadStreamError { address: String, err: reqwest::Error },
    /// Failed to create the file to which we write the download stream.
    TarCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to (re-)open the file to which we've written the download stream.
    TarOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    TarWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to extract the downloaded tar.
    DataExtractError { err: brane_shr::fs::Error },
    /// Failed to serialize the preprocessrequest.
    AccessKindSerializeError { err: serde_json::Error },

    /// Failed to parse the backend file.
    BackendFileError { err: brane_cfg::backend::Error },
    /// The given backend type is not (yet) supported.
    UnsupportedBackend { what: &'static str },
}
impl Display for PreprocessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::PreprocessError::*;
        match self {
            UnavailableData { name } => write!(f, "{} '{}' is not available locally", name.variant(), name.name()),

            NodeConfigReadError { path, .. } => write!(f, "Failed to load node config file '{}'", path.display()),
            InfraReadError { path, .. } => write!(f, "Failed to load infrastructure file '{}'", path.display()),
            UnknownLocationError { loc } => write!(f, "Unknown location '{loc}'"),
            ProxyError { .. } => write!(f, "Failed to prepare proxy service"),
            GrpcConnectError { endpoint, .. } => write!(f, "Failed to start gRPC connection with delegate node '{endpoint}'"),
            GrpcRequestError { what, endpoint, .. } => write!(f, "Failed to send {what} request to delegate node '{endpoint}'"),
            AccessKindParseError { endpoint, raw, .. } => {
                write!(f, "Failed to parse access kind '{raw}' sent by remote delegate '{endpoint}'")
            },

            // KeypairLoadError{ err }                          => write!(f, "Failed to load keypair: {}", err),
            // StoreLoadError{ err }                            => write!(f, "Failed to load root store: {}", err),
            // EmptyCertFile{ path }                            => write!(f, "No certificates found in certificate file '{}'", path.display()),
            // IdentityFileError{ certfile, keyfile, err }      => write!(f, "Failed to parse '{}' and '{}' as a single Identity: {}", certfile.display(), keyfile.display(), err),
            // RootError{ cafile, err }                         => write!(f, "Failed to parse '{}' as a root certificate: {}", cafile.display(), err),
            FileReadError { what, path, .. } => write!(f, "Failed to read {} file '{}'", what, path.display()),
            IdentityFileError { path, .. } => write!(f, "Failed to parse identity file '{}'", path.display()),
            CertificateError { path, .. } => write!(f, "Failed to parse certificate '{}'", path.display()),
            LocationResolve { id, .. } => write!(f, "Failed to resolve location ID '{id}' to a local registry address"),
            DirNotADirError { what, path } => write!(f, "{} directory '{}' is not a directory", what.capitalize(), path.display()),
            DirNotExistsError { what, path } => write!(f, "{} directory '{}' doesn't exist", what.capitalize(), path.display()),
            DirRemoveError { what, path, .. } => write!(f, "Failed to remove {} directory '{}'", what, path.display()),
            DirCreateError { what, path, .. } => write!(f, "Failed to create {} directory '{}'", what, path.display()),
            ProxyCreateError { address, .. } => write!(f, "Failed to create proxy to '{address}'"),
            ClientCreateError { .. } => write!(f, "Failed to create HTTP-client"),
            DownloadRequestError { address, .. } => write!(f, "Failed to send GET download request to '{address}'"),
            DownloadRequestFailure { address, code, message } => write!(
                f,
                "GET download request to '{}' failed with status code {} ({}){}",
                address,
                code,
                code.canonical_reason().unwrap_or("???"),
                if let Some(message) = message { format!(": {message}") } else { String::new() }
            ),
            DownloadStreamError { address, .. } => write!(f, "Failed to get next chunk in download stream from '{address}'"),
            TarCreateError { path, .. } => write!(f, "Failed to create tarball file '{}'", path.display()),
            TarOpenError { path, .. } => write!(f, "Failed to re-open tarball file '{}'", path.display()),
            TarWriteError { path, .. } => write!(f, "Failed to write to tarball file '{}'", path.display()),
            DataExtractError { .. } => write!(f, "Failed to extract dataset"),
            AccessKindSerializeError { .. } => write!(f, "Failed to serialize the given AccessKind"),

            BackendFileError { .. } => write!(f, "Failed to load backend file"),
            UnsupportedBackend { what } => write!(f, "Backend type '{what}' is not (yet) supported"),
        }
    }
}
impl Error for PreprocessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use PreprocessError::*;
        match self {
            UnavailableData { .. } => None,

            NodeConfigReadError { err, .. } => Some(err),
            InfraReadError { err, .. } => Some(err),
            UnknownLocationError { .. } => None,
            ProxyError { err } => Some(&**err),
            GrpcConnectError { err, .. } => Some(err),
            GrpcRequestError { err, .. } => Some(err),
            AccessKindParseError { err, .. } => Some(err),

            FileReadError { err, .. } => Some(err),
            IdentityFileError { err, .. } => Some(err),
            CertificateError { err, .. } => Some(err),
            LocationResolve { err, .. } => Some(err),
            DirNotADirError { .. } => None,
            DirNotExistsError { .. } => None,
            DirRemoveError { err, .. } => Some(err),
            DirCreateError { err, .. } => Some(err),
            ProxyCreateError { err, .. } => Some(err),
            ClientCreateError { err } => Some(err),
            DownloadRequestError { err, .. } => Some(err),
            DownloadRequestFailure { .. } => None,
            DownloadStreamError { err, .. } => Some(err),
            TarCreateError { err, .. } => Some(err),
            TarOpenError { err, .. } => Some(err),
            TarWriteError { err, .. } => Some(err),
            DataExtractError { err } => Some(err),
            AccessKindSerializeError { err } => Some(err),

            BackendFileError { err } => Some(err),
            UnsupportedBackend { .. } => None,
        }
    }
}



/// Defines common errors that occur when trying to execute tasks.
///
/// Note: we've boxed `Image` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug)]
pub enum ExecuteError {
    // General errors
    /// We encountered a package call that we didn't know.
    UnknownPackage { name: String, version: Version },
    /// We encountered a dataset/result that we didn't know.
    UnknownData { name: DataName },
    /// Failed to serialize task's input arguments
    ArgsEncodeError { err: serde_json::Error },
    /// The external call failed with a nonzero exit code and some stdout/stderr
    ExternalCallFailed { name: String, image: Box<Image>, code: i32, stdout: String, stderr: String },
    /// Failed to decode the branelet output from base64 to raw bytes
    Base64DecodeError { raw: String, err: base64::DecodeError },
    /// Failed to decode the branelet output from raw bytes to an UTF-8 string
    Utf8DecodeError { raw: String, err: std::string::FromUtf8Error },
    /// Failed to decode the branelet output from an UTF-8 string to a FullValue
    JsonDecodeError { raw: String, err: serde_json::Error },

    // Docker errors
    /// Failed to create a new volume bind
    VolumeBindError { err: specifications::container::VolumeBindError },
    /// The generated path of a result is not a directory
    ResultDirNotADir { path: PathBuf },
    /// Could not remove the old result directory
    ResultDirRemoveError { path: PathBuf, err: std::io::Error },
    /// Could not create the new result directory
    ResultDirCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to run the task as a local Docker container
    DockerError { name: String, image: Box<Image>, err: DockerError },

    // Instance-only (client side)
    /// The given job status was missing a string while we expected one
    StatusEmptyStringError { status: TaskStatus },
    /// Failed to parse the given value as a FullValue
    StatusValueParseError { status: TaskStatus, raw: String, err: serde_json::Error },
    /// Failed to parse the given value as a return code/stdout/stderr triplet.
    StatusTripletParseError { status: TaskStatus, raw: String, err: serde_json::Error },
    /// Failed to update the client of a status change.
    ClientUpdateError { status: TaskStatus, err: tokio::sync::mpsc::error::SendError<Result<TaskReply, Status>> },
    /// Failed to load the node config file.
    NodeConfigReadError { path: PathBuf, err: brane_cfg::info::YamlError },
    /// Failed to load the infra file.
    InfraReadError { path: PathBuf, err: brane_cfg::infra::Error },
    /// The given location was unknown.
    UnknownLocationError { loc: Location },
    /// Failed to prepare the proxy service.
    ProxyError { err: Box<dyn 'static + Send + Sync + Error> },
    /// Failed to connect to a delegate node with gRPC
    GrpcConnectError { endpoint: Address, err: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    GrpcRequestError { what: &'static str, endpoint: Address, err: tonic::Status },
    /// Preprocessing failed with the following error.
    ExecuteError { endpoint: Address, name: String, status: TaskStatus, err: StringError },

    // Instance-only (worker side)
    /// Failed to load the digest cache file
    DigestReadError { path: PathBuf, err: std::io::Error },
    /// Failed to fetch the digest of an already existing image.
    DigestError { path: PathBuf, err: DockerError },
    /// Failed to create a reqwest proxy object.
    ProxyCreateError { address: Address, err: reqwest::Error },
    /// Failed to create a reqwest client.
    ClientCreateError { err: reqwest::Error },
    /// Failed to send a GET-request to fetch the data.
    DownloadRequestError { address: String, err: reqwest::Error },
    /// The given download request failed with a non-success status code.
    DownloadRequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to reach the next chunk of data.
    DownloadStreamError { address: String, err: reqwest::Error },
    /// Failed to create the file to which we write the download stream.
    ImageCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    ImageWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to write to the file where we write the container ID.
    IdWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to read from the file where we cached the container ID.
    IdReadError { path: PathBuf, err: std::io::Error },
    /// Failed to hash the given container.
    HashError { err: DockerError },
    /// Failed to write to the file where we write the container hash.
    HashWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to read to the file where we cached the container hash.
    HashReadError { path: PathBuf, err: std::io::Error },

    /// The checker rejected the workflow.
    AuthorizationFailure { checker: Address },
    /// The checker failed to check workflow authorization.
    AuthorizationError { checker: Address, err: AuthorizeError },
    /// Failed to get an up-to-date package index.
    PackageIndexError { endpoint: String, err: ApiError },
    /// Failed to load the backend file.
    BackendFileError { path: PathBuf, err: brane_cfg::backend::Error },
}
impl Display for ExecuteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::ExecuteError::*;
        match self {
            UnknownPackage { name, version } => write!(f, "Unknown package '{name}' (or it does not have version {version})"),
            UnknownData { name } => write!(f, "Unknown {} '{}'", name.variant(), name.name()),
            ArgsEncodeError { .. } => write!(f, "Failed to serialize input arguments"),
            ExternalCallFailed { name, image, code, stdout, stderr } => write!(
                f,
                "Task '{}' (image '{}') failed with exit code {}\n\n{}\n\n{}\n\n",
                name,
                image,
                code,
                BlockFormatter::new(stdout),
                BlockFormatter::new(stderr)
            ),
            Base64DecodeError { raw, .. } => {
                write!(f, "Failed to decode the following task output as valid Base64:\n{}\n\n", BlockFormatter::new(raw))
            },
            Utf8DecodeError { raw, .. } => {
                write!(f, "Failed to decode the following task output as valid UTF-8:\n{}\n\n", BlockFormatter::new(raw))
            },
            JsonDecodeError { raw, .. } => {
                write!(f, "Failed to decode the following task output as valid JSON:\n{}\n\n", BlockFormatter::new(raw))
            },

            VolumeBindError { .. } => write!(f, "Failed to create VolumeBind"),
            ResultDirNotADir { path } => write!(f, "Result directory '{}' exists but is not a directory", path.display()),
            ResultDirRemoveError { path, .. } => write!(f, "Failed to remove existing result directory '{}'", path.display()),
            ResultDirCreateError { path, .. } => write!(f, "Failed to create result directory '{}'", path.display()),
            DockerError { name, image, .. } => write!(f, "Failed to execute task '{name}' (image '{image}') as a Docker container"),

            StatusEmptyStringError { status } => write!(f, "Incoming status update {status:?} is missing mandatory `value` field"),
            StatusValueParseError { status, raw, .. } => {
                write!(f, "Failed to parse '{raw}' as a FullValue in incoming status update {status:?}")
            },
            StatusTripletParseError { status, raw, .. } => {
                write!(f, "Failed to parse '{raw}' as a return code/stdout/stderr triplet in incoming status update {status:?}")
            },
            ClientUpdateError { status, .. } => write!(f, "Failed to update client of status {status:?}"),
            NodeConfigReadError { path, .. } => write!(f, "Failed to load node config file '{}'", path.display()),
            InfraReadError { path, .. } => write!(f, "Failed to load infrastructure file '{}'", path.display()),
            UnknownLocationError { loc } => write!(f, "Unknown location '{loc}'"),
            ProxyError { .. } => write!(f, "Failed to prepare proxy service"),
            GrpcConnectError { endpoint, .. } => write!(f, "Failed to start gRPC connection with delegate node '{endpoint}'"),
            GrpcRequestError { what, endpoint, .. } => write!(f, "Failed to send {what} request to delegate node '{endpoint}'"),
            ExecuteError { endpoint, name, status, .. } => {
                write!(f, "Remote delegate '{endpoint}' returned status '{status:?}' while executing task '{name}'")
            },

            DigestReadError { path, .. } => write!(f, "Failed to read cached digest in '{}'", path.display()),
            DigestError { path, .. } => write!(f, "Failed to read digest of image '{}'", path.display()),
            ProxyCreateError { address, .. } => write!(f, "Failed to create proxy to '{address}'"),
            ClientCreateError { .. } => write!(f, "Failed to create HTTP-client"),
            DownloadRequestError { address, .. } => write!(f, "Failed to send GET download request to '{address}'"),
            DownloadRequestFailure { address, code, message } => write!(
                f,
                "GET download request to '{}' failed with status code {} ({}){}",
                address,
                code,
                code.canonical_reason().unwrap_or("???"),
                if let Some(message) = message { format!(": {message}") } else { String::new() }
            ),
            DownloadStreamError { address, .. } => write!(f, "Failed to get next chunk in download stream from '{address}'"),
            ImageCreateError { path, .. } => write!(f, "Failed to create tarball file '{}'", path.display()),
            ImageWriteError { path, .. } => write!(f, "Failed to write to tarball file '{}'", path.display()),
            IdWriteError { path, .. } => write!(f, "Failed to write image ID to file '{}'", path.display()),
            IdReadError { path, .. } => write!(f, "Failed to read image from file '{}'", path.display()),
            HashError { .. } => write!(f, "Failed to hash image"),
            HashWriteError { path, .. } => write!(f, "Failed to write image hash to file '{}'", path.display()),
            HashReadError { path, .. } => write!(f, "Failed to read image hash from file '{}'", path.display()),

            AuthorizationFailure { checker: _ } => write!(f, "Checker rejected workflow"),
            AuthorizationError { checker: _, .. } => write!(f, "Checker failed to authorize workflow"),
            PackageIndexError { endpoint, .. } => write!(f, "Failed to get PackageIndex from '{endpoint}'"),
            BackendFileError { path, .. } => write!(f, "Failed to load backend file '{}'", path.display()),
        }
    }
}
impl Error for ExecuteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use self::ExecuteError::*;
        match self {
            UnknownPackage { .. } => None,
            UnknownData { .. } => None,
            ArgsEncodeError { err } => Some(err),
            ExternalCallFailed { .. } => None,
            Base64DecodeError { err, .. } => Some(err),
            Utf8DecodeError { err, .. } => Some(err),
            JsonDecodeError { err, .. } => Some(err),

            VolumeBindError { err } => Some(err),
            ResultDirNotADir { .. } => None,
            ResultDirRemoveError { err, .. } => Some(err),
            ResultDirCreateError { err, .. } => Some(err),
            DockerError { err, .. } => Some(err),

            StatusEmptyStringError { .. } => None,
            StatusValueParseError { err, .. } => Some(err),
            StatusTripletParseError { err, .. } => Some(err),
            ClientUpdateError { err, .. } => Some(err),
            NodeConfigReadError { err, .. } => Some(err),
            InfraReadError { err, .. } => Some(err),
            UnknownLocationError { .. } => None,
            ProxyError { err } => Some(&**err),
            GrpcConnectError { err, .. } => Some(err),
            GrpcRequestError { err, .. } => Some(err),

            DigestReadError { err, .. } => Some(err),
            DigestError { err, .. } => Some(err),
            ProxyCreateError { err, .. } => Some(err),
            ClientCreateError { err } => Some(err),
            DownloadRequestError { err, .. } => Some(err),
            DownloadRequestFailure { .. } => None,
            DownloadStreamError { err, .. } => Some(err),
            ImageCreateError { err, .. } => Some(err),
            ImageWriteError { err, .. } => Some(err),
            IdWriteError { err, .. } => Some(err),
            IdReadError { err, .. } => Some(err),
            HashError { err } => Some(err),
            HashWriteError { err, .. } => Some(err),
            HashReadError { err, .. } => Some(err),

            AuthorizationFailure { .. } => None,
            AuthorizationError { err, .. } => Some(err),
            PackageIndexError { err, .. } => Some(err),
            BackendFileError { err, .. } => Some(err),
            ExecuteError { err, .. } => Some(err),
        }
    }
}



/// A special case of the execute error, this relates to authorization errors in the backend eFLINT reasoner (or other reasoners).
#[derive(Debug)]
pub enum AuthorizeError {
    /// Failed to generate a new JWT for a request.
    TokenGenerate { secret: PathBuf, err: specifications::policy::Error },
    /// Failed to build a `reqwest::Client`.
    ClientBuild { err: reqwest::Error },
    /// Failed to build a request to the policy reasoner.
    ExecuteRequestBuild { addr: String, err: reqwest::Error },
    /// Failed to send a request to the policy reasoner.
    ExecuteRequestSend { addr: String, err: reqwest::Error },
    /// Request did not succeed
    ExecuteRequestFailure { addr: String, code: StatusCode, err: Option<String> },
    /// Failed to download the body of an execute request response.
    ExecuteBodyDownload { addr: String, err: reqwest::Error },
    /// Failed to deserialize the body of an execute request response.
    ExecuteBodyDeserialize { addr: String, raw: String, err: serde_json::Error },

    /// The data to authorize is not input to the task given as context.
    AuthorizationDataMismatch { pc: ProgramCounter, data_name: DataName },
    /// The user to authorize does not execute the given task.
    AuthorizationUserMismatch { who: String, authenticated: String, workflow: Workflow },
    /// An edge was referenced to be executed which wasn't an [`Edge::Node`](brane_ast::ast::Edge).
    AuthorizationWrongEdge { pc: ProgramCounter, got: String },
    /// An edge index given was out-of-bounds for the given function.
    IllegalEdgeIdx { func: FunctionId, got: usize, max: usize },
    /// A given function does not exist
    IllegalFuncId { got: FunctionId },
    /// There was a node in a workflow with no `at`-specified.
    MissingLocation { pc: ProgramCounter },
    /// The workflow has no end user specified.
    NoWorkflowUser { workflow: String },
}
impl Display for AuthorizeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AuthorizeError::*;
        match self {
            TokenGenerate { secret, .. } => write!(f, "Failed to generate new JWT using secret '{}'", secret.display()),
            ClientBuild { .. } => write!(f, "Failed to build HTTP client"),
            ExecuteRequestBuild { addr, .. } => write!(f, "Failed to build an ExecuteRequest destined for the checker at '{addr}'"),
            ExecuteRequestSend { addr, .. } => write!(f, "Failed to send ExecuteRequest to checker '{addr}'"),
            ExecuteRequestFailure { addr, code, err } => write!(
                f,
                "ExecuteRequest to checker '{}' failed with status code {} ({}){}",
                addr,
                code,
                code.canonical_reason().unwrap_or("???"),
                if let Some(err) = err {
                    format!("\n\nResponse:\n{}\n{}\n{}\n", (0..80).map(|_| '-').collect::<String>(), err, (0..80).map(|_| '-').collect::<String>())
                } else {
                    String::new()
                }
            ),
            ExecuteBodyDownload { addr, .. } => write!(f, "Failed to download response body from '{addr}'"),
            ExecuteBodyDeserialize { addr, raw, .. } => {
                write!(f, "Failed to deserialize response body received from '{}' as valid JSON\n\nResponse:\n{}\n", addr, BlockFormatter::new(raw))
            },

            AuthorizationDataMismatch { pc, data_name } => write!(f, "Dataset '{data_name}' is not an input to task {pc}"),
            AuthorizationUserMismatch { who, authenticated, workflow } => {
                write!(f, "Authorized user '{}' does not match '{}' user in workflow\n\nWorkflow:\n{:#?}\n", authenticated, who, workflow)
            },
            AuthorizationWrongEdge { pc, got } => write!(f, "Edge {pc} in workflow is not an Edge::Node but an Edge::{got}"),
            IllegalEdgeIdx { func, got, max } => write!(f, "Edge index {got} is out-of-bounds for function {func} with {max} edges"),
            IllegalFuncId { got } => write!(f, "Function {got} does not exist in given workflow"),
            MissingLocation { pc } => write!(f, "Node call at {pc} has no location planned"),
            NoWorkflowUser { workflow } => write!(f, "Given workflow has no end user specified\n\nWorkflow:\n{}\n", BlockFormatter::new(workflow)),
        }
    }
}
impl Error for AuthorizeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use AuthorizeError::*;
        match self {
            TokenGenerate { err, .. } => Some(err),
            ClientBuild { err, .. } => Some(err),
            ExecuteRequestBuild { err, .. } => Some(err),
            ExecuteRequestSend { err, .. } => Some(err),
            ExecuteRequestFailure { .. } => None,
            ExecuteBodyDownload { err, .. } => Some(err),
            ExecuteBodyDeserialize { err, .. } => Some(err),

            AuthorizationDataMismatch { .. } => None,
            AuthorizationUserMismatch { .. } => None,
            AuthorizationWrongEdge { .. } => None,
            IllegalEdgeIdx { .. } => None,
            IllegalFuncId { .. } => None,
            MissingLocation { .. } => None,
            NoWorkflowUser { .. } => None,
        }
    }
}



/// Defines common errors that occur when trying to write to stdout.
#[derive(Debug)]
pub enum StdoutError {
    /// Failed to write to the gRPC channel to feedback stdout back to the client.
    TxWriteError { err: tokio::sync::mpsc::error::SendError<Result<ExecuteReply, Status>> },
}
impl Display for StdoutError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use StdoutError::*;
        match self {
            TxWriteError { .. } => write!(f, "Failed to write on gRPC channel back to client"),
        }
    }
}
impl Error for StdoutError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use StdoutError::*;
        match self {
            TxWriteError { err } => Some(err),
        }
    }
}



/// Defines common errors that occur when trying to commit an intermediate result.
#[derive(Debug)]
pub enum CommitError {
    // Docker-local errors
    /// The given dataset was unavailable locally
    UnavailableDataError { name: String, locs: Vec<String> },
    /// The generated path of a data is not a directory
    DataDirNotADir { path: PathBuf },
    /// Could not create the new data directory
    DataDirCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to create a new DataInfo file.
    DataInfoCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to serialize a new DataInfo file.
    DataInfoSerializeError { err: serde_yaml::Error },
    /// Failed to write the DataInfo the the created file.
    DataInfoWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to read the given directory.
    DirReadError { path: PathBuf, err: std::io::Error },
    /// Failed to read the given directory entry.
    DirEntryReadError { path: PathBuf, i: usize, err: std::io::Error },
    /// Failed to copy the data
    DataCopyError { err: brane_shr::fs::Error },

    // Instance-only (client side)
    /// Failed to load the node config file.
    NodeConfigReadError { path: PathBuf, err: brane_cfg::info::YamlError },
    /// Failed to load the infra file.
    InfraReadError { path: PathBuf, err: brane_cfg::infra::Error },
    /// The given location was unknown.
    UnknownLocationError { loc: Location },
    /// Failed to prepare the proxy service.
    ProxyError { err: Box<dyn 'static + Send + Sync + Error> },
    /// Failed to connect to a delegate node with gRPC
    GrpcConnectError { endpoint: Address, err: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    GrpcRequestError { what: &'static str, endpoint: Address, err: tonic::Status },

    // Instance-only (worker side)
    /// Failed to read the AssetInfo file.
    AssetInfoReadError { path: PathBuf, err: specifications::data::AssetInfoError },
    /// Failed to remove a file.
    FileRemoveError { path: PathBuf, err: std::io::Error },
    /// Failed to remove a directory.
    DirRemoveError { path: PathBuf, err: std::io::Error },
    /// A given path is neither a file nor a directory.
    PathNotFileNotDir { path: PathBuf },
}
impl Display for CommitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::CommitError::*;
        match self {
            UnavailableDataError { name, locs } => write!(
                f,
                "Dataset '{}' is unavailable{}",
                name,
                if !locs.is_empty() {
                    format!(
                        "; however, locations {} do (try to get download permission to those datasets)",
                        locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")
                    )
                } else {
                    String::new()
                }
            ),
            DataDirNotADir { path } => write!(f, "Dataset directory '{}' exists but is not a directory", path.display()),
            DataDirCreateError { path, .. } => write!(f, "Failed to create dataset directory '{}'", path.display()),
            DataInfoCreateError { path, .. } => write!(f, "Failed to create new data info file '{}'", path.display()),
            DataInfoSerializeError { .. } => write!(f, "Failed to serialize DataInfo struct"),
            DataInfoWriteError { path, .. } => write!(f, "Failed to write DataInfo to '{}'", path.display()),
            DirReadError { path, .. } => write!(f, "Failed to read directory '{}'", path.display()),
            DirEntryReadError { path, i, .. } => write!(f, "Failed to read entry {} in directory '{}'", i, path.display()),
            DataCopyError { .. } => write!(f, "Failed to copy data directory"),

            NodeConfigReadError { path, .. } => write!(f, "Failed to load node config file '{}'", path.display()),
            InfraReadError { path, .. } => write!(f, "Failed to load infrastructure file '{}'", path.display()),
            UnknownLocationError { loc } => write!(f, "Unknown location '{loc}'"),
            ProxyError { .. } => write!(f, "Failed to prepare proxy service"),
            GrpcConnectError { endpoint, .. } => write!(f, "Failed to start gRPC connection with delegate node '{endpoint}'"),
            GrpcRequestError { what, endpoint, .. } => write!(f, "Failed to send {what} request to delegate node '{endpoint}'"),

            AssetInfoReadError { path, .. } => write!(f, "Failed to load asset info file '{}'", path.display()),
            FileRemoveError { path, .. } => write!(f, "Failed to remove file '{}'", path.display()),
            DirRemoveError { path, .. } => write!(f, "Failed to remove directory '{}'", path.display()),
            PathNotFileNotDir { path } => write!(f, "Given path '{}' neither points to a file nor a directory", path.display()),
        }
    }
}
impl Error for CommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use CommitError::*;
        match self {
            UnavailableDataError { .. } => None,
            DataDirNotADir { .. } => None,
            DataDirCreateError { err, .. } => Some(err),
            DataInfoCreateError { err, .. } => Some(err),
            DataInfoSerializeError { err } => Some(err),
            DataInfoWriteError { err, .. } => Some(err),
            DirReadError { err, .. } => Some(err),
            DirEntryReadError { err, .. } => Some(err),
            DataCopyError { err } => Some(err),

            NodeConfigReadError { err, .. } => Some(err),
            InfraReadError { err, .. } => Some(err),
            UnknownLocationError { .. } => None,
            ProxyError { err } => Some(&**err),
            GrpcConnectError { err, .. } => Some(err),
            GrpcRequestError { err, .. } => Some(err),

            AssetInfoReadError { err, .. } => Some(err),
            FileRemoveError { err, .. } => Some(err),
            DirRemoveError { err, .. } => Some(err),
            PathNotFileNotDir { .. } => None,
        }
    }
}



/// Collects errors that relate to the AppId or TaskId (actually only parser errors).
#[derive(Debug)]
pub enum IdError {
    /// Failed to parse the AppId from a string.
    ParseError { what: &'static str, raw: String, err: uuid::Error },
}
impl Display for IdError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use IdError::*;
        match self {
            ParseError { what, raw, .. } => write!(f, "Failed to parse {what} from '{raw}'"),
        }
    }
}
impl Error for IdError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use IdError::*;
        match self {
            ParseError { err, .. } => Some(err),
        }
    }
}



/// Collects errors that relate to Docker.
///
/// Note: we've boxed `Image` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug)]
pub enum DockerError {
    /// We failed to connect to the local Docker daemon.
    ConnectionError { path: PathBuf, version: ClientVersion, err: bollard::errors::Error },

    /// Failed to wait for the container with the given name.
    WaitError { name: String, err: bollard::errors::Error },
    /// Failed to read the logs of a container.
    LogsError { name: String, err: bollard::errors::Error },

    /// Failed to inspect the given container.
    InspectContainerError { name: String, err: bollard::errors::Error },
    /// The given container was not attached to any networks.
    ContainerNoNetwork { name: String },

    /// Could not create and/or start the given container.
    CreateContainerError { name: String, image: Box<Image>, err: bollard::errors::Error },
    /// Fialed to start the given container.
    StartError { name: String, image: Box<Image>, err: bollard::errors::Error },

    /// An executing container had no execution state (it wasn't started?)
    ContainerNoState { name: String },
    /// An executing container had no return code.
    ContainerNoExitCode { name: String },

    /// Failed to remove the given container.
    ContainerRemoveError { name: String, err: bollard::errors::Error },

    /// Failed to open the given image file.
    ImageFileOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to import the given image file.
    ImageImportError { path: PathBuf, err: bollard::errors::Error },
    /// Failed to create the given image file.
    ImageFileCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to download a piece of the image from the Docker client.
    ImageExportError { name: String, err: bollard::errors::Error },
    /// Failed to write a chunk of the exported image.
    ImageFileWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to shutdown the given file.
    ImageFileShutdownError { path: PathBuf, err: std::io::Error },

    /// Failed to pull the given image file.
    ImagePullError { source: String, err: bollard::errors::Error },
    /// Failed to appropriately tag the pulled image.
    ImageTagError { image: Box<Image>, source: String, err: bollard::errors::Error },

    /// Failed to inspect a certain image.
    ImageInspectError { image: Box<Image>, err: bollard::errors::Error },
    /// Failed to remove a certain image.
    ImageRemoveError { image: Box<Image>, id: String, err: bollard::errors::Error },

    /// Could not open the given image.tar.
    ImageTarOpenError { path: PathBuf, err: std::io::Error },
    /// Could not read from the given image.tar.
    ImageTarReadError { path: PathBuf, err: std::io::Error },
    /// Could not get the list of entries from the given image.tar.
    ImageTarEntriesError { path: PathBuf, err: std::io::Error },
    /// COuld not read a single entry from the given image.tar.
    ImageTarEntryError { path: PathBuf, err: std::io::Error },
    /// Could not get path from entry
    ImageTarIllegalPath { path: PathBuf, err: std::io::Error },
    /// Could not read the manifest.json file
    ImageTarManifestReadError { path: PathBuf, entry: PathBuf, err: std::io::Error },
    /// Could not parse the manifest.json file
    ImageTarManifestParseError { path: PathBuf, entry: PathBuf, err: serde_json::Error },
    /// Incorrect number of items found in the toplevel list of the manifest.json file
    ImageTarIllegalManifestNum { path: PathBuf, entry: PathBuf, got: usize },
    /// Could not find the expected part of the config digest
    ImageTarIllegalDigest { path: PathBuf, entry: PathBuf, digest: String },
    /// Could not find the manifest.json file in the given image.tar.
    ImageTarNoManifest { path: PathBuf },
}
impl Display for DockerError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DockerError::*;
        match self {
            ConnectionError { path, version, .. } => {
                write!(f, "Failed to connect to the local Docker daemon through socket '{}' and with client version {}", path.display(), version)
            },

            WaitError { name, .. } => write!(f, "Failed to wait for Docker container with name '{name}'"),
            LogsError { name, .. } => write!(f, "Failed to get logs of Docker container with name '{name}'"),

            InspectContainerError { name, .. } => write!(f, "Failed to inspect Docker container with name '{name}'"),
            ContainerNoNetwork { name } => write!(f, "Docker container with name '{name}' is not connected to any networks"),

            CreateContainerError { name, image, .. } => write!(f, "Could not create Docker container with name '{name}' (image: {image})"),
            StartError { name, image, .. } => write!(f, "Could not start Docker container with name '{name}' (image: {image})"),

            ContainerNoState { name } => write!(f, "Docker container with name '{name}' has no execution state (has it been started?)"),
            ContainerNoExitCode { name } => write!(f, "Docker container with name '{name}' has no return code (did you wait before completing?)"),

            ContainerRemoveError { name, .. } => write!(f, "Fialed to remove Docker container with name '{name}'"),

            ImageFileOpenError { path, .. } => write!(f, "Failed to open image file '{}'", path.display()),
            ImageImportError { path, .. } => write!(f, "Failed to import image file '{}' into Docker engine", path.display()),
            ImageFileCreateError { path, .. } => write!(f, "Failed to create image file '{}'", path.display()),
            ImageExportError { name, .. } => write!(f, "Failed to export image '{name}'"),
            ImageFileWriteError { path, .. } => write!(f, "Failed to write to image file '{}'", path.display()),
            ImageFileShutdownError { path, .. } => write!(f, "Failed to shut image file '{}' down", path.display()),

            ImagePullError { source, .. } => write!(f, "Failed to pull image '{source}' into Docker engine"),
            ImageTagError { image, source, .. } => write!(f, "Failed to tag pulled image '{source}' as '{image}'"),

            ImageInspectError { image, .. } => write!(
                f,
                "Failed to inspect image '{}'{}",
                image.name(),
                if let Some(digest) = image.digest() { format!(" ({digest})") } else { String::new() }
            ),
            ImageRemoveError { image, id, .. } => write!(f, "Failed to remove image '{}' (id: {}) from Docker engine", image.name(), id),

            ImageTarOpenError { path, .. } => write!(f, "Could not open given Docker image file '{}'", path.display()),
            ImageTarReadError { path, .. } => write!(f, "Could not read given Docker image file '{}'", path.display()),
            ImageTarEntriesError { path, .. } => write!(f, "Could not get file entries in Docker image file '{}'", path.display()),
            ImageTarEntryError { path, .. } => write!(f, "Could not get file entry from Docker image file '{}'", path.display()),
            ImageTarNoManifest { path } => write!(f, "Could not find manifest.json in given Docker image file '{}'", path.display()),
            ImageTarManifestReadError { path, entry, .. } => {
                write!(f, "Failed to read '{}' in Docker image file '{}'", entry.display(), path.display())
            },
            ImageTarManifestParseError { path, entry, .. } => {
                write!(f, "Could not parse '{}' in Docker image file '{}'", entry.display(), path.display())
            },
            ImageTarIllegalManifestNum { path, entry, got } => write!(
                f,
                "Got incorrect number of entries in '{}' in Docker image file '{}': got {}, expected 1",
                entry.display(),
                path.display(),
                got
            ),
            ImageTarIllegalDigest { path, entry, digest } => write!(
                f,
                "Found image digest '{}' in '{}' in Docker image file '{}' is illegal: does not start with '{}'",
                digest,
                entry.display(),
                path.display(),
                crate::docker::MANIFEST_CONFIG_PREFIX
            ),
            ImageTarIllegalPath { path, .. } => write!(f, "Given Docker image file '{}' contains illegal path entry", path.display()),
        }
    }
}
impl Error for DockerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use DockerError::*;
        match self {
            ConnectionError { err, .. } => Some(err),

            WaitError { err, .. } => Some(err),
            LogsError { err, .. } => Some(err),

            InspectContainerError { err, .. } => Some(err),
            ContainerNoNetwork { .. } => None,

            CreateContainerError { err, .. } => Some(err),
            StartError { err, .. } => Some(err),

            ContainerNoState { .. } => None,
            ContainerNoExitCode { .. } => None,

            ContainerRemoveError { err, .. } => Some(err),

            ImageFileOpenError { err, .. } => Some(err),
            ImageImportError { err, .. } => Some(err),
            ImageFileCreateError { err, .. } => Some(err),
            ImageExportError { err, .. } => Some(err),
            ImageFileWriteError { err, .. } => Some(err),
            ImageFileShutdownError { err, .. } => Some(err),

            ImagePullError { err, .. } => Some(err),
            ImageTagError { err, .. } => Some(err),

            ImageInspectError { err, .. } => Some(err),
            ImageRemoveError { err, .. } => Some(err),

            ImageTarOpenError { err, .. } => Some(err),
            ImageTarReadError { err, .. } => Some(err),
            ImageTarEntriesError { err, .. } => Some(err),
            ImageTarEntryError { err, .. } => Some(err),
            ImageTarIllegalPath { err, .. } => Some(err),
            ImageTarManifestReadError { err, .. } => Some(err),
            ImageTarManifestParseError { err, .. } => Some(err),
            ImageTarIllegalManifestNum { .. } => None,
            ImageTarIllegalDigest { .. } => None,
            ImageTarNoManifest { .. } => None,
        }
    }
}



/// Collects errors that relate to local index interaction.
#[derive(Debug)]
pub enum LocalError {
    /// There was an error reading entries from a package's directory
    PackageDirReadError { path: PathBuf, err: std::io::Error },
    /// Found a version entry who's path could not be split into a filename
    UnreadableVersionEntry { path: PathBuf },
    /// The name of version directory in a package's dir is not a valid version
    IllegalVersionEntry { package: String, version: String, err: specifications::version::ParseError },
    /// The given package has no versions registered to it
    NoVersions { package: String },

    /// There was an error reading entries from the packages directory
    PackagesDirReadError { path: PathBuf, err: std::io::Error },
    /// We tried to load a package YML but failed
    InvalidPackageYml { package: String, path: PathBuf, err: specifications::package::PackageInfoError },
    /// We tried to load a Package Index from a JSON value with PackageInfos but we failed
    PackageIndexError { err: specifications::package::PackageIndexError },

    /// Failed to read the datasets folder
    DatasetsReadError { path: PathBuf, err: std::io::Error },
    /// Failed to open a data.yml file.
    DataInfoOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to read/parse a data.yml file.
    DataInfoReadError { path: PathBuf, err: serde_yaml::Error },
    /// Failed to create a new DataIndex from the infos locally read.
    DataIndexError { err: specifications::data::DataIndexError },
}
impl Display for LocalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LocalError::*;
        match self {
            PackageDirReadError { path, .. } => write!(f, "Could not read package directory '{}'", path.display()),
            UnreadableVersionEntry { path } => write!(f, "Could not get the version directory from '{}'", path.display()),
            IllegalVersionEntry { package, version, .. } => write!(f, "Entry '{version}' for package '{package}' is not a valid version"),
            NoVersions { package } => write!(f, "Package '{package}' does not have any registered versions"),

            PackagesDirReadError { path, .. } => write!(f, "Could not read from Brane packages directory '{}'", path.display()),
            InvalidPackageYml { package, path, .. } => write!(f, "Could not read '{}' for package '{}'", path.display(), package),
            PackageIndexError { .. } => write!(f, "Could not create PackageIndex"),

            DatasetsReadError { path, .. } => write!(f, "Failed to read datasets folder '{}'", path.display()),
            DataInfoOpenError { path, .. } => write!(f, "Failed to open data info file '{}'", path.display()),
            DataInfoReadError { path, .. } => write!(f, "Failed to read/parse data info file '{}'", path.display()),
            DataIndexError { .. } => write!(f, "Failed to create data index from local datasets"),
        }
    }
}
impl Error for LocalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use LocalError::*;
        match self {
            PackageDirReadError { err, .. } => Some(err),
            UnreadableVersionEntry { .. } => None,
            IllegalVersionEntry { err, .. } => Some(err),
            NoVersions { .. } => None,

            PackagesDirReadError { err, .. } => Some(err),
            InvalidPackageYml { err, .. } => Some(err),
            PackageIndexError { err } => Some(err),

            DatasetsReadError { err, .. } => Some(err),
            DataInfoOpenError { err, .. } => Some(err),
            DataInfoReadError { err, .. } => Some(err),
            DataIndexError { err } => Some(err),
        }
    }
}



/// Collects errors that relate to API interaction.
#[derive(Debug)]
pub enum ApiError {
    /// Failed to send a GraphQL request.
    RequestError { address: String, err: reqwest::Error },
    /// Failed to get the body of a response.
    ResponseBodyError { address: String, err: reqwest::Error },
    /// Failed to parse the response from the server.
    ResponseJsonParseError { address: String, raw: String, err: serde_json::Error },
    /// The remote failed to produce even a single result (not even 'no packages').
    NoResponse { address: String },

    /// Failed to parse the package kind in a package info.
    PackageKindParseError { address: String, index: usize, raw: String, err: specifications::package::PackageKindError },
    /// Failed to parse the package's version in a package info.
    VersionParseError { address: String, index: usize, raw: String, err: specifications::version::ParseError },
    /// Failed to create a package index from the given infos.
    PackageIndexError { address: String, err: specifications::package::PackageIndexError },

    /// Failed to create a data index from the given infos.
    DataIndexError { address: String, err: specifications::data::DataIndexError },
}
impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ApiError::*;
        match self {
            RequestError { address, .. } => write!(f, "Failed to post request to '{address}'"),
            ResponseBodyError { address, .. } => write!(f, "Failed to get body from response from '{address}'"),
            ResponseJsonParseError { address, raw, .. } => write!(f, "Failed to parse response \"\"\"{raw}\"\"\" from '{address}' as JSON"),
            NoResponse { address } => write!(f, "'{address}' responded without a body (not even that no packages are available)"),

            PackageKindParseError { address, index, raw, .. } => {
                write!(f, "Failed to parse '{raw}' as package kind in package {index} returned by '{address}'")
            },
            VersionParseError { address, index, raw, .. } => {
                write!(f, "Failed to parse '{raw}' as version in package {index} returned by '{address}'")
            },
            PackageIndexError { address, .. } => write!(f, "Failed to create a package index from the package infos given by '{address}'"),

            DataIndexError { address, .. } => write!(f, "Failed to create a data index from the data infos given by '{address}'"),
        }
    }
}
impl Error for ApiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ApiError::*;
        match self {
            RequestError { err, .. } => Some(err),
            ResponseBodyError { err, .. } => Some(err),
            ResponseJsonParseError { err, .. } => Some(err),
            NoResponse { .. } => None,

            PackageKindParseError { err, .. } => Some(err),
            VersionParseError { err, .. } => Some(err),
            PackageIndexError { err, .. } => Some(err),

            DataIndexError { err, .. } => Some(err),
        }
    }
}



/// Errors that relate to parsing Docker client version numbers.
#[derive(Debug)]
pub enum ClientVersionParseError {
    /// Missing a dot in the version number
    MissingDot { raw: String },
    /// The given major version was not a valid usize
    IllegalMajorNumber { raw: String, err: std::num::ParseIntError },
    /// The given major version was not a valid usize
    IllegalMinorNumber { raw: String, err: std::num::ParseIntError },
}
impl Display for ClientVersionParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ClientVersionParseError::*;
        match self {
            MissingDot { raw } => write!(f, "Missing '.' in Docket client version number '{raw}'"),
            IllegalMajorNumber { raw, .. } => write!(f, "'{raw}' is not a valid Docket client version major number"),
            IllegalMinorNumber { raw, .. } => write!(f, "'{raw}' is not a valid Docket client version minor number"),
        }
    }
}
impl Error for ClientVersionParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ClientVersionParseError::*;
        match self {
            MissingDot { .. } => None,
            IllegalMajorNumber { err, .. } => Some(err),
            IllegalMinorNumber { err, .. } => Some(err),
        }
    }
}
