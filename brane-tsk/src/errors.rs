//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    24 Oct 2022, 15:27:26
//  Last edited:
//    01 Mar 2023, 10:56:51
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines errors that occur in the `brane-tsk` crate.
// 

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;

use bollard::ClientVersion;
use enum_debug::EnumDebug as _;
use reqwest::StatusCode;
use tonic::Status;

use brane_ast::locations::{Location, Locations};
use brane_ast::ast::DataName;
use brane_shr::debug::{BlockFormatter, Capitalizeable};
use specifications::address::Address;
use specifications::container::Image;
use specifications::package::Capability;
use specifications::planning::PlanningStatusKind;
use specifications::version::Version;
use specifications::driving::ExecuteReply;
// The TaskReply is here for legacy reasons; bad name
use specifications::working::{ExecuteReply as TaskReply, TaskStatus};


/***** LIBRARY *****/
/// Defines a kind of combination of all the possible errors that may occur in the process.
#[derive(Debug)]
pub enum TaskError {
    /// Something went wrong while planning.
    PlanError{ err: PlanError },
    /// Something went wrong while executing.
    ExecError{ err: brane_exe::errors::VmError },
}
impl Display for TaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use TaskError::*;
        match self {
            PlanError{ err } => write!(f, "Failed to plan workflow: {}", err),
            ExecError{ err } => write!(f, "Failed to execute workflow: {}", err),
        }
    }
}
impl Error for TaskError {}





/// Defines common errors that occur when trying to plan a workflow.
#[derive(Debug)]
pub enum PlanError {
    /// Failed to load the infrastructure file.
    InfraFileLoadError{ err: brane_cfg::infra::Error },

    /// The user didn't specify the location (specifically enough).
    AmbigiousLocationError{ name: String, locs: Locations },
    /// Failed to send a request to the API service.
    RequestError{ address: String, err: reqwest::Error },
    /// The request failed with a non-OK status code
    RequestFailure{ address: String, code: reqwest::StatusCode, err: Option<String> },
    /// Failed to get the body of a request.
    RequestBodyError{ address: String, err: reqwest::Error },
    /// Failed to parse the body of the request as valid JSON
    RequestParseError{ address: String, raw: String, err: serde_json::Error },
    /// The planned domain does not support the task.
    UnsupportedCapabilities{ task: String, loc: String, expected: HashSet<Capability>, got: HashSet<Capability> },
    /// The given dataset was unknown to us.
    UnknownDataset{ name: String },
    /// The given intermediate result was unknown to us.
    UnknownIntermediateResult{ name: String },
    /// We failed to insert one of the dataset in the runtime set.
    DataPlanError{ err: specifications::data::RuntimeDataIndexError },
    /// We can't access a dataset in the local instance.
    DatasetUnavailable{ name: String, locs: Vec<String> },
    /// We can't access an intermediate result in the local instance.
    IntermediateResultUnavailable{ name: String, locs: Vec<String> },

    // Instance-only
    /// Failed to encode the planning update to send.
    UpdateEncodeError{ correlation_id: String, kind: PlanningStatusKind, err: prost::EncodeError },
    /// Failed to send the update on a Kafka channel.
    KafkaSendError{ correlation_id: String, topic: String, err: rdkafka::error::KafkaError },

    /// The planner didn't respond that it started planning in time.
    PlanningTimeout{ correlation_id: String, timeout: u128 },
    /// Failed to parse the result of the planning session.
    PlanParseError{ correlation_id: String, raw: String, err: serde_json::Error },
    /// The planner failed for some reason (possibly defined). This is different from an error in that we typically expect these to happen.
    PlanningFailed{ correlation_id: String, reason: Option<String> },
    /// The planner errored for some reason. This is different from a failure in that this indicates bad configuration or some service being down.
    PlanningError{ correlation_id: String, err: String },

    /// The planner failed to ensure certain topics existed.
    KafkaTopicError{ brokers: String, topics: Vec<String>, err: brane_shr::kafka::Error },
    /// Failed to create a Kafka producer.
    KafkaProducerError{ err: rdkafka::error::KafkaError },
    /// Failed to create a Kafka consumer.
    KafkaConsumerError{ err: rdkafka::error::KafkaError },
    /// Failed to restore the offsets to the Kafka consumer.
    KafkaOffsetsError{ err: brane_shr::kafka::Error },
    /// Failed to listen for incoming Kafka events.
    KafkaStreamError{ err: rdkafka::error::KafkaError },
    /// Failed to serialize the internal workflow.
    WorkflowSerializeError{ err: serde_json::Error },
}
impl Display for PlanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PlanError::*;
        match self {
            InfraFileLoadError{ err } => write!(f, "Failed to load infrastructure file: {}", err),

            AmbigiousLocationError{ name, locs }                => write!(f, "Ambigious location for task '{}': {}", name, if let Locations::Restricted(locs) = locs { format!("possible locations are {}, but you need to reduce that to only 1 (use On-structs for that)", locs.join(", ")) } else { "all locations are possible, but you need to reduce that to only 1 (use On-structs for that)".into() }),
            RequestError{ address, err }                        => write!(f, "Failed to send GET-request to '{}': {}", address, err),
            RequestFailure{ address, code, err }                => write!(f, "GET-request to '{}' failed with {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(err) = err { format!(": {}", err) } else { String::new() }),
            RequestBodyError{ address, err }                    => write!(f, "Failed to get the body of response from '{}' as UTF-8 text: {}", address, err),
            RequestParseError{ address, raw, err }              => write!(f, "Failed to parse response '{}' from '{}' as valid JSON: {}", raw, address, err),
            UnsupportedCapabilities{ task, loc, expected, got } => write!(f, "Location '{}' only supports capabilities {:?}, whereas task '{}' requires capabilities {:?}", loc, got, task, expected),
            UnknownDataset{ name }                              => write!(f, "Unknown dataset '{}'", name),
            UnknownIntermediateResult{ name }                   => write!(f, "Unknown intermediate result '{}'", name),
            DataPlanError{ err }                                => write!(f, "Failed to plan dataset: {}", err),
            DatasetUnavailable{ name, locs }                    => write!(f, "Dataset '{}' is unavailable{}", name, if !locs.is_empty() { format!("; however, locations {} do (try to get download permission to those datasets)", locs.iter().map(|l| format!("'{}'", l)).collect::<Vec<String>>().join(", ")) } else { String::new() }),
            IntermediateResultUnavailable{ name, locs }         => write!(f, "Intermediate result '{}' is unavailable{}", name, if !locs.is_empty() { format!("; however, locations {} do (try to get download permission to those datasets)", locs.iter().map(|l| format!("'{}'", l)).collect::<Vec<String>>().join(", ")) } else { String::new() }),

            UpdateEncodeError{ correlation_id, kind, err } => write!(f, "Failed to encode status update '{:?}' for a planning session with ID '{}': {}", kind, correlation_id, err),
            KafkaSendError{ correlation_id, topic, err }   => write!(f, "Failed to send status update on Kafka topic '{}' for a planning session with ID '{}': {}", topic, correlation_id, err),

            PlanningTimeout{ correlation_id, timeout } => write!(f, "The planner didn't start planning workflow with ID '{}' in time (timed out after {} seconds)", correlation_id, timeout / 1000),
            PlanParseError{ correlation_id, raw, err } => write!(f, "Failed to parse planning result of workflow with ID '{}': {}\n\n{}\n\n", correlation_id, err, BlockFormatter::new(raw)),
            PlanningFailed{ correlation_id, reason }   => write!(f, "Failed to plan workflow with ID '{}'{}", correlation_id, if let Some(reason) = reason { format!(": {}", reason) } else { String::new() }),
            PlanningError{ correlation_id, err }       => write!(f, "Encountered an error while planning workflow with ID '{}': {}", correlation_id, err),

            KafkaTopicError{ brokers, topics, err }        => write!(f, "Failed to ensure Kafka topics {} on brokers '{}': {}", topics.iter().map(|t| format!("'{}'", t)).collect::<Vec<String>>().join(", "), brokers, err),
            KafkaProducerError{ err }                      => write!(f, "Failed to create Kafka producer: {}", err),
            KafkaConsumerError{ err }                      => write!(f, "Failed to create Kafka consumer: {}", err),
            KafkaOffsetsError{ err }                       => write!(f, "Failed to restore committed offsets to Kafka consumer: {}", err),
            KafkaStreamError{ err }                        => write!(f, "Failed to listen for incoming Kafka events: {}", err),
            WorkflowSerializeError{ err }                  => write!(f, "Failed to serialize workflow: {}", err),
        }
    }
}
impl Error for PlanError {}



/// Defines common errors that occur when trying to preprocess datasets.
#[derive(Debug)]
pub enum PreprocessError {
    /// The dataset was _still_ unavailable after preprocessing
    UnavailableData{ name: DataName },

    // Instance only (client-side)
    /// Failed to load the node config file.
    NodeConfigReadError{ path: PathBuf, err: brane_cfg::spec::YamlError },
    /// Failed to load the infra file.
    InfraReadError{ path: PathBuf, err: brane_cfg::infra::Error },
    /// The given location was unknown.
    UnknownLocationError{ loc: Location },
    /// Failed to connect to a proxy.
    ProxyError{ err: String },
    /// Failed to connect to a delegate node with gRPC
    GrpcConnectError{ endpoint: Address, err: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    GrpcRequestError{ what: &'static str, endpoint: Address, err: tonic::Status },
    /// Preprocessing failed with the following error.
    PreprocessError{ endpoint: Address, kind: String, name: String, err: String },
    /// Failed to re-serialize the access kind.
    AccessKindParseError{ endpoint: Address, raw: String, err: serde_json::Error },

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
    FileReadError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to parse an identity file.
    IdentityFileError{ path: PathBuf, err: reqwest::Error },
    /// Failed to parse a certificate.
    CertificateError{ path: PathBuf, err: reqwest::Error },
    /// A directory was not a directory but a file.
    DirNotADirError{ what: &'static str, path: PathBuf },
    /// A directory what not a directory because it didn't exist.
    DirNotExistsError{ what: &'static str, path: PathBuf },
    /// A directory could not be removed.
    DirRemoveError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// A directory could not be created.
    DirCreateError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to create a reqwest proxy object.
    ProxyCreateError{ address: Address, err: reqwest::Error },
    /// Failed to create a reqwest client.
    ClientCreateError{ err: reqwest::Error },
    /// Failed to send a GET-request to fetch the data.
    DownloadRequestError{ address: String, err: reqwest::Error },
    /// The given download request failed with a non-success status code.
    DownloadRequestFailure{ address: String, code: StatusCode, message: Option<String> },
    /// Failed to reach the next chunk of data.
    DownloadStreamError{ address: String, err: reqwest::Error },
    /// Failed to create the file to which we write the download stream.
    TarCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to (re-)open the file to which we've written the download stream.
    TarOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    TarWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to extract the downloaded tar.
    DataExtractError{ err: brane_shr::fs::Error },
    /// Failed to serialize the preprocessrequest.
    AccessKindSerializeError{ err: serde_json::Error },
}
impl Display for PreprocessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::PreprocessError::*;
        match self {
            UnavailableData{ name } => write!(f, "{} '{}' is not available locally", name.variant(), name.name()),

            NodeConfigReadError{ err, .. }               => write!(f, "Failed to load node config file: {}", err),
            InfraReadError{ path, err }                  => write!(f, "Failed to load infrastructure file '{}': {}", path.display(), err),
            UnknownLocationError{ loc }                  => write!(f, "Unknown location '{}'", loc),
            ProxyError{ err }                            => write!(f, "Failed to prepare proxy service: {}", err),
            GrpcConnectError{ endpoint, err }            => write!(f, "Failed to start gRPC connection with delegate node '{}': {}", endpoint, err),
            GrpcRequestError{ what, endpoint, err }      => write!(f, "Failed to send {} request to delegate node '{}': {}", what, endpoint, err),
            PreprocessError{ endpoint, kind, name, err } => write!(f, "Remote delegate '{}' failed to preprocess {} '{}': {}", endpoint, kind, name, err),
            AccessKindParseError{ endpoint, raw, err }   => write!(f, "Failed to parse access kind '{}' sent by remote delegate '{}': {}", raw, endpoint, err),

            // KeypairLoadError{ err }                          => write!(f, "Failed to load keypair: {}", err),
            // StoreLoadError{ err }                            => write!(f, "Failed to load root store: {}", err),
            // EmptyCertFile{ path }                            => write!(f, "No certificates found in certificate file '{}'", path.display()),
            // IdentityFileError{ certfile, keyfile, err }      => write!(f, "Failed to parse '{}' and '{}' as a single Identity: {}", certfile.display(), keyfile.display(), err),
            // RootError{ cafile, err }                         => write!(f, "Failed to parse '{}' as a root certificate: {}", cafile.display(), err),
            FileReadError{ what, path, err }                 => write!(f, "Failed to read {} file '{}': {}", what, path.display(), err),
            IdentityFileError{ path, err }                   => write!(f, "Failed to parse identity file '{}': {}", path.display(), err),
            CertificateError{ path, err }                    => write!(f, "Failed to parse certificate '{}': {}", path.display(), err),
            DirNotADirError{ what, path }                    => write!(f, "{} directory '{}' is not a directory", what.capitalize(), path.display()),
            DirNotExistsError{ what, path }                  => write!(f, "{} directory '{}' doesn't exist", what.capitalize(), path.display()),
            DirRemoveError{ what, path, err }                => write!(f, "Failed to remove {} directory '{}': {}", what, path.display(), err),
            DirCreateError{ what, path, err }                => write!(f, "Failed to create {} directory '{}': {}", what, path.display(), err),
            ProxyCreateError{ address, err }                 => write!(f, "Failed to create proxy to '{}': {}", address, err),
            ClientCreateError{ err }                         => write!(f, "Failed to create HTTP-client: {}", err),
            DownloadRequestError{ address, err }             => write!(f, "Failed to send GET download request to '{}': {}", address, err),
            DownloadRequestFailure{ address, code, message } => write!(f, "GET download request to '{}' failed with status code {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(message) = message { format!(": {}", message) } else { String::new() }),
            DownloadStreamError{ address, err }              => write!(f, "Failed to get next chunk in download stream from '{}': {}", address, err),
            TarCreateError{ path, err }                      => write!(f, "Failed to create tarball file '{}': {}", path.display(), err),
            TarOpenError{ path, err }                        => write!(f, "Failed to re-open tarball file '{}': {}", path.display(), err),
            TarWriteError{ path, err }                       => write!(f, "Failed to write to tarball file '{}': {}", path.display(), err),
            DataExtractError{ err }                          => write!(f, "Failed to extract dataset: {}", err),
            AccessKindSerializeError{ err }                  => write!(f, "Failed to serialize the given AccessKind: {}", err),
        }
    }
}
impl Error for PreprocessError {}



/// Defines common errors that occur when trying to execute tasks.
/// 
/// Note: we've boxed `Image` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug)]
pub enum ExecuteError {
    // General errors
    /// We encountered a package call that we didn't know.
    UnknownPackage{ name: String, version: Version },
    /// We encountered a dataset/result that we didn't know.
    UnknownData{ name: DataName },
    /// Failed to serialize task's input arguments
    ArgsEncodeError{ err: serde_json::Error },
    /// The external call failed with a nonzero exit code and some stdout/stderr
    ExternalCallFailed{ name: String, image: Box<Image>, code: i32, stdout: String, stderr: String },
    /// Failed to decode the branelet output from base64 to raw bytes
    Base64DecodeError{ raw: String, err: base64::DecodeError },
    /// Failed to decode the branelet output from raw bytes to an UTF-8 string
    Utf8DecodeError{ raw: String, err: std::string::FromUtf8Error },
    /// Failed to decode the branelet output from an UTF-8 string to a FullValue
    JsonDecodeError{ raw: String, err: serde_json::Error },

    // Docker errors
    /// Failed to create a new volume bind
    VolumeBindError{ err: specifications::container::VolumeBindError },
    /// The generated path of a result is not a directory
    ResultDirNotADir{ path: PathBuf },
    /// Could not remove the old result directory
    ResultDirRemoveError{ path: PathBuf, err: std::io::Error },
    /// Could not create the new result directory
    ResultDirCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to run the task as a local Docker container
    DockerError{ name: String, image: Box<Image>, err: DockerError },

    // Instance-only (client side)
    /// The given job status was missing a string while we expected one
    StatusEmptyStringError{ status: TaskStatus },
    /// Failed to parse the given value as a FullValue
    StatusValueParseError{ status: TaskStatus, raw: String, err: serde_json::Error },
    /// Failed to parse the given value as a return code/stdout/stderr triplet.
    StatusTripletParseError{ status: TaskStatus, raw: String, err: serde_json::Error },
    /// Failed to update the client of a status change.
    ClientUpdateError{ status: TaskStatus, err: tokio::sync::mpsc::error::SendError<Result<TaskReply, Status>> },
    /// Failed to load the node config file.
    NodeConfigReadError{ path: PathBuf, err: brane_cfg::spec::YamlError },
    /// Failed to load the infra file.
    InfraReadError{ path: PathBuf, err: brane_cfg::infra::Error },
    /// The given location was unknown.
    UnknownLocationError{ loc: Location },
    /// Failed to prepare the proxy service.
    ProxyError{ err: String },
    /// Failed to connect to a delegate node with gRPC
    GrpcConnectError{ endpoint: Address, err: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    GrpcRequestError{ what: &'static str, endpoint: Address, err: tonic::Status },
    /// Preprocessing failed with the following error.
    ExecuteError{ endpoint: Address, name: String, status: TaskStatus, err: String },

    // Instance-only (worker side)
    /// Failed to load the digest cache file
    DigestReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to fetch the digest of an already existing image.
    DigestError{ path: PathBuf, err: DockerError },
    /// Failed to create a reqwest proxy object.
    ProxyCreateError{ address: Address, err: reqwest::Error },
    /// Failed to create a reqwest client.
    ClientCreateError{ err: reqwest::Error },
    /// Failed to send a GET-request to fetch the data.
    DownloadRequestError{ address: String, err: reqwest::Error },
    /// The given download request failed with a non-success status code.
    DownloadRequestFailure{ address: String, code: StatusCode, message: Option<String> },
    /// Failed to reach the next chunk of data.
    DownloadStreamError{ address: String, err: reqwest::Error },
    /// Failed to create the file to which we write the download stream.
    ImageCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    ImageWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the file where we write the container ID.
    IdWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to read from the file where we cached the container ID.
    IdReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to hash the given container.
    HashError{ err: DockerError },
    /// Failed to write to the file where we write the container hash.
    HashWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to read to the file where we cached the container hash.
    HashReadError{ path: PathBuf, err: std::io::Error },

    /// The checker rejected the workflow.
    AuthorizationFailure{ checker: Address },
    /// The checker failed to check workflow authorization.
    AuthorizationError{ checker: Address, err: AuthorizeError },
    /// Failed to get an up-to-date package index.
    PackageIndexError{ endpoint: String, err: ApiError },
    /// Failed to load the backend file.
    BackendFileError{ path: PathBuf, err: brane_cfg::backend::Error },
}
impl Display for ExecuteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::ExecuteError::*;
        match self {
            UnknownPackage{ name, version }                         => write!(f, "Unknown package '{}' (or it does not have version {})", name, version),
            UnknownData{ name }                                     => write!(f, "Unknown {} '{}'", name.variant(), name.name()),
            ArgsEncodeError{ err }                                  => write!(f, "Failed to serialize input arguments: {}", err),
            ExternalCallFailed{ name, image, code, stdout, stderr } => write!(f, "Task '{}' (image '{}') failed with exit code {}\n\n{}\n\n{}\n\n", name, image, code, BlockFormatter::new(stdout), BlockFormatter::new(stderr)),
            Base64DecodeError{ raw, err }                           => write!(f, "Failed to decode task output as valid Base64: {}\n\n{}\n\n", BlockFormatter::new(raw), err),
            Utf8DecodeError{ raw, err }                             => write!(f, "Failed to decode task output as valid UTF-8: {}\n\n{}\n\n", BlockFormatter::new(raw), err),
            JsonDecodeError{ raw, err }                             => write!(f, "Failed to decode task output as valid JSON: {}\n\n{}\n\n", BlockFormatter::new(raw), err),

            VolumeBindError{ err }            => write!(f, "Failed to create VolumeBind: {}", err),
            ResultDirNotADir{ path }          => write!(f, "Result directory '{}' exists but is not a directory", path.display()),
            ResultDirRemoveError{ path, err } => write!(f, "Failed to remove existing result directory '{}': {}", path.display(), err),
            ResultDirCreateError{ path, err } => write!(f, "Failed to create result directory '{}': {}", path.display(), err),
            DockerError{ name, image, err }   => write!(f, "Failed to execute task '{}' (image '{}') as a Docker container: {}", name, image, err),

            StatusEmptyStringError{ status }            => write!(f, "Incoming status update {:?} is missing mandatory `value` field", status),
            StatusValueParseError{ status, raw, err }   => write!(f, "Failed to parse '{}' as a FullValue in incoming status update {:?}: {}", raw, status, err),
            StatusTripletParseError{ status, raw, err } => write!(f, "Failed to parse '{}' as a return code/stdout/stderr triplet in incoming status update {:?}: {}", raw, status, err),
            ClientUpdateError{ status, err }            => write!(f, "Failed to update client of status {:?}: {}", status, err),
            NodeConfigReadError{ err, .. }              => write!(f, "Failed to load node config file: {}", err),
            InfraReadError{ path, err }                 => write!(f, "Failed to load infrastructure file '{}': {}", path.display(), err),
            UnknownLocationError{ loc }                 => write!(f, "Unknown location '{}'", loc),
            ProxyError{ err }                           => write!(f, "Failed to prepare proxy service: {}", err),
            GrpcConnectError{ endpoint, err }           => write!(f, "Failed to start gRPC connection with delegate node '{}': {}", endpoint, err),
            GrpcRequestError{ what, endpoint, err }     => write!(f, "Failed to send {} request to delegate node '{}': {}", what, endpoint, err),
            ExecuteError{ endpoint, name, status, err } => write!(f, "Remote delegate '{}' returned status '{:?}' while executing task '{}': {}", endpoint, status, name, err),

            DigestReadError{ path, err }                     => write!(f, "Failed to read cached digest in '{}': {}", path.display(), err),
            DigestError{ path, err }                         => write!(f, "Failed to read digest of image '{}': {}", path.display(), err),
            ProxyCreateError{ address, err }                 => write!(f, "Failed to create proxy to '{}': {}", address, err),
            ClientCreateError{ err }                         => write!(f, "Failed to create HTTP-client: {}", err),
            DownloadRequestError{ address, err }             => write!(f, "Failed to send GET download request to '{}': {}", address, err),
            DownloadRequestFailure{ address, code, message } => write!(f, "GET download request to '{}' failed with status code {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(message) = message { format!(": {}", message) } else { String::new() }),
            DownloadStreamError{ address, err }              => write!(f, "Failed to get next chunk in download stream from '{}': {}", address, err),
            ImageCreateError{ path, err }                    => write!(f, "Failed to create tarball file '{}': {}", path.display(), err),
            ImageWriteError{ path, err }                     => write!(f, "Failed to write to tarball file '{}': {}", path.display(), err),
            IdWriteError{ path, err }                        => write!(f, "Failed to write image ID to file '{}': {}", path.display(), err),
            IdReadError{ path, err }                         => write!(f, "Failed to read image from file '{}': {}", path.display(), err),
            HashError{ err }                                 => write!(f, "Failed to hash image: {}", err),
            HashWriteError{ path, err }                      => write!(f, "Failed to write image hash to file '{}': {}", path.display(), err),
            HashReadError{ path, err }                       => write!(f, "Failed to read image hash from file '{}': {}", path.display(), err),

            AuthorizationFailure{ checker: _ }    => write!(f, "Checker rejected workflow"),
            AuthorizationError{ checker: _, err } => write!(f, "Checker failed to authorize workflow: {}", err),
            PackageIndexError{ endpoint, err }    => write!(f, "Failed to get PackageIndex from '{}': {}", endpoint, err),
            BackendFileError{ path, err }         => write!(f, "Failed to load backend file '{}': {}", path.display(), err),
        }
    }
}
impl Error for ExecuteError {}



/// A special case of the execute error, this relates to authorization errors in the backend eFLINT reasoner (or other reasoners).
#[derive(Debug)]
pub enum AuthorizeError {
    /// Failed to load the policy file.
    PolicyFileError{ err: brane_cfg::policies::Error },
    /// No policy rule defined for the given container.
    NoContainerPolicy{ hash: String },
}
impl Display for AuthorizeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AuthorizeError::*;
        match self {
            PolicyFileError{ err }    => write!(f, "Failed to load policy file: {}", err),
            NoContainerPolicy{ hash } => write!(f, "No policy found that applies to a container with hash '{}' (did you add a final AllowAll/DenyAll?)", hash),
        }
    }
}
impl Error for AuthorizeError {}



/// Defines common errors that occur when trying to write to stdout.
#[derive(Debug)]
pub enum StdoutError {
    /// Failed to write to the gRPC channel to feedback stdout back to the client.
    TxWriteError{ err: tokio::sync::mpsc::error::SendError<Result<ExecuteReply, Status>> },
}
impl Display for StdoutError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use StdoutError::*;
        match self {
            TxWriteError{ err } => write!(f, "Failed to write '{}' on gRPC channel back to client", err),
        }
    }
}
impl Error for StdoutError {}



/// Defines common errors that occur when trying to commit an intermediate result.
#[derive(Debug)]
pub enum CommitError {
    // Docker-local errors
    /// The given dataset was unavailable locally
    UnavailableDataError{ name: String, locs: Vec<String> },
    /// The generated path of a data is not a directory
    DataDirNotADir{ path: PathBuf },
    /// Could not create the new data directory
    DataDirCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to create a new DataInfo file.
    DataInfoCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to serialize a new DataInfo file.
    DataInfoSerializeError{ err: serde_json::Error },
    /// Failed to write the DataInfo the the created file.
    DataInfoWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to read the given directory.
    DirReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to read the given directory entry.
    DirEntryReadError{ path: PathBuf, i: usize, err: std::io::Error },
    /// Failed to copy the data
    DataCopyError{ err: brane_shr::fs::Error },

    // Instance-only (client side)
    /// Failed to load the node config file.
    NodeConfigReadError{ path: PathBuf, err: brane_cfg::spec::YamlError },
    /// Failed to load the infra file.
    InfraReadError{ path: PathBuf, err: brane_cfg::infra::Error },
    /// The given location was unknown.
    UnknownLocationError{ loc: Location },
    /// Failed to prepare the proxy service.
    ProxyError{ err: String },
    /// Failed to connect to a delegate node with gRPC
    GrpcConnectError{ endpoint: Address, err: specifications::working::Error },
    /// Failed to send a preprocess request to a delegate node with gRPC
    GrpcRequestError{ what: &'static str, endpoint: Address, err: tonic::Status },
    /// Preprocessing failed with the following error.
    CommitError{ endpoint: Address, name: String, err: Option<String> },

    // Instance-only (worker side)
    /// Failed to read the AssetInfo file.
    AssetInfoReadError{ path: PathBuf, err: specifications::data::AssetInfoError },
    /// Failed to remove a file.
    FileRemoveError{ path: PathBuf, err: std::io::Error },
    /// Failed to remove a directory.
    DirRemoveError{ path: PathBuf, err: std::io::Error },
    /// A given path is neither a file nor a directory.
    PathNotFileNotDir{ path: PathBuf },
}
impl Display for CommitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::CommitError::*;
        match self {
            UnavailableDataError{ name, locs }   => write!(f, "Dataset '{}' is unavailable{}", name, if !locs.is_empty() { format!("; however, locations {} do (try to get download permission to those datasets)", locs.iter().map(|l| format!("'{}'", l)).collect::<Vec<String>>().join(", ")) } else { String::new() }),
            DataDirNotADir{ path }               => write!(f, "Dataset directory '{}' exists but is not a directory", path.display()),
            DataDirCreateError{ path, err }      => write!(f, "Failed to create dataset directory '{}': {}", path.display(), err),
            DataInfoCreateError{ path, err }     => write!(f, "Failed to create new data info file '{}': {}", path.display(), err),
            DataInfoSerializeError{ err }        => write!(f, "Failed to serialize DataInfo struct: {}", err),
            DataInfoWriteError{ path, err }      => write!(f, "Failed to write DataInfo to '{}': {}", path.display(), err),
            DirReadError{ path, err }            => write!(f, "Failed to read directory '{}': {}", path.display(), err),
            DirEntryReadError{ path, i, err }    => write!(f, "Failed to read entry {} in directory '{}': {}", i, path.display(), err),
            DataCopyError{ err }                 => write!(f, "Failed to copy data directory: {}", err),

            NodeConfigReadError{ err, .. }          => write!(f, "Failed to load node config file: {}", err),
            InfraReadError{ path, err }             => write!(f, "Failed to load infrastructure file '{}': {}", path.display(), err),
            UnknownLocationError{ loc }             => write!(f, "Unknown location '{}'", loc),
            ProxyError{ err }                       => write!(f, "Failed to prepare proxy service: {}", err),
            GrpcConnectError{ endpoint, err }       => write!(f, "Failed to start gRPC connection with delegate node '{}': {}", endpoint, err),
            GrpcRequestError{ what, endpoint, err } => write!(f, "Failed to send {} request to delegate node '{}': {}", what, endpoint, err),
            CommitError{ endpoint, name, err }      => write!(f, "Remote delegate '{}' failed to commit intermediate result '{}'{}", endpoint, name, if let Some(err) = err { format!(": {}", err) } else { String::new() }),

            AssetInfoReadError{ path, err } => write!(f, "Failed to load asset info file '{}': {}", path.display(), err),
            FileRemoveError{ path, err }    => write!(f, "Failed to remove file '{}': {}", path.display(), err),
            DirRemoveError{ path, err }     => write!(f, "Failed to remove directory '{}': {}", path.display(), err),
            PathNotFileNotDir{ path }       => write!(f, "Given path '{}' neither points to a file nor a directory", path.display()),
        }
    }
}
impl Error for CommitError {}



/// Collects errors that relate to the AppId or TaskId (actually only parser errors).
#[derive(Debug)]
pub enum IdError {
    /// Failed to parse the AppId from a string.
    ParseError{ what: &'static str, raw: String, err: uuid::Error },
}
impl Display for IdError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use IdError::*;
        match self {
            ParseError{ what, raw, err } => write!(f, "Failed to parse {} from '{}': {}", what, raw, err),
        }
    }
}
impl Error for IdError {}



/// Collects errors that relate to Docker.
/// 
/// Note: we've boxed `Image` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug)]
pub enum DockerError {
    /// We failed to connect to the local Docker daemon.
    ConnectionError{ path: PathBuf, version: ClientVersion, err: bollard::errors::Error },

    /// Failed to wait for the container with the given name.
    WaitError{ name: String, err: bollard::errors::Error },
    /// Failed to read the logs of a container.
    LogsError{ name: String, err: bollard::errors::Error },

    /// Failed to inspect the given container.
    InspectContainerError{ name: String, err: bollard::errors::Error },
    /// The given container was not attached to any networks.
    ContainerNoNetwork{ name: String },

    /// Could not create and/or start the given container.
    CreateContainerError{ name: String, image: Box<Image>, err: bollard::errors::Error },
    /// Fialed to start the given container.
    StartError{ name: String, image: Box<Image>, err: bollard::errors::Error },

    /// An executing container had no execution state (it wasn't started?)
    ContainerNoState{ name: String },
    /// An executing container had no return code.
    ContainerNoExitCode{ name: String },

    /// Failed to remove the given container.
    ContainerRemoveError{ name: String, err: bollard::errors::Error },

    /// Failed to open the given image file.
    ImageFileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to import the given image file.
    ImageImportError{ path: PathBuf, err: bollard::errors::Error },
    /// Failed to create the given image file.
    ImageFileCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to download a piece of the image from the Docker client.
    ImageExportError{ name: String, err: bollard::errors::Error },
    /// Failed to write a chunk of the exported image.
    ImageFileWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to shutdown the given file.
    ImageFileShutdownError{ path: PathBuf, err: std::io::Error },

    /// Failed to pull the given image file.
    ImagePullError{ source: String, err: bollard::errors::Error },
    /// Failed to appropriately tag the pulled image.
    ImageTagError{ image: Box<Image>, source: String, err: bollard::errors::Error },

    /// Failed to inspect a certain image.
    ImageInspectError{ image: Box<Image>, err: bollard::errors::Error },
    /// Failed to remove a certain image.
    ImageRemoveError{ image: Box<Image>, id: String, err: bollard::errors::Error },

    /// Could not open the given image.tar.
    ImageTarOpenError{ path: PathBuf, err: std::io::Error },
    /// Could not read from the given image.tar.
    ImageTarReadError{ path: PathBuf, err: std::io::Error },
    /// Could not get the list of entries from the given image.tar.
    ImageTarEntriesError{ path: PathBuf, err: std::io::Error },
    /// COuld not read a single entry from the given image.tar.
    ImageTarEntryError{ path: PathBuf, err: std::io::Error },
    /// Could not get path from entry
    ImageTarIllegalPath{ path: PathBuf, err: std::io::Error },
    /// Could not read the manifest.json file
    ImageTarManifestReadError{ path: PathBuf, entry: PathBuf, err: std::io::Error },
    /// Could not parse the manifest.json file
    ImageTarManifestParseError{ path: PathBuf, entry: PathBuf, err: serde_json::Error },
    /// Incorrect number of items found in the toplevel list of the manifest.json file
    ImageTarIllegalManifestNum{ path: PathBuf, entry: PathBuf, got: usize },
    /// Could not find the expected part of the config digest
    ImageTarIllegalDigest{ path: PathBuf, entry: PathBuf, digest: String },
    /// Could not find the manifest.json file in the given image.tar.
    ImageTarNoManifest{ path: PathBuf },
}
impl Display for DockerError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DockerError::*;
        match self {
            ConnectionError{ path, version, err } => write!(f, "Failed to connect to the local Docker daemon through socket '{}' and with client version {}: {}", path.display(), version, err),

            WaitError{ name, err } => write!(f, "Failed to wait for Docker container with name '{}': {}", name, err),
            LogsError{ name, err } => write!(f, "Failed to get logs of Docker container with name '{}': {}", name, err),

            InspectContainerError{ name, err } => write!(f, "Failed to inspect Docker container with name '{}': {}", name, err),
            ContainerNoNetwork{ name }         => write!(f, "Docker container with name '{}' is not connected to any networks", name),

            CreateContainerError{ name, image, err } => write!(f, "Could not create Docker container with name '{}' (image: {}): {}", name, image, err),
            StartError{ name, image, err }           => write!(f, "Could not start Docker container with name '{}' (image: {}): {}", name, image, err),

            ContainerNoState{ name }    => write!(f, "Docker container with name '{}' has no execution state (has it been started?)", name),
            ContainerNoExitCode{ name } => write!(f, "Docker container with name '{}' has no return code (did you wait before completing?)", name),

            ContainerRemoveError{ name, err } => write!(f, "Fialed to remove Docker container with name '{}': {}", name, err),

            ImageFileOpenError{ path, err }     => write!(f, "Failed to open image file '{}': {}", path.display(), err),
            ImageImportError{ path, err }       => write!(f, "Failed to import image file '{}' into Docker engine: {}", path.display(), err),
            ImageFileCreateError{ path, err }   => write!(f, "Failed to create image file '{}': {}", path.display(), err),
            ImageExportError{ name, err }       => write!(f, "Failed to export image '{}': {}", name, err),
            ImageFileWriteError{ path, err }    => write!(f, "Failed to write to image file '{}': {}", path.display(), err),
            ImageFileShutdownError{ path, err } => write!(f, "Failed to shut image file '{}' down: {}", path.display(), err),

            ImagePullError{ source, err }       => write!(f, "Failed to pull image '{}' into Docker engine: {}", source, err),
            ImageTagError{ image, source, err } => write!(f, "Failed to tag pulled image '{}' as '{}': {}", source, image, err),

            ImageInspectError{ image, err }    => write!(f, "Failed to inspect image '{}'{}: {}", image.name(), if let Some(digest) = image.digest() { format!(" ({})", digest) } else { String::new() }, err),
            ImageRemoveError{ image, id, err } => write!(f, "Failed to remove image '{}' (id: {}) from Docker engine: {}", image.name(), id, err),

            ImageTarOpenError{ path, err }                 => write!(f, "Could not open given Docker image file '{}': {}", path.display(), err),
            ImageTarReadError{ path, err }                 => write!(f, "Could not read given Docker image file '{}': {}", path.display(), err),
            ImageTarEntriesError{ path, err }              => write!(f, "Could not get file entries in Docker image file '{}': {}", path.display(), err),
            ImageTarEntryError{ path, err }                => write!(f, "Could not get file entry from Docker image file '{}': {}", path.display(), err),
            ImageTarNoManifest{ path }                     => write!(f, "Could not find manifest.json in given Docker image file '{}'", path.display()),
            ImageTarManifestReadError{ path, entry, err }  => write!(f, "Failed to read '{}' in Docker image file '{}': {}", entry.display(), path.display(), err),
            ImageTarManifestParseError{ path, entry, err } => write!(f, "Could not parse '{}' in Docker image file '{}': {}", entry.display(), path.display(), err),
            ImageTarIllegalManifestNum{ path, entry, got } => write!(f, "Got incorrect number of entries in '{}' in Docker image file '{}': got {}, expected 1", entry.display(), path.display(), got),
            ImageTarIllegalDigest{ path, entry, digest }   => write!(f, "Found image digest '{}' in '{}' in Docker image file '{}' is illegal: does not start with '{}'", digest, entry.display(), path.display(), crate::docker::MANIFEST_CONFIG_PREFIX),
            ImageTarIllegalPath{ path, err }               => write!(f, "Given Docker image file '{}' contains illegal path entry: {}", path.display(), err),
        }
    }
}
impl Error for DockerError {}



/// Collects errors that relate to local index interaction.
#[derive(Debug)]
pub enum LocalError {
    /// There was an error reading entries from a package's directory
    PackageDirReadError{ path: PathBuf, err: std::io::Error },
    /// Found a version entry who's path could not be split into a filename
    UnreadableVersionEntry{ path: PathBuf },
    /// The name of version directory in a package's dir is not a valid version
    IllegalVersionEntry{ package: String, version: String, err: specifications::version::ParseError },
    /// The given package has no versions registered to it
    NoVersions{ package: String },

    /// There was an error reading entries from the packages directory
    PackagesDirReadError{ path: PathBuf, err: std::io::Error },
    /// We tried to load a package YML but failed
    InvalidPackageYml{ package: String, path: PathBuf, err: specifications::package::PackageInfoError },
    /// We tried to load a Package Index from a JSON value with PackageInfos but we failed
    PackageIndexError{ err: specifications::package::PackageIndexError },

    /// Failed to read the datasets folder
    DatasetsReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to open a data.yml file.
    DataInfoOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read/parse a data.yml file.
    DataInfoReadError{ path: PathBuf, err: serde_yaml::Error },
    /// Failed to create a new DataIndex from the infos locally read.
    DataIndexError{ err: specifications::data::DataIndexError },
}
impl Display for LocalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LocalError::*;
        match self {
            PackageDirReadError{ path, err }             => write!(f, "Could not read package directory '{}': {}", path.display(), err),
            UnreadableVersionEntry{ path }               => write!(f, "Could not get the version directory from '{}'", path.display()),
            IllegalVersionEntry{ package, version, err } => write!(f, "Entry '{}' for package '{}' is not a valid version: {}", version, package, err),
            NoVersions{ package }                        => write!(f, "Package '{}' does not have any registered versions", package),

            PackagesDirReadError{ path, err }        => write!(f, "Could not read from Brane packages directory '{}': {}", path.display(), err),
            InvalidPackageYml{ package, path, err }  => write!(f, "Could not read '{}' for package '{}': {}", path.display(), package, err),
            PackageIndexError{ err }                 => write!(f, "Could not create PackageIndex: {}", err),

            DatasetsReadError{ path, err } => write!(f, "Failed to read datasets folder '{}': {}", path.display(), err),
            DataInfoOpenError{ path, err } => write!(f, "Failed to open data info file '{}': {}", path.display(), err),
            DataInfoReadError{ path, err } => write!(f, "Failed to read/parse data info file '{}': {}", path.display(), err),
            DataIndexError{ err }          => write!(f, "Failed to create data index from local datasets: {}", err),
        }
    }
}
impl Error for LocalError {}



/// Collects errors that relate to API interaction.
#[derive(Debug)]
pub enum ApiError {
    /// Failed to send a GraphQL request.
    RequestError{ address: String, err: reqwest::Error },
    /// Failed to get the body of a response.
    ResponseBodyError{ address: String, err: reqwest::Error },
    /// Failed to parse the response from the server.
    ResponseJsonParseError{ address: String, raw: String, err: serde_json::Error },
    /// The remote failed to produce even a single result (not even 'no packages').
    NoResponse{ address: String },

    /// Failed to parse the package kind in a package info.
    PackageKindParseError{ address: String, index: usize, raw: String, err: specifications::package::PackageKindError },
    /// Failed to parse the package's version in a package info.
    VersionParseError{ address: String, index: usize, raw: String, err: specifications::version::ParseError },
    /// Failed to create a package index from the given infos.
    PackageIndexError{ address: String, err: specifications::package::PackageIndexError },

    /// Failed to create a data index from the given infos.
    DataIndexError{ address: String, err: specifications::data::DataIndexError },
}
impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ApiError::*;
        match self {
            RequestError{ address, err }                => write!(f, "Failed to post request to '{}': {}", address, err),
            ResponseBodyError{ address, err }           => write!(f, "Failed to get body from response from '{}': {}", address, err),
            ResponseJsonParseError{ address, raw, err } => write!(f, "Failed to parse response \"\"\"{}\"\"\" from '{}' as JSON: {}", raw, address, err),
            NoResponse{ address }                       => write!(f, "'{}' responded without a body (not even that no packages are available)", address),

            PackageKindParseError{ address, index, raw, err } => write!(f, "Failed to parse '{}' as package kind in package {} returned by '{}': {}", raw, index, address, err),
            VersionParseError{ address, index, raw, err }     => write!(f, "Failed to parse '{}' as version in package {} returned by '{}': {}", raw, index, address, err),
            PackageIndexError{ address, err }                 => write!(f, "Failed to create a package index from the package infos given by '{}': {}", address, err),

            DataIndexError{ address, err } => write!(f, "Failed to create a data index from the data infos given by '{}': {}", address, err),
        }
    }
}
impl Error for ApiError {}
