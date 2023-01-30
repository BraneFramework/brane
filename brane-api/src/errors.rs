//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    04 Feb 2022, 10:35:12
//  Last edited:
//    26 Jan 2023, 09:58:44
//  Auto updated?
//    Yes
// 
//  Description:
//!   Contains general errors for across the brane-api package.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;

use enum_debug::EnumDebug as _;
use reqwest::StatusCode;
use scylla::transport::errors::NewSessionError;

use brane_cfg::node::NodeKind;
use brane_shr::debug::PrettyListFormatter;
use specifications::address::Address;
use specifications::version::Version;


/***** ERRORS *****/
/// Collects errors for the most general case in the brane-api package
#[derive(Debug)]
pub enum ApiError {
    /// Could not create a Scylla session
    ScyllaConnectError{ host: Address, err: NewSessionError },
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            ApiError::ScyllaConnectError{ host, err } => write!(f, "Could not connect to Scylla host '{}': {}", host, err),
        }
    }
}

impl Error for ApiError {}



/// Contains errors relating to the `/infra` path (and nested).
#[derive(Debug)]
pub enum InfraError {
    /// Failed to open/load the infrastructure file.
    InfrastructureOpenError{ path: PathBuf, err: brane_cfg::infra::Error },
    /// Failed to serialize the response body.
    SerializeError{ what: &'static str, err: serde_json::Error },

    /// Failed to do the proxy redirection thing.
    ProxyError{ err: brane_prx::errors::ClientError },
    /// Failed to send a request to the given address.
    RequestError{ address: String, err: reqwest::Error },
    /// The request was not met with an OK
    RequestFailure{ address: String, code: StatusCode, message: Option<String> },
    /// Failed to read the body sent by the other domain.
    ResponseBodyError{ address: String, err: reqwest::Error },
    /// Failed to parse the body as JSON
    ResponseParseError{ address: String, raw: String, err: serde_json::Error },
    /// Failed to re-serialize the parsed body
    CapabilitiesSerializeError{ err: serde_json::Error },

    /// An internal error occurred that we would not like to divulge.
    SecretError,
}

impl Display for InfraError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use InfraError::*;
        match self {
            InfrastructureOpenError{ path, err } => write!(f, "Failed to open infrastructure file '{}': {}", path.display(), err),
            SerializeError{ what, err }          => write!(f, "Failed to serialize {}: {}", what, err),

            ProxyError{ err }                        => write!(f, "Failed to send request through Brane proxy service: {}", err),
            RequestError{ address, err }             => write!(f, "Failed to send GET-request to '{}': {}", address, err),
            RequestFailure{ address, code, message } => write!(f, "Request to '{}' failed with status code {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(err) = message { format!(": {}", err) } else { String::new() }),
            ResponseBodyError{ address, err }        => write!(f, "Failed to get body of response sent by '{}': {}", address, err),
            ResponseParseError{ address, raw, err }  => write!(f, "Failed to parse '{}' as valid JSON sent by '{}': {}", raw, address, err),
            CapabilitiesSerializeError{ err }        => write!(f, "Failed to re-serialize capabilities: {}", err),

            SecretError => write!(f, "An internal error has occurred"),
        }
    }
}

impl Error for InfraError {}

impl warp::reject::Reject for InfraError {}



/// Contains errors relating to the `/data` path (and nested).
#[derive(Debug)]
pub enum DataError {
    /// Failed to open/load the infrastructure file.
    InfrastructureOpenError{ path: PathBuf, err: brane_cfg::infra::Error },
    /// Failed to get the list of all locations.
    InfrastructureLocationsError{ path: PathBuf, err: brane_cfg::infra::Error },
    /// Failed to get the metadata of a location.
    InfrastructureMetadataError{ path: PathBuf, name: String, err: brane_cfg::infra::Error },

    /// Failed to create a new port on the proxy.
    ProxyError{ err: brane_prx::client::Error },
    /// Failed to send a GET-request to the given URL
    RequestError{ address: String, err: reqwest::Error },
    /// Failed to get the body of a response.
    ResponseBodyError{ address: String, err: reqwest::Error },
    /// Failed to parse the body of a response.
    ResponseParseError{ address: String, err: serde_json::Error },
    /// Failed to serialize the response body.
    SerializeError{ what: &'static str, err: serde_json::Error },

    /// An internal error occurred that we would not like to divulge.
    SecretError,
}

impl Display for DataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DataError::*;
        match self {
            InfrastructureOpenError{ path, err }           => write!(f, "Failed to open infrastructure file '{}': {}", path.display(), err),
            InfrastructureLocationsError{ path, err }      => write!(f, "Failed to get locations from infrastructure file '{}': {}", path.display(), err),
            InfrastructureMetadataError{ path, name, err } => write!(f, "Failed to get metadata of location '{}' from infrastructure file '{}': {}", name, path.display(), err),

            ProxyError{ err }                  => write!(f, "Failed to prepare sending a request using the proxy service: {}", err),
            RequestError{ address, err }       => write!(f, "Failed to send GET-request to '{}': {}", address, err),
            ResponseBodyError{ address, err }  => write!(f, "Failed to get the response body received from '{}': {}", address, err),
            ResponseParseError{ address, err } => write!(f, "Failed to parse response from '{}' as JSON: {}", address, err),
            SerializeError{ what, err }        => write!(f, "Failed to serialize {}: {}", what, err),

            SecretError => write!(f, "An internal error has occurred"),
        }
    }
}

impl Error for DataError {}

impl warp::reject::Reject for DataError {}



/// Contains errors relating to the `/packages` path (and nested).
#[derive(Debug)]
pub enum PackageError {
    /// Failed to serialize the funcitions in a PackageInfo.
    FunctionsSerializeError{ name: String, err: serde_json::Error },
    /// Failed to serialize the types in a PackageInfo.
    TypesSerializeError{ name: String, err: serde_json::Error },
    /// The given PackageInfo did not have a digest registered.
    MissingDigest{ name: String },

    /// Failed to define the `brane.package` type in the Scylla database.
    PackageTypeDefineError{ err: scylla::transport::errors::QueryError },
    /// Failed to define the package table in the Scylla database.
    PackageTableDefineError{ err: scylla::transport::errors::QueryError },
    /// Failed to insert a new package in the database.
    PackageInsertError{ name: String, err: scylla::transport::errors::QueryError },

    /// Failed to query for the given package in the Scylla database.
    VersionsQueryError{ name: String, err: scylla::transport::errors::QueryError },
    /// Failed to parse a Version string
    VersionParseError{ raw: String, err: specifications::version::ParseError },
    /// No versions found for the given package
    NoVersionsFound{ name: String },
    /// Failed to query the database for the file of the given package.
    PathQueryError{ name: String, version: Version, err: scylla::transport::errors::QueryError },
    /// The given package was unknown.
    UnknownPackage{ name: String, version: Version },
    /// Failed to get the metadata of a file.
    FileMetadataError{ path: PathBuf, err: std::io::Error },
    /// Failed to open a file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read a file.
    FileReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to send a file chunk.
    FileSendError{ path: PathBuf, err: warp::hyper::Error },

    /// Failed to load the node config.
    NodeConfigLoadError{ err: brane_cfg::node::Error },
    /// The given node config was not for central nodes.
    NodeConfigUnexpectedKind{ path: PathBuf, got: NodeKind, expected: NodeKind },
    /// Failed to create a temporary directory.
    TempDirCreateError{ err: std::io::Error },
    /// Failed to create a particular file.
    TarCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to read the next chunk in the body stream.
    BodyReadError{ err: warp::Error },
    /// Failed to write a chunk to a particular tar file.
    TarWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to flush the tarfile handle.
    TarFlushError{ path: PathBuf, err: std::io::Error },
    /// Failed to re-open the downloaded tarfile to extract it.
    TarReopenError{ path: PathBuf, err: std::io::Error },
    /// Failed to get the list of entries in the tar file.
    TarEntriesError{ path: PathBuf, err: std::io::Error },
    /// Failed to get a single entry in the entries of a tar file.
    TarEntryError{ path: PathBuf, entry: usize, err: std::io::Error },
    /// The given tar file had less entries than we expected.
    TarNotEnoughEntries{ path: PathBuf, expected: usize, got: usize },
    /// The given tar file had too many entries.
    TarTooManyEntries{ path: PathBuf, expected: usize },
    /// Failed to get the path of an entry.
    TarEntryPathError{ path: PathBuf, entry: usize, err: std::io::Error },
    /// The given tar file is missing expected entries.
    TarMissingEntries{ expected: Vec<&'static str>, path: PathBuf },
    /// Failed to properly close the tar file.
    TarFileCloseError{ path: PathBuf },
    /// Failed to unpack the given image file.
    TarFileUnpackError{ file: PathBuf, tarball: PathBuf, target: PathBuf, err: std::io::Error },
    /// Failed to read the extracted package info file.
    PackageInfoReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the extracted package info file.
    PackageInfoParseError{ path: PathBuf, err: serde_yaml::Error },
    /// Failed to move the temporary image to its final destination.
    FileMoveError{ from: PathBuf, to: PathBuf, err: std::io::Error },
}

impl Display for PackageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PackageError::*;
        match self {
            FunctionsSerializeError{ name, err } => write!(f, "Failed to serialize functions in package '{}': {}", name, err),
            TypesSerializeError{ name, err }     => write!(f, "Failed to serialize types in package '{}': {}", name, err),
            MissingDigest{ name }                => write!(f, "Package '{}' does not have a digest specified", name),

            PackageTypeDefineError{ err }   => write!(f, "Failed to define the 'brane.package' type in the Scylla database: {}", err),
            PackageTableDefineError{ err }  => write!(f, "Failed to define the 'brane.packages' table in the Scylla database: {}", err),
            PackageInsertError{ name, err } => write!(f, "Failed to insert package '{}' into the Scylla database: {}", name, err),

            VersionsQueryError{ name, err }      => write!(f, "Failed to query versions for package '{}' from the Scylla database: {}", name, err),
            VersionParseError{ raw, err }        => write!(f, "Failed to parse '{}' as a valid version string: {}", raw, err),
            NoVersionsFound{ name }              => write!(f, "No versions found for package '{}'", name),
            PathQueryError{ name, version, err } => write!(f, "Failed to get path of package '{}', version {}: {}", name, version, err),
            UnknownPackage{ name, version }      => write!(f, "No package '{}' exists (or has version {})", name, version),
            FileMetadataError{ path, err }       => write!(f, "Failed to get metadata of file '{}': {}", path.display(), err),
            FileOpenError{ path, err }           => write!(f, "Failed to open file '{}': {}", path.display(), err),
            FileReadError{ path, err }           => write!(f, "Failed to read file '{}': {}", path.display(), err),
            FileSendError{ path, err }           => write!(f, "Failed to send chunk of file '{}': {}", path.display(), err),

            NodeConfigLoadError{ err }                       => write!(f, "Failed to load node config file: {}", err),
            NodeConfigUnexpectedKind{ path, got, expected }  => write!(f, "Given node config file '{}' is for a {} node, but expected a {} node", path.display(), got.variant(), expected.variant()),
            TempDirCreateError{ err }                        => write!(f, "Failed to create temporary directory: {}", err),
            TarCreateError{ path, err }                      => write!(f, "Failed to create new tar file '{}': {}", path.display(), err),
            BodyReadError{ err }                             => write!(f, "Failed to get next chunk in body stream: {}", err),
            TarWriteError{ path, err }                       => write!(f, "Failed to write body chunk to tar file '{}': {}", path.display(), err),
            TarFlushError{ path, err }                       => write!(f, "Failed to flush new far file '{}': {}", path.display(), err),
            TarReopenError{ path, err }                      => write!(f, "Failed to re-open new tar file '{}': {}", path.display(), err),
            TarEntriesError{ path, err }                     => write!(f, "Failed to get list of entries in tar file '{}': {}", path.display(), err),
            TarEntryError{ path, entry, err }                => write!(f, "Failed to get entry {} in tar file '{}': {}", entry, path.display(), err),
            TarNotEnoughEntries{ path, expected, got }       => write!(f, "Tar file '{}' has only {} entries, but expected {}", path.display(), expected, got),
            TarTooManyEntries{ path, expected }              => write!(f, "Tar file '{}' has more than {} entries", path.display(), expected),
            TarEntryPathError{ path, entry, err }            => write!(f, "Failed to get the path of entry {} in tar file '{}': {}", entry, path.display(), err),
            TarMissingEntries{ expected, path }              => write!(f, "Tar file '{}' does not have entries {}", path.display(), PrettyListFormatter::new(expected.iter(), "or")),
            TarFileCloseError{ path }                        => write!(f, "Failed to close tar file '{}'", path.display()),
            TarFileUnpackError{ file, tarball, target, err } => write!(f, "Failed to extract '{}' file from tar file '{}' to '{}': {}", file.display(), tarball.display(), target.display(), err),
            PackageInfoReadError{ path, err }                => write!(f, "Failed to read extracted package info file '{}': {}", path.display(), err),
            PackageInfoParseError{ path, err }               => write!(f, "Failed to parse extracted package info file '{}' as YAML: {}", path.display(), err),
            FileMoveError{ from, to, err }                   => write!(f, "Failed to move '{}' to '{}': {}", from.display(), to.display(), err),
        }
    }
}

impl Error for PackageError {}
