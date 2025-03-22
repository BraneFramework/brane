//  ERRORS.rs
//    by Lut99
//
//  Created:
//    04 Feb 2022, 10:35:12
//  Last edited:
//    07 Jun 2023, 16:29:32
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains general errors for across the brane-api package.
//

use std::path::PathBuf;

use brane_cfg::node::NodeKind;
use brane_shr::formatters::PrettyListFormatter;
use enum_debug::EnumDebug as _;
use reqwest::StatusCode;
use scylla::transport::errors::NewSessionError;
use specifications::address::Address;
use specifications::version::Version;


/***** ERRORS *****/
/// Collects errors for the most general case in the brane-api package
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Could not create a Scylla session
    #[error("Could not connect to Scylla host '{host}'")]
    ScyllaConnectError { host: Address, source: NewSessionError },
}


/// Contains errors relating to the `/infra` path (and nested).
#[derive(Debug, thiserror::Error)]
pub enum InfraError {
    /// Failed to open/load the infrastructure file.
    #[error("Failed to open infrastructure file '{}'", path.display())]
    InfrastructureOpenError { path: PathBuf, source: brane_cfg::infra::Error },
    /// Failed to serialize the response body.
    #[error("Failed to serialize {what}")]
    SerializeError { what: &'static str, source: serde_json::Error },

    /// Failed to do the proxy redirection thing.
    #[error("Failed to send request through Brane proxy service")]
    ProxyError { source: brane_prx::errors::ClientError },
    /// Failed to send a request to the given address.
    #[error("Failed to send GET-request to '{address}'")]
    RequestError { address: String, source: reqwest::Error },
    /// The request was not met with an OK
    #[error(
        "Request to '{}' failed with status code {} ({}){}",
        address,
        code,
        code.canonical_reason().unwrap_or("???"),
        if let Some(err) = message { format!(": {err}") } else { String::new() }
    )]
    RequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to read the body sent by the other domain.
    #[error("Failed to get body of response sent by '{address}'")]
    ResponseBodyError { address: String, source: reqwest::Error },
    /// Failed to parse the body as JSON
    #[error("Failed to parse '{raw}' as valid JSON sent by '{address}'")]
    ResponseParseError { address: String, raw: String, source: serde_json::Error },
    /// Failed to re-serialize the parsed body
    #[error("Failed to re-serialize capabilities")]
    CapabilitiesSerializeError { source: serde_json::Error },

    /// An internal error occurred that we would not like to divulge.
    #[error("An internal error has occurred")]
    SecretError,
}

impl warp::reject::Reject for InfraError {}



/// Contains errors relating to the `/data` path (and nested).
#[derive(Debug, thiserror::Error)]
pub enum DataError {
    /// Failed to open/load the infrastructure file.
    #[error("Failed to open infrastructure file '{}'", path.display())]
    InfrastructureOpenError { path: PathBuf, source: brane_cfg::infra::Error },
    /// Failed to get the list of all locations.
    #[error("Failed to get locations from infrastructure file '{}'", path.display())]
    InfrastructureLocationsError { path: PathBuf, source: brane_cfg::infra::Error },
    /// Failed to get the metadata of a location.
    #[error("Failed to get metadata of location '{}' from infrastructure file '{}'", name, path.display())]
    InfrastructureMetadataError { path: PathBuf, name: String, source: brane_cfg::infra::Error },

    /// Failed to create a new port on the proxy.
    #[error("Failed to prepare sending a request using the proxy service")]
    ProxyError { source: brane_prx::client::Error },
    /// Failed to send a GET-request to the given URL
    #[error("Failed to send GET-request to '{address}'")]
    RequestError { address: String, source: reqwest::Error },
    /// Failed to get the body of a response.
    #[error("Failed to get the response body received from '{address}'")]
    ResponseBodyError { address: String, source: reqwest::Error },
    /// Failed to parse the body of a response.
    #[error("Failed to parse response from '{address}' as JSON")]
    ResponseParseError { address: String, source: serde_json::Error },
    /// Failed to serialize the response body.
    #[error("Failed to serialize {what}")]
    SerializeError { what: &'static str, source: serde_json::Error },

    /// An internal error occurred that we would not like to divulge.
    #[error("An internal error has occurred")]
    SecretError,
}


impl warp::reject::Reject for DataError {}

/// Contains errors relating to the `/packages` path (and nested).
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// Failed to serialize the funcitions in a PackageInfo.
    #[error("Failed to serialize functions in package '{name}'")]
    FunctionsSerializeError { name: String, source: serde_json::Error },
    /// Failed to serialize the types in a PackageInfo.
    #[error("Failed to serialize types in package '{name}'")]
    TypesSerializeError { name: String, source: serde_json::Error },
    /// The given PackageInfo did not have a digest registered.
    #[error("Package '{name}' does not have a digest specified")]
    MissingDigest { name: String },

    /// Failed to define the `brane.package` type in the Scylla database.
    #[error("Failed to define the 'brane.package' type in the Scylla database")]
    PackageTypeDefineError { source: scylla::transport::errors::QueryError },
    /// Failed to define the package table in the Scylla database.
    #[error("Failed to define the 'brane.packages' table in the Scylla database")]
    PackageTableDefineError { source: scylla::transport::errors::QueryError },
    /// Failed to insert a new package in the database.
    #[error("Failed to insert package '{name}' into the Scylla database")]
    PackageInsertError { name: String, source: scylla::transport::errors::QueryError },

    /// Failed to query for the given package in the Scylla database.
    #[error("Failed to query versions for package '{name}' from the Scylla database")]
    VersionsQueryError { name: String, source: scylla::transport::errors::QueryError },
    /// Failed to parse a Version string
    #[error("Failed to parse '{raw}' as a valid version string")]
    VersionParseError { raw: String, source: specifications::version::ParseError },
    /// No versions found for the given package
    #[error("No versions found for package '{name}'")]
    NoVersionsFound { name: String },
    /// Failed to query the database for the file of the given package.
    #[error("Failed to get path of package '{name}', version {version}")]
    PathQueryError { name: String, version: Version, source: scylla::transport::errors::QueryError },
    /// The given package was unknown.
    #[error("No package '{name}' exists (or has version {version})")]
    UnknownPackage { name: String, version: Version },
    /// Failed to get the metadata of a file.
    #[error("Failed to get metadata of file '{}'", path.display())]
    FileMetadataError { path: PathBuf, source: std::io::Error },
    /// Failed to open a file.
    #[error("Failed to open file '{}'", path.display())]
    FileOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to read a file.
    #[error("Failed to read file '{}'", path.display())]
    FileReadError { path: PathBuf, source: std::io::Error },
    /// Failed to send a file chunk.
    #[error("Failed to send chunk of file '{}'", path.display())]
    FileSendError { path: PathBuf, source: warp::hyper::Error },

    /// Failed to load the node config.
    #[error("Failed to load node config file")]
    NodeConfigLoadError { source: brane_cfg::info::YamlError },
    /// The given node config was not for central nodes.
    #[error("Given node config file '{}' is for a {} node, but expected a {} node", path.display(), got.variant(), expected.variant())]
    NodeConfigUnexpectedKind { path: PathBuf, got: NodeKind, expected: NodeKind },
    /// Failed to create a temporary directory.
    #[error("Failed to create temporary directory")]
    TempDirCreateError { source: std::io::Error },
    /// Failed to create a particular file.
    #[error("Failed to create new tar file '{}'", path.display())]
    TarCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to read the next chunk in the body stream.
    #[error("Failed to get next chunk in body stream")]
    BodyReadError { source: warp::Error },
    /// Failed to write a chunk to a particular tar file.
    #[error("Failed to write body chunk to tar file '{}'", path.display())]
    TarWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to flush the tarfile handle.
    #[error("Failed to flush new far file '{}'", path.display())]
    TarFlushError { path: PathBuf, source: std::io::Error },
    /// Failed to re-open the downloaded tarfile to extract it.
    #[error("Failed to re-open new tar file '{}'", path.display())]
    TarReopenError { path: PathBuf, source: std::io::Error },
    /// Failed to get the list of entries in the tar file.
    #[error("Failed to get list of entries in tar file '{}'", path.display())]
    TarEntriesError { path: PathBuf, source: std::io::Error },
    /// Failed to get a single entry in the entries of a tar file.
    #[error("Failed to get entry {} in tar file '{}'", entry, path.display())]
    TarEntryError { path: PathBuf, entry: usize, source: std::io::Error },
    /// The given tar file had less entries than we expected.
    #[error("Tar file '{}' has only {} entries, but expected {}", path.display(), expected, got)]
    TarNotEnoughEntries { path: PathBuf, expected: usize, got: usize },
    /// The given tar file had too many entries.
    #[error("Tar file '{}' has more than {} entries", path.display(), expected)]
    TarTooManyEntries { path: PathBuf, expected: usize },
    /// Failed to get the path of an entry.
    #[error("Failed to get the path of entry {} in tar file '{}'", entry, path.display())]
    TarEntryPathError { path: PathBuf, entry: usize, source: std::io::Error },
    /// The given tar file is missing expected entries.
    #[error("Tar file '{}' does not have entries {}", path.display(), PrettyListFormatter::new(expected.iter(), "or"))]
    TarMissingEntries { expected: Vec<&'static str>, path: PathBuf },
    /// Failed to properly close the tar file.
    #[error("Failed to close tar file '{}'", path.display())]
    TarFileCloseError { path: PathBuf },
    /// Failed to unpack the given image file.
    #[error("Failed to extract '{}' file from tar file '{}' to '{}'", file.display(), tarball.display(), target.display())]
    TarFileUnpackError { file: PathBuf, tarball: PathBuf, target: PathBuf, source: std::io::Error },
    /// Failed to read the extracted package info file.
    #[error("Failed to read extracted package info file '{}'", path.display())]
    PackageInfoReadError { path: PathBuf, source: std::io::Error },
    /// Failed to parse the extracted package info file.
    #[error("Failed to parse extracted package info file '{}' as YAML", path.display())]
    PackageInfoParseError { path: PathBuf, source: serde_yaml::Error },
    /// Failed to move the temporary image to its final destination.
    #[error("Failed to move '{}' to '{}'", from.display(), to.display())]
    FileMoveError { from: PathBuf, to: PathBuf, source: std::io::Error },
}
