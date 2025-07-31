//  ERRORS.rs
//    by Lut99
//
//  Created:
//    21 Nov 2022, 15:46:26
//  Last edited:
//    01 May 2025, 10:43:15
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the errors that may occur in the `brane-ctl` executable.
//

use std::error::Error;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

use brane_cfg::node::NodeKind;
use brane_shr::formatters::Capitalizeable;
use brane_tsk::docker::ImageSource;
use console::style;
use enum_debug::EnumDebug as _;
use jsonwebtoken::jwk::KeyAlgorithm;
use specifications::container::Image;
use specifications::version::Version;


/***** LIBRARY *****/
/// Errors that relate to downloading stuff (the subcommand, specifically).
///
/// Note: we box `brane_shr::fs::Error` to avoid the error enum growing too large (see `clippy::result_large_err`).
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    /// Failed to create a new CACHEDIR.TAG
    #[error("Failed to create CACHEDIR.TAG file '{}'", path.display())]
    CachedirTagCreate { path: PathBuf, source: std::io::Error },
    /// Failed to write to a new CACHEDIR.TAG
    #[error("Failed to write to CACHEDIR.TAG file '{}'", path.display())]
    CachedirTagWrite { path: PathBuf, source: std::io::Error },

    /// The given directory does not exist.
    #[error("{} directory '{}' not found", what.capitalize(), path.display())]
    DirNotFound { what: &'static str, path: PathBuf },
    /// The given directory exists but is not a directory.
    #[error("{} directory '{}' exists but is not a directory", what.capitalize(), path.display())]
    DirNotADir { what: &'static str, path: PathBuf },
    /// Could not create a new directory at the given location.
    #[error("Failed to create {} directory '{}'", what, path.display())]
    DirCreateError { what: &'static str, path: PathBuf, source: std::io::Error },

    /// Failed to create a temporary directory.
    #[error("Failed to create a temporary directory")]
    TempDirError { source: std::io::Error },
    /// Failed to run the actual download command.
    #[error("Failed to download '{}' to '{}'", address, path.display())]
    DownloadError { address: String, path: PathBuf, source: Box<brane_shr::fs::Error> },
    /// Failed to extract the given archive.
    #[error("Failed to unpack '{}' to '{}'", tar.display(), target.display())]
    UnarchiveError { tar: PathBuf, target: PathBuf, source: Box<brane_shr::fs::Error> },
    /// Failed to read all entries in a directory.
    #[error("Failed to read directory '{}'", path.display())]
    ReadDirError { path: PathBuf, source: std::io::Error },
    /// Failed to read a certain entry in a directory.
    #[error("Failed to read entry {} in directory '{}'", entry, path.display())]
    ReadEntryError { path: PathBuf, entry: usize, source: std::io::Error },
    /// Failed to move something.
    #[error("Failed to move '{}' to '{}'", original.display(), target.display())]
    MoveError { original: PathBuf, target: PathBuf, source: Box<brane_shr::fs::Error> },

    /// Failed to connect to local Docker client.
    #[error("Failed to connect to local Docker daemon")]
    DockerConnectError { source: brane_tsk::docker::Error },
    /// Failed to pull an image.
    #[error("Failed to pull '{image}' as '{name}'")]
    PullError { name: String, image: String, source: brane_tsk::docker::Error },
    /// Failed to save a pulled image.
    #[error("Failed to save image '{}' to '{}'", name, path.display())]
    SaveError { name: String, image: String, path: PathBuf, source: brane_tsk::docker::Error },
}


/// Errors that relate to generating files.
///
/// Note: we box `brane_shr::fs::Error` to avoid the error enum growing too large (see `clippy::result_large_err`).
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    /// Directory not found.
    #[error("Directory '{}' not found", path.display())]
    DirNotFound { path: PathBuf },
    /// Directory found but not as a directory
    #[error("Directory '{}' exists but not as a directory", path.display())]
    DirNotADir { path: PathBuf },
    /// Failed to create a directory.
    #[error("Failed to create directory '{}'", path.display())]
    DirCreateError { path: PathBuf, source: std::io::Error },

    /// Failed to canonicalize the given path.
    #[error("Failed to canonicalize path '{}'", path.display())]
    CanonicalizeError { path: PathBuf, source: std::io::Error },

    /// The given file is not a file.
    #[error("File '{}' exists but not as a file", path.display())]
    FileNotAFile { path: PathBuf },
    /// Failed to write to the output file.
    #[error("Failed to write to {} file '{}'", what, path.display())]
    FileWriteError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to serialize & write to the output file.
    #[error("Failed to write JSON to {} file '{}'", what, path.display())]
    FileSerializeError { what: &'static str, path: PathBuf, source: serde_json::Error },
    /// Failed to deserialize & read an input file.
    #[error("Failed to read JSON from {} file '{}'", what, path.display())]
    FileDeserializeError { what: &'static str, path: PathBuf, source: serde_json::Error },
    /// Failed to extract a file.
    #[error("Failed to extract embedded {}-binary to '{}'", what, path.display())]
    ExtractError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to set a file to executable.
    #[error("Failed to make file executable")]
    ExecutableError { source: Box<brane_shr::fs::Error> },

    /// Failed to get a file handle's metadata.
    #[error("Failed to get metadata of {} file '{}'", what, path.display())]
    FileMetadataError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to set the permissions of a file.
    #[error("Failed to set permissions of {} file '{}'", what, path.display())]
    FilePermissionsError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// The downloaded file did not have the required checksum.
    #[error("File '{}' had unexpected checksum (might indicate the download is no longer valid)", path.display())]
    FileChecksumError { path: PathBuf, expected: String, got: String },
    /// Failed to serialize a config file.
    #[error("Failed to serialize config")]
    ConfigSerializeError { source: serde_json::Error },
    /// Failed to spawn a new job.
    #[error("Failed to run command '{cmd:?}'")]
    SpawnError { cmd: Command, source: std::io::Error },
    /// A spawned fob failed.
    #[error("Command '{cmd:?}' failed{code}\n\nstderr:\n{stderr}\n\n", code = if let Some(code) = status.code() { format!(" with exit code {code}") } else { String::new() })]
    SpawnFailure { cmd: Command, status: ExitStatus, stderr: String },
    /// Assertion that the CA certificate exists failed.
    #[error("Certificate authority's certificate '{}' not found", path.display())]
    CaCertNotFound { path: PathBuf },
    /// Assertion that the CA certificate is a file failed.
    #[error("Certificate authority's certificate '{}' exists but is not a file", path.display())]
    CaCertNotAFile { path: PathBuf },
    /// Assertion that the CA key exists failed.
    #[error("Certificate authority's private key '{}' not found", path.display())]
    CaKeyNotFound { path: PathBuf },
    /// Assertion that the CA key is a file failed.
    #[error("Certificate authority's private key '{}' exists but is not a file", path.display())]
    CaKeyNotAFile { path: PathBuf },
    /// Failed to open a new file.
    #[error("Failed to open {} file '{}'", what, path.display())]
    FileOpenError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to copy one file into another.
    #[error("Failed to write '{}' to '{}'", original.display(), target.display())]
    CopyError { original: PathBuf, target: PathBuf, source: std::io::Error },

    /// Failed to create a new file.
    #[error("Failed to create new {} file '{what}'", path.display())]
    FileCreateError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to write the header to the new file.
    #[error("Failed to write header to {} file '{what}'", path.display())]
    FileHeaderWriteError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to write the main body to the new file.
    #[error("Failed to write body to {what} file")]
    FileBodyWriteError { what: &'static str, path: PathBuf, source: brane_cfg::info::YamlError },

    /// The given location is unknown.
    #[error("Unknown location '{loc}' (did you forget to specify it in the LOCATIONS argument?)")]
    UnknownLocation { loc: String },

    /// Failed to create a temporary directory.
    #[error("Failed to create temporary directory in system temp folder")]
    TempDirError { source: std::io::Error },
    /// Failed to download the repo
    #[error("Failed to download repository archive '{}' to '{}'", repo, target.display())]
    RepoDownloadError { repo: String, target: PathBuf, source: brane_shr::fs::Error },
    /// Failed to unpack the downloaded repo archive
    #[error("Failed to unpack repository archive '{}' to '{}'", tar.display(), target.display())]
    RepoUnpackError { tar: PathBuf, target: PathBuf, source: brane_shr::fs::Error },
    /// Failed to recurse into the downloaded repo archive's only folder
    #[error("Failed to recurse into only directory of unpacked repository archive '{}'", target.display())]
    RepoRecurseError { target: PathBuf, source: brane_shr::fs::Error },
    /// Failed to find the migrations in the repo.
    #[error("Failed to find Diesel migrations in '{}'", path.display())]
    MigrationsRetrieve { path: PathBuf, source: diesel_migrations::MigrationError },
    /// Failed to connect to the database file.
    #[error("Failed to connect to SQLite database file '{}'", path.display())]
    DatabaseCreate { path: PathBuf, source: policy_store::databases::sqlite::DatabaseError },
    /// Failed to apply a set of mitigations.
    #[error("Failed to apply migrations to SQLite database file '{}'", path.display())]
    MigrationsApply { path: PathBuf, source: Box<dyn 'static + Error> },

    /// A particular combination of policy secret settings was not supported.
    #[error("Policy key algorithm {key_alg} is unsupported")]
    UnsupportedKeyAlgorithm { key_alg: KeyAlgorithm },
    /// Failed to generate a new policy token.
    #[error("Failed to generate new policy token")]
    TokenGenerate { source: specifications::policy::Error },
}

/// Errors that relate to managing the lifetime of the node.
///
/// Note: we've boxed `Image` and `ImageSource` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug, thiserror::Error)]
pub enum LifetimeError {
    /// Failed to canonicalize the given path.
    #[error("Failed to canonicalize path '{}'", path.display())]
    CanonicalizeError { path: PathBuf, source: std::io::Error },
    /// Failed to resolve the executable to a list of shell arguments.
    #[error("Failed to parse '{raw}' as a valid string of bash-arguments")]
    ExeParseError { raw: String },

    /// Failed to verify the given Docker Compose file exists.
    #[error("Docker Compose file '{}' not found", path.display())]
    DockerComposeNotFound { path: PathBuf },
    /// Failed to verify the given Docker Compose file is a file.
    #[error("Docker Compose file '{}' exists but is not a file", path.display())]
    DockerComposeNotAFile { path: PathBuf },
    /// Relied on a build-in for a Docker Compose version that is not the default one.
    #[error("No baked-in {kind} Docker Compose for Brane version v{version} exists (give it yourself using '--file')")]
    DockerComposeNotBakedIn { kind: NodeKind, version: Version },
    /// Failed to open a new Docker Compose file.
    #[error("Failed to create Docker Compose file '{}'", path.display())]
    DockerComposeCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to write to a Docker Compose file.
    #[error("Failed to write to Docker Compose file '{}'", path.display())]
    DockerComposeWriteError { path: PathBuf, source: std::io::Error },

    /// Failed to touch the audit log into existance.
    #[error("Failed to touch audit log '{}' into existance", path.display())]
    AuditLogCreate { path: PathBuf, source: std::io::Error },

    /// Failed to read the `proxy.yml` file.
    #[error("Failed to read proxy config file")]
    ProxyReadError { source: brane_cfg::info::YamlError },
    /// Failed to open the extra hosts file.
    #[error("Failed to create extra hosts file '{}'", path.display())]
    HostsFileCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to write to the extra hosts file.
    #[error("Failed to write to extra hosts file '{}'", path.display())]
    HostsFileWriteError { path: PathBuf, source: serde_yaml::Error },

    /// Failed to get the digest of the given image file.
    #[error("Failed to get digest of image {}", style(path.display()).bold())]
    ImageDigestError { path: PathBuf, source: brane_tsk::docker::Error },
    /// Failed to load/import the given image.
    #[error("Failed to load image {} from '{}'", style(image).bold(), style(source).bold())]
    ImageLoadError { image: Box<Image>, image_source: Box<ImageSource>, source: brane_tsk::docker::Error },

    /// The user gave us a proxy service definition, but not a proxy file path.
    #[error(
        "A proxy service specification is given, but not a path to a 'proxy.yml' file. Specify both if you want to host a proxy service in this \
         node, or none if you want to use an external one."
    )]
    MissingProxyPath,
    /// The user gave use a proxy file path, but not a proxy service definition.
    #[error(
        "A path to a 'proxy.yml' file is given, but not a proxy service specification. Specify both if you want to host a proxy service in this \
         node, or none if you want to use an external one."
    )]
    MissingProxyService,

    /// Failed to load the given node config file.
    #[error("Failed to load node.yml file")]
    NodeConfigLoadError { source: brane_cfg::info::YamlError },
    /// Failed to connect to the local Docker daemon.
    #[error("Failed to connect to local Docker socket")]
    DockerConnectError { source: brane_tsk::errors::DockerError },
    /// The given start command (got) did not match the one in the `node.yml` file (expected).
    #[error("Got command to start {} node, but 'node.yml' defined a {} node", got.variant(), expected.variant())]
    UnmatchedNodeKind { got: NodeKind, expected: NodeKind },

    /// Failed to launch the given job.
    #[error("Failed to launch command '{command:?}'")]
    JobLaunchError { command: Command, source: std::io::Error },
    /// The given job failed.
    #[error("Command '{}' failed with exit code {} (see output above)", style(format!("{command:?}")).bold(), style(status.code().map(|c| c.to_string()).unwrap_or_else(|| "non-zero".into())).bold())]
    JobFailure { command: Command, status: ExitStatus },

    /// Failed to generate a new JWT given the given key.
    #[error("Failed to generate a JWT with the given key {key:?}")]
    TokenGenerate { key: PathBuf, source: specifications::policy::Error },
}

/// Errors that relate to package subcommands.
#[derive(Debug, thiserror::Error)]
pub enum PackagesError {
    /// Failed to load the given node config file.
    #[error("Failed to load node.yml file")]
    NodeConfigLoadError { source: brane_cfg::info::YamlError },
    /// The given node type is not supported for this operation.
    /// The `what` should fill in the \<WHAT\> in: "Cannot \<WHAT\> on a ... node"
    #[error("Cannot {what} on a {} node", kind.variant())]
    UnsupportedNode { what: &'static str, kind: NodeKind },
    /// The given file is not a file.
    #[error("Given image path '{}' exists but is not a file", path.display())]
    FileNotAFile { path: PathBuf },
    /// Failed to parse the given `NAME[:VERSION]` pair.
    #[error("Failed to parse given image name[:version] pair '{raw}'")]
    IllegalNameVersionPair { raw: String, source: specifications::version::ParseError },
    /// Failed to read the given directory
    #[error("Failed to read {} directory '{}'", what, path.display())]
    DirReadError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to read an entry in the given directory
    #[error("Failed to read entry {} in {} directory '{}'", entry, what, path.display())]
    DirEntryReadError { what: &'static str, entry: usize, path: PathBuf, source: std::io::Error },
    /// The given `NAME[:VERSION]` pair did not have a candidate.
    #[error("No image for package '{}', version {} found in '{}'", name, version, path.display())]
    UnknownImage { path: PathBuf, name: String, version: Version },
    /// Failed to hash the found image file.
    #[error("Failed to hash image")]
    HashError { source: brane_tsk::docker::Error },
}

/// Errors that relate to unpacking files.
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    /// Failed to get the NodeConfig file.
    #[error("Failed to read node config file (specify a kind manually using '--kind')")]
    NodeConfigError { source: brane_cfg::info::YamlError },
    /// Failed to write the given file.
    #[error("Failed to write {} file to '{}'", what, path.display())]
    FileWriteError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to create the target directory.
    #[error("Failed to create target directory '{}'", path.display())]
    TargetDirCreateError { path: PathBuf, source: std::io::Error },
    /// The target directory was not found.
    #[error("Target directory '{}' not found (you can create it by re-running this command with '-f')", path.display())]
    TargetDirNotFound { path: PathBuf },
    /// The target directory was not a directory.
    #[error("Target directory '{}' exists but is not a directory", path.display())]
    TargetDirNotADir { path: PathBuf },
}

/// Errors that relate to parsing Docker client version numbers.
#[derive(Debug, thiserror::Error)]
pub enum DockerClientVersionParseError {
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

/// Errors that relate to parsing InclusiveRanges.
#[derive(Debug, thiserror::Error)]
pub enum InclusiveRangeParseError {
    /// Did not find the separating dash
    #[error("Missing '-' in range '{raw}'")]
    MissingDash { raw: String },
    /// Failed to parse one of the numbers
    #[error("Failed to parse '{raw}' as a valid {what}")]
    NumberParseError { what: &'static str, raw: String, source: Box<dyn Send + Sync + Error> },
    /// The first number is not equal to or higher than the second one
    #[error("Start index '{start}' is larger than end index '{end}'")]
    StartLargerThanEnd { start: String, end: String },
}

/// Errors that relate to parsing pairs of things.
#[derive(Debug, thiserror::Error)]
pub enum PairParseError {
    /// Missing an equals in the pair.
    #[error("Missing '{separator}' in location pair '{raw}'")]
    MissingSeparator { separator: char, raw: String },
    /// Failed to parse the given something as a certain other thing
    #[error("Failed to parse '{raw}' as a {what}")]
    IllegalSomething { what: &'static str, raw: String, source: Box<dyn Send + Sync + Error> },
}

/// Errors that relate to parsing [`PolicyInputLanguage`](crate::spec::PolicyInputLanguage)s.
#[derive(Debug, thiserror::Error)]
pub enum PolicyInputLanguageParseError {
    /// The given identifier was not recognized.
    #[error("Unknown policy input language '{raw}' (options are 'eflint')")]
    Unknown { raw: String },
}

/// Errors that relate to parsing architecture iDs.
#[derive(Debug, thiserror::Error)]
pub enum ArchParseError {
    /// Failed to spawn the `uname -m` command.
    #[error("Failed to run '{command:?}'")]
    SpawnError { command: Command, source: std::io::Error },
    /// The `uname -m` command returned a non-zero exit code.
    #[error("Command '{command:?}' failed with exit code {code}\n\nstderr:\n{stderr}\n\n", code = status.code().unwrap_or(-1))]
    SpawnFailure { command: Command, status: ExitStatus, stderr: String },
    /// It's an unknown architecture.
    #[error("Unknown architecture '{raw}'")]
    UnknownArch { raw: String },
}

/// Errors that relate to parsing JWT signing algorithm IDs.
#[derive(Debug, thiserror::Error)]
pub enum JwtAlgorithmParseError {
    /// Unknown identifier given.
    #[error("Unknown JWT algorithm '{raw}' (options are: 'HS256')")]
    Unknown { raw: String },
}

/// Errors that relate to parsing key type IDs.
#[derive(Debug, thiserror::Error)]
pub enum KeyTypeParseError {
    /// Unknown identifier given.
    #[error("Unknown key type '{raw}' (options are: 'oct')")]
    Unknown { raw: String },
}

/// Errors that relate to parsing key usage IDs.
#[derive(Debug, thiserror::Error)]
pub enum KeyUsageParseError {
    /// Unknown identifier given.
    #[error("Unknown key usage '{raw}' (options are: 'sig')")]
    Unknown { raw: String },
}
