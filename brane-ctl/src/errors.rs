//  ERRORS.rs
//    by Lut99
//
//  Created:
//    21 Nov 2022, 15:46:26
//  Last edited:
//    07 Feb 2025, 14:25:11
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the errors that may occur in the `brane-ctl` executable.
//

use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
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
#[derive(Debug)]
pub enum DownloadError {
    /// Failed to create a new CACHEDIR.TAG
    CachedirTagCreate { path: PathBuf, err: std::io::Error },
    /// Failed to write to a new CACHEDIR.TAG
    CachedirTagWrite { path: PathBuf, err: std::io::Error },

    /// The given directory does not exist.
    DirNotFound { what: &'static str, path: PathBuf },
    /// The given directory exists but is not a directory.
    DirNotADir { what: &'static str, path: PathBuf },
    /// Could not create a new directory at the given location.
    DirCreateError { what: &'static str, path: PathBuf, err: std::io::Error },

    /// Failed to create a temporary directory.
    TempDirError { err: std::io::Error },
    /// Failed to run the actual download command.
    DownloadError { address: String, path: PathBuf, err: Box<brane_shr::fs::Error> },
    /// Failed to extract the given archive.
    UnarchiveError { tar: PathBuf, target: PathBuf, err: Box<brane_shr::fs::Error> },
    /// Failed to read all entries in a directory.
    ReadDirError { path: PathBuf, err: std::io::Error },
    /// Failed to read a certain entry in a directory.
    ReadEntryError { path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to move something.
    MoveError { source: PathBuf, target: PathBuf, err: Box<brane_shr::fs::Error> },

    /// Failed to connect to local Docker client.
    DockerConnectError { err: brane_tsk::docker::Error },
    /// Failed to pull an image.
    PullError { name: String, image: String, err: brane_tsk::docker::Error },
    /// Failed to save a pulled image.
    SaveError { name: String, image: String, path: PathBuf, err: brane_tsk::docker::Error },
}
impl Display for DownloadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::DownloadError::*;
        match self {
            CachedirTagCreate { path, .. } => write!(f, "Failed to create CACHEDIR.TAG file '{}'", path.display()),
            CachedirTagWrite { path, .. } => write!(f, "Failed to write to CACHEDIR.TAG file '{}'", path.display()),

            DirNotFound { what, path } => write!(f, "{} directory '{}' not found", what.capitalize(), path.display()),
            DirNotADir { what, path } => write!(f, "{} directory '{}' exists but is not a directory", what.capitalize(), path.display()),
            DirCreateError { what, path, .. } => write!(f, "Failed to create {} directory '{}'", what, path.display()),

            TempDirError { .. } => write!(f, "Failed to create a temporary directory"),
            DownloadError { address, path, .. } => write!(f, "Failed to download '{}' to '{}'", address, path.display()),
            UnarchiveError { tar, target, .. } => write!(f, "Failed to unpack '{}' to '{}'", tar.display(), target.display()),
            ReadDirError { path, .. } => write!(f, "Failed to read directory '{}'", path.display()),
            ReadEntryError { path, entry, .. } => write!(f, "Failed to read entry {} in directory '{}'", entry, path.display()),
            MoveError { source, target, .. } => write!(f, "Failed to move '{}' to '{}'", source.display(), target.display()),

            DockerConnectError { .. } => write!(f, "Failed to connect to local Docker daemon"),
            PullError { name, image, .. } => write!(f, "Failed to pull '{image}' as '{name}'"),
            SaveError { name, path, .. } => write!(f, "Failed to save image '{}' to '{}'", name, path.display()),
        }
    }
}
impl Error for DownloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use self::DownloadError::*;
        match self {
            CachedirTagCreate { err, .. } => Some(err),
            CachedirTagWrite { err, .. } => Some(err),

            DirNotFound { .. } => None,
            DirNotADir { .. } => None,
            DirCreateError { err, .. } => Some(err),

            TempDirError { err } => Some(err),
            DownloadError { err, .. } => Some(err),
            UnarchiveError { err, .. } => Some(err),
            ReadDirError { err, .. } => Some(err),
            ReadEntryError { err, .. } => Some(err),
            MoveError { err, .. } => Some(err),

            DockerConnectError { err } => Some(err),
            PullError { err, .. } => Some(err),
            SaveError { err, .. } => Some(err),
        }
    }
}



/// Errors that relate to generating files.
///
/// Note: we box `brane_shr::fs::Error` to avoid the error enum growing too large (see `clippy::result_large_err`).
#[derive(Debug)]
pub enum GenerateError {
    /// Directory not found.
    DirNotFound { path: PathBuf },
    /// Directory found but not as a directory
    DirNotADir { path: PathBuf },
    /// Failed to create a directory.
    DirCreateError { path: PathBuf, err: std::io::Error },

    /// Failed to canonicalize the given path.
    CanonicalizeError { path: PathBuf, err: std::io::Error },

    /// The given file is not a file.
    FileNotAFile { path: PathBuf },
    /// Failed to write to the output file.
    FileWriteError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to serialize & write to the output file.
    FileSerializeError { what: &'static str, path: PathBuf, err: serde_json::Error },
    /// Failed to deserialize & read an input file.
    FileDeserializeError { what: &'static str, path: PathBuf, err: serde_json::Error },
    /// Failed to extract a file.
    ExtractError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to set a file to executable.
    ExecutableError { err: Box<brane_shr::fs::Error> },

    /// Failed to get a file handle's metadata.
    FileMetadataError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to set the permissions of a file.
    FilePermissionsError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// The downloaded file did not have the required checksum.
    FileChecksumError { path: PathBuf, expected: String, got: String },
    /// Failed to serialize a config file.
    ConfigSerializeError { err: serde_json::Error },
    /// Failed to spawn a new job.
    SpawnError { cmd: Command, err: std::io::Error },
    /// A spawned fob failed.
    SpawnFailure { cmd: Command, status: ExitStatus, err: String },
    /// Assertion that the CA certificate exists failed.
    CaCertNotFound { path: PathBuf },
    /// Assertion that the CA certificate is a file failed.
    CaCertNotAFile { path: PathBuf },
    /// Assertion that the CA key exists failed.
    CaKeyNotFound { path: PathBuf },
    /// Assertion that the CA key is a file failed.
    CaKeyNotAFile { path: PathBuf },
    /// Failed to open a new file.
    FileOpenError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to copy one file into another.
    CopyError { source: PathBuf, target: PathBuf, err: std::io::Error },

    /// Failed to create a new file.
    FileCreateError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to write the header to the new file.
    FileHeaderWriteError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to write the main body to the new file.
    FileBodyWriteError { what: &'static str, path: PathBuf, err: brane_cfg::info::YamlError },

    /// The given location is unknown.
    UnknownLocation { loc: String },

    /// Failed to create a temporary directory.
    TempDirError { err: std::io::Error },
    /// Failed to download the repo
    RepoDownloadError { repo: String, target: PathBuf, err: brane_shr::fs::Error },
    /// Failed to unpack the downloaded repo archive
    RepoUnpackError { tar: PathBuf, target: PathBuf, err: brane_shr::fs::Error },
    /// Failed to recurse into the downloaded repo archive's only folder
    RepoRecurseError { target: PathBuf, err: brane_shr::fs::Error },
    /// Failed to find the migrations in the repo.
    MigrationsRetrieve { path: PathBuf, err: diesel_migrations::MigrationError },
    /// Failed to connect to the database file.
    DatabaseCreate { path: PathBuf, err: policy_store::databases::sqlite::DatabaseError },
    /// Failed to apply a set of mitigations.
    MigrationsApply { path: PathBuf, err: Box<dyn 'static + Error> },

    /// A particular combination of policy secret settings was not supported.
    UnsupportedKeyAlgorithm { key_alg: KeyAlgorithm },
    /// Failed to generate a new policy token.
    TokenGenerate { err: specifications::policy::Error },
}
impl Display for GenerateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use GenerateError::*;
        match self {
            DirNotFound { path } => write!(f, "Directory '{}' not found", path.display()),
            DirNotADir { path } => write!(f, "Directory '{}' exists but not as a directory", path.display()),
            DirCreateError { path, .. } => write!(f, "Failed to create directory '{}'", path.display()),

            CanonicalizeError { path, .. } => write!(f, "Failed to canonicalize path '{}'", path.display()),

            FileNotAFile { path } => write!(f, "File '{}' exists but not as a file", path.display()),
            FileWriteError { what, path, .. } => write!(f, "Failed to write to {} file '{}'", what, path.display()),
            FileSerializeError { what, path, .. } => write!(f, "Failed to write JSON to {} file '{}'", what, path.display()),
            FileDeserializeError { what, path, .. } => write!(f, "Failed to read JSON from {} file '{}'", what, path.display()),
            ExtractError { what, path, .. } => write!(f, "Failed to extract embedded {}-binary to '{}'", what, path.display()),
            ExecutableError { .. } => write!(f, "Failed to make file executable"),

            FileMetadataError { what, path, .. } => write!(f, "Failed to get metadata of {} file '{}'", what, path.display()),
            FilePermissionsError { what, path, .. } => write!(f, "Failed to set permissions of {} file '{}'", what, path.display()),
            FileChecksumError { path, .. } => {
                write!(f, "File '{}' had unexpected checksum (might indicate the download is no longer valid)", path.display())
            },
            ConfigSerializeError { .. } => write!(f, "Failed to serialize config"),
            SpawnError { cmd, .. } => write!(f, "Failed to run command '{cmd:?}'"),
            SpawnFailure { cmd, status, err } => write!(
                f,
                "Command '{:?}' failed{}\n\nstderr:\n{}\n\n",
                cmd,
                if let Some(code) = status.code() { format!(" with exit code {code}") } else { String::new() },
                err
            ),
            CaCertNotFound { path } => write!(f, "Certificate authority's certificate '{}' not found", path.display()),
            CaCertNotAFile { path } => write!(f, "Certificate authority's certificate '{}' exists but is not a file", path.display()),
            CaKeyNotFound { path } => write!(f, "Certificate authority's private key '{}' not found", path.display()),
            CaKeyNotAFile { path } => write!(f, "Certificate authority's private key '{}' exists but is not a file", path.display()),
            FileOpenError { what, path, .. } => write!(f, "Failed to open {} file '{}'", what, path.display()),
            CopyError { source, target, .. } => write!(f, "Failed to write '{}' to '{}'", source.display(), target.display()),

            FileCreateError { what, path, .. } => write!(f, "Failed to create new {} file '{what}'", path.display()),
            FileHeaderWriteError { what, path, .. } => write!(f, "Failed to write header to {} file '{what}'", path.display()),
            FileBodyWriteError { what, .. } => write!(f, "Failed to write body to {what} file"),

            UnknownLocation { loc } => write!(f, "Unknown location '{loc}' (did you forget to specify it in the LOCATIONS argument?)"),

            TempDirError { .. } => write!(f, "Failed to create temporary directory in system temp folder"),
            RepoDownloadError { repo, target, .. } => write!(f, "Failed to download repository archive '{}' to '{}'", repo, target.display()),
            RepoUnpackError { tar, target, .. } => write!(f, "Failed to unpack repository archive '{}' to '{}'", tar.display(), target.display()),
            RepoRecurseError { target, .. } => {
                write!(f, "Failed to recurse into only directory of unpacked repository archive '{}'", target.display())
            },
            MigrationsRetrieve { path, .. } => write!(f, "Failed to find Diesel migrations in '{}'", path.display()),
            DatabaseCreate { path, .. } => write!(f, "Failed to create SQLite database '{}'", path.display()),
            MigrationsApply { path, .. } => write!(f, "Failed to apply migrations to SQLite database file '{}'", path.display()),

            UnsupportedKeyAlgorithm { key_alg } => {
                write!(f, "Policy key algorithm {key_alg} is unsupported")
            },
            TokenGenerate { .. } => write!(f, "Failed to generate new policy token"),
        }
    }
}
impl Error for GenerateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use GenerateError::*;
        match self {
            DirNotFound { .. } => None,
            DirNotADir { .. } => None,
            DirCreateError { err, .. } => Some(err),

            CanonicalizeError { err, .. } => Some(err),

            FileNotAFile { .. } => None,
            FileWriteError { err, .. } => Some(err),
            FileSerializeError { err, .. } => Some(err),
            FileDeserializeError { err, .. } => Some(err),
            ExtractError { err, .. } => Some(err),
            ExecutableError { err } => Some(err),

            FileMetadataError { err, .. } => Some(err),
            FilePermissionsError { err, .. } => Some(err),
            FileChecksumError { .. } => None,
            ConfigSerializeError { err } => Some(err),
            SpawnError { err, .. } => Some(err),
            SpawnFailure { .. } => None,
            CaCertNotFound { .. } => None,
            CaCertNotAFile { .. } => None,
            CaKeyNotFound { .. } => None,
            CaKeyNotAFile { .. } => None,
            FileOpenError { err, .. } => Some(err),
            CopyError { err, .. } => Some(err),

            FileCreateError { err, .. } => Some(err),
            FileHeaderWriteError { err, .. } => Some(err),
            FileBodyWriteError { err, .. } => Some(err),

            UnknownLocation { .. } => None,

            TempDirError { err } => Some(err),
            RepoDownloadError { err, .. } => Some(err),
            RepoUnpackError { err, .. } => Some(err),
            RepoRecurseError { err, .. } => Some(err),
            MigrationsRetrieve { err, .. } => Some(err),
            DatabaseCreate { err, .. } => Some(err),
            MigrationsApply { err, .. } => Some(&**err),

            UnsupportedKeyAlgorithm { .. } => None,
            TokenGenerate { err, .. } => Some(err),
        }
    }
}



/// Errors that relate to managing the lifetime of the node.
///
/// Note: we've boxed `Image` and `ImageSource` to reduce the size of the error (and avoid running into `clippy::result_large_err`).
#[derive(Debug)]
pub enum LifetimeError {
    /// Failed to canonicalize the given path.
    CanonicalizeError { path: PathBuf, err: std::io::Error },
    /// Failed to resolve the executable to a list of shell arguments.
    ExeParseError { raw: String },

    /// Failed to verify the given Docker Compose file exists.
    DockerComposeNotFound { path: PathBuf },
    /// Failed to verify the given Docker Compose file is a file.
    DockerComposeNotAFile { path: PathBuf },
    /// Relied on a build-in for a Docker Compose version that is not the default one.
    DockerComposeNotBakedIn { kind: NodeKind, version: Version },
    /// Failed to open a new Docker Compose file.
    DockerComposeCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to write to a Docker Compose file.
    DockerComposeWriteError { path: PathBuf, err: std::io::Error },

    /// Failed to touch the audit log into existance.
    AuditLogCreate { path: PathBuf, err: std::io::Error },

    /// Failed to read the `proxy.yml` file.
    ProxyReadError { err: brane_cfg::info::YamlError },
    /// Failed to open the extra hosts file.
    HostsFileCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to write to the extra hosts file.
    HostsFileWriteError { path: PathBuf, err: serde_yaml::Error },

    /// Failed to get the digest of the given image file.
    ImageDigestError { path: PathBuf, err: brane_tsk::docker::Error },
    /// Failed to load/import the given image.
    ImageLoadError { image: Box<Image>, source: Box<ImageSource>, err: brane_tsk::docker::Error },

    /// The user gave us a proxy service definition, but not a proxy file path.
    MissingProxyPath,
    /// The user gave use a proxy file path, but not a proxy service definition.
    MissingProxyService,

    /// Failed to load the given node config file.
    NodeConfigLoadError { err: brane_cfg::info::YamlError },
    /// Failed to connect to the local Docker daemon.
    DockerConnectError { err: brane_tsk::errors::DockerError },
    /// The given start command (got) did not match the one in the `node.yml` file (expected).
    UnmatchedNodeKind { got: NodeKind, expected: NodeKind },

    /// Failed to launch the given job.
    JobLaunchError { command: Command, err: std::io::Error },
    /// The given job failed.
    JobFailure { command: Command, status: ExitStatus },

    /// Failed to generate a new JWT given the given key.
    TokenGenerate { key: PathBuf, err: specifications::policy::Error },
}
impl Display for LifetimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LifetimeError::*;
        match self {
            CanonicalizeError { path, .. } => write!(f, "Failed to canonicalize path '{}'", path.display()),
            ExeParseError { raw } => write!(f, "Failed to parse '{raw}' as a valid string of bash-arguments"),

            DockerComposeNotFound { path } => write!(f, "Docker Compose file '{}' not found", path.display()),
            DockerComposeNotAFile { path } => write!(f, "Docker Compose file '{}' exists but is not a file", path.display()),
            DockerComposeNotBakedIn { kind, version } => {
                write!(f, "No baked-in {kind} Docker Compose for Brane version v{version} exists (give it yourself using '--file')")
            },
            DockerComposeCreateError { path, .. } => write!(f, "Failed to create Docker Compose file '{}'", path.display()),
            DockerComposeWriteError { path, .. } => write!(f, "Failed to write to Docker Compose file '{}'", path.display()),

            AuditLogCreate { path, .. } => write!(f, "Failed to touch audit log '{}' into existance", path.display()),

            ProxyReadError { .. } => write!(f, "Failed to read proxy config file"),
            HostsFileCreateError { path, .. } => write!(f, "Failed to create extra hosts file '{}'", path.display()),
            HostsFileWriteError { path, .. } => write!(f, "Failed to write to extra hosts file '{}'", path.display()),

            ImageDigestError { path, .. } => write!(f, "Failed to get digest of image {}", style(path.display()).bold()),
            ImageLoadError { image, source, .. } => {
                write!(f, "Failed to load image {} from '{}'", style(image).bold(), style(source).bold())
            },

            MissingProxyPath => write!(
                f,
                "A proxy service specification is given, but not a path to a 'proxy.yml' file. Specify both if you want to host a proxy service in \
                 this node, or none if you want to use an external one."
            ),
            MissingProxyService => write!(
                f,
                "A path to a 'proxy.yml' file is given, but not a proxy service specification. Specify both if you want to host a proxy service in \
                 this node, or none if you want to use an external one."
            ),

            NodeConfigLoadError { .. } => write!(f, "Failed to load node.yml file"),
            DockerConnectError { .. } => write!(f, "Failed to connect to local Docker socket"),
            UnmatchedNodeKind { got, expected } => {
                write!(f, "Got command to start {} node, but 'node.yml' defined a {} node", got.variant(), expected.variant())
            },

            JobLaunchError { command, .. } => write!(f, "Failed to launch command '{command:?}'"),
            JobFailure { command, status } => write!(
                f,
                "Command '{}' failed with exit code {} (see output above)",
                style(format!("{command:?}")).bold(),
                style(status.code().map(|c| c.to_string()).unwrap_or_else(|| "non-zero".into())).bold()
            ),

            TokenGenerate { key, .. } => write!(f, "Failed to generate a JWT from key {:?}", key.display()),
        }
    }
}
impl Error for LifetimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use LifetimeError::*;
        match self {
            CanonicalizeError { err, .. } => Some(err),
            ExeParseError { .. } => None,

            DockerComposeNotFound { .. } => None,
            DockerComposeNotAFile { .. } => None,
            DockerComposeNotBakedIn { .. } => None,
            DockerComposeCreateError { err, .. } => Some(err),
            DockerComposeWriteError { err, .. } => Some(err),

            AuditLogCreate { err, .. } => Some(err),

            ProxyReadError { err } => Some(err),
            HostsFileCreateError { err, .. } => Some(err),
            HostsFileWriteError { err, .. } => Some(err),

            ImageDigestError { err, .. } => Some(err),
            ImageLoadError { err, .. } => Some(err),

            MissingProxyPath => None,
            MissingProxyService => None,

            NodeConfigLoadError { err } => Some(err),
            DockerConnectError { err } => Some(err),
            UnmatchedNodeKind { .. } => None,

            JobLaunchError { err, .. } => Some(err),
            JobFailure { .. } => None,

            TokenGenerate { err, .. } => Some(err),
        }
    }
}



/// Errors that relate to package subcommands.
#[derive(Debug)]
pub enum PackagesError {
    /// Failed to load the given node config file.
    NodeConfigLoadError { err: brane_cfg::info::YamlError },
    /// The given node type is not supported for this operation.
    ///
    /// The `what` should fill in the \<WHAT\> in: "Cannot \<WHAT\> on a ... node"
    UnsupportedNode { what: &'static str, kind: NodeKind },
    /// The given file is not a file.
    FileNotAFile { path: PathBuf },
    /// Failed to parse the given `NAME[:VERSION]` pair.
    IllegalNameVersionPair { raw: String, err: specifications::version::ParseError },
    /// Failed to read the given directory
    DirReadError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to read an entry in the given directory
    DirEntryReadError { what: &'static str, entry: usize, path: PathBuf, err: std::io::Error },
    /// The given `NAME[:VERSION]` pair did not have a candidate.
    UnknownImage { path: PathBuf, name: String, version: Version },
    /// Failed to hash the found image file.
    HashError { err: brane_tsk::docker::Error },
}
impl Display for PackagesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PackagesError::*;
        match self {
            NodeConfigLoadError { err } => write!(f, "Failed to load node.yml file: {err}"),
            UnsupportedNode { what, kind } => write!(f, "Cannot {what} on a {} node", kind.variant()),
            FileNotAFile { path } => write!(f, "Given image path '{}' exists but is not a file", path.display()),
            IllegalNameVersionPair { raw, err } => write!(f, "Failed to parse given image name[:version] pair '{raw}': {err}"),
            DirReadError { what, path, err } => write!(f, "Failed to read {} directory '{}': {}", what, path.display(), err),
            DirEntryReadError { what, entry, path, err } => {
                write!(f, "Failed to read entry {} in {} directory '{}': {}", entry, what, path.display(), err)
            },
            UnknownImage { path, name, version } => write!(f, "No image for package '{}', version {} found in '{}'", name, version, path.display()),
            HashError { err } => write!(f, "Failed to hash image: {err}"),
        }
    }
}
impl Error for PackagesError {}



/// Errors that relate to unpacking files.
#[derive(Debug)]
pub enum UnpackError {
    /// Failed to get the NodeConfig file.
    NodeConfigError { err: brane_cfg::info::YamlError },
    /// Failed to write the given file.
    FileWriteError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to create the target directory.
    TargetDirCreateError { path: PathBuf, err: std::io::Error },
    /// The target directory was not found.
    TargetDirNotFound { path: PathBuf },
    /// The target directory was not a directory.
    TargetDirNotADir { path: PathBuf },
}
impl Display for UnpackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use UnpackError::*;
        match self {
            NodeConfigError { err } => write!(f, "Failed to read node config file: {err} (specify a kind manually using '--kind')"),
            FileWriteError { what, path, err } => write!(f, "Failed to write {} file to '{}': {}", what, path.display(), err),
            TargetDirCreateError { path, err } => write!(f, "Failed to create target directory '{}': {}", path.display(), err),
            TargetDirNotFound { path } => {
                write!(f, "Target directory '{}' not found (you can create it by re-running this command with '-f')", path.display())
            },
            TargetDirNotADir { path } => write!(f, "Target directory '{}' exists but is not a directory", path.display()),
        }
    }
}
impl Error for UnpackError {}



/// Errors that relate to parsing Docker client version numbers.
#[derive(Debug)]
pub enum DockerClientVersionParseError {
    /// Missing a dot in the version number
    MissingDot { raw: String },
    /// The given major version was not a valid usize
    IllegalMajorNumber { raw: String, err: std::num::ParseIntError },
    /// The given major version was not a valid usize
    IllegalMinorNumber { raw: String, err: std::num::ParseIntError },
}
impl Display for DockerClientVersionParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DockerClientVersionParseError::*;
        match self {
            MissingDot { raw } => write!(f, "Missing '.' in Docket client version number '{raw}'"),
            IllegalMajorNumber { raw, err } => write!(f, "'{raw}' is not a valid Docket client version major number: {err}"),
            IllegalMinorNumber { raw, err } => write!(f, "'{raw}' is not a valid Docket client version minor number: {err}"),
        }
    }
}
impl Error for DockerClientVersionParseError {}



/// Errors that relate to parsing InclusiveRanges.
#[derive(Debug)]
pub enum InclusiveRangeParseError {
    /// Did not find the separating dash
    MissingDash { raw: String },
    /// Failed to parse one of the numbers
    NumberParseError { what: &'static str, raw: String, err: Box<dyn Send + Sync + Error> },
    /// The first number is not equal to or higher than the second one
    StartLargerThanEnd { start: String, end: String },
}
impl Display for InclusiveRangeParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use InclusiveRangeParseError::*;
        match self {
            MissingDash { raw } => write!(f, "Missing '-' in range '{raw}'"),
            NumberParseError { what, raw, err } => write!(f, "Failed to parse '{raw}' as a valid {what}: {err}"),
            StartLargerThanEnd { start, end } => write!(f, "Start index '{start}' is larger than end index '{end}'"),
        }
    }
}
impl Error for InclusiveRangeParseError {}



/// Errors that relate to parsing pairs of things.
#[derive(Debug)]
pub enum PairParseError {
    /// Missing an equals in the pair.
    MissingSeparator { separator: char, raw: String },
    /// Failed to parse the given something as a certain other thing
    IllegalSomething { what: &'static str, raw: String, err: Box<dyn Send + Sync + Error> },
}
impl Display for PairParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PairParseError::*;
        match self {
            MissingSeparator { separator, raw } => write!(f, "Missing '{separator}' in location pair '{raw}'"),
            IllegalSomething { what, raw, err } => write!(f, "Failed to parse '{raw}' as a {what}: {err}"),
        }
    }
}
impl Error for PairParseError {}



/// Errors that relate to parsing [`PolicyInputLanguage`](crate::spec::PolicyInputLanguage)s.
#[derive(Debug)]
pub enum PolicyInputLanguageParseError {
    /// The given identifier was not recognized.
    Unknown { raw: String },
}
impl Display for PolicyInputLanguageParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PolicyInputLanguageParseError::*;
        match self {
            Unknown { raw } => write!(f, "Unknown policy input language '{raw}' (options are 'eflint' or 'eflint-json')"),
        }
    }
}
impl Error for PolicyInputLanguageParseError {}



/// Errors that relate to parsing architecture iDs.
#[derive(Debug)]
pub enum ArchParseError {
    /// Failed to spawn the `uname -m` command.
    SpawnError { command: Command, err: std::io::Error },
    /// The `uname -m` command returned a non-zero exit code.
    SpawnFailure { command: Command, status: ExitStatus, err: String },
    /// It's an unknown architecture.
    UnknownArch { raw: String },
}
impl Display for ArchParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ArchParseError::*;
        match self {
            SpawnError { command, err } => write!(f, "Failed to run '{command:?}': {err}"),
            SpawnFailure { command, status, err } => {
                write!(f, "Command '{:?}' failed with exit code {}\n\nstderr:\n{}\n\n", command, status.code().unwrap_or(-1), err)
            },
            UnknownArch { raw } => write!(f, "Unknown architecture '{raw}'"),
        }
    }
}
impl Error for ArchParseError {}



/// Errors that relate to parsing JWT signing algorithm IDs.
#[derive(Debug)]
pub enum JwtAlgorithmParseError {
    /// Unknown identifier given.
    Unknown { raw: String },
}
impl Display for JwtAlgorithmParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use JwtAlgorithmParseError::*;
        match self {
            Unknown { raw } => write!(f, "Unknown JWT algorithm '{raw}' (options are: 'HS256')"),
        }
    }
}
impl Error for JwtAlgorithmParseError {}

/// Errors that relate to parsing key type IDs.
#[derive(Debug)]
pub enum KeyTypeParseError {
    /// Unknown identifier given.
    Unknown { raw: String },
}
impl Display for KeyTypeParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use KeyTypeParseError::*;
        match self {
            Unknown { raw } => write!(f, "Unknown key type '{raw}' (options are: 'oct')"),
        }
    }
}
impl Error for KeyTypeParseError {}

/// Errors that relate to parsing key usage IDs.
#[derive(Debug)]
pub enum KeyUsageParseError {
    /// Unknown identifier given.
    Unknown { raw: String },
}
impl Display for KeyUsageParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use KeyUsageParseError::*;
        match self {
            Unknown { raw } => write!(f, "Unknown key usage '{raw}' (options are: 'sig')"),
        }
    }
}
impl Error for KeyUsageParseError {}
