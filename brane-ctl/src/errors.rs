//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    21 Nov 2022, 15:46:26
//  Last edited:
//    22 Feb 2023, 14:43:26
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

use bollard::ClientVersion;
use console::style;
use enum_debug::EnumDebug as _;

use brane_cfg::node::NodeKind;
use brane_shr::debug::Capitalizeable;
use brane_tsk::docker::ImageSource;
use specifications::container::Image;
use specifications::version::Version;


/***** LIBRARY *****/
/// Errors that relate to downloading stuff (the subcommand, specifically).
#[derive(Debug)]
pub enum DownloadError {
    /// The given directory does not exist.
    DirNotFound{ what: &'static str, path: PathBuf },
    /// The given directory exists but is not a directory.
    DirNotADir{ what: &'static str, path: PathBuf },
    /// Could not create a new directory at the given location.
    DirCreateError{ what: &'static str, path: PathBuf, err: std::io::Error },

    /// Failed to create a temporary directory.
    TempDirError{ err: std::io::Error },
    /// Failed to run the actual download command.
    DownloadError{ address: String, path: PathBuf, err: brane_shr::fs::Error },
    /// Failed to extract the given archive.
    UnarchiveError{ tar: PathBuf, target: PathBuf, err: brane_shr::fs::Error },
    /// Failed to read all entries in a directory.
    ReadDirError{ path: PathBuf, err: std::io::Error },
    /// Failed to read a certain entry in a directory.
    ReadEntryError{ path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to move something.
    MoveError{ source: PathBuf, target: PathBuf, err: brane_shr::fs::Error },

    /// Failed to connect to local Docker client.
    DockerConnectError{ err: brane_tsk::docker::Error },
    /// Failed to pull an image.
    PullError{ name: String, image: String, err: brane_tsk::docker::Error },
    /// Failed to save a pulled image.
    SaveError{ name: String, image: String, path: PathBuf, err: brane_tsk::docker::Error },
}
impl Display for DownloadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::DownloadError::*;
        match self {
            DirNotFound{ what, path }         => write!(f, "{} directory '{}' not found", what.capitalize(), path.display()),
            DirNotADir{ what, path }          => write!(f, "{} directory '{}' exists but is not a directory", what.capitalize(), path.display()),
            DirCreateError{ what, path, err } => write!(f, "Failed to create {} directory '{}': {}", what, path.display(), err),

            TempDirError{ err }                 => write!(f, "Failed to create a temporary directory: {}", err),
            DownloadError{ address, path, err } => write!(f, "Failed to download '{}' to '{}': {}", address, path.display(), err),
            UnarchiveError{ tar, target, err }  => write!(f, "Failed to unpack '{}' to '{}': {}", tar.display(), target.display(), err),
            ReadDirError{ path, err }           => write!(f, "Failed to read directory '{}': {}", path.display(), err),
            ReadEntryError{ path, entry, err }  => write!(f, "Failed to read entry {} in directory '{}': {}", entry, path.display(), err),
            MoveError{ source, target, err }    => write!(f, "Failed to move '{}' to '{}': {}", source.display(), target.display(), err),

            DockerConnectError{ err }        => write!(f, "Failed to connect to local Docker daemon: {}", err),
            PullError{ name, image, err }    => write!(f, "Failed to pull '{}' as '{}': {}", image, name, err),
            SaveError{ name, path, err, .. } => write!(f, "Failed to save image '{}' to '{}': {}", name, path.display(), err),
        }
    }
}
impl Error for DownloadError {}



/// Errors that relate to generating files.
#[derive(Debug)]
pub enum GenerateError {
    /// Directory not found.
    DirNotFound{ path: PathBuf },
    /// Directory found but not as a directory
    DirNotADir{ path: PathBuf },
    /// Failed to create a directory.
    DirCreateError{ path: PathBuf, err: std::io::Error },

    /// Failed to canonicalize the given path.
    CanonicalizeError{ path: PathBuf, err: std::io::Error },

    /// The given file is not a file.
    FileNotAFile{ path: PathBuf },
    /// Failed to write to the output file.
    FileWriteError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to download a file.
    DownloadError{ source: String, target: PathBuf, err: brane_shr::fs::Error },
    /// Failed to set a file to executable.
    ExecutableError{ err: brane_shr::fs::Error },

    /// Failed to get a file handle's metadata.
    FileMetadataError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to set the permissions of a file.
    FilePermissionsError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// The downloaded file did not have the required checksum.
    FileChecksumError{ path: PathBuf, expected: String, got: String },
    /// Failed to serialize a config file.
    ConfigSerializeError{ err: serde_json::Error },
    /// Failed to spawn a new job.
    SpawnError{ cmd: Command, err: std::io::Error },
    /// A spawned fob failed.
    SpawnFailure{ cmd: Command, status: ExitStatus, err: String },
    /// Assertion that the CA certificate exists failed.
    CaCertNotFound{ path: PathBuf },
    /// Assertion that the CA certificate is a file failed.
    CaCertNotAFile{ path: PathBuf },
    /// Assertion that the CA key exists failed.
    CaKeyNotFound{ path: PathBuf },
    /// Assertion that the CA key is a file failed.
    CaKeyNotAFile{ path: PathBuf },
    /// Failed to open a new file.
    FileOpenError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to copy one file into another.
    CopyError{ source: PathBuf, target: PathBuf, err: std::io::Error },

    /// Failed to create a new file.
    FileCreateError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to write the header to the new file.
    FileHeaderWriteError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to write the main body to the new file.
    NodeWriteError{ path: PathBuf, err: brane_cfg::node::Error },

    /// The given location is unknown.
    UnknownLocation{ loc: String },
    /// Failed to write the main body to the new file.
    InfraWriteError{ path: PathBuf, err: brane_cfg::infra::Error },

    /// Failed to write the main body to the new file.
    BackendWriteError{ path: PathBuf, err: brane_cfg::backend::Error },

    /// Failed to write the main body to the new file.
    PolicyWriteError{ path: PathBuf, err: brane_cfg::policies::Error },
}
impl Display for GenerateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use GenerateError::*;
        match self {
            DirNotFound{ path }         => write!(f, "Directory '{}' not found", path.display()),
            DirNotADir{ path }          => write!(f, "Directory '{}' exists but not as a directory", path.display()),
            DirCreateError{ path, err } => write!(f, "Failed to create directory '{}': {}", path.display(), err),

            CanonicalizeError{ path, err } => write!(f, "Failed to canonicalize path '{}': {}", path.display(), err),

            FileNotAFile{ path }                 => write!(f, "File '{}' exists but not as a file", path.display()),
            FileWriteError{ what, path, err }    => write!(f, "Failed to write to {} file '{}': {}", what, path.display(), err),
            DownloadError{ source, target, err } => write!(f, "Failed to download '{}' to '{}': {}", source, target.display(), err),
            ExecutableError{ err }               => write!(f, "Failed to make file executable: {}", err),

            FileMetadataError{ what, path, err }    => write!(f, "Failed to get metadata of {} file '{}': {}", what, path.display(), err),
            FilePermissionsError{ what, path, err } => write!(f, "Failed to set permissions of {} file '{}': {}", what, path.display(), err),
            FileChecksumError{ path, .. }           => write!(f, "File '{}' had unexpected checksum (might indicate the download is no longer valid)", path.display()),
            ConfigSerializeError{ err }             => write!(f, "Failed to serialize config: {}", err),
            SpawnError{ cmd, err }                  => write!(f, "Failed to run command '{:?}': {}", cmd, err),
            SpawnFailure{ cmd, status, err }        => write!(f, "Command '{:?}' failed{}\n\nstderr:\n{}\n\n", cmd, if let Some(code) = status.code() { format!(" with exit code {}", code) } else { String::new() }, err),
            CaCertNotFound{ path }                  => write!(f, "Certificate authority's certificate '{}' not found", path.display()),
            CaCertNotAFile{ path }                  => write!(f, "Certificate authority's certificate '{}' exists but is not a file", path.display()),
            CaKeyNotFound{ path }                   => write!(f, "Certificate authority's private key '{}' not found", path.display()),
            CaKeyNotAFile{ path }                   => write!(f, "Certificate authority's private key '{}' exists but is not a file", path.display()),
            FileOpenError{ what, path, err }        => write!(f, "Failed to open {} file '{}': {}", what, path.display(), err),
            CopyError{ source, target, err }        => write!(f, "Failed to write '{}' to '{}': {}", source.display(), target.display(), err),

            FileCreateError{ what, path, err }      => write!(f, "Failed to create new {} file '{}': {}", what, path.display(), err),
            FileHeaderWriteError{ what, path, err } => write!(f, "Failed to write header to {} file '{}': {}", what, path.display(), err),
            NodeWriteError{ err, .. }               => write!(f, "Failed to write body to node.yml file: {}", err),

            UnknownLocation{ loc }     => write!(f, "Unknown location '{}' (did you forget to specify it in the LOCATIONS argument?)", loc),
            InfraWriteError{ err, .. } => write!(f, "Failed to write body to infra.yml file: {}", err),

            BackendWriteError{ err, .. } => write!(f, "Failed to write body to backend.yml file: {}", err),

            PolicyWriteError{ err, .. } => write!(f, "Failed to write body to policies.yml file: {}", err),
        }
    }
}
impl Error for GenerateError {}



/// Errors that relate to managing the lifetime of the node.
#[derive(Debug)]
pub enum LifetimeError {
    /// Failed to canonicalize the given path.
    CanonicalizeError{ path: PathBuf, err: std::io::Error },
    /// Failed to resolve the executable to a list of shell arguments.
    ExeParseError{ raw: String },

    /// Failed to open the extra hosts file.
    HostsFileCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the extra hosts file.
    HostsFileWriteError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to get the digest of the given image file.
    ImageDigestError{ path: PathBuf, err: brane_tsk::docker::Error },
    /// Failed to load/import the given image.
    ImageLoadError{ image: Image, source: ImageSource, err: brane_tsk::docker::Error },

    /// Failed to load the given node config file.
    NodeConfigLoadError{ err: brane_cfg::node::Error },
    /// Failed to connect to the local Docker daemon.
    DockerConnectError{ socket: PathBuf, version: ClientVersion, err: bollard::errors::Error },
    /// The given start command (got) did not match the one in the `node.yml` file (expected).
    UnmatchedNodeKind{ got: NodeKind, expected: NodeKind },

    /// Failed to launch the given job.
    JobLaunchError{ command: Command, err: std::io::Error },
    /// The given job failed.
    JobFailure{ command: Command, status: ExitStatus },
}
impl Display for LifetimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LifetimeError::*;
        match self {
            CanonicalizeError{ path, err } => write!(f, "Failed to canonicalize path '{}': {}", path.display(), err),
            ExeParseError{ raw }           => write!(f, "Failed to parse '{}' as a valid string of bash-arguments", raw),

            HostsFileCreateError{ path, err } => write!(f, "Failed to create extra hosts file '{}': {}", path.display(), err),
            HostsFileWriteError{ path, err }  => write!(f, "Failed to write to extra hosts file '{}': {}", path.display(), err),
    
            ImageDigestError{ path, err }        => write!(f, "Failed to get digest of image {}: {}", style(path.display()).bold(), err),
            ImageLoadError{ image, source, err } => write!(f, "Failed to load image {} from '{}': {}", style(image).bold(), style(source).bold(), err),

            NodeConfigLoadError{ err }                 => write!(f, "Failed to load node.yml file: {}", err),
            DockerConnectError{ socket, version, err } => write!(f, "Failed to connect to local Docker socket '{}' using API version {}: {}", socket.display(), version, err),
            UnmatchedNodeKind{ got, expected }         => write!(f, "Got command to start {} node, but 'node.yml' defined a {} node", got.variant(), expected.variant()),

            JobLaunchError{ command, err } => write!(f, "Failed to launch command '{:?}': {}", command, err),
            JobFailure{ command, status }  => write!(f, "Command '{}' failed with exit code {} (see output above)", style(format!("{:?}", command)).bold(), style(status.code().map(|c| c.to_string()).unwrap_or_else(|| "non-zero".into())).bold()),
        }
    }
}
impl Error for LifetimeError {}



/// Errors that relate to package subcommands.
#[derive(Debug)]
pub enum PackagesError {
    /// Failed to load the given node config file.
    NodeConfigLoadError{ err: brane_cfg::node::Error },
    /// The given file is not a file.
    FileNotAFile{ path: PathBuf },
    /// Failed to parse the given `NAME[:VERSION]` pair.
    IllegalNameVersionPair{ raw: String, err: specifications::version::ParseError },
    /// Failed to read the given directory
    DirReadError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to read an entry in the given directory
    DirEntryReadError{ what: &'static str, entry: usize, path: PathBuf, err: std::io::Error },
    /// The given `NAME[:VERSION]` pair did not have a candidate.
    UnknownImage{ path: PathBuf, name: String, version: Version },
    /// Failed to hash the found image file.
    HashError{ err: brane_tsk::docker::Error },
}
impl Display for PackagesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PackagesError::*;
        match self {
            NodeConfigLoadError{ err }                  => write!(f, "Failed to load node.yml file: {}", err),
            FileNotAFile{ path }                        => write!(f, "Given image path '{}' exists but is not a file", path.display()),
            IllegalNameVersionPair{ raw, err }          => write!(f, "Failed to parse given image name[:version] pair '{}': {}", raw, err),
            DirReadError{ what, path, err }             => write!(f, "Failed to read {} directory '{}': {}", what, path.display(), err),
            DirEntryReadError{ what, entry, path, err } => write!(f, "Failed to read entry {} in {} directory '{}': {}", entry, what, path.display(), err),
            UnknownImage{ path, name, version }         => write!(f, "No image for package '{}', version {} found in '{}'", name, version, path.display()),
            HashError{ err }                            => write!(f, "Failed to hash image: {}", err),
        }
    }
}
impl Error for PackagesError {}



/// Errors that relate to parsing Docker client version numbers.
#[derive(Debug)]
pub enum DockerClientVersionParseError {
    /// Missing a dot in the version number
    MissingDot{ raw: String },
    /// The given major version was not a valid usize
    IllegalMajorNumber{ raw: String, err: std::num::ParseIntError },
    /// The given major version was not a valid usize
    IllegalMinorNumber{ raw: String, err: std::num::ParseIntError },
}
impl Display for DockerClientVersionParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DockerClientVersionParseError::*;
        match self {
            MissingDot{ raw }              => write!(f, "Missing '.' in Docket client version number '{}'", raw),
            IllegalMajorNumber{ raw, err } => write!(f, "'{}' is not a valid Docket client version major number: {}", raw, err),
            IllegalMinorNumber{ raw, err } => write!(f, "'{}' is not a valid Docket client version minor number: {}", raw, err),
        }
    }
}
impl Error for DockerClientVersionParseError {}



/// Errors that relate to parsing HostnamePairs.
#[derive(Debug)]
pub enum HostnamePairParseError {
    /// Missing a colon in the pair.
    MissingColon{ raw: String },
    /// Failed to parse the given IP as an IPv4 or an IPv6
    IllegalIpAddr{ raw: String, err: std::net::AddrParseError },
}
impl Display for HostnamePairParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use HostnamePairParseError::*;
        match self {
            MissingColon{ raw }       => write!(f, "Missing ':' in hostname/IP pair '{}'", raw),
            IllegalIpAddr{ raw, err } => write!(f, "Failed to parse '{}' as a valid IP address: {}", raw, err),
        }
    }
}
impl Error for HostnamePairParseError {}



/// Errors that relate to parsing LocationPairs.
#[derive(Debug)]
pub enum LocationPairParseError<E> {
    /// Missing an equals in the pair.
    MissingSeparator{ separator: char, raw: String },
    /// Failed to parse the given something as a certain other thing
    IllegalSomething{ what: &'static str, raw: String, err: E },
}
impl<E: Display> Display for LocationPairParseError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LocationPairParseError::*;
        match self {
            MissingSeparator{ separator, raw } => write!(f, "Missing '{}' in location pair '{}'", separator, raw),
            IllegalSomething{ what, raw, err } => write!(f, "Failed to parse '{}' as a {}: {}", raw, what, err),
        }
    }
}
impl<E: Debug + Display> Error for LocationPairParseError<E> {}



/// Errors that relate to parsing architecture iDs.
#[derive(Debug)]
pub enum ArchParseError {
    /// Failed to spawn the `uname -m` command.
    SpawnError{ command: Command, err: std::io::Error },
    /// The `uname -m` command returned a non-zero exit code.
    SpawnFailure{ command: Command, status: ExitStatus, err: String },
    /// It's an unknown architecture.
    UnknownArch{ raw: String },
}
impl Display for ArchParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ArchParseError::*;
        match self {
            SpawnError{ command, err }           => write!(f, "Failed to run '{:?}': {}", command, err),
            SpawnFailure{ command, status, err } => write!(f, "Command '{:?}' failed with exit code {}\n\nstderr:\n{}\n\n", command, status.code().unwrap_or(-1), err),
            UnknownArch{ raw }                   => write!(f, "Unknown architecture '{}'", raw),
        }
    }
}
impl Error for ArchParseError {}
