//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    21 Nov 2022, 15:46:26
//  Last edited:
//    12 Dec 2022, 14:04:03
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
use brane_tsk::docker::ImageSource;
use specifications::container::Image;
use specifications::version::Version;


/***** LIBRARY *****/
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

    /// Failed to create a new file.
    FileCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to write the header to the new file.
    FileHeaderWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to write the main body to the new file.
    NodeWriteError{ path: PathBuf, err: brane_cfg::node::Error },

    /// The given location is unknown.
    UnknownLocation{ loc: String },
    /// Failed to write the main body to the new file.
    InfraWriteError{ path: PathBuf, err: brane_cfg::infra::Error },

    /// Failed to write the main body to the new file.
    CredsWriteError{ path: PathBuf, err: brane_cfg::creds::Error },

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

            FileCreateError{ path, err }      => write!(f, "Failed to create new node.yml file '{}': {}", path.display(), err),
            FileHeaderWriteError{ path, err } => write!(f, "Failed to write header to node.yml file '{}': {}", path.display(), err),
            NodeWriteError{ err, .. }         => write!(f, "Failed to write body to node.yml file: {}", err),

            UnknownLocation{ loc }     => write!(f, "Unknown location '{}' (did you forget to specify it in the LOCATIONS argument?)", loc),
            InfraWriteError{ err, .. } => write!(f, "Failed to write body to infra.yml file: {}", err),

            CredsWriteError{ err, .. } => write!(f, "Failed to write body to creds.yml file: {}", err),

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
