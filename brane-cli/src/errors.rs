/* ERRORS.rs
 *   by Lut99
 *
 * Created:
 *   17 Feb 2022, 10:27:28
 * Last edited:
 *   23 May 2022, 10:40:28
 * Auto updated?
 *   Yes
 *
 * Description:
 *   File that contains file-spanning error definitions for the brane-cli
 *   package.
**/

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;

use brane_bvm::vm::VmError;
use specifications::package::{PackageInfoError, PackageKindError};
use specifications::container::{ContainerInfoError, LocalContainerInfoError};
use specifications::version::{ParseError as VersionParseError, Version};

use crate::packages::PackageError;


/***** GLOBALS *****/
lazy_static! { static ref CLI_LINE_SEPARATOR: String = (0..80).map(|_| '-').collect::<String>(); }





/***** ERROR ENUMS *****/
/// Collects toplevel and uncategorized errors in the brane-cli package.
#[derive(Debug)]
pub enum CliError {
    // Toplevel errors for the subcommands
    /// Errors that occur during the build command
    BuildError{ err: BuildError },
    /// Errors that occur during the import command
    ImportError{ err: ImportError },
    /// Errors that occur during the repl command
    ReplError{ err: ReplError },
    /// Errors that occur in the version command
    VersionError{ err: VersionError },
    /// Errors that occur in some inter-subcommand utility
    UtilError{ err: UtilError },
    /// Temporary wrapper around any anyhow error
    OtherError{ err: anyhow::Error },

    // A few miscellanous errors occuring in main.rs
    /// Could not resolve the path to the package file
    PackageFileCanonicalizeError{ path: PathBuf, err: std::io::Error },
    /// Could not resolve the path to the context
    WorkdirCanonicalizeError{ path: PathBuf, err: std::io::Error },
    /// Could not resolve a string to a package kind
    IllegalPackageKind{ kind: String, err: PackageKindError },
}

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            CliError::BuildError{ err }   => write!(f, "{}", err),
            CliError::ImportError{ err }  => write!(f, "{}", err),
            CliError::ReplError{ err }    => write!(f, "{}", err),
            CliError::UtilError{ err }    => write!(f, "{}", err),
            CliError::VersionError{ err } => write!(f, "{}", err),
            CliError::OtherError{ err }   => write!(f, "{}", err),

            CliError::PackageFileCanonicalizeError{ path, err } => write!(f, "Could not resolve package file path '{}': {}", path.display(), err),
            CliError::WorkdirCanonicalizeError{ path, err }     => write!(f, "Could not resolve working directory '{}': {}", path.display(), err),
            CliError::IllegalPackageKind{ kind, err }           => write!(f, "Illegal package kind '{}': {}", kind, err),
        }
    }
}

impl Error for CliError {}



/// Collects errors during the build subcommand
#[derive(Debug)]
pub enum BuildError {
    /// Could not open the given container info file
    ContainerInfoOpenError{ file: PathBuf, err: std::io::Error },
    /// Could not read/open the given container info file
    ContainerInfoParseError{ file: PathBuf, err: ContainerInfoError },
    /// Could not create/resolve the package directory
    PackageDirError{ err: UtilError },

    /// Could not read/open the given OAS document
    OasDocumentParseError{ file: PathBuf, err: anyhow::Error },
    /// Could not parse the version in the given OAS document
    VersionParseError{ err: VersionParseError },
    /// Could not properly convert the OpenAPI document into a PackageInfo
    PackageInfoFromOpenAPIError{ err: anyhow::Error },

    /// A lock file exists for the current building package, so wait
    LockFileExists{ path: PathBuf },
    /// Could not create a file lock for system reasons
    LockCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to cleanup the .lock file from the build directory after a successfull build.
    LockCleanupError{ path: PathBuf, err: std::io::Error },

    /// Could not write to the DockerFile string.
    DockerfileStrWriteError{ err: std::fmt::Error },
    /// A given filepath escaped the working directory
    UnsafePath{ path: String },
    /// The entrypoint executable referenced was not found
    MissingExecutable{ path: PathBuf },

    /// Could not create the Dockerfile in the build directory.
    DockerfileCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not write to the Dockerfile in the build directory.
    DockerfileWriteError{ path: PathBuf, err: std::io::Error },
    /// Could not create the container directory
    ContainerDirCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not resolve the custom branelet's path
    BraneletCanonicalizeError{ path: PathBuf, err: std::io::Error },
    /// Could not copy the branelet executable
    BraneletCopyError{ source: PathBuf, target: PathBuf, err: std::io::Error },
    /// Could not clear an existing working directory
    WdClearError{ path: PathBuf, err: std::io::Error },
    /// Could not create a new working directory
    WdCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not write the LocalContainerInfo to the container directory.
    LocalContainerInfoCreateError{ err: LocalContainerInfoError },
    /// Could not canonicalize file's path that will be copied to the working directory
    WdSourceFileCanonicalizeError{ path: PathBuf, err: std::io::Error },
    /// Could not canonicalize a workdir file's path
    WdTargetFileCanonicalizeError{ path: PathBuf, err: std::io::Error },
    /// Could not create a directory in the working directory
    WdDirCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not copy a file to the working directory
    WdFileCopyError{ source: PathBuf, target: PathBuf, err: std::io::Error },
    /// Could not copy a directory to the working directory
    WdDirCopyError{ source: PathBuf, target: PathBuf, err: fs_extra::error::Error },
    /// Could not launch the command to compress the working directory
    WdCompressionLaunchError{ command: String, err: std::io::Error },
    /// Command to compress the working directory returned a non-zero exit code
    WdCompressionError{ command: String, code: i32, stdout: String, stderr: String },

    /// Could not serialize the OPenAPI file
    OpenAPISerializeError{ err: serde_yaml::Error },
    /// COuld not create a new OpenAPI file
    OpenAPIFileCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not write to a new OpenAPI file
    OpenAPIFileWriteError{ path: PathBuf, err: std::io::Error },

    // /// Could not create a file within the package directory
    // PackageFileCreateError{ path: PathBuf, err: std::io::Error },
    // /// Could not write to a file within the package directory
    // PackageFileWriteError{ path: PathBuf, err: std::io::Error },
    // /// Could not serialize the ContainerInfo back to text.
    // ContainerInfoSerializeError{ err: serde_yaml::Error },
    // /// Could not serialize the LocalContainerInfo back to text.
    // LocalContainerInfoSerializeError{ err: serde_yaml::Error },
    // /// Could not serialize the OpenAPI document back to text.
    // OpenAPISerializeError{ err: serde_yaml::Error },
    // /// Could not serialize the PackageInfo.
    // PackageInfoSerializeError{ err: serde_yaml::Error },

    /// Could not launch the command to see if buildkit is installed
    BuildKitLaunchError{ command: String, err: std::io::Error },
    /// The simple command to instantiate/test the BuildKit plugin for Docker returned a non-success
    BuildKitError{ command: String, code: i32, stdout: String, stderr: String },
    /// Could not launch the command to build the package image
    ImageBuildLaunchError{ command: String, err: std::io::Error },
    /// The command to build the image returned a non-zero exit code (we don't accept stdout or stderr here, as the command's output itself will be passed to stdout & stderr)
    ImageBuildError{ command: String, code: i32 },

    /// Could not get the digest from the just-built image
    DigestError{ err: PackageInfoError },
    /// Could not write the PackageFile to the build directory.
    PackageFileCreateError{ err: PackageInfoError },

    // /// Failed to remove an existing build of this package/version from the docker daemon
    // DockerCleanupError{ image: String, err: ExecutorError },
    /// Failed to cleanup a file from the build directory after a successfull build.
    FileCleanupError{ path: PathBuf, err: std::io::Error },
    /// Failed to cleanup a directory from the build directory after a successfull build.
    DirCleanupError{ path: PathBuf, err: std::io::Error },
    /// Failed to cleanup the build directory after a failed build.
    CleanupError{ path: PathBuf, err: std::io::Error },

    /// Could not open the just-build image.tar
    ImageTarOpenError{ path: PathBuf, err: std::io::Error },
    /// Could not get the entries in the image.tar
    ImageTarEntriesError{ path: PathBuf, err: std::io::Error },
    /// Could not parse the extracted manifest file
    ManifestParseError{ path: PathBuf, err: serde_json::Error },
    /// The number of entries in the given manifest is not one (?)
    ManifestNotOneEntry{ path: PathBuf, n: usize },
    /// The path to the config blob (which contains Docker's digest) is invalid
    ManifestInvalidConfigBlob{ path: PathBuf, config: String },
    /// Didn't find any manifest.json in the image.tar
    NoManifest{ path: PathBuf },
    /// Could not create the resulting digest.txt file
    DigestFileCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not write to the resulting digest.txt file
    DigestFileWriteError{ path: PathBuf, err: std::io::Error },

    /// Could not get the host architecture
    HostArchError{ err: specifications::arch::ArchError },
}

impl Display for BuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use BuildError::*;
        match self {
            ContainerInfoOpenError{ file, err }  => write!(f, "Could not open the container info file '{}': {}", file.display(), err),
            ContainerInfoParseError{ file, err } => write!(f, "Could not parse the container info file '{}': {}", file.display(), err),
            PackageDirError{ err }               => write!(f, "Could not create package directory: '{}'", err),

            OasDocumentParseError{ file, err } => write!(f, "Could not parse the OAS Document '{}': {}", file.display(), err),
            VersionParseError{ err }           => write!(f, "Could not parse OAS Document version number: {}", err),
            PackageInfoFromOpenAPIError{ err } => write!(f, "Could not convert the OAS Document into a Package Info file: {}", err),

            LockFileExists{ path }        => write!(f, "The build directory '{}' is busy; try again later (a lock file exists)", path.display()),
            LockCreateError{ path, err }  => write!(f, "Could not create lock file '{}': {}", path.display(), err),
            LockCleanupError{ path, err } => write!(f, "Could not clean the lock file ('{}') from build directory: {}", path.display(), err),

            DockerfileStrWriteError{ err } => write!(f, "Could not write to the internal DockerFile: {}", err),
            UnsafePath{ path }             => write!(f, "File '{}' tries to escape package working directory; consider moving Brane's working directory up (using --workdir) and avoid '..'", path),
            MissingExecutable{ path }      => write!(f, "Could not find the package entrypoint '{}'", path.display()),

            DockerfileCreateError{ path, err }                  => write!(f, "Could not create Dockerfile '{}': {}", path.display(), err),
            DockerfileWriteError{ path, err }                   => write!(f, "Could not write to Dockerfile '{}': {}", path.display(), err),
            ContainerDirCreateError{ path, err }                => write!(f, "Could not create container directory '{}': {}", path.display(), err),
            BraneletCanonicalizeError{ path, err }              => write!(f, "Could not resolve custom init binary path '{}': {}", path.display(), err),
            BraneletCopyError{ source, target, err }            => write!(f, "Could not copy custom init binary from '{}' to '{}': {}", source.display(), target.display(), err),
            WdClearError{ path, err }                           => write!(f, "Could not clear existing package working directory '{}': {}", path.display(), err),
            WdCreateError{ path, err }                          => write!(f, "Could not create package working directory '{}': {}", path.display(), err),
            LocalContainerInfoCreateError{ err }                => write!(f, "Could not write local container info to container directory: {}", err),
            WdSourceFileCanonicalizeError{ path, err }          => write!(f, "Could not resolve file '{}' in the package info file: {}", path.display(), err),
            WdTargetFileCanonicalizeError{ path, err }          => write!(f, "Could not resolve file '{}' in the package working directory: {}", path.display(), err),
            WdDirCreateError{ path, err }                       => write!(f, "Could not create directory '{}' in the package working directory: {}", path.display(), err),
            BuildError::WdFileCopyError{ source, target, err }              => write!(f, "Could not copy file '{}' to '{}' in the package working directory: {}", source.display(), target.display(), err),
            WdDirCopyError{ source, target, err }               => write!(f, "Could not copy directory '{}' to '{}' in the package working directory: {}", source.display(), target.display(), err),
            WdCompressionLaunchError{ command, err }            => write!(f, "Could not run command '{}' to compress working directory: {}", command, err),
            WdCompressionError{ command, code, stdout, stderr } => write!(f, "Command '{}' to compress working directory returned exit code {}:\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n", command, code, *CLI_LINE_SEPARATOR, stdout, *CLI_LINE_SEPARATOR, *CLI_LINE_SEPARATOR, stderr, *CLI_LINE_SEPARATOR),

            OpenAPISerializeError{ err }        => write!(f, "Could not re-serialize OpenAPI document: {}", err),
            OpenAPIFileCreateError{ path, err } => write!(f, "Could not create OpenAPI file '{}': {}", path.display(), err),
            OpenAPIFileWriteError{ path, err }  => write!(f, "Could not write to OpenAPI file '{}': {}", path.display(), err),

            // PackageFileCreateError{ path, err }     => write!(f, "Could not create file '{}' within the package directory: {}", path.display(), err),
            // PackageFileWriteError{ path, err }      => write!(f, "Could not write to file '{}' within the package directory: {}", path.display(), err),
            // ContainerInfoSerializeError{ err }      => write!(f, "Could not re-serialize container.yml: {}", err),
            // LocalContainerInfoSerializeError{ err } => write!(f, "Could not re-serialize container.yml as local_container.yml: {}", err),
            // PackageInfoSerializeError{ err }        => write!(f, "Could not serialize generated package info file: {}", err),

            BuildKitLaunchError{ command, err }            => write!(f, "Could not determine if Docker & BuildKit are installed: failed to run command '{}': {}", command, err),
            BuildKitError{ command, code, stdout, stderr } => write!(f, "Could not run a Docker BuildKit (command '{}' returned exit code {}): is BuildKit installed?\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n", command, code, *CLI_LINE_SEPARATOR, stdout, *CLI_LINE_SEPARATOR, *CLI_LINE_SEPARATOR, stderr,*CLI_LINE_SEPARATOR),
            ImageBuildLaunchError{ command, err }          => write!(f, "Could not run command '{}' to build the package image: {}", command, err),
            ImageBuildError{ command, code }               => write!(f, "Command '{}' to build the package image returned exit code {}", command, code),

            DigestError{ err }            => write!(f, "Could not get Docker image digest: {}", err),
            PackageFileCreateError{ err } => write!(f, "Could not write package info to build directory: {}", err),

            // BuildError::DockerCleanupError{ image, err } => write!(f, "Could not remove existing image '{}' from docker daemon: {}", image, err),
            FileCleanupError{ path, err } => write!(f, "Could not clean file '{}' from build directory: {}", path.display(), err),
            DirCleanupError{ path, err }  => write!(f, "Could not clean directory '{}' from build directory: {}", path.display(), err),
            CleanupError{ path, err }     => write!(f, "Could not clean build directory '{}': {}", path.display(), err),

            ImageTarOpenError{ path, err }            => write!(f, "Could not open the built image.tar ('{}'): {}", path.display(), err),
            ImageTarEntriesError{ path, err }         => write!(f, "Could get entries in the built image.tar ('{}'): {}", path.display(), err),
            ManifestParseError{ path, err }           => write!(f, "Could not parse extracted Docker manifest '{}': {}", path.display(), err),
            ManifestNotOneEntry{ path, n }            => write!(f, "Extracted Docker manifest '{}' has an incorrect number of entries: got {}, expected 1", path.display(), n),
            ManifestInvalidConfigBlob{ path, config } => write!(f, "Extracted Docker manifest '{}' has an incorrect path to the config blob: got {}, expected it to start with 'blobs/sha256/'", path.display(), config),
            NoManifest{ path }                        => write!(f, "Built image.tar ('{}') does not contain a manifest.json", path.display()),
            DigestFileCreateError{ path, err }        => write!(f, "Could not open digest file '{}': {}", path.display(), err),
            DigestFileWriteError{ path, err }         => write!(f, "Could not write to digest file '{}': {}", path.display(), err),

            HostArchError{ err } => write!(f, "Could not get host architecture: {}", err),
        }
    }
}

impl Error for BuildError {}



/// Collects errors during the import subcommand
#[derive(Debug)]
pub enum ImportError {
    /// Error for when we could not create a temporary directory
    TempDirError{ err: std::io::Error },
    /// Could not resolve the path to the temporary repository directory
    TempDirCanonicalizeError{ path: PathBuf, err: std::io::Error },
    /// Error for when we failed to clone a repository
    RepoCloneError{ repo: String, target: PathBuf, err: git2::Error },

    /// Error for when a path supposed to refer inside the repository escaped out of it
    RepoEscapeError{ path: PathBuf },
}

impl Display for ImportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            ImportError::TempDirError{ err }                   => write!(f, "Could not create temporary repository directory: {}", err),
            ImportError::TempDirCanonicalizeError{ path, err } => write!(f, "Could not resolve temporary directory path '{}': {}", path.display(), err),
            ImportError::RepoCloneError{ repo, target, err }   => write!(f, "Could not clone repository at '{}' to directory '{}': {}", repo, target.display(), err),

            ImportError::RepoEscapeError{ path } => write!(f, "Path '{}' points outside of repository folder", path.display()),
        }
    }
}

impl Error for ImportError {}



/// Collects errors during the repl subcommand
#[derive(Debug)]
pub enum ReplError {
    /// Could not create the config directory
    ConfigDirCreateError{ err: UtilError },
    /// Could not get the location of the REPL history file
    HistoryFileError{ err: UtilError },

    /// Could not connect to the given address
    ClientConnectError{ address: String, err: tonic::transport::Error },
    /// Could not create a new session on the given address
    SessionCreateError{ address: String, err: tonic::Status },
    /// Requesting a command failed
    CommandRequestError{ address: String, err: tonic::Status },

    /// Failed to 'read' the local package index
    PackageIndexError{ err: PackageError },
    /// Failed to create the local VM
    VmCreateError{ err: VmError },
}

impl Display for ReplError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            ReplError::ConfigDirCreateError{ err } => write!(f, "Could not create the configuration directory for the REPL history: {}", err),
            ReplError::HistoryFileError{ err }     => write!(f, "Could not get REPL history file location: {}", err),

            ReplError::ClientConnectError{ address, err }  => write!(f, "Could not connect to remote Brane instance '{}': {}", address, err),
            ReplError::SessionCreateError{ address, err }  => write!(f, "Could not create new session with remote Brane instance '{}': remote returned status: {}", address, err),
            ReplError::CommandRequestError{ address, err } => write!(f, "Could not run command on remote Brane instance '{}': request failed: remote returned status: {}", address, err),

            ReplError::PackageIndexError{ err } => write!(f, "Could not read local package index: {}", err),
            ReplError::VmCreateError{ err }     => write!(f, "Could not create local VM: {}", err),
        }
    }
}

impl Error for ReplError {}



/// Collects errors relating to the version command.
#[derive(Debug)]
pub enum VersionError {
    /// Could not get the host architecture
    HostArchError{ err: specifications::arch::ArchError },
    /// Could not parse a Version number.
    VersionParseError{ raw: String, err: specifications::version::ParseError },

    /// Could not get the configuration directory
    ConfigDirError{ err: UtilError },
    /// Could not open the registry file
    RegistryFileError{ err: specifications::registry::RegistryConfigError },
    /// Could not perform the request
    RequestError{ url: String, err: reqwest::Error },
    /// The request returned a non-200 exit code
    RequestFailure{ url: String, status: reqwest::StatusCode },
    /// The request's body could not be get.
    RequestBodyError{ url: String, err: reqwest::Error },
}

impl Display for VersionError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use VersionError::*;
        match self {
            HostArchError{ err }          => write!(f, "Could not get the host processor architecture: {}", err),
            VersionParseError{ raw, err } => write!(f, "Could parse '{}' as Version: {}", raw, err),

            ConfigDirError{ err }         => write!(f, "Could not get the Brane configuration directory: {}", err),
            RegistryFileError{ err }      => write!(f, "{}", err),
            RequestError{ url, err }      => write!(f, "Could not perform request to '{}': {}", url, err),
            RequestFailure{ url, status } => write!(f, "Request to '{}' returned non-zero exit code {} ({})", url, status.as_u16(), status.canonical_reason().unwrap_or("<???>")),
            RequestBodyError{ url, err }  => write!(f, "Could not get body from response from '{}': {}", url, err),
        }
    }
}

impl Error for VersionError {}



/// Collects errors of utilities that don't find an origin in just one subcommand.
#[derive(Debug)]
pub enum UtilError {
    /// Could not connect to the local Docker instance
    DockerConnectionFailed{ err: bollard::errors::Error },
    /// Could not get the version of the Docker daemon
    DockerVersionError{ err: bollard::errors::Error },
    /// The docker daemon returned something, but not the version
    DockerNoVersion,
    /// The version reported by the Docker daemon is not a valid version
    IllegalDockerVersion{ version: String, err: VersionParseError },
    /// Could not launch the command to get the Buildx version
    BuildxLaunchError{ command: String, err: std::io::Error },
    /// The Buildx version in the buildx command does not have at least two parts, separated by spaces
    BuildxVersionNoParts{ version: String },
    /// The Buildx version is not prepended with a 'v'
    BuildxVersionNoV{ version: String },
    /// The version reported by Buildx is not a valid version
    IllegalBuildxVersion{ version: String, err: VersionParseError },

    /// Could not read from a given directory
    DirectoryReadError{ dir: PathBuf, err: std::io::Error },
    /// Could not automatically determine package file inside a directory.
    UndeterminedPackageFile{ dir: PathBuf },

    /// Could not open the main package file of the package to build.
    PackageFileOpenError{ file: PathBuf, err: std::io::Error },
    /// Could not read the main package file of the package to build.
    PackageFileReadError{ file: PathBuf, err: std::io::Error },
    /// Could not automatically determine package kind based on the file.
    UndeterminedPackageKind{ file: PathBuf },

    /// Could not find the user config folder
    UserConfigDirNotFound,
    /// Could not create brane's folder in the config folder
    BraneConfigDirCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not find brane's folder in the config folder
    BraneConfigDirNotFound{ path: PathBuf },

    /// Could not create Brane's history file
    HistoryFileCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not find Brane's history file
    HistoryFileNotFound{ path: PathBuf },

    /// Could not find the user local data folder
    UserLocalDataDirNotFound,
    /// Could not find create brane's folder in the data folder
    BraneDataDirCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not find brane's folder in the data folder
    BraneDataDirNotFound{ path: PathBuf },

    /// Could not find create the package folder inside brane's data folder
    BranePackageDirCreateError{ path: PathBuf, err: std::io::Error },
    /// Could not find the package folder inside brane's data folder
    BranePackageDirNotFound{ path: PathBuf },

    /// Could not create the directory for a package
    PackageDirCreateError{ package: String, path: PathBuf, err: std::io::Error },
    /// The target package directory does not exist
    PackageDirNotFound{ package: String, path: PathBuf },
    /// Could not create a new directory for the given version
    VersionDirCreateError{ package: String, version: Version, path: PathBuf, err: std::io::Error },
    /// The target package/version directory does not exist
    VersionDirNotFound{ package: String, version: Version, path: PathBuf },

    /// There was an error reading entries from a package's directory
    PackageDirReadError{ path: PathBuf, err: std::io::Error },
    /// Found a version entry who's path could not be split into a filename
    UnreadableVersionEntry{ path: PathBuf },
    /// The name of version directory in a package's dir is not a valid version
    IllegalVersionEntry{ package: String, version: String, err: VersionParseError },
    /// The given package has no versions registered to it
    NoVersions{ package: String },
    // /// Could not canonicalize a package/version directory
    // VersionCanonicalizeError{ path: PathBuf, err: std::io::Error },

    /// The given name is not a valid bakery name.
    InvalidBakeryName{ name: String },
}

impl Display for UtilError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            UtilError::DockerConnectionFailed{ err }        => write!(f, "Could not connect to local Docker instance: {}", err),
            UtilError::DockerVersionError{ err }            => write!(f, "Could not get version of the local Docker instance: {}", err),
            UtilError::DockerNoVersion                      => write!(f, "Local Docker instance doesn't report a version number"),
            UtilError::IllegalDockerVersion{ version, err } => write!(f, "Local Docker instance reports unparseable version '{}': {}", version, err),
            UtilError::BuildxLaunchError{ command, err }    => write!(f, "Could not run command '{}' to get Buildx version information: {}", command, err),
            UtilError::BuildxVersionNoParts{ version }      => write!(f, "Illegal Buildx version '{}': did not find second part (separted by spaces) with version number", version),
            UtilError::BuildxVersionNoV{ version }          => write!(f, "Illegal Buildx version '{}': did not find 'v' prepending version number", version),
            UtilError::IllegalBuildxVersion{ version, err } => write!(f, "Buildx reports unparseable version '{}': {}", version, err),

            UtilError::DirectoryReadError{ dir, err } => write!(f, "Could not read from directory '{}': {}", dir.display(), err),
            UtilError::UndeterminedPackageFile{ dir } => write!(f, "Could not determine package file in directory '{}'; specify it manually with '--file'", dir.display()),

            UtilError::PackageFileOpenError{ file, err } => write!(f, "Could not open package file '{}': {}", file.display(), err),
            UtilError::PackageFileReadError{ file, err } => write!(f, "Could not read from package file '{}': {}", file.display(), err),
            UtilError::UndeterminedPackageKind{ file }   => write!(f, "Could not determine package from package file '{}'; specify it manually with '--kind'", file.display()),
    
            UtilError::UserConfigDirNotFound                        => write!(f, "Could not find the user's config directory for your OS (reported as {})", std::env::consts::OS),
            UtilError::BraneConfigDirCreateError{ path, err }       => write!(f, "Could not create Brane config directory '{}': {}", path.display(), err),
            UtilError::BraneConfigDirNotFound{ path }               => write!(f, "Brane config directory '{}' not found", path.display()),

            UtilError::HistoryFileCreateError{ path, err } => write!(f, "Could not create history file '{}' for the REPL: {}", path.display(), err),
            UtilError::HistoryFileNotFound{ path }         => write!(f, "History file '{}' for the REPL does not exist", path.display()),

            UtilError::UserLocalDataDirNotFound                   => write!(f, "Could not find the user's local data directory for your OS (reported as {})", std::env::consts::OS),
            UtilError::BraneDataDirCreateError{ path, err }       => write!(f, "Could not create Brane data directory '{}': {}", path.display(), err),
            UtilError::BraneDataDirNotFound{ path }               => write!(f, "Brane data directory '{}' not found", path.display()),

            UtilError::BranePackageDirCreateError{ path, err } => write!(f, "Could not create Brane package directory '{}': {}", path.display(), err),
            UtilError::BranePackageDirNotFound{ path }         => write!(f, "Brane package directory '{}' not found", path.display()),

            UtilError::PackageDirCreateError{ package, path, err }          => write!(f, "Could not create directory for package '{}' (path: '{}'): {}", package, path.display(), err),
            UtilError::PackageDirNotFound{ package, path }                  => write!(f, "Directory for package '{}' does not exist (path: '{}')", package, path.display()),
            UtilError::VersionDirCreateError{ package, version, path, err } => write!(f, "Could not create directory for package '{}', version: {} (path: '{}'): {}", package, version, path.display(), err),
            UtilError::VersionDirNotFound{ package, version, path }         => write!(f, "Directory for package '{}', version: {} does not exist (path: '{}')", package, version, path.display()),

            UtilError::PackageDirReadError{ path, err }             => write!(f, "Could not read package directory '{}': {}", path.display(), err),
            UtilError::UnreadableVersionEntry{ path }               => write!(f, "Could not get the version directory from '{}'", path.display()),
            UtilError::IllegalVersionEntry{ package, version, err } => write!(f, "Entry '{}' for package '{}' is not a valid version: {}", version, package, err),
            UtilError::NoVersions{ package }                        => write!(f, "Package '{}' does not have any registered versions", package),
            // UtilError::VersionCanonicalizeError{ path, err }        => write!(f, "Could not resolve version directory '{}': {}", path.display(), err),

            UtilError::InvalidBakeryName{ name } => write!(f, "The given name '{}' is not a valid name; expected alphanumeric or underscore characters", name),
        }
    }
}

impl Error for UtilError {}
