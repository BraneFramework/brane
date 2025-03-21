//  ERRORS.rs
//    by Lut99
//
//  Created:
//    17 Feb 2022, 10:27:28
//  Last edited:
//    07 Mar 2024, 14:16:08
//  Auto updated?
//    Yes
//
//  Description:
//!   File that contains file-spanning error definitions for the brane-cli
//

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;

use brane_shr::errors::ErrorTrace as _;
use brane_shr::formatters::{BlockFormatter, PrettyListFormatter};
use reqwest::StatusCode;
use specifications::address::Address;
use specifications::container::{ContainerInfoError, Image, LocalContainerInfoError};
use specifications::package::{PackageInfoError, PackageKindError};
use specifications::version::{ParseError as VersionParseError, Version};


/***** GLOBALS *****/
lazy_static! {
    static ref CLI_LINE_SEPARATOR: String = (0..80).map(|_| '-').collect::<String>();
}





/***** ERROR ENUMS *****/
/// Collects toplevel and uncategorized errors in the brane-cli package.
#[derive(Debug)]
pub enum CliError {
    // Toplevel errors for the subcommands
    /// Errors that occur during the build command
    BuildError { err: BuildError },
    /// Errors that occur when managing certificates.
    CertsError { err: CertsError },
    /// Errors that occur when validating workflow against policy.
    CheckError { err: CheckError },
    /// Errors that occur during any of the data(-related) command(s)
    DataError { err: DataError },
    /// Errors that occur during the import command
    ImportError { err: ImportError },
    /// Errors that occur during identity management.
    InstanceError { err: InstanceError },
    /// Errors that occur during some package command
    PackageError { err: PackageError },
    /// Errors that occur during some registry command
    RegistryError { err: RegistryError },
    /// Errors that occur during the repl command
    ReplError { err: ReplError },
    /// Errors that occur during the run command
    RunError { err: RunError },
    /// Errors that occur in the test command
    TestError { err: TestError },
    /// Errors that occur in the verify command
    VerifyError { err: VerifyError },
    /// Errors that occur in the version command
    VersionError { err: VersionError },
    /// Errors that occur when upgrading old config files.
    UpgradeError { err: crate::upgrade::Error },
    /// Errors that occur in some inter-subcommand utility
    UtilError { err: UtilError },
    /// Temporary wrapper around any anyhow error
    OtherError { err: anyhow::Error },

    // A few miscellanous errors occuring in main.rs
    /// Could not resolve the path to the package file
    PackageFileCanonicalizeError { path: PathBuf, err: std::io::Error },
    /// Could not resolve the path to the context
    WorkdirCanonicalizeError { path: PathBuf, err: std::io::Error },
    /// Could not resolve a string to a package kind
    IllegalPackageKind { kind: String, err: PackageKindError },
    /// Could not parse a NAME:VERSION pair
    PackagePairParseError { raw: String, err: specifications::version::ParseError },
}
impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CliError::*;
        match self {
            BuildError { err } => write!(f, "{err}"),
            CertsError { err } => write!(f, "{err}"),
            CheckError { err } => write!(f, "{err}"),
            DataError { err } => write!(f, "{err}"),
            ImportError { err } => write!(f, "{err}"),
            InstanceError { err } => write!(f, "{err}"),
            PackageError { err } => write!(f, "{err}"),
            RegistryError { err } => write!(f, "{err}"),
            ReplError { err } => write!(f, "{err}"),
            RunError { err } => write!(f, "{err}"),
            TestError { err } => write!(f, "{err}"),
            VerifyError { err } => write!(f, "{err}"),
            VersionError { err } => write!(f, "{err}"),
            UpgradeError { err } => write!(f, "{err}"),
            UtilError { err } => write!(f, "{err}"),
            OtherError { err } => write!(f, "{err}"),

            PackageFileCanonicalizeError { path, .. } => write!(f, "Could not resolve package file path '{}'", path.display()),
            WorkdirCanonicalizeError { path, .. } => write!(f, "Could not resolve working directory '{}'", path.display()),
            IllegalPackageKind { kind, .. } => write!(f, "Illegal package kind '{kind}'"),
            PackagePairParseError { raw, .. } => write!(f, "Could not parse '{raw}'"),
        }
    }
}
impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use CliError::*;
        match self {
            BuildError { err } => err.source(),
            CertsError { err } => err.source(),
            CheckError { err } => err.source(),
            DataError { err } => err.source(),
            ImportError { err } => err.source(),
            InstanceError { err } => err.source(),
            PackageError { err } => err.source(),
            RegistryError { err } => err.source(),
            ReplError { err } => err.source(),
            RunError { err } => err.source(),
            TestError { err } => err.source(),
            VerifyError { err } => err.source(),
            VersionError { err } => err.source(),
            UpgradeError { err } => err.source(),
            UtilError { err } => err.source(),
            OtherError { err } => err.source(),

            PackageFileCanonicalizeError { err, .. } => Some(err),
            WorkdirCanonicalizeError { err, .. } => Some(err),
            IllegalPackageKind { err, .. } => Some(err),
            PackagePairParseError { err, .. } => Some(err),
        }
    }
}



/// Collects errors during the build subcommand
#[derive(Debug)]
pub enum BuildError {
    /// Could not open the given container info file
    ContainerInfoOpenError { file: PathBuf, err: std::io::Error },
    /// Could not read/open the given container info file
    ContainerInfoParseError { file: PathBuf, err: ContainerInfoError },
    /// Could not create/resolve the package directory
    PackageDirError { err: UtilError },

    /// Could not read/open the given OAS document
    OasDocumentParseError { file: PathBuf, err: anyhow::Error },
    /// Could not parse the version in the given OAS document
    VersionParseError { err: VersionParseError },
    /// Could not properly convert the OpenAPI document into a PackageInfo
    PackageInfoFromOpenAPIError { err: anyhow::Error },

    // /// A lock file exists for the current building package, so wait
    // LockFileExists{ path: PathBuf },
    // /// Could not create a file lock for system reasons
    // LockCreateError{ path: PathBuf, err: std::io::Error },
    // /// Failed to cleanup the .lock file from the build directory after a successfull build.
    // LockCleanupError{ path: PathBuf, err: std::io::Error },
    /// Failed to create a LockFile.
    LockCreateError { name: String, err: brane_shr::fs::Error },

    /// Could not write to the DockerFile string.
    DockerfileStrWriteError { err: std::fmt::Error },
    /// A given filepath escaped the working directory
    UnsafePath { path: PathBuf },
    /// The entrypoint executable referenced was not found
    MissingExecutable { path: PathBuf },

    /// Could not create the Dockerfile in the build directory.
    DockerfileCreateError { path: PathBuf, err: std::io::Error },
    /// Could not write to the Dockerfile in the build directory.
    DockerfileWriteError { path: PathBuf, err: std::io::Error },
    /// Could not create the container directory
    ContainerDirCreateError { path: PathBuf, err: std::io::Error },
    /// Could not resolve the custom branelet's path
    BraneletCanonicalizeError { path: PathBuf, err: std::io::Error },
    /// Could not copy the branelet executable
    BraneletCopyError { source: PathBuf, target: PathBuf, err: std::io::Error },
    /// Could not clear an existing working directory
    WdClearError { path: PathBuf, err: std::io::Error },
    /// Could not create a new working directory
    WdCreateError { path: PathBuf, err: std::io::Error },
    /// Could not write the LocalContainerInfo to the container directory.
    LocalContainerInfoCreateError { err: LocalContainerInfoError },
    /// Could not canonicalize file's path that will be copied to the working directory
    WdSourceFileCanonicalizeError { path: PathBuf, err: std::io::Error },
    /// Could not canonicalize a workdir file's path
    WdTargetFileCanonicalizeError { path: PathBuf, err: std::io::Error },
    /// Could not create a directory in the working directory
    WdDirCreateError { path: PathBuf, err: std::io::Error },
    /// Could not copy a file to the working directory
    WdFileCopyError { source: PathBuf, target: PathBuf, err: std::io::Error },
    /// Could not read a directory's entries.
    WdDirReadError { path: PathBuf, err: std::io::Error },
    /// Could not unwrap an entry in a directory.
    WdDirEntryError { path: PathBuf, err: std::io::Error },
    /// Could not rename a file.
    WdFileRenameError { source: PathBuf, target: PathBuf, err: std::io::Error },
    /// Failed to create a new file.
    WdFileCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to open a file.
    WdFileOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to read a file.
    WdFileReadError { path: PathBuf, err: std::io::Error },
    /// Failed to write to a file.
    WdFileWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to remove a file.
    WdFileRemoveError { path: PathBuf, err: std::io::Error },
    /// Could not launch the command to compress the working directory
    WdCompressionLaunchError { command: String, err: std::io::Error },
    /// Command to compress the working directory returned a non-zero exit code
    WdCompressionError { command: String, code: i32, stdout: String, stderr: String },
    /// Failed to ask the user for consent.
    WdConfirmationError { err: dialoguer::Error },

    /// Could not serialize the OPenAPI file
    OpenAPISerializeError { err: serde_yaml::Error },
    /// COuld not create a new OpenAPI file
    OpenAPIFileCreateError { path: PathBuf, err: std::io::Error },
    /// Could not write to a new OpenAPI file
    OpenAPIFileWriteError { path: PathBuf, err: std::io::Error },

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
    BuildKitLaunchError { command: String, err: std::io::Error },
    /// The simple command to instantiate/test the BuildKit plugin for Docker returned a non-success
    BuildKitError { command: String, code: i32, stdout: String, stderr: String },
    /// Could not launch the command to build the package image
    ImageBuildLaunchError { command: String, err: std::io::Error },
    /// The command to build the image returned a non-zero exit code (we don't accept stdout or stderr here, as the command's output itself will be passed to stdout & stderr)
    ImageBuildError { command: String, code: i32 },

    /// Could not get the digest from the just-built image
    DigestError { err: brane_tsk::docker::Error },
    /// Could not write the PackageFile to the build directory.
    PackageFileCreateError { err: PackageInfoError },

    // /// Failed to remove an existing build of this package/version from the docker daemon
    // DockerCleanupError{ image: String, err: ExecutorError },
    /// Failed to cleanup a file from the build directory after a successfull build.
    FileCleanupError { path: PathBuf, err: std::io::Error },
    /// Failed to cleanup a directory from the build directory after a successfull build.
    DirCleanupError { path: PathBuf, err: std::io::Error },
    /// Failed to cleanup the build directory after a failed build.
    CleanupError { path: PathBuf, err: std::io::Error },

    /// Could not open the just-build image.tar
    ImageTarOpenError { path: PathBuf, err: std::io::Error },
    /// Could not get the entries in the image.tar
    ImageTarEntriesError { path: PathBuf, err: std::io::Error },
    /// Could not parse the extracted manifest file
    ManifestParseError { path: PathBuf, err: serde_json::Error },
    /// The number of entries in the given manifest is not one (?)
    ManifestNotOneEntry { path: PathBuf, n: usize },
    /// The path to the config blob (which contains Docker's digest) is invalid
    ManifestInvalidConfigBlob { path: PathBuf, config: String },
    /// Didn't find any manifest.json in the image.tar
    NoManifest { path: PathBuf },
    /// Could not create the resulting digest.txt file
    DigestFileCreateError { path: PathBuf, err: std::io::Error },
    /// Could not write to the resulting digest.txt file
    DigestFileWriteError { path: PathBuf, err: std::io::Error },

    /// Could not get the host architecture
    HostArchError { err: specifications::arch::ArchError },
}
impl Display for BuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use BuildError::*;
        match self {
            ContainerInfoOpenError { file, .. } => write!(f, "Could not open the container info file '{}'", file.display()),
            ContainerInfoParseError { file, .. } => write!(f, "Could not parse the container info file '{}'", file.display()),
            PackageDirError { .. } => write!(f, "Could not create package directory"),

            OasDocumentParseError { file, .. } => write!(f, "Could not parse the OAS Document '{}'", file.display()),
            VersionParseError { .. } => write!(f, "Could not parse OAS Document version number"),
            PackageInfoFromOpenAPIError { .. } => write!(f, "Could not convert the OAS Document into a Package Info file"),

            // LockFileExists{ path }        => write!(f, "The build directory '{}' is busy; try again later (a lock file exists)", path.display()),
            // LockCreateError{ path, .. }  => write!(f, "Could not create lock file '{}'", path.display()),
            // LockCleanupError{ path, .. } => write!(f, "Could not clean the lock file ('{}') from build directory", path.display()),
            LockCreateError { name, .. } => write!(f, "Failed to create lockfile for package '{name}'"),

            DockerfileStrWriteError { .. } => write!(f, "Could not write to the internal DockerFile"),
            UnsafePath { path } => write!(
                f,
                "File '{}' tries to escape package working directory; consider moving Brane's working directory up (using --workdir) and avoid '..'",
                path.display()
            ),
            MissingExecutable { path } => write!(f, "Could not find the package entrypoint '{}'", path.display()),

            DockerfileCreateError { path, .. } => write!(f, "Could not create Dockerfile '{}'", path.display()),
            DockerfileWriteError { path, .. } => write!(f, "Could not write to Dockerfile '{}'", path.display()),
            ContainerDirCreateError { path, .. } => write!(f, "Could not create container directory '{}'", path.display()),
            BraneletCanonicalizeError { path, .. } => write!(f, "Could not resolve custom init binary path '{}'", path.display()),
            BraneletCopyError { source, target, .. } => {
                write!(f, "Could not copy custom init binary from '{}' to '{}'", source.display(), target.display())
            },
            WdClearError { path, .. } => write!(f, "Could not clear existing package working directory '{}'", path.display()),
            WdCreateError { path, .. } => write!(f, "Could not create package working directory '{}'", path.display()),
            LocalContainerInfoCreateError { .. } => write!(f, "Could not write local container info to container directory"),
            WdSourceFileCanonicalizeError { path, .. } => write!(f, "Could not resolve file '{}' in the package info file", path.display()),
            WdTargetFileCanonicalizeError { path, .. } => {
                write!(f, "Could not resolve file '{}' in the package working directory", path.display())
            },
            WdDirCreateError { path, .. } => write!(f, "Could not create directory '{}' in the package working directory", path.display()),
            WdDirEntryError { path, .. } => {
                write!(f, "Could not read entry in directory '{}' in the package working directory", path.display())
            },
            WdDirReadError { path, .. } => write!(f, "Could not read directory '{}' in the package working directory", path.display()),
            WdFileCopyError { source, target, .. } => {
                write!(f, "Could not copy file '{}' to '{}' in the package working directory", source.display(), target.display())
            },
            WdFileRenameError { source, target, .. } => {
                write!(f, "Could not rename file '{}' to '{}' in the package working directory", source.display(), target.display())
            },
            WdFileCreateError { path, .. } => write!(f, "Could not create new file '{}' in the package working directory", path.display()),
            WdFileOpenError { path, .. } => write!(f, "Could not open file '{}' in the package working directory", path.display()),
            WdFileReadError { path, .. } => write!(f, "Could not read from file '{}' in the package working directory", path.display()),
            WdFileWriteError { path, .. } => write!(f, "Could not write to file '{}' in the package working directory", path.display()),
            WdFileRemoveError { path, .. } => write!(f, "Could not remove file '{}' in the package working directory", path.display()),
            WdCompressionLaunchError { command, .. } => write!(f, "Could not run command '{command}' to compress working directory"),
            WdCompressionError { command, code, stdout, stderr } => write!(
                f,
                "Command '{}' to compress working directory returned exit code {}:\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n",
                command, code, *CLI_LINE_SEPARATOR, stdout, *CLI_LINE_SEPARATOR, *CLI_LINE_SEPARATOR, stderr, *CLI_LINE_SEPARATOR
            ),
            WdConfirmationError { .. } => write!(f, "Failed to ask the user (you!) for consent"),

            OpenAPISerializeError { .. } => write!(f, "Could not re-serialize OpenAPI document"),
            OpenAPIFileCreateError { path, .. } => write!(f, "Could not create OpenAPI file '{}'", path.display()),
            OpenAPIFileWriteError { path, .. } => write!(f, "Could not write to OpenAPI file '{}'", path.display()),

            // PackageFileCreateError{ path, .. }     => write!(f, "Could not create file '{}' within the package directory", path.display()),
            // PackageFileWriteError{ path, .. }      => write!(f, "Could not write to file '{}' within the package directory", path.display()),
            // ContainerInfoSerializeError{ .. }      => write!(f, "Could not re-serialize container.yml: {}", err),
            // LocalContainerInfoSerializeError{ .. } => write!(f, "Could not re-serialize container.yml as local_container.yml: {}", err),
            // PackageInfoSerializeError{ .. }        => write!(f, "Could not serialize generated package info file: {}", err),
            BuildKitLaunchError { command, .. } => {
                write!(f, "Could not determine if Docker & BuildKit are installed: failed to run command '{command}'")
            },
            BuildKitError { command, code, stdout, stderr } => write!(
                f,
                "Could not run a Docker BuildKit (command '{}' returned exit code {}): is BuildKit \
                 installed?\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n",
                command, code, *CLI_LINE_SEPARATOR, stdout, *CLI_LINE_SEPARATOR, *CLI_LINE_SEPARATOR, stderr, *CLI_LINE_SEPARATOR
            ),
            ImageBuildLaunchError { command, .. } => write!(f, "Could not run command '{command}' to build the package image"),
            ImageBuildError { command, code } => write!(f, "Command '{command}' to build the package image returned exit code {code}"),

            DigestError { .. } => write!(f, "Could not get Docker image digest"),
            PackageFileCreateError { .. } => write!(f, "Could not write package info to build directory"),

            // BuildError::DockerCleanupError{ image, .. } => write!(f, "Could not remove existing image '{}' from docker daemon", image),
            FileCleanupError { path, .. } => write!(f, "Could not clean file '{}' from build directory", path.display()),
            DirCleanupError { path, .. } => write!(f, "Could not clean directory '{}' from build directory", path.display()),
            CleanupError { path, .. } => write!(f, "Could not clean build directory '{}'", path.display()),

            ImageTarOpenError { path, .. } => write!(f, "Could not open the built image.tar ('{}')", path.display()),
            ImageTarEntriesError { path, .. } => write!(f, "Could get entries in the built image.tar ('{}')", path.display()),
            ManifestParseError { path, .. } => write!(f, "Could not parse extracted Docker manifest '{}'", path.display()),
            ManifestNotOneEntry { path, n } => {
                write!(f, "Extracted Docker manifest '{}' has an incorrect number of entries: got {}, expected 1", path.display(), n)
            },
            ManifestInvalidConfigBlob { path, config } => write!(
                f,
                "Extracted Docker manifest '{}' has an incorrect path to the config blob: got {}, expected it to start with 'blobs/sha256/'",
                path.display(),
                config
            ),
            NoManifest { path } => write!(f, "Built image.tar ('{}') does not contain a manifest.json", path.display()),
            DigestFileCreateError { path, .. } => write!(f, "Could not open digest file '{}'", path.display()),
            DigestFileWriteError { path, .. } => write!(f, "Could not write to digest file '{}'", path.display()),

            HostArchError { .. } => write!(f, "Could not get host architecture"),
        }
    }
}
impl Error for BuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use BuildError::*;
        match self {
            ContainerInfoOpenError { err, .. } => Some(err),
            ContainerInfoParseError { err, .. } => Some(err),
            PackageDirError { err } => Some(err),

            OasDocumentParseError { err, .. } => Some(&**err),
            VersionParseError { err } => Some(err),
            PackageInfoFromOpenAPIError { err } => Some(&**err),

            LockCreateError { err, .. } => Some(err),

            DockerfileStrWriteError { err, .. } => Some(err),
            UnsafePath { .. } => None,
            MissingExecutable { .. } => None,

            DockerfileCreateError { err, .. } => Some(err),
            DockerfileWriteError { err, .. } => Some(err),
            ContainerDirCreateError { err, .. } => Some(err),
            BraneletCanonicalizeError { err, .. } => Some(err),
            BraneletCopyError { err, .. } => Some(err),
            WdClearError { err, .. } => Some(err),
            WdCreateError { err, .. } => Some(err),
            LocalContainerInfoCreateError { err } => Some(err),
            WdSourceFileCanonicalizeError { err, .. } => Some(err),
            WdTargetFileCanonicalizeError { err, .. } => Some(err),
            WdDirCreateError { err, .. } => Some(err),
            WdFileCopyError { err, .. } => Some(err),
            WdDirReadError { err, .. } => Some(err),
            WdDirEntryError { err, .. } => Some(err),
            WdFileRenameError { err, .. } => Some(err),
            WdFileCreateError { err, .. } => Some(err),
            WdFileOpenError { err, .. } => Some(err),
            WdFileReadError { err, .. } => Some(err),
            WdFileWriteError { err, .. } => Some(err),
            WdFileRemoveError { err, .. } => Some(err),
            WdCompressionLaunchError { err, .. } => Some(err),
            WdCompressionError { .. } => None,
            WdConfirmationError { err } => Some(err),

            OpenAPISerializeError { err } => Some(err),
            OpenAPIFileCreateError { err, .. } => Some(err),
            OpenAPIFileWriteError { err, .. } => Some(err),

            BuildKitLaunchError { err, .. } => Some(err),
            BuildKitError { .. } => None,
            ImageBuildLaunchError { err, .. } => Some(err),
            ImageBuildError { .. } => None,

            DigestError { err } => Some(err),
            PackageFileCreateError { err } => Some(err),

            FileCleanupError { err, .. } => Some(err),
            DirCleanupError { err, .. } => Some(err),
            CleanupError { err, .. } => Some(err),

            ImageTarOpenError { err, .. } => Some(err),
            ImageTarEntriesError { err, .. } => Some(err),
            ManifestParseError { err, .. } => Some(err),
            ManifestNotOneEntry { .. } => None,
            ManifestInvalidConfigBlob { .. } => None,
            NoManifest { .. } => None,
            DigestFileCreateError { err, .. } => Some(err),
            DigestFileWriteError { err, .. } => Some(err),

            HostArchError { err } => Some(err),
        }
    }
}



/// Collects errors relating to certificate management.
#[derive(Debug)]
pub enum CertsError {
    /// The active instance file exists but is not a softlink.
    ActiveInstanceNotASoftlinkError { path: PathBuf },

    /// Failed to parse the name in a certificate.
    CertParseError { path: PathBuf, i: usize, err: x509_parser::nom::Err<x509_parser::error::X509Error> },
    /// Failed to get the extensions from the given certificate.
    CertExtensionsError { path: PathBuf, i: usize, err: x509_parser::error::X509Error },
    /// Did not find the key usage extension in the given certificate.
    CertNoKeyUsageError { path: PathBuf, i: usize },
    /// The given certificate had an ambigious key usage flag set.
    CertAmbigiousUsageError { path: PathBuf, i: usize },
    /// The given certificate had no (valid) key usage flag set.
    CertNoUsageError { path: PathBuf, i: usize },
    /// Failed to get the issuer CA string.
    CertIssuerCaError { path: PathBuf, i: usize, err: x509_parser::error::X509Error },

    /// Failed to load instance directory.
    InstanceDirError { err: UtilError },
    /// An unknown instance was given.
    UnknownInstance { name: String },
    /// Failed to read the directory behind the active instance link.
    ActiveInstanceReadError { err: InstanceError },
    /// Failed to get the path behind an instance name.
    InstancePathError { name: String, err: InstanceError },
    /// Did not manage to load (one of) the given PEM files.
    PemLoadError { path: PathBuf, err: brane_cfg::certs::Error },
    /// No CA certificate was provided.
    NoCaCert,
    /// No client certificate was provided.
    NoClientCert,
    /// The no client key was provided.
    NoClientKey,
    /// No domain name found in the certificates.
    NoDomainName,
    /// Failed to ask the user for confirmation.
    ConfirmationError { err: dialoguer::Error },
    /// The given certs directory existed but was not a directory.
    CertsDirNotADir { path: PathBuf },
    /// Failed to remove the certificates directory.
    CertsDirRemoveError { path: PathBuf, err: std::io::Error },
    /// Failed to create the certificates directory.
    CertsDirCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to open the given file in append mode.
    FileOpenError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to write to the given file.
    FileWriteError { what: &'static str, path: PathBuf, err: std::io::Error },

    /// Failed to load instances directory.
    InstancesDirError { err: UtilError },
    /// Failed to read the directory with instances.
    DirReadError { what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to read a specific entry within the directory with instances.
    DirEntryReadError { what: &'static str, path: PathBuf, entry: usize, err: std::io::Error },
}
impl Display for CertsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CertsError::*;
        match self {
            ActiveInstanceNotASoftlinkError { path } => write!(f, "Active instance link '{}' exists but is not a symlink", path.display()),

            CertParseError { path, i, .. } => write!(f, "Failed to parse certificate {} in file '{}'", i, path.display()),
            CertExtensionsError { path, i, .. } => write!(f, "Failed to get extensions in certificate {} in file '{}'", i, path.display()),
            CertNoKeyUsageError { path, i } => {
                write!(f, "Certificate {} in file '{}' does not have key usage defined (extension)", i, path.display())
            },
            CertAmbigiousUsageError { path, i } => {
                write!(f, "Certificate {} in file '{}' has both Digital Signature and CRL Sign flags set (ambigious usage)", i, path.display())
            },
            CertNoUsageError { path, i } => write!(
                f,
                "Certificate {} in file '{}' has neither Digital Signature, nor CRL Sign flags set (cannot determine usage)",
                i,
                path.display()
            ),
            CertIssuerCaError { path, i, .. } => {
                write!(f, "Failed to get the CA field in the issuer field of certificate {} in file '{}'", i, path.display())
            },

            InstanceDirError { .. } => write!(f, "Failed to get instance directory"),
            UnknownInstance { name } => write!(f, "Unknown instance '{name}'"),
            ActiveInstanceReadError { .. } => write!(f, "Failed to read active instance"),
            InstancePathError { name, .. } => write!(f, "Failed to get instance path for instance '{name}'"),
            PemLoadError { path, .. } => write!(f, "Failed to load PEM file '{}'", path.display()),
            NoCaCert => write!(f, "No CA certificate given (specify at least one certificate that has 'CRL Sign' key usage flag set)"),
            NoClientCert => {
                write!(f, "No client certificate given (specify at least one certificate that has 'Digital Signature' key usage flag set)")
            },
            NoClientKey => write!(f, "No client private key given (specify at least one private key)"),
            NoDomainName => write!(f, "Location name not specified in certificates; specify the target location name manually using '--domain'"),
            ConfirmationError { .. } => {
                write!(f, "Failed to ask the user (you!) for confirmation (if you are sure, you can skip this step by using '--force')")
            },
            CertsDirNotADir { path } => write!(f, "Certificate directory '{}' exists but is not a directory", path.display()),
            CertsDirRemoveError { path, .. } => write!(f, "Failed to remove certificate directory '{}'", path.display()),
            CertsDirCreateError { path, .. } => write!(f, "Failed to create certificate directory '{}'", path.display()),
            FileOpenError { what, path, .. } => write!(f, "Failed to open {} file '{}' for appending", what, path.display()),
            FileWriteError { what, path, .. } => write!(f, "Failed to write to {} file '{}'", what, path.display()),

            InstancesDirError { .. } => write!(f, "Failed to get instances directory"),
            DirReadError { what, path, .. } => write!(f, "Failed to read {} directory '{}'", what, path.display()),
            DirEntryReadError { what, path, entry, .. } => {
                write!(f, "Failed to read entry {} in {} directory '{}'", entry, what, path.display())
            },
        }
    }
}
impl Error for CertsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use CertsError::*;
        match self {
            ActiveInstanceNotASoftlinkError { .. } => None,

            CertParseError { err, .. } => Some(err),
            CertExtensionsError { err, .. } => Some(err),
            CertNoKeyUsageError { .. } => None,
            CertAmbigiousUsageError { .. } => None,
            CertNoUsageError { .. } => None,
            CertIssuerCaError { err, .. } => Some(err),

            InstanceDirError { err } => Some(err),
            UnknownInstance { .. } => None,
            ActiveInstanceReadError { err } => Some(err),
            InstancePathError { err, .. } => Some(err),
            PemLoadError { err, .. } => Some(err),
            NoCaCert => None,
            NoClientCert => None,
            NoClientKey => None,
            NoDomainName => None,
            ConfirmationError { err } => Some(err),
            CertsDirNotADir { .. } => None,
            CertsDirRemoveError { err, .. } => Some(err),
            CertsDirCreateError { err, .. } => Some(err),
            FileOpenError { err, .. } => Some(err),
            FileWriteError { err, .. } => Some(err),

            InstancesDirError { err } => Some(err),
            DirReadError { err, .. } => Some(err),
            DirEntryReadError { err, .. } => Some(err),
        }
    }
}



/// Defines errors originating from the `brane check`-subcommand.
#[derive(Debug)]
pub enum CheckError {
    /// Failed to load the active instance info file.
    ActiveInstanceInfoLoad { err: InstanceError },
    /// The compile step from `brane_ast` failed.
    AstCompile { input: String },
    /// Failed to retrieve the data index.
    DataIndexRetrieve { url: String, err: brane_tsk::api::Error },
    /// The Driver failed to check.
    DriverCheck { address: Address, err: tonic::Status },
    /// Failed to connect to the driver.
    DriverConnect { address: Address, err: specifications::driving::DriverServiceError },
    /// Failed to read the input from the given file.
    InputFileRead { path: PathBuf, err: std::io::Error },
    /// Failed to read the input from stdin.
    InputStdinRead { err: std::io::Error },
    /// Failed to retrieve the package index.
    PackageIndexRetrieve { url: String, err: brane_tsk::api::Error },
    /// Failed to compile a given workflow.
    WorkflowCompile { input: String, err: Box<Self> },
    /// Failed to serialize the compiled workflow.
    WorkflowSerialize { input: String, err: serde_json::Error },
}
impl Display for CheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CheckError::*;
        match self {
            ActiveInstanceInfoLoad { .. } => write!(f, "Failed to get currently active instance"),
            AstCompile { input } => write!(f, "Failed to compile workflow '{input}' (see output above)"),
            DataIndexRetrieve { url, .. } => write!(f, "Failed to retrieve data index from '{url}'"),
            DriverCheck { address, .. } => write!(f, "Failed to send CheckRequest to driver '{address}'"),
            DriverConnect { address, .. } => write!(f, "Failed to connect to driver '{address}'"),
            InputFileRead { path, .. } => write!(f, "Failed to read input file '{}'", path.display()),
            InputStdinRead { .. } => write!(f, "Failed to read input from stdin"),
            PackageIndexRetrieve { url, .. } => write!(f, "Failed to retrieve package index from '{url}'"),
            WorkflowCompile { input, .. } => write!(f, "Failed to compile workflow '{input}'"),
            WorkflowSerialize { input, .. } => write!(f, "Failed to serialize workflow '{input}'"),
        }
    }
}
impl Error for CheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use CheckError::*;
        match self {
            ActiveInstanceInfoLoad { err } => Some(err),
            AstCompile { .. } => None,
            DataIndexRetrieve { err, .. } => Some(err),
            DriverCheck { err, .. } => Some(err),
            DriverConnect { err, .. } => Some(err),
            InputFileRead { err, .. } => Some(err),
            InputStdinRead { err } => Some(err),
            PackageIndexRetrieve { err, .. } => Some(err),
            WorkflowCompile { err, .. } => Some(err),
            WorkflowSerialize { err, .. } => Some(err),
        }
    }
}



/// Collects errors during the build subcommand
#[derive(Debug)]
pub enum DataError {
    /// Failed to sent the GET-request to fetch the dfelegate.
    RequestError {
        what:    &'static str,
        address: String,
        err:     reqwest::Error,
    },
    /// The request returned a non-2xx status code.
    RequestFailure {
        address: String,
        code:    StatusCode,
        message: Option<String>,
    },
    /// Failed to get the request body properly.
    ResponseTextError {
        address: String,
        err:     reqwest::Error,
    },
    // /// Failed to load the keypair.
    // KeypairLoadError{ err: brane_cfg::certs::Error },
    // /// Failed to load the certificate root store.
    // StoreLoadError{ err: brane_cfg::certs::Error },
    /// Failed to open/read a given file.
    FileReadError {
        what: &'static str,
        path: PathBuf,
        err:  std::io::Error,
    },
    /// Failed to get the directory of the certificates.
    CertsDirError {
        err: CertsError,
    },
    /// Failed to parse an identity file.
    IdentityFileError {
        path: PathBuf,
        err:  reqwest::Error,
    },
    /// Failed to parse a certificate.
    CertificateError {
        path: PathBuf,
        err:  reqwest::Error,
    },
    /// A directory was not a directory but a file.
    DirNotADirError {
        what: &'static str,
        path: PathBuf,
    },
    /// A directory could not be removed.
    DirRemoveError {
        what: &'static str,
        path: PathBuf,
        err:  std::io::Error,
    },
    /// A directory could not be created.
    DirCreateError {
        what: &'static str,
        path: PathBuf,
        err:  std::io::Error,
    },
    // /// The given certificate file was empty.
    // EmptyCertFile{ path: PathBuf },
    // /// Failed to parse the given key/cert pair as an IdentityFile.
    // IdentityFileError{ certfile: PathBuf, keyfile: PathBuf, err: reqwest::Error },
    // /// Failed to load the given certificate as PEM root certificate.
    // RootError{ cafile: PathBuf, err: reqwest::Error },
    /// Failed to create a temporary directory.
    TempDirError {
        err: std::io::Error,
    },
    /// Failed to create the dataset directory.
    DatasetDirError {
        name: String,
        err:  UtilError,
    },
    /// Failed to create a new reqwest proxy
    ProxyCreateError {
        address: String,
        err:     reqwest::Error,
    },
    /// Failed to create a new reqwest client
    ClientCreateError {
        err: reqwest::Error,
    },
    /// Failed to reach the next chunk of data.
    DownloadStreamError {
        address: String,
        err:     reqwest::Error,
    },
    /// Failed to create the file to which we write the download stream.
    TarCreateError {
        path: PathBuf,
        err:  std::io::Error,
    },
    // /// Failed to (re-)open the file to which we've written the download stream.
    // TarOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    TarWriteError {
        path: PathBuf,
        err:  std::io::Error,
    },
    /// Failed to extract the downloaded tar.
    TarExtractError {
        err: brane_shr::fs::Error,
    },

    /// Failed to get the datasets folder
    DatasetsError {
        err: UtilError,
    },
    /// Failed to fetch the local data index.
    LocalDataIndexError {
        err: brane_tsk::local::Error,
    },

    /// Failed to load the given AssetInfo file.
    AssetFileError {
        path: PathBuf,
        err:  specifications::data::AssetInfoError,
    },
    /// Could not canonicalize the given (relative) path.
    FileCanonicalizeError {
        path: PathBuf,
        err:  std::io::Error,
    },
    /// The given file does not exist
    FileNotFoundError {
        path: PathBuf,
    },
    /// The given file is not a file
    FileNotAFileError {
        path: PathBuf,
    },
    /// Failed to create the dataset's directory.
    DatasetDirCreateError {
        err: UtilError,
    },
    /// A dataset with the given name already exists.
    DuplicateDatasetError {
        name: String,
    },
    /// Failed to copy the data directory over.
    DataCopyError {
        err: brane_shr::fs::Error,
    },
    /// Failed to write the DataInfo.
    DataInfoWriteError {
        err: specifications::data::DataInfoError,
    },

    /// The given "keypair" was not a keypair at all
    NoEqualsInKeyPair {
        raw: String,
    },
    /// Failed to fetch the login file.
    InstanceInfoError {
        err: InstanceError,
    },
    /// Failed to get the path of the active instance.
    ActiveInstanceReadError {
        err: InstanceError,
    },
    /// Failed to get the active instance.
    InstancePathError {
        name: String,
        err:  InstanceError,
    },
    /// Failed to create the remote data index.
    RemoteDataIndexError {
        address: String,
        err:     brane_tsk::errors::ApiError,
    },
    /// Failed to select the download location in case there are multiple.
    DataSelectError {
        err: dialoguer::Error,
    },
    /// We encountered a location we did not know
    UnknownLocation {
        name: String,
    },

    /// The given dataset was unknown to us.
    UnknownDataset {
        name: String,
    },
    /// the given dataset was known but not locally available.
    UnavailableDataset {
        name: String,
        locs: Vec<String>,
    },

    // /// Failed to ensure the directory of the given dataset.
    // DatasetDirError{ err: UtilError },
    /// Failed to ask the user for consent before removing the dataset.
    ConfirmationError {
        err: dialoguer::Error,
    },
    /// Failed to remove the dataset's directory
    RemoveError {
        path: PathBuf,
        err:  std::io::Error,
    },
    WorkflowSerializeError {
        context: String,
        err:     serde_json::Error,
    },
}
impl Display for DataError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DataError::*;
        match self {
            RequestError { what, address, .. } => write!(f, "Failed to send {what} request to '{address}'"),
            RequestFailure { address, code, message } => write!(
                f,
                "Request to '{}' failed with status code {} ({}){}",
                address,
                code,
                code.canonical_reason().unwrap_or("???"),
                if let Some(msg) = message { format!(": {msg}") } else { String::new() }
            ),
            ResponseTextError { address, .. } => write!(f, "Failed to get body from response sent by '{address}' as text"),
            // KeypairLoadError{ .. }                          => write!(f, "Failed to load keypair: {}", err),
            // StoreLoadError{ .. }                            => write!(f, "Failed to load root store: {}", err),
            FileReadError { what, path, .. } => write!(f, "Failed to read {} file '{}'", what, path.display()),
            CertsDirError { .. } => write!(f, "Failed to get certificates directory for active instance"),
            IdentityFileError { path, .. } => write!(f, "Failed to parse identity file '{}'", path.display()),
            CertificateError { path, .. } => write!(f, "Failed to parse certificate '{}'", path.display()),
            DirNotADirError { what, path } => write!(f, "{} directory '{}' is not a directory", what, path.display()),
            DirRemoveError { what, path, .. } => write!(f, "Failed to remove {} directory '{}'", what, path.display()),
            DirCreateError { what, path, .. } => write!(f, "Failed to create {} directory '{}'", what, path.display()),
            // EmptyCertFile{ path }                            => write!(f, "No certificates found in certificate file '{}'", path.display()),
            // IdentityFileError{ certfile, keyfile, .. }      => write!(f, "Failed to parse '{}' and '{}' as a single Identity", certfile.display(), keyfile.display()),
            // RootError{ cafile, .. }                         => write!(f, "Failed to parse '{}' as a root certificate", cafile.display()),
            TempDirError { .. } => write!(f, "Failed to create temporary directory"),
            DatasetDirError { name, .. } => write!(f, "Failed to create dataset directory for dataset '{name}'"),
            ProxyCreateError { address, .. } => write!(f, "Failed to create new proxy to '{address}'"),
            ClientCreateError { .. } => write!(f, "Failed to create new client"),
            DownloadStreamError { address, .. } => write!(f, "Failed to get next chunk in download stream from '{address}'"),
            TarCreateError { path, .. } => write!(f, "Failed to create tarball file '{}'", path.display()),
            // TarOpenError{ path, .. }                => write!(f, "Failed to re-open tarball file '{}'", path.display()),
            TarWriteError { path, .. } => write!(f, "Failed to write to tarball file '{}'", path.display()),
            TarExtractError { .. } => write!(f, "Failed to extract downloaded archive"),

            DatasetsError { .. } => write!(f, "Failed to get datasets folder"),
            LocalDataIndexError { .. } => write!(f, "Failed to get local data index"),

            AssetFileError { path, .. } => write!(f, "Failed to load given asset file '{}'", path.display()),
            FileCanonicalizeError { path, .. } => write!(f, "Failed to resolve path '{}'", path.display()),
            FileNotFoundError { path } => write!(f, "Referenced file '{}' not found (are you using the correct working directory?)", path.display()),
            FileNotAFileError { path } => write!(f, "Referenced file '{}' is not a file", path.display()),
            DatasetDirCreateError { .. } => write!(f, "Failed to create target dataset directory in the Brane data folder"),
            DuplicateDatasetError { name } => write!(f, "A dataset with the name '{name}' already exists locally"),
            DataCopyError { .. } => write!(f, "Failed to data directory"),
            DataInfoWriteError { .. } => write!(f, "Failed to write DataInfo file"),

            NoEqualsInKeyPair { raw } => write!(f, "Missing '=' in key/value pair '{raw}'"),
            InstanceInfoError { .. } => write!(f, "Could not read active instance info file"),
            ActiveInstanceReadError { .. } => write!(f, "Failed to read active instance link"),
            InstancePathError { name, .. } => write!(f, "Could not get path of instance '{name}'"),
            RemoteDataIndexError { address, .. } => write!(f, "Failed to fetch remote data index from '{address}'"),
            DataSelectError { .. } => write!(f, "Failed to ask the user (you!) to select a download location"),
            UnknownLocation { name } => write!(f, "Unknown location '{name}'"),

            UnknownDataset { name } => write!(f, "Unknown dataset '{name}'"),
            UnavailableDataset { name, locs } => write!(
                f,
                "Dataset '{}' is unavailable{}",
                name,
                if !locs.is_empty() {
                    format!("; try {} instead", locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", "))
                } else {
                    String::new()
                }
            ),

            // DatasetDirError{ .. }   => write!(f, "Failed to get to-be-removed dataset directory: {}", err),
            ConfirmationError { .. } => write!(f, "Failed to ask the user (you) for confirmation before removing a dataset"),
            RemoveError { path, .. } => write!(f, "Failed to remove dataset directory '{}'", path.display()),
            WorkflowSerializeError { context, .. } => write!(f, "Could not serialize workflow when: {context}"),
        }
    }
}
impl Error for DataError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use DataError::*;
        match self {
            RequestError { err, .. } => Some(err),
            RequestFailure { .. } => None,
            ResponseTextError { err, .. } => Some(err),
            // KeypairLoadError{ .. } => None,
            // StoreLoadError{ .. } => None,
            FileReadError { err, .. } => Some(err),
            CertsDirError { .. } => None,
            IdentityFileError { err, .. } => Some(err),
            CertificateError { err, .. } => Some(err),
            DirNotADirError { .. } => None,
            DirRemoveError { err, .. } => Some(err),
            DirCreateError { err, .. } => Some(err),
            // EmptyCertFile{ .. } => None,
            // IdentityFileError{ err, .. } => Some(err),
            // RootError{ err, .. } => Some(err),
            TempDirError { .. } => None,
            DatasetDirError { err, .. } => Some(err),
            ProxyCreateError { err, .. } => Some(err),
            ClientCreateError { .. } => None,
            DownloadStreamError { err, .. } => Some(err),
            TarCreateError { err, .. } => Some(err),
            // TarOpenError{ err, .. } => Some(err),
            TarWriteError { err, .. } => Some(err),
            // TarExtractError{ err, .. } => Some(err),
            TarExtractError { err, .. } => Some(err),

            DatasetsError { .. } => None,
            LocalDataIndexError { .. } => None,

            AssetFileError { err, .. } => Some(err),
            FileCanonicalizeError { err, .. } => Some(err),
            FileNotFoundError { .. } => None,
            FileNotAFileError { .. } => None,
            DatasetDirCreateError { .. } => None,
            DuplicateDatasetError { .. } => None,
            DataCopyError { .. } => None,
            DataInfoWriteError { .. } => None,

            NoEqualsInKeyPair { .. } => None,
            InstanceInfoError { .. } => None,
            ActiveInstanceReadError { .. } => None,
            InstancePathError { err, .. } => Some(err),
            RemoteDataIndexError { err, .. } => Some(err),
            DataSelectError { .. } => None,
            UnknownLocation { .. } => None,

            UnknownDataset { .. } => None,
            UnavailableDataset { .. } => None,

            // DatasetDirError{ .. } => None,
            ConfirmationError { .. } => None,
            RemoveError { err, .. } => Some(err),
            WorkflowSerializeError { err, .. } => Some(err),
        }
    }
}



/// Collects errors during the import subcommand
#[derive(Debug)]
pub enum ImportError {
    /// Error for when we could not create a temporary directory
    TempDirError { err: std::io::Error },
    /// Could not resolve the path to the temporary repository directory
    TempDirCanonicalizeError { path: PathBuf, err: std::io::Error },
    /// Error for when we failed to download a repository
    RepoCloneError { repo: String, target: PathBuf, err: brane_shr::fs::Error },

    /// Error for when a path supposed to refer inside the repository escaped out of it
    RepoEscapeError { path: PathBuf },
}
impl Display for ImportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ImportError::*;
        match self {
            TempDirError { .. } => write!(f, "Could not create temporary repository directory"),
            TempDirCanonicalizeError { path, .. } => {
                write!(f, "Could not resolve temporary directory path '{}'", path.display())
            },
            RepoCloneError { repo, target, .. } => {
                write!(f, "Could not clone repository at '{}' to directory '{}'", repo, target.display())
            },

            RepoEscapeError { path } => write!(f, "Path '{}' points outside of repository folder", path.display()),
        }
    }
}
impl Error for ImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ImportError::*;
        match self {
            TempDirError { err, .. } => Some(err),
            TempDirCanonicalizeError { err, .. } => Some(err),
            RepoCloneError { err, .. } => Some(err),

            RepoEscapeError { .. } => None,
        }
    }
}



/// Collects errors  during the identity-related subcommands (login, logout).
#[derive(Debug)]
pub enum InstanceError {
    /// Failed to get the directory of a specific instance.
    InstanceDirError { err: UtilError },
    /// Failed to open a file to load an InstanceInfo.
    InstanceInfoOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to read a file to load an InstanceInfo.
    InstanceInfoReadError { path: PathBuf, err: std::io::Error },
    /// Failed to parse the file to load an InstanceInfo.
    InstanceInfoParseError { path: PathBuf, err: serde_yaml::Error },
    /// Failed to (re-)serialize an InstanceInfo.
    InstanceInfoSerializeError { err: serde_yaml::Error },
    /// Failed to create a new file to write an InstanceInfo to.
    InstanceInfoCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to write an InstanceInfo the given file.
    InstanceInfoWriteError { path: PathBuf, err: std::io::Error },

    /// The given instance name is invalid.
    IllegalInstanceName { raw: String, illegal_char: char },
    /// Failed to parse an address from the hostname (and a little modification).
    AddressParseError { err: specifications::address::AddressError },
    /// Failed to send a request to the remote instance.
    RequestError { address: String, err: reqwest::Error },
    /// The remote instance was not alive (at least, API/health was not)
    InstanceNotAliveError { address: String, code: StatusCode, err: Option<String> },

    /// Failed to ask the user for confirmation.
    ConfirmationError { err: dialoguer::Error },

    /// Failed to get the instances directory.
    InstancesDirError { err: UtilError },
    /// Failed to read the instances directory.
    InstancesDirReadError { path: PathBuf, err: std::io::Error },
    /// Failed to read an entry in the instances directory.
    InstancesDirEntryReadError { path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to get the actual directory behind the active instance link.
    ActiveInstanceTargetError { path: PathBuf, err: std::io::Error },

    /// The given instance is unknown to us.
    UnknownInstance { name: String },
    /// The given instance exists but is not a directory.
    InstanceNotADirError { path: PathBuf },
    /// Failed to get the path of the active instance link.
    ActiveInstancePathError { err: UtilError },
    /// The active instance file exists but is not a softlink.
    ActiveInstanceNotAFileError { path: PathBuf },
    /// Failed to read the active instance link file.
    ActiveInstanceReadError { path: PathBuf, err: std::io::Error },
    /// Failed to remove an already existing active instance link.
    ActiveInstanceRemoveError { path: PathBuf, err: std::io::Error },
    /// Failed to create a new active instance link.
    ActiveInstanceCreateError { path: PathBuf, target: String, err: std::io::Error },

    /// No instance is active
    NoActiveInstance,
}
impl Display for InstanceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use InstanceError::*;
        match self {
            InstanceDirError { .. } => write!(f, "Failed to get directory for instance"),
            InstanceInfoOpenError { path, .. } => write!(f, "Failed to open instance info file '{}'", path.display()),
            InstanceInfoReadError { path, .. } => write!(f, "Failed to read instance info file '{}'", path.display()),
            InstanceInfoParseError { path, .. } => write!(f, "Failed to parse instance info file '{}' as valid YAML", path.display()),
            InstanceInfoSerializeError { .. } => write!(f, "Failed to serialize instance info struct"),
            InstanceInfoCreateError { path, .. } => write!(f, "Failed to create new info instance file '{}'", path.display()),
            InstanceInfoWriteError { path, .. } => write!(f, "Failed to write to instance info file '{}'", path.display()),

            IllegalInstanceName { raw, illegal_char } => {
                write!(f, "Instance name '{raw}' contains illegal character '{illegal_char}' (use '--name' to override it with a custom one)")
            },
            AddressParseError { .. } => write!(f, "Failed to convert hostname to a valid address"),
            RequestError { address, .. } => write!(
                f,
                "Failed to send request to the instance API at '{address}' (if this is something on your end, you may skip this check by providing \
                 '--unchecked')"
            ),
            InstanceNotAliveError { address, code, err } => write!(
                f,
                "Remote instance at '{}' is not alive (returned {} ({}){})",
                address,
                code,
                code.canonical_reason().unwrap_or("???"),
                if let Some(err) = err { format!("\n\nResponse:\n{}\n", BlockFormatter::new(err)) } else { String::new() }
            ),

            ConfirmationError { .. } => {
                write!(f, "Failed to ask the user (you!) for confirmation (if you are sure, you can skip this step by using '--force')")
            },

            InstancesDirError { .. } => write!(f, "Failed to get the instances directory"),
            InstancesDirReadError { path, .. } => write!(f, "Failed to read instances directory '{}'", path.display()),
            InstancesDirEntryReadError { path, entry, .. } => {
                write!(f, "Failed to read instances directory '{}' entry {}", path.display(), entry)
            },
            ActiveInstanceTargetError { path, .. } => write!(f, "Failed to get target of active instance link '{}'", path.display()),

            UnknownInstance { name } => write!(f, "Unknown instance '{name}'"),
            InstanceNotADirError { path } => write!(f, "Instance directory '{}' exists but is not a directory", path.display()),
            ActiveInstancePathError { .. } => write!(f, "Failed to get active instance link path"),
            ActiveInstanceNotAFileError { path } => write!(f, "Active instance link '{}' exists but is not a file", path.display()),
            ActiveInstanceReadError { path, .. } => write!(f, "Failed to read active instance link '{}'", path.display()),
            ActiveInstanceRemoveError { path, .. } => write!(f, "Failed to remove existing active instance link '{}'", path.display()),
            ActiveInstanceCreateError { path, target, .. } => {
                write!(f, "Failed to create active instance link '{}' to '{}'", path.display(), target)
            },

            NoActiveInstance => write!(f, "No active instance is set (run 'brane instance select' first)"),
        }
    }
}
impl Error for InstanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use InstanceError::*;
        match self {
            InstanceDirError { err, .. } => Some(err),
            InstanceInfoOpenError { err, .. } => Some(err),
            InstanceInfoReadError { err, .. } => Some(err),
            InstanceInfoParseError { err, .. } => Some(err),
            InstanceInfoSerializeError { err, .. } => Some(err),
            InstanceInfoCreateError { err, .. } => Some(err),
            InstanceInfoWriteError { err, .. } => Some(err),

            IllegalInstanceName { .. } => None,
            AddressParseError { err, .. } => Some(err),
            RequestError { err, .. } => Some(err),
            InstanceNotAliveError { .. } => None,

            ConfirmationError { err, .. } => Some(err),

            InstancesDirError { err, .. } => Some(err),
            InstancesDirReadError { err, .. } => Some(err),
            InstancesDirEntryReadError { err, .. } => Some(err),
            ActiveInstanceTargetError { err, .. } => Some(err),

            UnknownInstance { .. } => None,
            InstanceNotADirError { .. } => None,
            ActiveInstancePathError { err, .. } => Some(err),
            ActiveInstanceNotAFileError { .. } => None,
            ActiveInstanceReadError { err, .. } => Some(err),
            ActiveInstanceRemoveError { err, .. } => Some(err),
            ActiveInstanceCreateError { err, .. } => Some(err),

            NoActiveInstance => None,
        }
    }
}



/// Lists the errors that can occur when trying to do stuff with packages
///
/// Note: `Image` is boxed to avoid the error enum growing too large (see `clippy::reslt_large_err`).
#[derive(Debug)]
pub enum PackageError {
    /// Something went wrong while calling utilities
    UtilError { err: UtilError },
    /// Something went wrong when fetching an index.
    IndexError { err: brane_tsk::local::Error },

    /// Failed to resolve a specific package/version pair
    PackageVersionError { name: String, version: Version, err: UtilError },
    /// Failed to resolve a specific package
    PackageError { name: String, err: UtilError },
    /// Failed to ask for the user's consent
    ConsentError { err: dialoguer::Error },
    /// Failed to remove a package directory
    PackageRemoveError { name: String, version: Version, dir: PathBuf, err: std::io::Error },
    /// Failed to get the versions of a package
    VersionsError { name: String, dir: PathBuf, err: std::io::Error },
    /// Failed to parse the version of a package
    VersionParseError { name: String, raw: String, err: specifications::version::ParseError },
    /// Failed to load the PackageInfo of the given package
    PackageInfoError { path: PathBuf, err: specifications::package::PackageInfoError },
    /// The given PackageInfo has no digest set
    PackageInfoNoDigest { path: PathBuf },
    /// Could not remove the given image from the Docker daemon
    DockerRemoveError { image: Box<Image>, err: brane_tsk::errors::DockerError },
}
impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::PackageError::*;
        match self {
            UtilError { err } => write!(f, "{}", err.trace()),
            IndexError { .. } => write!(f, "Failed to fetch a local package index"),

            PackageVersionError { name, version, .. } => write!(f, "Package '{name}' does not exist or has no version {version}"),
            PackageError { name, .. } => write!(f, "Package '{name}' does not exist"),
            ConsentError { .. } => write!(f, "Failed to ask for your consent"),
            PackageRemoveError { name, version, dir, .. } => {
                write!(f, "Failed to remove package '{}' (version {}) at '{}'", name, version, dir.display())
            },
            VersionsError { name, dir, .. } => write!(f, "Failed to get versions of package '{}' (at '{}')", name, dir.display()),
            VersionParseError { name, raw, .. } => write!(f, "Could not parse '{raw}' as a version for package '{name}'"),
            PackageInfoError { path, .. } => write!(f, "Could not load package info file '{}'", path.display()),
            PackageInfoNoDigest { path } => write!(f, "Package info file '{}' has no digest set", path.display()),
            DockerRemoveError { image, .. } => {
                write!(f, "Failed to remove image '{}' from the local Docker daemon", image.digest().unwrap_or("<no digest given>"))
            },
        }
    }
}
impl std::error::Error for PackageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use self::PackageError::*;
        match self {
            UtilError { .. } => None,
            IndexError { err } => Some(err),

            PackageVersionError { err, .. } => Some(err),
            PackageError { err, .. } => Some(err),
            ConsentError { err } => Some(err),
            PackageRemoveError { err, .. } => Some(err),
            VersionsError { err, .. } => Some(err),
            VersionParseError { err, .. } => Some(err),
            PackageInfoError { err, .. } => Some(err),
            PackageInfoNoDigest { .. } => None,
            DockerRemoveError { err, .. } => Some(err),
        }
    }
}



/// Collects errors during the registry subcommands
#[derive(Debug)]
pub enum RegistryError {
    /// Wrapper error indeed.
    InstanceInfoError { err: InstanceError },

    /// Failed to successfully send the package pull request
    PullRequestError { url: String, err: reqwest::Error },
    /// The request was sent successfully, but the server replied with a non-200 access code
    PullRequestFailure { url: String, status: reqwest::StatusCode },
    /// The request did not have a content length specified
    MissingContentLength { url: String },
    /// Failed to convert the content length from raw bytes to string
    ContentLengthStrError { url: String, err: reqwest::header::ToStrError },
    /// Failed to parse the content length as a number
    ContentLengthParseError { url: String, raw: String, err: std::num::ParseIntError },
    /// Failed to download the actual package
    PackageDownloadError { url: String, err: reqwest::Error },
    /// Failed to write the downloaded package to the given file
    PackageWriteError { url: String, path: PathBuf, err: std::io::Error },
    /// Failed to create the package directory
    PackageDirCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to copy the downloaded package over
    PackageCopyError { source: PathBuf, target: PathBuf, err: std::io::Error },
    /// Failed to send GraphQL request for package info
    GraphQLRequestError { url: String, err: reqwest::Error },
    /// Failed to receive GraphQL response with package info
    GraphQLResponseError { url: String, err: reqwest::Error },
    /// Could not parse the kind as a proper PackageInfo kind
    KindParseError { url: String, raw: String, err: specifications::package::PackageKindError },
    /// Could not parse the version as a proper PackageInfo version
    VersionParseError { url: String, raw: String, err: specifications::version::ParseError },
    /// Could not parse the list of requirements of the package.
    RequirementParseError { url: String, raw: String, err: serde_json::Error },
    /// Could not parse the functions as proper PackageInfo functions
    FunctionsParseError { url: String, raw: String, err: serde_json::Error },
    /// Could not parse the types as proper PackageInfo types
    TypesParseError { url: String, raw: String, err: serde_json::Error },
    /// Could not create a file for the PackageInfo
    PackageInfoCreateError { path: PathBuf, err: std::io::Error },
    /// Could not write the PackageInfo
    PackageInfoWriteError { path: PathBuf, err: serde_yaml::Error },
    /// Failed to retrieve the PackageInfo
    NoPackageInfo { url: String },

    /// Failed to resolve the packages directory
    PackagesDirError { err: UtilError },
    /// Failed to get all versions for the given package
    VersionsError { name: String, err: brane_tsk::local::Error },
    /// Failed to resolve the directory of a specific package
    PackageDirError { name: String, version: Version, err: UtilError },
    /// Could not create a new temporary file
    TempFileError { err: std::io::Error },
    /// Could not compress the package file
    CompressionError { name: String, version: Version, path: PathBuf, err: std::io::Error },
    /// Failed to re-open the compressed package file
    PackageArchiveOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to upload the compressed file to the instance
    UploadError { path: PathBuf, endpoint: String, err: reqwest::Error },
}
impl Display for RegistryError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use RegistryError::*;
        match self {
            InstanceInfoError { err } => write!(f, "{err}"),

            PullRequestError { url, err } => write!(f, "Could not send the request to pull pacakge to '{url}': {err}"),
            PullRequestFailure { url, status } => write!(
                f,
                "Request to pull package from '{}' was met with status code {} ({})",
                url,
                status.as_u16(),
                status.canonical_reason().unwrap_or("???")
            ),
            MissingContentLength { url } => write!(f, "Response from '{url}' did not have 'Content-Length' header set"),
            ContentLengthStrError { url, err } => write!(f, "Could not convert content length received from '{url}' to string: {err}"),
            ContentLengthParseError { url, raw, err } => {
                write!(f, "Could not parse '{raw}' as a number (the content-length received from '{url}'): {err}")
            },
            PackageDownloadError { url, err } => write!(f, "Could not download package from '{url}': {err}"),
            PackageWriteError { url, path, err } => write!(f, "Could not write package downloaded from '{}' to '{}': {}", url, path.display(), err),
            PackageDirCreateError { path, err } => write!(f, "Could not create package directory '{}': {}", path.display(), err),
            PackageCopyError { source, target, err } => {
                write!(f, "Could not copy package from '{}' to '{}': {}", source.display(), target.display(), err)
            },
            GraphQLRequestError { url, err } => write!(f, "Could not send a GraphQL request to '{url}': {err}"),
            GraphQLResponseError { url, err } => write!(f, "Could not get the GraphQL respones from '{url}': {err}"),
            KindParseError { url, raw, err } => write!(f, "Could not parse '{raw}' (received from '{url}') as package kind: {err}"),
            VersionParseError { url, raw, err } => write!(f, "Could not parse '{raw}' (received from '{url}') as package version: {err}"),
            RequirementParseError { url, raw, err } => write!(f, "Could not parse '{raw}' (received from '{url}') as package requirement: {err}"),
            FunctionsParseError { url, raw, err } => write!(f, "Could not parse '{raw}' (received from '{url}') as package functions: {err}"),
            TypesParseError { url, raw, err } => write!(f, "Could not parse '{raw}' (received from '{url}') as package types: {err}"),
            PackageInfoCreateError { path, err } => write!(f, "Could not create PackageInfo file '{}': {}", path.display(), err),
            PackageInfoWriteError { path, err } => write!(f, "Could not write to PackageInfo file '{}': {}", path.display(), err),
            NoPackageInfo { url } => write!(f, "Server '{url}' responded with empty response (is your name/version correct?)"),

            PackagesDirError { err } => write!(f, "Could not resolve the packages directory: {err}"),
            VersionsError { name, err } => write!(f, "Could not get version list for package '{name}': {err}"),
            PackageDirError { name, version, err } => write!(f, "Could not resolve package directory of package '{name}' (version {version}): {err}"),
            TempFileError { err } => write!(f, "Could not create a new temporary file: {err}"),
            CompressionError { name, version, path, err } => {
                write!(f, "Could not compress package '{}' (version {}) to '{}': {}", name, version, path.display(), err)
            },
            PackageArchiveOpenError { path, err } => write!(f, "Could not re-open compressed package archive '{}': {}", path.display(), err),
            UploadError { path, endpoint, err } => {
                write!(f, "Could not upload compressed package archive '{}' to '{}': {}", path.display(), endpoint, err)
            },
        }
    }
}
impl Error for RegistryError {}



/// Collects errors during the repl subcommand
#[derive(Debug)]
pub enum ReplError {
    /// Could not create the config directory
    ConfigDirCreateError { err: UtilError },
    /// Could not get the location of the REPL history file
    HistoryFileError { err: UtilError },
    /// Failed to create the new rustyline editor.
    EditorCreateError { err: rustyline::error::ReadlineError },
    /// Failed to load the login file.
    InstanceInfoError { err: InstanceError },

    /// Failed to initialize one of the states.
    InitializeError { what: &'static str, err: RunError },
    /// Failed to run one of the VMs/clients.
    RunError { what: &'static str, err: RunError },
    /// Failed to process the VM result.
    ProcessError { what: &'static str, err: RunError },
}
impl Display for ReplError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ReplError::*;
        match self {
            ConfigDirCreateError { .. } => write!(f, "Could not create the configuration directory for the REPL history"),
            HistoryFileError { .. } => write!(f, "Could not get REPL history file location"),
            EditorCreateError { .. } => write!(f, "Failed to create new rustyline editor"),
            InstanceInfoError { .. } => write!(f, "Failed to load instance info file"),

            InitializeError { what, .. } => write!(f, "Failed to initialize {what} and associated structures"),
            RunError { what, .. } => write!(f, "Failed to execute workflow on {what}"),
            ProcessError { what, .. } => write!(f, "Failed to process {what} workflow results"),
        }
    }
}
impl Error for ReplError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ReplError::*;
        match self {
            ConfigDirCreateError { err } => Some(err),
            HistoryFileError { err } => Some(err),
            EditorCreateError { err } => Some(err),
            InstanceInfoError { err } => Some(err),

            InitializeError { err, .. } => Some(err),
            RunError { err, .. } => Some(err),
            ProcessError { err, .. } => Some(err),
        }
    }
}



/// Collects errors during the run subcommand.
#[derive(Debug)]
pub enum RunError {
    /// Failed to write to the given formatter.
    WriteError { err: std::io::Error },

    /// Failed to create the local package index.
    LocalPackageIndexError { err: brane_tsk::local::Error },
    /// Failed to create the local data index.
    LocalDataIndexError { err: brane_tsk::local::Error },
    /// Failed to get the packages directory.
    PackagesDirError { err: UtilError },
    /// Failed to get the datasets directory.
    DatasetsDirError { err: UtilError },
    /// Failed to create a temporary intermediate results directory.
    ResultsDirCreateError { err: std::io::Error },

    /// Failed to fetch the login file.
    InstanceInfoError { err: InstanceError },
    /// Failed to get the path of the active instance.
    ActiveInstanceReadError { err: InstanceError },
    /// Failed to get the active instance.
    InstancePathError { name: String, err: InstanceError },
    /// Failed to create the remote package index.
    RemotePackageIndexError { address: String, err: brane_tsk::errors::ApiError },
    /// Failed to create the remote data index.
    RemoteDataIndexError { address: String, err: brane_tsk::errors::ApiError },
    /// Failed to pull the delegate map from the remote delegate index(ish - `brane-api`)
    RemoteDelegatesError { address: String, err: DelegatesError },
    /// Could not connect to the given address
    ClientConnectError { address: String, err: specifications::driving::Error },
    /// Failed to parse the AppId send by the remote driver.
    ///
    /// Note: `err` is boxed to avoid this error enum growing too large.
    AppIdError { address: String, raw: String, err: Box<brane_tsk::errors::IdError> },
    /// Could not create a new session on the given address
    SessionCreateError { address: String, err: tonic::Status },

    /// An error occurred while compile the given snippet. It will already have been printed to stdout.
    CompileError(brane_ast::errors::CompileError),
    /// Failed to serialize the compiled workflow.
    WorkflowSerializeError { err: serde_json::Error },
    /// Requesting a command failed
    CommandRequestError { address: String, err: tonic::Status },
    /// Failed to parse the value returned by the remote driver.
    ValueParseError { address: String, raw: String, err: serde_json::Error },
    /// The workflow was denied by some checker.
    ExecDenied { err: Box<dyn Error> },
    /// Failed to run the workflow
    ExecError { err: Box<dyn Error> },

    /// The returned dataset was unknown.
    UnknownDataset { name: String },
    /// The returend dataset was known but not available locally.
    UnavailableDataset { name: String, locs: Vec<String> },
    /// Failed to download remote dataset.
    DataDownloadError { err: DataError },

    /// Failed to read the source from stdin
    StdinReadError { err: std::io::Error },
    /// Failed to read the source from a given file
    FileReadError { path: PathBuf, err: std::io::Error },
    /// Failed to load the login file.
    LoginFileError { err: UtilError },
    // /// Failed to compile the given file (the reasons have already been printed to stderr).
    // CompileError{ path: PathBuf, errs: Vec<brane_ast::Error> },
}
impl Display for RunError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use RunError::*;
        match self {
            WriteError { .. } => write!(f, "Failed to write to the given formatter"),

            LocalPackageIndexError { .. } => write!(f, "Failed to fetch local package index"),
            LocalDataIndexError { .. } => write!(f, "Failed to fetch local data index"),
            PackagesDirError { .. } => write!(f, "Failed to get packages directory"),
            DatasetsDirError { .. } => write!(f, "Failed to get datasets directory"),
            ResultsDirCreateError { .. } => write!(f, "Failed to create new temporary directory as an intermediate result directory"),

            InstanceInfoError { err } => write!(f, "{err}"),
            ActiveInstanceReadError { .. } => write!(f, "Failed to read active instance link"),
            InstancePathError { name, .. } => write!(f, "Could not get path of instance '{name}'"),
            RemotePackageIndexError { address, .. } => write!(f, "Failed to fetch remote package index from '{address}'"),
            RemoteDataIndexError { address, .. } => write!(f, "Failed to fetch remote data index from '{address}'"),
            RemoteDelegatesError { address, .. } => write!(f, "Failed to fetch delegates map from '{address}'"),
            ClientConnectError { address, .. } => write!(f, "Could not connect to remote Brane instance '{address}'"),
            AppIdError { address, raw, .. } => write!(f, "Could not parse '{raw}' send by remote '{address}' as an application ID"),
            SessionCreateError { address, .. } => {
                write!(f, "Could not create new session with remote Brane instance '{address}': remote returned status")
            },

            CompileError { .. } => write!(f, "Compilation of workflow failed (see output above)"),
            WorkflowSerializeError { .. } => write!(f, "Failed to serialize the compiled workflow"),
            CommandRequestError { address, .. } => {
                write!(f, "Could not run command on remote Brane instance '{address}': request failed: remote returned status")
            },
            ValueParseError { address, raw, .. } => write!(f, "Could not parse '{raw}' sent by remote '{address}' as a value"),
            ExecDenied { .. } => write!(f, "Workflow was denied"),
            ExecError { .. } => write!(f, "Failed to run workflow"),

            UnknownDataset { name } => write!(f, "Unknown dataset '{name}'"),
            UnavailableDataset { name, locs } => write!(
                f,
                "Unavailable dataset '{}'{}",
                name,
                if !locs.is_empty() {
                    format!("; it is available at {}", PrettyListFormatter::new(locs.iter().map(|l| format!("'{l}'")), "or"))
                } else {
                    String::new()
                }
            ),
            DataDownloadError { .. } => write!(f, "Failed to download remote dataset"),

            StdinReadError { .. } => write!(f, "Failed to read source from stdin"),
            FileReadError { path, .. } => write!(f, "Failed to read source from file '{}'", path.display()),
            LoginFileError { err } => write!(f, "{err}"),
        }
    }
}
impl Error for RunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use RunError::*;
        match self {
            WriteError { err } => Some(err),

            LocalPackageIndexError { err } => Some(err),
            LocalDataIndexError { err } => Some(err),
            PackagesDirError { err } => Some(err),
            DatasetsDirError { err } => Some(err),
            ResultsDirCreateError { err } => Some(err),

            InstanceInfoError { err } => err.source(),
            ActiveInstanceReadError { err } => Some(err),
            InstancePathError { err, .. } => Some(err),
            RemotePackageIndexError { err, .. } => Some(err),
            RemoteDataIndexError { err, .. } => Some(err),
            RemoteDelegatesError { err, .. } => Some(err),
            ClientConnectError { err, .. } => Some(err),
            AppIdError { err, .. } => Some(err),
            SessionCreateError { err, .. } => Some(err),

            CompileError { .. } => None,
            WorkflowSerializeError { err } => Some(err),
            CommandRequestError { err, .. } => Some(err),
            ValueParseError { err, .. } => Some(err),
            ExecDenied { err } => Some(&**err),
            ExecError { err } => Some(&**err),

            UnknownDataset { .. } => None,
            UnavailableDataset { .. } => None,
            DataDownloadError { err } => Some(err),

            StdinReadError { err } => Some(err),
            FileReadError { err, .. } => Some(err),
            LoginFileError { err } => err.source(),
        }
    }
}
impl From<std::io::Error> for RunError {
    #[inline]
    fn from(value: std::io::Error) -> Self { RunError::WriteError { err: value } }
}



/// Collects errors during the test subcommand.
#[derive(Debug)]
pub enum TestError {
    /// Failed to get the local data index.
    DataIndexError { err: brane_tsk::local::Error },
    /// Failed to prompt the user for the function/input selection.
    InputError { err: brane_tsk::input::Error },

    /// Failed to create a temporary directory
    TempDirError { err: std::io::Error },
    /// We can't access a dataset in the local instance.
    DatasetUnavailable { name: String, locs: Vec<String> },
    /// The given dataset was unknown to us.
    UnknownDataset { name: String },
    /// Failed to get the general package directory.
    PackagesDirError { err: UtilError },
    /// Failed to get the general dataset directory.
    DatasetsDirError { err: UtilError },
    /// Failed to get the directory of a package.
    PackageDirError { name: String, version: Version, err: UtilError },
    /// Failed to read the PackageInfo of the given package.
    PackageInfoError { name: String, version: Version, err: specifications::package::PackageInfoError },

    /// Failed to initialize the offline VM.
    InitializeError { err: RunError },
    /// Failed to run the offline VM.
    RunError { err: RunError },
    /// Failed to read the intermediate results file.
    IntermediateResultFileReadError { path: PathBuf, err: std::io::Error },
}
impl Display for TestError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use TestError::*;
        match self {
            DataIndexError { err } => write!(f, "Failed to load local data index: {err}"),
            InputError { err } => write!(f, "Failed to ask the user (you!) for input: {}", err.trace()),

            TempDirError { err } => write!(f, "Failed to create temporary results directory: {err}"),
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
            UnknownDataset { name } => write!(f, "Unknown dataset '{name}'"),
            PackagesDirError { err } => write!(f, "Failed to get packages directory: {err}"),
            DatasetsDirError { err } => write!(f, "Failed to get datasets directory: {err}"),
            PackageDirError { name, version, err } => write!(f, "Failed to get directory of package '{name}' (version {version}): {err}"),
            PackageInfoError { name, version, err } => write!(f, "Failed to read package info for package '{name}' (version {version}): {err}"),

            InitializeError { err } => write!(f, "Failed to initialize offline VM: {err}"),
            RunError { err } => write!(f, "Failed to run offline VM: {err}"),
            IntermediateResultFileReadError { path, err } => write!(f, "Failed to read intermediate result file '{}': {}", path.display(), err),
        }
    }
}
impl Error for TestError {}



/// Collects errors relating to the verify command.
#[derive(Debug)]
pub enum VerifyError {
    /// Failed to verify the config
    ConfigFailed { err: brane_cfg::infra::Error },
}
impl Display for VerifyError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use VerifyError::*;
        match self {
            ConfigFailed { err } => write!(f, "Failed to verify configuration: {err}"),
        }
    }
}
impl Error for VerifyError {}



/// Collects errors relating to the version command.
#[derive(Debug)]
pub enum VersionError {
    /// Could not get the host architecture
    HostArchError { err: specifications::arch::ArchError },
    /// Could not parse a Version number.
    VersionParseError { raw: String, err: specifications::version::ParseError },

    /// Could not discover if the instance existed.
    InstanceInfoExistsError { err: InstanceError },
    /// Could not open the login file
    InstanceInfoError { err: InstanceError },
    /// Could not perform the request
    RequestError { url: String, err: reqwest::Error },
    /// The request returned a non-200 exit code
    RequestFailure { url: String, status: reqwest::StatusCode },
    /// The request's body could not be get.
    RequestBodyError { url: String, err: reqwest::Error },
}
impl Display for VersionError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use VersionError::*;
        match self {
            HostArchError { err } => write!(f, "Could not get the host processor architecture: {err}"),
            VersionParseError { raw, err } => write!(f, "Could parse '{raw}' as Version: {err}"),

            InstanceInfoExistsError { err } => write!(f, "Could not check if active instance exists: {err}"),
            InstanceInfoError { err } => write!(f, "{err}"),
            RequestError { url, err } => write!(f, "Could not perform request to '{url}': {err}"),
            RequestFailure { url, status } => {
                write!(f, "Request to '{}' returned non-zero exit code {} ({})", url, status.as_u16(), status.canonical_reason().unwrap_or("<???>"))
            },
            RequestBodyError { url, err } => write!(f, "Could not get body from response from '{url}': {err}"),
        }
    }
}
impl Error for VersionError {}



/// Collects errors of utilities that don't find an origin in just one subcommand.
#[derive(Debug)]
pub enum UtilError {
    /// Could not connect to the local Docker instance
    DockerConnectionFailed { err: bollard::errors::Error },
    /// Could not get the version of the Docker daemon
    DockerVersionError { err: bollard::errors::Error },
    /// The docker daemon returned something, but not the version
    DockerNoVersion,
    /// The version reported by the Docker daemon is not a valid version
    IllegalDockerVersion { version: String, err: VersionParseError },
    /// Could not launch the command to get the Buildx version
    BuildxLaunchError { command: String, err: std::io::Error },
    /// The Buildx version in the buildx command does not have at least two parts, separated by spaces
    BuildxVersionNoParts { version: String },
    /// The Buildx version is not prepended with a 'v'
    BuildxVersionNoV { version: String },
    /// The version reported by Buildx is not a valid version
    IllegalBuildxVersion { version: String, err: VersionParseError },

    /// Could not read from a given directory
    DirectoryReadError { dir: PathBuf, err: std::io::Error },
    /// Could not automatically determine package file inside a directory.
    UndeterminedPackageFile { dir: PathBuf },

    /// Could not open the main package file of the package to build.
    PackageFileOpenError { file: PathBuf, err: std::io::Error },
    /// Could not read the main package file of the package to build.
    PackageFileReadError { file: PathBuf, err: std::io::Error },
    /// Could not automatically determine package kind based on the file.
    UndeterminedPackageKind { file: PathBuf },

    /// Could not find the user config folder
    UserConfigDirNotFound,
    /// Could not create brane's folder in the config folder
    BraneConfigDirCreateError { path: PathBuf, err: std::io::Error },
    /// Could not find brane's folder in the config folder
    BraneConfigDirNotFound { path: PathBuf },

    /// Could not create Brane's history file
    HistoryFileCreateError { path: PathBuf, err: std::io::Error },
    /// Could not find Brane's history file
    HistoryFileNotFound { path: PathBuf },

    /// Could not find the user local data folder
    UserLocalDataDirNotFound,
    /// Could not find create brane's folder in the data folder
    BraneDataDirCreateError { path: PathBuf, err: std::io::Error },
    /// Could not find brane's folder in the data folder
    BraneDataDirNotFound { path: PathBuf },

    /// Could not find create the package folder inside brane's data folder
    BranePackageDirCreateError { path: PathBuf, err: std::io::Error },
    /// Could not find the package folder inside brane's data folder
    BranePackageDirNotFound { path: PathBuf },

    /// Could not create the dataset folder inside brane's data folder
    BraneDatasetsDirCreateError { path: PathBuf, err: std::io::Error },
    /// Could not find the dataset folder inside brane's data folder.
    BraneDatasetsDirNotFound { path: PathBuf },

    /// Failed to read the versions in a package's directory.
    VersionsError { err: brane_tsk::errors::LocalError },

    /// Could not create the directory for a package
    PackageDirCreateError { package: String, path: PathBuf, err: std::io::Error },
    /// The target package directory does not exist
    PackageDirNotFound { package: String, path: PathBuf },
    /// Could not create a new directory for the given version
    VersionDirCreateError { package: String, version: Version, path: PathBuf, err: std::io::Error },
    /// The target package/version directory does not exist
    VersionDirNotFound { package: String, version: Version, path: PathBuf },

    /// Could not create the dataset folder for a specific dataset
    BraneDatasetDirCreateError { name: String, path: PathBuf, err: std::io::Error },
    /// Could not find the dataset folder for a specific dataset.
    BraneDatasetDirNotFound { name: String, path: PathBuf },

    /// Could not create the instances folder.
    BraneInstancesDirCreateError { path: PathBuf, err: std::io::Error },
    /// The instances folder did not exist.
    BraneInstancesDirNotFound { path: PathBuf },
    /// Could not create the instance folder for a specific instance.
    BraneInstanceDirCreateError { path: PathBuf, name: String, err: std::io::Error },
    /// The instance folder for a specific instance did not exist.
    BraneInstanceDirNotFound { path: PathBuf, name: String },

    /// The given name is not a valid bakery name.
    InvalidBakeryName { name: String },
}
impl Display for UtilError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use UtilError::*;
        match self {
            DockerConnectionFailed { err } => write!(f, "Could not connect to local Docker instance: {err}"),
            DockerVersionError { err } => write!(f, "Could not get version of the local Docker instance: {err}"),
            DockerNoVersion => write!(f, "Local Docker instance doesn't report a version number"),
            IllegalDockerVersion { version, err } => write!(f, "Local Docker instance reports unparseable version '{version}': {err}"),
            BuildxLaunchError { command, err } => write!(f, "Could not run command '{command}' to get Buildx version information: {err}"),
            BuildxVersionNoParts { version } => {
                write!(f, "Illegal Buildx version '{version}': did not find second part (separted by spaces) with version number")
            },
            BuildxVersionNoV { version } => write!(f, "Illegal Buildx version '{version}': did not find 'v' prepending version number"),
            IllegalBuildxVersion { version, err } => write!(f, "Buildx reports unparseable version '{version}': {err}"),

            DirectoryReadError { dir, err } => write!(f, "Could not read from directory '{}': {}", dir.display(), err),
            UndeterminedPackageFile { dir } => {
                write!(f, "Could not determine package file in directory '{}'; specify it manually with '--file'", dir.display())
            },

            PackageFileOpenError { file, err } => write!(f, "Could not open package file '{}': {}", file.display(), err),
            PackageFileReadError { file, err } => write!(f, "Could not read from package file '{}': {}", file.display(), err),
            UndeterminedPackageKind { file } => {
                write!(f, "Could not determine package from package file '{}'; specify it manually with '--kind'", file.display())
            },

            UserConfigDirNotFound => write!(f, "Could not find the user's config directory for your OS (reported as {})", std::env::consts::OS),
            BraneConfigDirCreateError { path, err } => write!(f, "Could not create Brane config directory '{}': {}", path.display(), err),
            BraneConfigDirNotFound { path } => write!(f, "Brane config directory '{}' not found", path.display()),

            HistoryFileCreateError { path, err } => write!(f, "Could not create history file '{}' for the REPL: {}", path.display(), err),
            HistoryFileNotFound { path } => write!(f, "History file '{}' for the REPL does not exist", path.display()),

            UserLocalDataDirNotFound => {
                write!(f, "Could not find the user's local data directory for your OS (reported as {})", std::env::consts::OS)
            },
            BraneDataDirCreateError { path, err } => write!(f, "Could not create Brane data directory '{}': {}", path.display(), err),
            BraneDataDirNotFound { path } => write!(f, "Brane data directory '{}' not found", path.display()),

            BranePackageDirCreateError { path, err } => write!(f, "Could not create Brane package directory '{}': {}", path.display(), err),
            BranePackageDirNotFound { path } => write!(f, "Brane package directory '{}' not found", path.display()),

            BraneDatasetsDirCreateError { path, err } => write!(f, "Could not create Brane datasets directory '{}': {}", path.display(), err),
            BraneDatasetsDirNotFound { path } => write!(f, "Brane datasets directory '{}' not found", path.display()),

            VersionsError { err } => write!(f, "Failed to read package versions: {err}"),

            PackageDirCreateError { package, path, err } => {
                write!(f, "Could not create directory for package '{}' (path: '{}'): {}", package, path.display(), err)
            },
            PackageDirNotFound { package, path } => write!(f, "Directory for package '{}' does not exist (path: '{}')", package, path.display()),
            VersionDirCreateError { package, version, path, err } => {
                write!(f, "Could not create directory for package '{}', version: {} (path: '{}'): {}", package, version, path.display(), err)
            },
            VersionDirNotFound { package, version, path } => {
                write!(f, "Directory for package '{}', version: {} does not exist (path: '{}')", package, version, path.display())
            },

            BraneDatasetDirCreateError { name, path, err } => {
                write!(f, "Could not create Brane dataset directory '{}' for dataset '{}': {}", path.display(), name, err)
            },
            BraneDatasetDirNotFound { name, path } => write!(f, "Brane dataset directory '{}' for dataset '{}' not found", path.display(), name),

            BraneInstancesDirCreateError { path, err } => write!(f, "Failed to create Brane instance directory '{}': {}", path.display(), err),
            BraneInstancesDirNotFound { path } => write!(f, "Brane instance directory '{}' not found", path.display()),
            BraneInstanceDirCreateError { path, name, err } => {
                write!(f, "Failed to create directory '{}' for new instance '{}': {}", path.display(), name, err)
            },
            BraneInstanceDirNotFound { path, name } => write!(f, "Brane instance directory '{}' for instance '{}' not found", path.display(), name),

            InvalidBakeryName { name } => write!(f, "The given name '{name}' is not a valid name; expected alphanumeric or underscore characters"),
        }
    }
}
impl Error for UtilError {}



/// Defines errors that relate to finding our directories.
#[derive(Debug)]
pub enum DirError {
    /// Failed to find a user directory. The `what` hints at the kind of user directory (fill in "\<what\> directory", e.g., "config", "data", ...)
    UserDirError { what: &'static str },
    /// Failed to read the softlink.
    SoftlinkReadError { path: PathBuf, err: std::io::Error },
}
impl Display for DirError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DirError::*;
        match self {
            UserDirError { what } => write!(f, "Failed to find user {} directory", what),
            SoftlinkReadError { path, err } => write!(f, "Failed to read softlink '{}': {}", path.display(), err),
        }
    }
}
impl Error for DirError {}



/// Declares errors that relate to parsing hostnames from a string.
#[derive(Debug)]
pub enum HostnameParseError {
    /// The scheme contained an illegal character.
    IllegalSchemeChar { raw: String, c: char },
    /// The hostname contained a path separator.
    HostnameContainsPath { raw: String },
}
impl Display for HostnameParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use HostnameParseError::*;
        match self {
            IllegalSchemeChar { raw, c } => write!(f, "URL scheme '{raw}' contains illegal character '{c}'"),
            HostnameContainsPath { raw } => write!(f, "Hostname '{raw}' is not just a hostname (it contains a nested path)"),
        }
    }
}
impl Error for HostnameParseError {}



/// Declares errors that relate to the offline VM.
#[derive(Debug)]
pub enum OfflineVmError {
    /// Failed to plan a workflow.
    PlanError { err: brane_tsk::errors::PlanError },
    /// Failed to run a workflow.
    ExecError { err: brane_exe::Error },
}
impl Display for OfflineVmError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use OfflineVmError::*;
        match self {
            PlanError { err } => write!(f, "Failed to plan workflow: {err}"),
            ExecError { err } => write!(f, "Failed to execute workflow: {err}"),
        }
    }
}
impl Error for OfflineVmError {}



/// A really specific error enum for errors relating to fetching delegates.
#[derive(Debug)]
pub enum DelegatesError {
    /// Failed to sent the GET-request to fetch the map.
    RequestError { address: String, err: reqwest::Error },
    /// The request returned a non-2xx status code.
    RequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to get the request body properly.
    ResponseTextError { address: String, err: reqwest::Error },
    /// Failed to parse the request body properly.
    ResponseParseError { address: String, raw: String, err: serde_json::Error },
}
impl Display for DelegatesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DelegatesError::*;
        match self {
            RequestError { address, err } => write!(f, "Failed to send delegates request to '{address}': {err}"),
            RequestFailure { address, code, message } => write!(
                f,
                "Request to '{}' failed with status code {} ({}){}",
                address,
                code,
                code.canonical_reason().unwrap_or("???"),
                if let Some(msg) = message { format!(": {msg}") } else { String::new() }
            ),
            ResponseTextError { address, err } => write!(f, "Failed to get body from response sent by '{address}' as text: {err}"),
            ResponseParseError { address, raw, err } => {
                write!(f, "Failed to parse response body '{raw}' sent by '{address}' as a delegate map: {err}")
            },
        }
    }
}
impl Error for DelegatesError {}
