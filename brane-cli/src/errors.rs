//  ERRORS.rs
//    by Lut99
//
//  Created:
//    17 Feb 2022, 10:27:28
//  Last edited:
//    02 May 2025, 14:16:13
//  Auto updated?
//    Yes
//
//  Description:
//!   File that contains file-spanning error definitions for the brane-cli
//

use std::error::Error;
use std::path::PathBuf;

use brane_exe::value::DataId;
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
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    // Toplevel errors for the subcommands
    /// Errors that occur during the build command
    #[error(transparent)]
    BuildError { source: BuildError },
    /// Errors that occur when managing certificates.
    #[error(transparent)]
    CertsError { source: CertsError },
    /// Errors that occur when validating workflow against policy.
    #[error(transparent)]
    CheckError { source: CheckError },
    /// Errors that occur during any of the data(-related) command(s)
    #[error(transparent)]
    DataError { source: DataError },
    /// Errors that occur during the import command
    #[error(transparent)]
    ImportError { source: ImportError },
    /// Errors that occur during identity management.
    #[error(transparent)]
    InstanceError { source: InstanceError },
    /// Errors that occur during some package command
    #[error(transparent)]
    PackageError { source: PackageError },
    /// Errors that occur during some registry command
    #[error(transparent)]
    RegistryError { source: RegistryError },
    /// Errors that occur during the repl command
    #[error(transparent)]
    ReplError { source: ReplError },
    /// Errors that occur during the run command
    #[error(transparent)]
    RunError { source: RunError },
    /// Errors that occur in the test command
    #[error(transparent)]
    TestError { source: TestError },
    /// Errors that occur in the verify command
    #[error(transparent)]
    VerifyError { source: VerifyError },
    /// Errors that occur in the version command
    #[error(transparent)]
    VersionError { source: VersionError },
    /// Errors that occur when upgrading old config files.
    #[error(transparent)]
    UpgradeError { source: crate::upgrade::Error },
    /// Errors that occur in some inter-subcommand utility
    #[error(transparent)]
    UtilError { source: UtilError },
    /// Temporary wrapper around any anyhow error
    #[error(transparent)]
    OtherError { source: anyhow::Error },

    // A few miscellanous errors occuring in main.rs
    /// Could not resolve the path to the package file
    #[error("Could not resolve package file path '{}'", path.display())]
    PackageFileCanonicalizeError { path: PathBuf, source: std::io::Error },
    /// Could not resolve the path to the context
    #[error("Could not resolve working directory '{}'", path.display())]
    WorkdirCanonicalizeError { path: PathBuf, source: std::io::Error },
    /// Could not resolve a string to a package kind
    #[error("Illegal package kind '{kind}'")]
    IllegalPackageKind { kind: String, source: PackageKindError },
    /// Could not parse a NAME:VERSION pair
    #[error("Could not parse '{raw}'")]
    PackagePairParseError { raw: String, source: specifications::version::ParseError },
}

/// Collects errors during the build subcommand
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Could not open the given container info file
    #[error("Could not open the container info file '{}'", file.display())]
    ContainerInfoOpenError { file: PathBuf, source: std::io::Error },
    /// Could not read/open the given container info file
    #[error("Could not parse the container info file '{}'", file.display())]
    ContainerInfoParseError { file: PathBuf, source: ContainerInfoError },
    /// Could not create/resolve the package directory
    #[error("Could not create package directory")]
    PackageDirError { source: UtilError },

    /// Could not read/open the given OAS document
    #[error("Could not parse the OAS Document '{}'", file.display())]
    OasDocumentParseError { file: PathBuf, source: anyhow::Error },
    /// Could not parse the version in the given OAS document
    #[error("Could not parse OAS Document version number")]
    VersionParseError { source: VersionParseError },
    /// Could not properly convert the OpenAPI document into a PackageInfo
    #[error("Could not convert the OAS Document into a Package Info file")]
    PackageInfoFromOpenAPIError { source: anyhow::Error },

    #[error("Failed to create lockfile for package '{name}'")]
    LockCreateError { name: String, source: brane_shr::fs::Error },

    /// Could not write to the DockerFile string.
    #[error("Could not write to the internal DockerFile")]
    DockerfileStrWriteError { source: std::fmt::Error },
    /// A given filepath escaped the working directory
    #[error("File '{}' tries to escape package working directory; consider moving Brane's working directory up (using --workdir) and avoid '..'", path.display())]
    UnsafePath { path: PathBuf },
    /// The entrypoint executable referenced was not found
    #[error("Could not find the package entrypoint '{}'", path.display())]
    MissingExecutable { path: PathBuf },

    /// Could not create the Dockerfile in the build directory.
    #[error("Could not create Dockerfile '{}'", path.display())]
    DockerfileCreateError { path: PathBuf, source: std::io::Error },
    /// Could not write to the Dockerfile in the build directory.
    #[error("Could not write to Dockerfile '{}'", path.display())]
    DockerfileWriteError { path: PathBuf, source: std::io::Error },
    /// Could not create the container directory
    #[error("Could not create container directory '{}'", path.display())]
    ContainerDirCreateError { path: PathBuf, source: std::io::Error },
    /// Could not resolve the custom branelet's path
    #[error("Could not resolve custom init binary path '{}'", path.display())]
    BraneletCanonicalizeError { path: PathBuf, source: std::io::Error },
    /// Could not copy the branelet executable
    #[error("Could not copy custom init binary from '{}' to '{}'", original.display(), target.display())]
    BraneletCopyError { original: PathBuf, target: PathBuf, source: std::io::Error },
    /// Could not clear an existing working directory
    #[error("Could not clear existing package working directory '{}'", path.display())]
    WdClearError { path: PathBuf, source: std::io::Error },
    /// Could not create a new working directory
    #[error("Could not create package working directory '{}'", path.display())]
    WdCreateError { path: PathBuf, source: std::io::Error },
    /// Could not write the LocalContainerInfo to the container directory.
    #[error("Could not write local container info to container directory")]
    LocalContainerInfoCreateError { source: LocalContainerInfoError },
    /// Could not canonicalize file's path that will be copied to the working directory
    #[error("Could not resolve file '{}' in the package info file", path.display())]
    WdSourceFileCanonicalizeError { path: PathBuf, source: std::io::Error },
    /// Could not canonicalize a workdir file's path
    #[error("Could not resolve file '{}' in the package working directory", path.display())]
    WdTargetFileCanonicalizeError { path: PathBuf, source: std::io::Error },
    /// Could not create a directory in the working directory
    #[error("Could not create directory '{}' in the package working directory", path.display())]
    WdDirCreateError { path: PathBuf, source: std::io::Error },
    /// Could not copy a file to the working directory
    #[error("Could not copy file '{}' to '{}' in the package working directory", original.display(), target.display())]
    WdFileCopyError { original: PathBuf, target: PathBuf, source: std::io::Error },
    /// Could not read a directory's entries.
    #[error("Could not read directory '{}' in the package working directory", path.display())]
    WdDirReadError { path: PathBuf, source: std::io::Error },
    /// Could not unwrap an entry in a directory.
    #[error("Could not read entry in directory '{}' in the package working directory", path.display())]
    WdDirEntryError { path: PathBuf, source: std::io::Error },
    /// Could not rename a file.
    #[error("Could not rename file '{}' to '{}' in the package working directory", original.display(), target.display())]
    WdFileRenameError { original: PathBuf, target: PathBuf, source: std::io::Error },
    /// Failed to create a new file.
    #[error("Could not create new file '{}' in the package working directory", path.display())]
    WdFileCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to open a file.
    #[error("Could not open file '{}' in the package working directory", path.display())]
    WdFileOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to read a file.
    #[error("Could not read from file '{}' in the package working directory", path.display())]
    WdFileReadError { path: PathBuf, source: std::io::Error },
    /// Failed to write to a file.
    #[error("Could not write to file '{}' in the package working directory", path.display())]
    WdFileWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to remove a file.
    #[error("Could not remove file '{}' in the package working directory", path.display())]
    WdFileRemoveError { path: PathBuf, source: std::io::Error },
    /// Could not launch the command to compress the working directory
    #[error("Could not run command '{command}' to compress working directory")]
    WdCompressionLaunchError { command: String, source: std::io::Error },
    /// Command to compress the working directory returned a non-zero exit code
    #[error("Command '{}' to compress working directory returned exit code {}:\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n", command, code, *CLI_LINE_SEPARATOR, stdout, *CLI_LINE_SEPARATOR, *CLI_LINE_SEPARATOR, stderr, *CLI_LINE_SEPARATOR)]
    WdCompressionError { command: String, code: i32, stdout: String, stderr: String },
    /// Failed to ask the user for consent.
    #[error("Failed to ask the user (you!) for consent")]
    WdConfirmationError { source: dialoguer::Error },

    /// Could not serialize the OPenAPI file
    #[error("Could not re-serialize OpenAPI document")]
    OpenAPISerializeError { source: serde_yaml::Error },
    /// COuld not create a new OpenAPI file
    #[error("Could not create OpenAPI file '{}'", path.display())]
    OpenAPIFileCreateError { path: PathBuf, source: std::io::Error },
    /// Could not write to a new OpenAPI file
    #[error("Could not write to OpenAPI file '{}'", path.display())]
    OpenAPIFileWriteError { path: PathBuf, source: std::io::Error },

    /// Could not launch the command to see if buildkit is installed
    #[error("Could not determine if Docker & BuildKit are installed: failed to run command '{command}'")]
    BuildKitLaunchError { command: String, source: std::io::Error },
    /// The simple command to instantiate/test the BuildKit plugin for Docker returned a non-success
    #[error("Could not run a Docker BuildKit (command '{}' returned exit code {}): is BuildKit installed?\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n", command, code, *CLI_LINE_SEPARATOR, stdout, *CLI_LINE_SEPARATOR, *CLI_LINE_SEPARATOR, stderr, *CLI_LINE_SEPARATOR)]
    BuildKitError { command: String, code: i32, stdout: String, stderr: String },
    /// Could not launch the command to build the package image
    #[error("Could not run command '{command}' to build the package image")]
    ImageBuildLaunchError { command: String, source: std::io::Error },
    /// The command to build the image returned a non-zero exit code (we don't accept stdout or stderr here, as the command's output itself will be passed to stdout & stderr)
    #[error("Command '{command}' to build the package image returned exit code {code}")]
    ImageBuildError { command: String, code: i32 },

    /// Could not get the digest from the just-built image
    #[error("Could not get Docker image digest")]
    DigestError { source: brane_tsk::docker::Error },
    /// Could not write the PackageFile to the build directory.
    #[error("Could not write package info to build directory")]
    PackageFileCreateError { source: PackageInfoError },

    /// Failed to cleanup a file from the build directory after a successfull build.
    #[error("Could not clean file '{}' from build directory", path.display())]
    FileCleanupError { path: PathBuf, source: std::io::Error },
    /// Failed to cleanup a directory from the build directory after a successfull build.
    #[error("Could not clean directory '{}' from build directory", path.display())]
    DirCleanupError { path: PathBuf, source: std::io::Error },
    /// Failed to cleanup the build directory after a failed build.
    #[error("Could not clean build directory '{}'", path.display())]
    CleanupError { path: PathBuf, source: std::io::Error },

    /// Could not open the just-build image.tar
    #[error("Could not open the built image.tar ('{}')", path.display())]
    ImageTarOpenError { path: PathBuf, source: std::io::Error },
    /// Could not get the entries in the image.tar
    #[error("Could get entries in the built image.tar ('{}')", path.display())]
    ImageTarEntriesError { path: PathBuf, source: std::io::Error },
    /// Could not parse the extracted manifest file
    #[error("Could not parse extracted Docker manifest '{}'", path.display())]
    ManifestParseError { path: PathBuf, source: serde_json::Error },
    /// The number of entries in the given manifest is not one (?)
    #[error("Extracted Docker manifest '{}' has an incorrect number of entries: got {}, expected 1", path.display(), n)]
    ManifestNotOneEntry { path: PathBuf, n: usize },
    /// The path to the config blob (which contains Docker's digest) is invalid
    #[error("Extracted Docker manifest '{}' has an incorrect path to the config blob: got {}, expected it to start with 'blobs/sha256/'", path.display(), config)]
    ManifestInvalidConfigBlob { path: PathBuf, config: String },
    /// Didn't find any manifest.json in the image.tar
    #[error("Built image.tar ('{}') does not contain a manifest.json", path.display())]
    NoManifest { path: PathBuf },
    /// Could not create the resulting digest.txt file
    #[error("Could not open digest file '{}'", path.display())]
    DigestFileCreateError { path: PathBuf, source: std::io::Error },
    /// Could not write to the resulting digest.txt file
    #[error("Could not write to digest file '{}'", path.display())]
    DigestFileWriteError { path: PathBuf, source: std::io::Error },

    /// Could not get the host architecture
    #[error("Could not get host architecture")]
    HostArchError { source: specifications::arch::ArchError },
}

/// Collects errors relating to certificate management.
#[derive(Debug, thiserror::Error)]
pub enum CertsError {
    /// The active instance file exists but is not a softlink.
    #[error("Active instance link '{}' exists but is not a symlink", path.display())]
    ActiveInstanceNotASoftlinkError { path: PathBuf },

    /// Failed to parse the name in a certificate.
    #[error("Failed to parse certificate {} in file '{}'", i, path.display())]
    CertParseError { path: PathBuf, i: usize, source: x509_parser::nom::Err<x509_parser::error::X509Error> },
    /// Failed to get the extensions from the given certificate.
    #[error("Failed to get extensions in certificate {} in file '{}'", i, path.display())]
    CertExtensionsError { path: PathBuf, i: usize, source: x509_parser::error::X509Error },
    /// Did not find the key usage extension in the given certificate.
    #[error("Certificate {} in file '{}' does not have key usage defined (extension)", i, path.display())]
    CertNoKeyUsageError { path: PathBuf, i: usize },
    /// The given certificate had an ambigious key usage flag set.
    #[error("Certificate {} in file '{}' has both Digital Signature and CRL Sign flags set (ambigious usage)", i, path.display())]
    CertAmbigiousUsageError { path: PathBuf, i: usize },
    /// The given certificate had no (valid) key usage flag set.
    #[error("Certificate {} in file '{}' has neither Digital Signature, nor CRL Sign flags set (cannot determine usage)", i, path.display())]
    CertNoUsageError { path: PathBuf, i: usize },
    /// Failed to get the issuer CA string.
    #[error("Failed to get the CA field in the issuer field of certificate {} in file '{}'", i, path.display())]
    CertIssuerCaError { path: PathBuf, i: usize, source: x509_parser::error::X509Error },

    /// Failed to load instance directory.
    #[error("Failed to get instance directory")]
    InstanceDirError { source: UtilError },
    /// An unknown instance was given.
    #[error("Unknown instance '{name}'")]
    UnknownInstance { name: String },
    /// Failed to read the directory behind the active instance link.
    #[error("Failed to read active instance")]
    ActiveInstanceReadError { source: InstanceError },
    /// Failed to get the path behind an instance name.
    #[error("Failed to get instance path for instance '{name}'")]
    InstancePathError { name: String, source: InstanceError },
    /// Did not manage to load (one of) the given PEM files.
    #[error("Failed to load PEM file '{}'", path.display())]
    PemLoadError { path: PathBuf, source: brane_cfg::certs::Error },
    /// No CA certificate was provided.
    #[error("No CA certificate given (specify at least one certificate that has 'CRL Sign' key usage flag set)")]
    NoCaCert,
    /// No client certificate was provided.
    #[error("No client certificate given (specify at least one certificate that has 'Digital Signature' key usage flag set)")]
    NoClientCert,
    /// The no client key was provided.
    #[error("No client private key given (specify at least one private key)")]
    NoClientKey,
    /// No domain name found in the certificates.
    #[error("Location name not specified in certificates; specify the target location name manually using '--domain'")]
    NoDomainName,
    /// Failed to ask the user for confirmation.
    #[error("Failed to ask the user (you!) for confirmation (if you are sure, you can skip this step by using '--force')")]
    ConfirmationError { source: dialoguer::Error },
    /// The given certs directory existed but was not a directory.
    #[error("Certificate directory '{}' exists but is not a directory", path.display())]
    CertsDirNotADir { path: PathBuf },
    /// Failed to remove the certificates directory.
    #[error("Failed to remove certificate directory '{}'", path.display())]
    CertsDirRemoveError { path: PathBuf, source: std::io::Error },
    /// Failed to create the certificates directory.
    #[error("Failed to create certificate directory '{}'", path.display())]
    CertsDirCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to open the given file in append mode.
    #[error("Failed to open {} file '{}' for appending", what, path.display())]
    FileOpenError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to write to the given file.
    #[error("Failed to write to {} file '{}'", what, path.display())]
    FileWriteError { what: &'static str, path: PathBuf, source: std::io::Error },

    /// Failed to load instances directory.
    #[error("Failed to get instances directory")]
    InstancesDirError { source: UtilError },
    /// Failed to read the directory with instances.
    #[error("Failed to read {} directory '{}'", what, path.display())]
    DirReadError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to read a specific entry within the directory with instances.
    #[error("Failed to read entry {} in {} directory '{}'", entry, what, path.display())]
    DirEntryReadError { what: &'static str, path: PathBuf, entry: usize, source: std::io::Error },
}

/// Defines errors originating from the `brane check`-subcommand.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// Failed to load the active instance info file.
    #[error("Failed to get currently active instance")]
    ActiveInstanceInfoLoad { source: InstanceError },
    /// The compile step from `brane_ast` failed.
    #[error("Failed to compile workflow '{input}' (see output above)")]
    AstCompile { input: String },
    /// Failed to retrieve the data index.
    #[error("Failed to retrieve data index from '{url}'")]
    DataIndexRetrieve { url: String, source: brane_tsk::api::Error },
    /// The Driver failed to check.
    #[error("Failed to send CheckRequest to driver '{address}'")]
    DriverCheck { address: Address, source: tonic::Status },
    /// Failed to connect to the driver.
    #[error("Failed to connect to driver '{address}'")]
    DriverConnect { address: Address, source: specifications::driving::DriverServiceError },
    /// Failed to read the input from the given file.
    #[error("Failed to read input file '{}'", path.display())]
    InputFileRead { path: PathBuf, source: std::io::Error },
    /// Failed to read the input from stdin.
    #[error("Failed to read input from stdin")]
    InputStdinRead { source: std::io::Error },
    /// Failed to retrieve the package index.
    #[error("Failed to retrieve package index from '{url}'")]
    PackageIndexRetrieve { url: String, source: brane_tsk::api::Error },
    /// Failed to compile a given workflow.
    #[error("Failed to compile workflow '{input}'")]
    WorkflowCompile { input: String, source: Box<Self> },
    /// Failed to serialize the compiled workflow.
    #[error("Failed to serialize workflow '{input}'")]
    WorkflowSerialize { input: String, source: serde_json::Error },
}

/// Collects errors during the build subcommand
#[derive(Debug, thiserror::Error)]
pub enum DataError {
    /// Failed to sent the GET-request to fetch the dfelegate.
    #[error("Failed to send {what} request to '{address}'")]
    RequestError { what: &'static str, address: String, source: reqwest::Error },
    /// The request returned a non-2xx status code.
    #[error("Request to '{}' failed with status code {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(msg) = message { format!(": {msg}") } else { String::new() })]
    RequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to get the request body properly.
    #[error("Failed to get body from response sent by '{address}' as text")]
    ResponseTextError { address: String, source: reqwest::Error },
    /// Failed to open/read a given file.
    #[error("Failed to read {} file '{}'", what, path.display())]
    FileReadError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to get the directory of the certificates.
    #[error("Failed to get certificates directory for active instance")]
    CertsDirError { source: CertsError },
    /// Failed to parse an identity file.
    #[error("Failed to parse identity file '{}'", path.display())]
    IdentityFileError { path: PathBuf, source: reqwest::Error },
    /// Failed to parse a certificate.
    #[error("Failed to parse certificate '{}'", path.display())]
    CertificateError { path: PathBuf, source: reqwest::Error },
    /// A directory was not a directory but a file.
    #[error("{} directory '{}' is not a directory", what, path.display())]
    DirNotADirError { what: &'static str, path: PathBuf },
    /// A directory could not be removed.
    #[error("Failed to remove {} directory '{}'", what, path.display())]
    DirRemoveError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// A directory could not be created.
    #[error("Failed to create {} directory '{}'", what, path.display())]
    DirCreateError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to create a temporary directory.
    #[error("Failed to create temporary directory")]
    TempDirError { source: std::io::Error },
    /// Failed to create the dataset directory.
    #[error("Failed to create dataset directory for dataset '{name}'")]
    DatasetDirError { name: String, source: UtilError },
    /// Failed to create a new reqwest proxy
    #[error("Failed to create new proxy to '{address}'")]
    ProxyCreateError { address: String, source: reqwest::Error },
    /// Failed to create a new reqwest client
    #[error("Failed to create new client")]
    ClientCreateError { source: reqwest::Error },
    /// Failed to reach the next chunk of data.
    #[error("Failed to get next chunk in download stream from '{address}'")]
    DownloadStreamError { address: String, source: reqwest::Error },
    /// Failed to create the file to which we write the download stream.
    #[error("Failed to create tarball file '{}'", path.display())]
    TarCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to write to the file where we write the download stream.
    #[error("Failed to write to tarball file '{}'", path.display())]
    TarWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to extract the downloaded tar.
    #[error("Failed to extract downloaded archive")]
    TarExtractError { source: brane_shr::fs::Error },

    /// Failed to get the datasets folder
    #[error("Failed to get datasets folder")]
    DatasetsError { source: UtilError },
    /// Failed to fetch the local data index.
    #[error("Failed to get local data index")]
    LocalDataIndexError { source: brane_tsk::local::Error },

    /// Failed to load the given AssetInfo file.
    #[error("Failed to load given asset file '{}'", path.display())]
    AssetFileError { path: PathBuf, source: specifications::data::AssetInfoError },
    /// Could not canonicalize the given (relative) path.
    #[error("Failed to resolve path '{}'", path.display())]
    FileCanonicalizeError { path: PathBuf, source: std::io::Error },
    /// The given file does not exist
    #[error("Referenced file '{}' not found (are you using the correct working directory?)", path.display())]
    FileNotFoundError { path: PathBuf },
    /// The given file is not a file
    #[error("Referenced file '{}' is not a file", path.display())]
    FileNotAFileError { path: PathBuf },
    /// Failed to create the dataset's directory.
    #[error("Failed to create target dataset directory in the Brane data folder")]
    DatasetDirCreateError { source: UtilError },
    /// A dataset with the given name already exists.
    #[error("A dataset with the name '{name}' already exists locally")]
    DuplicateDatasetError { name: String },
    /// Failed to copy the data directory over.
    #[error("Failed to data directory")]
    DataCopyError { source: brane_shr::fs::Error },
    /// Failed to write the DataInfo.
    #[error("Failed to write DataInfo file")]
    DataInfoWriteError { source: specifications::data::DataInfoError },

    /// The given "keypair" was not a keypair at all
    #[error("Missing '=' in key/value pair '{raw}'")]
    NoEqualsInKeyPair { raw: String },
    /// Failed to fetch the login file.
    #[error("Could not read active instance info file")]
    InstanceInfoError { source: InstanceError },
    /// Failed to get the path of the active instance.
    #[error("Failed to read active instance link")]
    ActiveInstanceReadError { source: InstanceError },
    /// Failed to get the active instance.
    #[error("Could not get path of instance '{name}'")]
    InstancePathError { name: String, source: InstanceError },
    /// Failed to create the remote data index.
    #[error("Failed to fetch remote data index from '{address}'")]
    RemoteDataIndexError { address: String, source: brane_tsk::errors::ApiError },
    /// Failed to select the download location in case there are multiple.
    #[error("Failed to ask the user (you!) to select a download location")]
    DataSelectError { source: dialoguer::Error },
    /// We encountered a location we did not know
    #[error("Unknown location '{name}'")]
    UnknownLocation { name: String },

    /// The given dataset was unknown to us.
    #[error("Unknown dataset '{name}'")]
    UnknownDataset { name: String },
    /// the given dataset was known but not locally available.
    #[error("Dataset '{}' is unavailable{}", name, if !locs.is_empty() { format!("; try {} instead", locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")) } else { String::new() })]
    UnavailableDataset { name: String, locs: Vec<String> },

    /// Failed to ask the user for consent before removing the dataset.
    #[error("Failed to ask the user (you) for confirmation before removing a dataset")]
    ConfirmationError { source: dialoguer::Error },
    /// Failed to remove the dataset's directory
    #[error("Failed to remove dataset directory '{}'", path.display())]
    RemoveError { path: PathBuf, source: std::io::Error },
    /// Failed to serialize workflow
    #[error("Could not serialize workflow when: {context}")]
    WorkflowSerializeError { context: String, source: serde_json::Error },
}

/// Collects errors during the import subcommand
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// Error for when we could not create a temporary directory
    #[error("Could not create temporary repository directory")]
    TempDirError { source: std::io::Error },
    /// Could not resolve the path to the temporary repository directory
    #[error("Could not resolve temporary directory path '{}'", path.display())]
    TempDirCanonicalizeError { path: PathBuf, source: std::io::Error },
    /// Error for when we failed to download a repository
    #[error("Could not clone repository at '{}' to directory '{}'", repo, target.display())]
    RepoCloneError { repo: String, target: PathBuf, source: brane_shr::fs::Error },
    /// Error for when a path supposed to refer inside the repository escaped out of it
    #[error("Path '{}' points outside of repository folder", path.display())]
    RepoEscapeError { path: PathBuf },
}

/// Collects errors  during the identity-related subcommands (login, logout).
#[derive(Debug, thiserror::Error)]
pub enum InstanceError {
    /// Failed to get the directory of a specific instance.
    #[error("Failed to get directory for instance")]
    InstanceDirError { source: UtilError },
    /// Failed to open a file to load an InstanceInfo.
    #[error("Failed to open instance info file '{}'", path.display())]
    InstanceInfoOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to read a file to load an InstanceInfo.
    #[error("Failed to read instance info file '{}'", path.display())]
    InstanceInfoReadError { path: PathBuf, source: std::io::Error },
    /// Failed to parse the file to load an InstanceInfo.
    #[error("Failed to parse instance info file '{}' as valid YAML", path.display())]
    InstanceInfoParseError { path: PathBuf, source: serde_yaml::Error },
    /// Failed to (re-)serialize an InstanceInfo.
    #[error("Failed to serialize instance info struct")]
    InstanceInfoSerializeError { source: serde_yaml::Error },
    /// Failed to create a new file to write an InstanceInfo to.
    #[error("Failed to create new info instance file '{}'", path.display())]
    InstanceInfoCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to write an InstanceInfo the given file.
    #[error("Failed to write to instance info file '{}'", path.display())]
    InstanceInfoWriteError { path: PathBuf, source: std::io::Error },

    /// The given instance name is invalid.
    #[error("Instance name '{raw}' contains illegal character '{illegal_char}' (use '--name' to override it with a custom one)")]
    IllegalInstanceName { raw: String, illegal_char: char },
    /// Failed to parse an address from the hostname (and a little modification).
    #[error("Failed to convert hostname to a valid address")]
    AddressParseError { source: specifications::address::AddressParseError },
    /// Failed to send a request to the remote instance.
    #[error(
        "Failed to send request to the instance API at '{address}' (if this is something on your end, you may skip this check by providing \
         '--unchecked')"
    )]
    RequestError { address: String, source: reqwest::Error },
    /// The remote instance was not alive (at least, API/health was not)
    #[error("Remote instance at '{}' is not alive (returned {} ({}){})", address, code, code.canonical_reason().unwrap_or("???"), if let Some(err) = err { format!("\n\nResponse:\n{}\n", BlockFormatter::new(err)) } else { String::new() })]
    InstanceNotAliveError { address: String, code: StatusCode, err: Option<String> },

    /// Failed to ask the user for confirmation.
    #[error("Failed to ask the user (you!) for confirmation (if you are sure, you can skip this step by using '--force')")]
    ConfirmationError { source: dialoguer::Error },

    /// Failed to get the instances directory.
    #[error("Failed to get the instances directory")]
    InstancesDirError { source: UtilError },
    /// Failed to read the instances directory.
    #[error("Failed to read instances directory '{}'", path.display())]
    InstancesDirReadError { path: PathBuf, source: std::io::Error },
    /// Failed to read an entry in the instances directory.
    #[error("Failed to read instances directory '{}' entry {}", path.display(), entry)]
    InstancesDirEntryReadError { path: PathBuf, entry: usize, source: std::io::Error },
    /// Failed to get the actual directory behind the active instance link.
    #[error("Failed to get target of active instance link '{}'", path.display())]
    ActiveInstanceTargetError { path: PathBuf, source: std::io::Error },

    /// The given instance is unknown to us.
    #[error("Unknown instance '{name}'")]
    UnknownInstance { name: String },
    /// The given instance exists but is not a directory.
    #[error("Instance directory '{}' exists but is not a directory", path.display())]
    InstanceNotADirError { path: PathBuf },
    /// Failed to get the path of the active instance link.
    #[error("Failed to get active instance link path")]
    ActiveInstancePathError { source: UtilError },
    /// The active instance file exists but is not a softlink.
    #[error("Active instance link '{}' exists but is not a file", path.display())]
    ActiveInstanceNotAFileError { path: PathBuf },
    /// Failed to read the active instance link file.
    #[error("Failed to read active instance link '{}'", path.display())]
    ActiveInstanceReadError { path: PathBuf, source: std::io::Error },
    /// Failed to remove an already existing active instance link.
    #[error("Failed to remove existing active instance link '{}'", path.display())]
    ActiveInstanceRemoveError { path: PathBuf, source: std::io::Error },
    /// Failed to create a new active instance link.
    #[error("Failed to create active instance link '{}' to '{}'", path.display(), target)]
    ActiveInstanceCreateError { path: PathBuf, target: String, source: std::io::Error },

    /// No instance is active
    #[error("No active instance is set (run 'brane instance select' first)")]
    NoActiveInstance,
}

/// Lists the errors that can occur when trying to do stuff with packages
///
/// Note: `Image` is boxed to avoid the error enum growing too large (see `clippy::reslt_large_err`).
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// Something went wrong while calling utilities
    #[error(transparent)]
    UtilError { source: UtilError },
    /// Something went wrong when fetching an index.
    #[error("Failed to fetch a local package index")]
    IndexError { source: brane_tsk::local::Error },

    /// Failed to resolve a specific package/version pair
    #[error("Package '{name}' does not exist or has no version {version}")]
    PackageVersionError { name: String, version: Version, source: UtilError },
    /// Failed to resolve a specific package
    #[error("Package '{name}' does not exist")]
    PackageError { name: String, source: UtilError },
    /// Failed to ask for the user's consent
    #[error("Failed to ask for your consent")]
    ConsentError { source: dialoguer::Error },
    /// Failed to remove a package directory
    #[error("Failed to remove package '{}' (version {}) at '{}'", name, version, dir.display())]
    PackageRemoveError { name: String, version: Version, dir: PathBuf, source: std::io::Error },
    /// Failed to get the versions of a package
    #[error("Failed to get versions of package '{}' (at '{}')", name, dir.display())]
    VersionsError { name: String, dir: PathBuf, source: std::io::Error },
    /// Failed to parse the version of a package
    #[error("Could not parse '{raw}' as a version for package '{name}'")]
    VersionParseError { name: String, raw: String, source: specifications::version::ParseError },
    /// Failed to load the PackageInfo of the given package
    #[error("Could not load package info file '{}'", path.display())]
    PackageInfoError { path: PathBuf, source: specifications::package::PackageInfoError },
    /// The given PackageInfo has no digest set
    #[error("Package info file '{}' has no digest set", path.display())]
    PackageInfoNoDigest { path: PathBuf },
    /// Could not remove the given image from the Docker daemon
    #[error("Failed to remove image '{}' from the local Docker daemon", image.digest().unwrap_or("<no digest given>"))]
    DockerRemoveError { image: Box<Image>, source: brane_tsk::errors::DockerError },
}

/// Collects errors during the registry subcommands
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Wrapper error indeed.
    #[error(transparent)]
    InstanceInfoError { source: InstanceError },

    /// Failed to successfully send the package pull request
    #[error("Could not send the request to pull pacakge to '{url}'")]
    PullRequestError { url: String, source: reqwest::Error },
    /// The request was sent successfully, but the server replied with a non-200 access code
    #[error("Request to pull package from '{}' was met with status code {} ({})", url, status.as_u16(), status.canonical_reason().unwrap_or("???"))]
    PullRequestFailure { url: String, status: reqwest::StatusCode },
    /// The request did not have a content length specified
    #[error("Response from '{url}' did not have 'Content-Length' header set")]
    MissingContentLength { url: String },
    /// Failed to convert the content length from raw bytes to string
    #[error("Could not convert content length received from '{url}' to string")]
    ContentLengthStrError { url: String, source: reqwest::header::ToStrError },
    /// Failed to parse the content length as a number
    #[error("Could not parse '{raw}' as a number (the content-length received from '{url}')")]
    ContentLengthParseError { url: String, raw: String, source: std::num::ParseIntError },
    /// Failed to download the actual package
    #[error("Could not download package from '{url}'")]
    PackageDownloadError { url: String, source: reqwest::Error },
    /// Failed to write the downloaded package to the given file
    #[error("Could not write package downloaded from '{}' to '{}'", url, path.display())]
    PackageWriteError { url: String, path: PathBuf, source: std::io::Error },
    /// Failed to create the package directory
    #[error("Could not create package directory '{}'", path.display())]
    PackageDirCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to copy the downloaded package over
    #[error("Could not copy package from '{}' to '{}'", original.display(), target.display())]
    PackageCopyError { original: PathBuf, target: PathBuf, source: std::io::Error },
    /// Failed to send GraphQL request for package info
    #[error("Could not send a GraphQL request to '{url}'")]
    GraphQLRequestError { url: String, source: reqwest::Error },
    /// Failed to receive GraphQL response with package info
    #[error("Could not get the GraphQL respones from '{url}'")]
    GraphQLResponseError { url: String, source: reqwest::Error },
    /// Could not parse the kind as a proper PackageInfo kind
    #[error("Could not parse '{raw}' (received from '{url}') as package kind")]
    KindParseError { url: String, raw: String, source: specifications::package::PackageKindError },
    /// Could not parse the version as a proper PackageInfo version
    #[error("Could not parse '{raw}' (received from '{url}') as package version")]
    VersionParseError { url: String, raw: String, source: specifications::version::ParseError },
    /// Could not parse the list of requirements of the package.
    #[error("Could not parse '{raw}' (received from '{url}') as package requirement")]
    RequirementParseError { url: String, raw: String, source: serde_json::Error },
    /// Could not parse the functions as proper PackageInfo functions
    #[error("Could not parse '{raw}' (received from '{url}') as package functions")]
    FunctionsParseError { url: String, raw: String, source: serde_json::Error },
    /// Could not parse the types as proper PackageInfo types
    #[error("Could not parse '{raw}' (received from '{url}') as package types")]
    TypesParseError { url: String, raw: String, source: serde_json::Error },
    /// Could not create a file for the PackageInfo
    #[error("Could not create PackageInfo file '{}'", path.display())]
    PackageInfoCreateError { path: PathBuf, source: std::io::Error },
    /// Could not write the PackageInfo
    #[error("Could not write to PackageInfo file '{}'", path.display())]
    PackageInfoWriteError { path: PathBuf, source: serde_yaml::Error },
    /// Failed to retrieve the PackageInfo
    #[error("Server '{url}' responded with empty response (is your name/version correct?)")]
    NoPackageInfo { url: String },

    /// Failed to resolve the packages directory
    #[error("Could not resolve the packages directory")]
    PackagesDirError { source: UtilError },
    /// Failed to get all versions for the given package
    #[error("Could not get version list for package '{name}'")]
    VersionsError { name: String, source: brane_tsk::local::Error },
    /// Failed to resolve the directory of a specific package
    #[error("Could not resolve package directory of package '{name}' (version {version})")]
    PackageDirError { name: String, version: Version, source: UtilError },
    /// Could not create a new temporary file
    #[error("Could not create a new temporary file")]
    TempFileError { source: std::io::Error },
    /// Could not compress the package file
    #[error("Could not compress package '{}' (version {}) to '{}'", name, version, path.display())]
    CompressionError { name: String, version: Version, path: PathBuf, source: std::io::Error },
    /// Failed to re-open the compressed package file
    #[error("Could not re-open compressed package archive '{}'", path.display())]
    PackageArchiveOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to upload the compressed file to the instance
    #[error("Could not upload compressed package archive '{}' to '{}'", path.display(), endpoint)]
    UploadError { path: PathBuf, endpoint: String, source: reqwest::Error },
}

/// Collects errors during the repl subcommand
#[derive(Debug, thiserror::Error)]
pub enum ReplError {
    /// Could not create the config directory
    #[error("Could not create the configuration directory for the REPL history")]
    ConfigDirCreateError { source: UtilError },
    /// Could not get the location of the REPL history file
    #[error("Could not get REPL history file location")]
    HistoryFileError { source: UtilError },
    /// Failed to create the new rustyline editor.
    #[error("Failed to create new rustyline editor")]
    EditorCreateError { source: rustyline::error::ReadlineError },
    /// Failed to load the login file.
    #[error("Failed to load instance info file")]
    InstanceInfoError { source: InstanceError },

    /// Failed to initialize one of the states.
    #[error("Failed to initialize {what} and associated structures")]
    InitializeError { what: &'static str, source: RunError },
    /// Failed to run one of the VMs/clients.
    #[error("Failed to execute workflow on {what}")]
    RunError { what: &'static str, source: RunError },
    /// Failed to process the VM result.
    #[error("Failed to process {what} workflow results")]
    ProcessError { what: &'static str, source: RunError },
}

/// Collects errors during the run subcommand.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// Failed to write to the given formatter.
    #[error("Failed to write to the given formatter")]
    WriteError {
        #[from]
        source: std::io::Error,
    },

    /// Failed to create the local package index.
    #[error("Failed to fetch local package index")]
    LocalPackageIndexError { source: brane_tsk::local::Error },
    /// Failed to create the local data index.
    #[error("Failed to fetch local data index")]
    LocalDataIndexError { source: brane_tsk::local::Error },
    /// Failed to get the packages directory.
    #[error("Failed to get packages directory")]
    PackagesDirError { source: UtilError },
    /// Failed to get the datasets directory.
    #[error("Failed to get datasets directory")]
    DatasetsDirError { source: UtilError },
    /// Failed to create a temporary intermediate results directory.
    #[error("Failed to create new temporary directory as an intermediate result directory")]
    ResultsDirCreateError { source: std::io::Error },

    /// Failed to fetch the login file.
    #[error(transparent)]
    InstanceInfoError { source: InstanceError },
    /// Failed to get the path of the active instance.
    #[error("Failed to read active instance link")]
    ActiveInstanceReadError { source: InstanceError },
    /// Failed to get the active instance.
    #[error("Could not get path of instance '{name}'")]
    InstancePathError { name: String, source: InstanceError },
    /// Failed to create the remote package index.
    #[error("Failed to fetch remote package index from '{address}'")]
    RemotePackageIndexError { address: String, source: brane_tsk::errors::ApiError },
    /// Failed to create the remote data index.
    #[error("Failed to fetch remote data index from '{address}'")]
    RemoteDataIndexError { address: String, source: brane_tsk::errors::ApiError },
    /// Failed to pull the delegate map from the remote delegate index(ish - `brane-api`)
    #[error("Failed to fetch delegates map from '{address}'")]
    RemoteDelegatesError { address: String, source: DelegatesError },
    /// Could not connect to the given address
    #[error("Could not connect to remote Brane instance '{address}'")]
    ClientConnectError { address: String, source: specifications::driving::Error },
    /// Failed to parse the AppId send by the remote driver.
    ///
    /// Note: `err` is boxed to avoid this error enum growing too large.
    #[error("Could not parse '{raw}' send by remote '{address}' as an application ID")]
    AppIdError { address: String, raw: String, source: Box<brane_tsk::errors::IdError> },
    /// Could not create a new session on the given address
    #[error("Could not create new session with remote Brane instance '{address}': remote returned status")]
    SessionCreateError { address: String, source: tonic::Status },

    /// An error occurred while compile the given snippet. It will already have been printed to stdout.
    #[error("Compilation of workflow failed (see output above)")]
    CompileError(brane_ast::errors::CompileError),
    /// Failed to serialize the compiled workflow.
    #[error("Failed to serialize the compiled workflow")]
    WorkflowSerializeError { source: serde_json::Error },
    /// Requesting a command failed
    #[error("Could not run command on remote Brane instance '{address}': request failed: remote returned status")]
    CommandRequestError { address: String, source: tonic::Status },
    /// Failed to parse the value returned by the remote driver.
    #[error("Could not parse '{raw}' sent by remote '{address}' as a value")]
    ValueParseError { address: String, raw: String, source: serde_json::Error },
    /// The workflow was denied by some checker.
    #[error("Workflow was denied")]
    ExecDenied { source: Box<dyn Error> },
    /// Failed to run the workflow
    #[error("Failed to run workflow")]
    ExecError { source: Box<dyn Error> },

    /// The returned dataset was unknown.
    #[error("Unknown dataset '{name}'")]
    UnknownDataset { name: String },
    /// The returend dataset was known but not available locally.
    #[error("Unavailable dataset '{}'{}", name, if !locs.is_empty() { format!("; it is available at {}", PrettyListFormatter::new(locs.iter().map(|l| format!("'{l}'")), "or")) } else { String::new() })]
    UnavailableDataset { name: String, locs: Vec<String> },
    /// Failed to download remote dataset.
    #[error("Failed to download remote dataset")]
    DataDownloadError { source: DataError },
    /// Workflow returned result without PC.
    #[error("Workflow returned data \"{data}\" without providing information where in the workflow it's downloaded from.")]
    DataDownloadWithoutPc { data: DataId },

    /// Failed to read the source from stdin
    #[error("Failed to read source from stdin")]
    StdinReadError { source: std::io::Error },
    /// Failed to read the source from a given file
    #[error("Failed to read source from file '{}'", path.display())]
    FileReadError { path: PathBuf, source: std::io::Error },
    /// Failed to load the login file.
    #[error(transparent)]
    LoginFileError { source: UtilError },
}

/// Collects errors during the test subcommand.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
    /// Failed to get the local data index.
    #[error("Failed to load local data index")]
    DataIndexError { source: brane_tsk::local::Error },
    /// Failed to prompt the user for the function/input selection.
    #[error("Failed to ask the user (you!) for input")]
    InputError { source: brane_tsk::input::Error },

    /// Failed to create a temporary directory
    #[error("Failed to create temporary results directory")]
    TempDirError { source: std::io::Error },
    /// We can't access a dataset in the local instance.
    #[error("Dataset '{}' is unavailable{}", name, if !locs.is_empty() { format!( "; however, locations {} do (try to get download permission to those datasets)", locs.iter().map(|l| format!("'{l}'")).collect::<Vec<String>>().join(", ")) } else { String::new() })]
    DatasetUnavailable { name: String, locs: Vec<String> },
    /// The given dataset was unknown to us.
    #[error("Unknown dataset '{name}'")]
    UnknownDataset { name: String },
    /// Failed to get the general package directory.
    #[error("Failed to get packages directory")]
    PackagesDirError { source: UtilError },
    /// Failed to get the general dataset directory.
    #[error("Failed to get datasets directory")]
    DatasetsDirError { source: UtilError },
    /// Failed to get the directory of a package.
    #[error("Failed to get directory of package '{name}' (version {version})")]
    PackageDirError { name: String, version: Version, source: UtilError },
    /// Failed to read the PackageInfo of the given package.
    #[error("Failed to read package info for package '{name}' (version {version})")]
    PackageInfoError { name: String, version: Version, source: specifications::package::PackageInfoError },

    /// Failed to initialize the offline VM.
    #[error("Failed to initialize offline VM")]
    InitializeError { source: RunError },
    /// Failed to run the offline VM.
    #[error("Failed to run offline VM")]
    RunError { source: RunError },
    /// Failed to read the intermediate results file.
    #[error("Failed to read intermediate result file '{}'", path.display())]
    IntermediateResultFileReadError { path: PathBuf, source: std::io::Error },
}

/// Collects errors relating to the verify command.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Failed to verify the config
    #[error("Failed to verify configuration")]
    ConfigFailed { source: brane_cfg::infra::Error },
}

/// Collects errors relating to the version command.
#[derive(Debug, thiserror::Error)]
pub enum VersionError {
    /// Could not get the host architecture
    #[error("Could not get the host processor architecture")]
    HostArchError { source: specifications::arch::ArchError },
    /// Could not parse a Version number.
    #[error("Could parse '{raw}' as Version")]
    VersionParseError { raw: String, source: specifications::version::ParseError },

    /// Could not discover if the instance existed.
    #[error("Could not check if active instance exists")]
    InstanceInfoExistsError { source: InstanceError },
    /// Could not open the login file
    #[error(transparent)]
    InstanceInfoError { source: InstanceError },
    /// Could not perform the request
    #[error("Could not perform request to '{url}'")]
    RequestError { url: String, source: reqwest::Error },
    /// The request returned a non-200 exit code
    #[error("Request to '{}' returned non-zero exit code {} ({})", url, status.as_u16(), status.canonical_reason().unwrap_or("<???>"))]
    RequestFailure { url: String, status: reqwest::StatusCode },
    /// The request's body could not be get.
    #[error("Could not get body from response from '{url}'")]
    RequestBodyError { url: String, source: reqwest::Error },
}

/// Collects errors of utilities that don't find an origin in just one subcommand.
#[derive(Debug, thiserror::Error)]
pub enum UtilError {
    /// Could not connect to the local Docker instance
    #[error("Could not connect to local Docker instance")]
    DockerConnectionFailed { source: bollard::errors::Error },
    /// Could not get the version of the Docker daemon
    #[error("Could not get version of the local Docker instance")]
    DockerVersionError { source: bollard::errors::Error },
    /// The docker daemon returned something, but not the version
    #[error("Local Docker instance doesn't report a version number")]
    DockerNoVersion,
    /// The version reported by the Docker daemon is not a valid version
    #[error("Local Docker instance reports unparseable version '{version}'")]
    IllegalDockerVersion { version: String, source: VersionParseError },
    /// Could not launch the command to get the Buildx version
    #[error("Could not run command '{command}' to get Buildx version information")]
    BuildxLaunchError { command: String, source: std::io::Error },
    /// The Buildx version in the buildx command does not have at least two parts, separated by spaces
    #[error("Illegal Buildx version '{version}': did not find second part (separted by spaces) with version number")]
    BuildxVersionNoParts { version: String },
    /// The Buildx version is not prepended with a 'v'
    #[error("Illegal Buildx version '{version}': did not find 'v' prepending version number")]
    BuildxVersionNoV { version: String },
    /// The version reported by Buildx is not a valid version
    #[error("Buildx reports unparseable version '{version}'")]
    IllegalBuildxVersion { version: String, source: VersionParseError },

    /// Could not read from a given directory
    #[error("Could not read from directory '{}'", dir.display())]
    DirectoryReadError { dir: PathBuf, source: std::io::Error },
    /// Could not automatically determine package file inside a directory.
    #[error("Could not determine package file in directory '{}'; specify it manually with '--file'", dir.display())]
    UndeterminedPackageFile { dir: PathBuf },

    /// Could not open the main package file of the package to build.
    #[error("Could not open package file '{}'", file.display())]
    PackageFileOpenError { file: PathBuf, source: std::io::Error },
    /// Could not read the main package file of the package to build.
    #[error("Could not read from package file '{}'", file.display())]
    PackageFileReadError { file: PathBuf, source: std::io::Error },
    /// Could not automatically determine package kind based on the file.
    #[error("Could not determine package from package file '{}'; specify it manually with '--kind'", file.display())]
    UndeterminedPackageKind { file: PathBuf },

    /// Could not find the user config folder
    #[error("Could not find the user's config directory for your OS (reported as {})", std::env::consts::OS)]
    UserConfigDirNotFound,
    /// Could not create brane's folder in the config folder
    #[error("Could not create Brane config directory '{}'", path.display())]
    BraneConfigDirCreateError { path: PathBuf, source: std::io::Error },
    /// Could not find brane's folder in the config folder
    #[error("Brane config directory '{}' not found", path.display())]
    BraneConfigDirNotFound { path: PathBuf },

    /// Could not create Brane's history file
    #[error("Could not create history file '{}' for the REPL", path.display())]
    HistoryFileCreateError { path: PathBuf, source: std::io::Error },
    /// Could not find Brane's history file
    #[error("History file '{}' for the REPL does not exist", path.display())]
    HistoryFileNotFound { path: PathBuf },

    /// Could not find the user local data folder
    #[error("Could not find the user's local data directory for your OS (reported as {})", std::env::consts::OS)]
    UserLocalDataDirNotFound,
    /// Could not find create brane's folder in the data folder
    #[error("Could not create Brane data directory '{}'", path.display())]
    BraneDataDirCreateError { path: PathBuf, source: std::io::Error },
    /// Could not find brane's folder in the data folder
    #[error("Brane data directory '{}' not found", path.display())]
    BraneDataDirNotFound { path: PathBuf },

    /// Could not find create the package folder inside brane's data folder
    #[error("Could not create Brane package directory '{}'", path.display())]
    BranePackageDirCreateError { path: PathBuf, source: std::io::Error },
    /// Could not find the package folder inside brane's data folder
    #[error("Brane package directory '{}' not found", path.display())]
    BranePackageDirNotFound { path: PathBuf },

    /// Could not create the dataset folder inside brane's data folder
    #[error("Could not create Brane datasets directory '{}'", path.display())]
    BraneDatasetsDirCreateError { path: PathBuf, source: std::io::Error },
    /// Could not find the dataset folder inside brane's data folder.
    #[error("Brane datasets directory '{}' not found", path.display())]
    BraneDatasetsDirNotFound { path: PathBuf },

    /// Failed to read the versions in a package's directory.
    #[error("Failed to read package versions")]
    VersionsError { source: brane_tsk::errors::LocalError },

    /// Could not create the directory for a package
    #[error("Could not create directory for package '{}' (path: '{}')", package, path.display())]
    PackageDirCreateError { package: String, path: PathBuf, source: std::io::Error },
    /// The target package directory does not exist
    #[error("Directory for package '{}' does not exist (path: '{}')", package, path.display())]
    PackageDirNotFound { package: String, path: PathBuf },
    /// Could not create a new directory for the given version
    #[error("Could not create directory for package '{}', version: {} (path: '{}')", package, version, path.display())]
    VersionDirCreateError { package: String, version: Version, path: PathBuf, source: std::io::Error },
    /// The target package/version directory does not exist
    #[error("Directory for package '{}', version: {} does not exist (path: '{}')", package, version, path.display())]
    VersionDirNotFound { package: String, version: Version, path: PathBuf },

    /// Could not create the dataset folder for a specific dataset
    #[error("Could not create Brane dataset directory '{}' for dataset '{}'", path.display(), name)]
    BraneDatasetDirCreateError { name: String, path: PathBuf, source: std::io::Error },
    /// Could not find the dataset folder for a specific dataset.
    #[error("Brane dataset directory '{}' for dataset '{}' not found", path.display(), name)]
    BraneDatasetDirNotFound { name: String, path: PathBuf },

    /// Could not create the instances folder.
    #[error("Failed to create Brane instance directory '{}'", path.display())]
    BraneInstancesDirCreateError { path: PathBuf, source: std::io::Error },
    /// The instances folder did not exist.
    #[error("Brane instance directory '{}' not found", path.display())]
    BraneInstancesDirNotFound { path: PathBuf },
    /// Could not create the instance folder for a specific instance.
    #[error("Failed to create directory '{}' for new instance '{}'", path.display(), name)]
    BraneInstanceDirCreateError { path: PathBuf, name: String, source: std::io::Error },
    /// The instance folder for a specific instance did not exist.
    #[error("Brane instance directory '{}' for instance '{}' not found", path.display(), name)]
    BraneInstanceDirNotFound { path: PathBuf, name: String },

    /// The given name is not a valid bakery name.
    #[error("The given name '{name}' is not a valid name; expected alphanumeric or underscore characters")]
    InvalidBakeryName { name: String },
}

/// Defines errors that relate to finding our directories.
#[derive(Debug, thiserror::Error)]
pub enum DirError {
    /// Failed to find a user directory. The `what` hints at the kind of user directory (fill in "\<what\> directory", e.g., "config", "data", ...)
    #[error("Failed to find user {} directory", what)]
    UserDirError { what: &'static str },
    /// Failed to read the softlink.
    #[error("Failed to read softlink '{}'", path.display())]
    SoftlinkReadError { path: PathBuf, source: std::io::Error },
}

/// Declares errors that relate to parsing hostnames from a string.
#[derive(Debug, thiserror::Error)]
pub enum HostnameParseError {
    /// The scheme contained an illegal character.
    #[error("URL scheme '{raw}' contains illegal character '{c}'")]
    IllegalSchemeChar { raw: String, c: char },
    /// The hostname contained a path separator.
    #[error("Hostname '{raw}' is not just a hostname (it contains a nested path)")]
    HostnameContainsPath { raw: String },
}

/// Declares errors that relate to the offline VM.
#[derive(Debug, thiserror::Error)]
pub enum OfflineVmError {
    /// Failed to plan a workflow.
    #[error("Failed to plan workflow")]
    PlanError { source: brane_tsk::errors::PlanError },
    /// Failed to run a workflow.
    #[error("Failed to execute workflow")]
    ExecError { source: brane_exe::Error },
}

/// A really specific error enum for errors relating to fetching delegates.
#[derive(Debug, thiserror::Error)]
pub enum DelegatesError {
    /// Failed to sent the GET-request to fetch the map.
    #[error("Failed to send delegates request to '{address}'")]
    RequestError { address: String, source: reqwest::Error },
    /// The request returned a non-2xx status code.
    #[error("Request to '{}' failed with status code {} ({}){}", address, code, code.canonical_reason().unwrap_or("???"), if let Some(msg) = message { format!(": {msg}") } else { String::new() })]
    RequestFailure { address: String, code: StatusCode, message: Option<String> },
    /// Failed to get the request body properly.
    #[error("Failed to get body from response sent by '{address}' as text")]
    ResponseTextError { address: String, source: reqwest::Error },
    /// Failed to parse the request body properly.
    #[error("Failed to parse response body '{raw}' sent by '{address}' as a delegate map")]
    ResponseParseError { address: String, raw: String, source: serde_json::Error },
}
