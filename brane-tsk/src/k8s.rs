//  K 8S.rs
//    by Lut99
// 
//  Created:
//    08 May 2023, 13:01:23
//  Last edited:
//    02 Oct 2023, 17:21:24
//  Auto updated?
//    Yes
// 
//  Description:
//!   Provides an API for running Brane tasks on a Kubernetes backend.
// 

use std::any::type_name;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::mem;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::str::FromStr as _;

pub use kube::Config;
pub use k8s_openapi::api::core::v1::{Pod, Secret};
pub use k8s_openapi::api::batch::v1::Job;
use base64::Engine as _;
use enum_debug::EnumDebug;
use hex_literal::hex;
use futures_util::TryStreamExt as _;
use k8s_openapi::NamespaceResourceScope;
use k8s_openapi::api::core::v1::{ContainerState, ContainerStateRunning, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus};
use kube::api::{Api, DeleteParams, LogParams, PostParams, Resource};
use kube::config::{Kubeconfig, KubeConfigOptions};
use kube::runtime::wait::await_condition;
use tracing::{debug, info, warn};
use rand::Rng as _;
use rand::distributions::Uniform;
use serde::de::DeserializeOwned;
use serde_json::json;
use tokio::fs as tfs;

use brane_shr::errors::ErrorTrace as _;
use brane_shr::fs::{download_file_async, set_executable, unarchive_async, DownloadSecurity};
use specifications::address::Address;
use specifications::container::Image;
use specifications::version::Version;

use crate::docker::ImageSource;


/***** TESTS *****/
#[cfg(test)]
mod tests {
    use brane_shr::errors::ErrorTrace as _;
    use super::*;

    /// Function that tests downloading the crane executable from the internet.
    /// 
    /// Essentially just checks if everything proceeds without errors, and if we can then call '--version' on it.
    #[tokio::test]
    async fn test_crane_download() {
        // Prepare a temporary directory
        if let Err(err) = tfs::create_dir_all("./temp").await { panic!("Failed to create temporary directory './temp': {err}"); }

        // Ensure the executable exists
        if let Err(err) = ensure_crane_exe("./temp/crane", "./temp").await {
            if let Err(err) = tfs::remove_dir_all("./temp").await { warn!("Failed to cleanup temporary directory './temp': {err}"); }
            panic!("Failed to ensure crane executable: {}", err.trace());
        }

        // Attempt to run `--version`
        let mut cmd: Command = Command::new("./temp/crane");
        cmd.arg("version");
        match cmd.status() {
            Ok(status) => if !status.success() {
                if let Err(err) = tfs::remove_dir_all("./temp").await { warn!("Failed to cleanup temporary directory './temp': {err}"); }
                panic!("Failed to run './temp/crane' (see output above)");
            },
            Err(err)   => {
                if let Err(err) = tfs::remove_dir_all("./temp").await { warn!("Failed to cleanup temporary directory './temp': {err}"); }
                panic!("Failed to spawn job './temp/crane': {err}");
            },
        }

        // Done! Cleanup
        if let Err(err) = tfs::remove_dir_all("./temp").await { warn!("Failed to cleanup temporary directory './temp': {err}"); }
    }
}





/***** CONSTANTS *****/
/// Defines the address we download the x86-64 `crane` tar from.
pub const CRANE_TAR_URL_X86_64: &str = "https://github.com/google/go-containerregistry/releases/download/v0.15.1/go-containerregistry_Linux_x86_64.tar.gz";
/// Defines the address we download the ARM64 `crane` tar from.
pub const CRANE_TAR_URL_ARM64: &str = "https://github.com/google/go-containerregistry/releases/download/v0.15.1/go-containerregistry_Linux_arm64.tar.gz";

/// The location where we expect the `crane` executable to be, locally.
pub const CRANE_PATH: &str = "/tmp/crane";
/// The checksum of the executable.
pub const CRANE_TAR_CHECKSUM: [u8; 32] = hex!("d4710014a3bd135eb1d4a9142f509cfd61d2be242e5f5785788e404448a4f3f2");

/// Defines the name of the output prefix environment variable.
const OUTPUT_PREFIX_NAME: &str = "ENABLE_STDOUT_PREFIX";
/// The thing we prefix to the output stdout so the Kubernetes engine can recognize valid output when it sees it.
const OUTPUT_PREFIX: &str = "[OUTPUT] ";





/***** ERRORS *****/
/// Defines errors that occur when downloading the `crane` executable.
#[derive(Debug)]
pub enum CraneError {
    /// Failed to download the `crane` executable tarball.
    DownloadCraneTar{ from: &'static str, to: PathBuf, err: brane_shr::fs::Error },
    /// Failed to unpack the `crane` executable tarball.
    UnpackCraneTar{ from: PathBuf, to: PathBuf, err: brane_shr::fs::Error },
    /// Failed to move the `crane` executable from the downloaded folder to the target path.
    MoveCrane{ from: PathBuf, to: PathBuf, err: std::io::Error },
    /// Failed to make the `crane` executable... executable.
    MakeCraneExecutable{ path: PathBuf, err: brane_shr::fs::Error },
}
impl Display for CraneError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CraneError::*;
        match self {
            DownloadCraneTar{ from, to, .. } => write!(f, "Failed to download tarball from '{}' to '{}'", from, to.display()),
            UnpackCraneTar{ from, to, .. }   => write!(f, "Failed to unpack tarball '{}' to '{}'", from.display(), to.display()),
            MoveCrane{ from, to, .. }        => write!(f, "Failed to move executable from '{}' to '{}'", from.display(), to.display()),
            MakeCraneExecutable{ path, .. }  => write!(f, "Failed to make executable '{}' executable", path.display()),
        }
    }
}
impl Error for CraneError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use CraneError::*;
        match self {
            DownloadCraneTar{ err, .. }    => Some(err),
            UnpackCraneTar{ err, .. }      => Some(err),
            MoveCrane{ err, .. }           => Some(err),
            MakeCraneExecutable{ err, .. } => Some(err),
        }
    }
}



/// Defines errors that occur when resolving an image source (i.e., pushing to a registry).
#[derive(Debug)]
pub enum ResolveError {
    /// Failed to download the crane client.
    CraneExe{ err: CraneError },
    /// Failed to launch the command to login to a registry.
    LaunchLogin{ what: Command, err: std::io::Error },
    /// Failed to launch the command to push the image to a remote registry.
    LaunchPush{ what: Command, err: std::io::Error },
    /// The login command was launched successfully, but failed.
    LoginFailure{ registry: Address, err: Box<Self> },
    /// The push command was launched successfully, but failed.
    PushFailure{ path: PathBuf, image: String, err: Box<Self> },
    /// Some command failed.
    CommandFailure{ what: Command, status: ExitStatus, stdout: String, stderr: String },
}
impl Display for ResolveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ResolveError::*;
        match self {
            CraneExe{ .. }                                 => write!(f, "Failed to download `crane` registry client"),
            LaunchLogin{ what, .. }                        => write!(f, "Failed to launch command '{what:?}' to login to remote registry"),
            LaunchPush{ what, .. }                         => write!(f, "Failed to launch command '{what:?}' to push image"),
            LoginFailure{ registry, .. }                   => write!(f, "Failed to login to remote registry '{registry}'"),
            PushFailure{ path, image, .. }                 => write!(f, "Failed to push image '{}' to '{}'", path.display(), image),
            CommandFailure{ what, status, stdout, stderr } => write!(f, "Command '{:?}' failed with exit code {}\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n", what, status.code().unwrap_or(-1), (0..80).map(|_| '-').collect::<String>(), stdout, (0..80).map(|_| '-').collect::<String>(), (0..80).map(|_| '-').collect::<String>(), stderr, (0..80).map(|_| '-').collect::<String>()),
        }
    }
}
impl Error for ResolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ResolveError::*;
        match self {
            CraneExe{ err }          => Some(err),
            LaunchLogin{ err, .. }   => Some(err),
            LaunchPush{ err, .. }    => Some(err),
            LoginFailure{ err, .. }  => Some(err),
            PushFailure{ err, .. }   => Some(err),
            CommandFailure{ .. } => None,
        }
    }
}

/// Defines errors that occur when reading a config.
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to open the config file for reading.
    FileRead{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the given file as a valid kube config YAML file.
    Parse{ path: PathBuf, err: serde_yaml::Error },
    /// Failed to compile the parsed YAML to a Kubernetes configuration.
    Compile{ path: PathBuf, err: kube::config::KubeconfigError },
}
impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ConfigError::*;
        match self {
            FileRead { path, err } => write!(f, "Failed to read file '{}': {}", path.display(), err),
            Parse{ path, .. }      => write!(f, "Failed to parse file '{}' as a Kubernetes configuration YAML file", path.display()),
            Compile{ path, .. }    => write!(f, "Failed to compile parsed Kubernetes configuration YAML (from '{}')", path.display()),
        }
    }
}
impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ConfigError::*;
        match self {
            FileRead { .. }    => None,
            Parse{ err, .. }   => Some(err),
            Compile{ err, .. } => Some(err),
        }
    }
}

/// Defines errors that occur when working with clients.
#[derive(Debug)]
pub enum ClientError {
    /// Failed to load a given config file.
    LoadConfig{ err: ConfigError },
    /// Failed to create a [`kube::Client`] from a [`kube::Config`].
    CreateClient{ err: kube::Error },
}
impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ClientError::*;
        match self {
            LoadConfig{ .. }    => write!(f, "Failed to load Kubernetes client config file"),
            CreateClient { .. } => write!(f, "Failed to create client from given config"),
        }
    }
}
impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ClientError::*;
        match self {
            LoadConfig{ err }    => Some(err),
            CreateClient { err } => Some(err),
        }
    }
}

/// Defines errors that occur when working with connections.
#[derive(Debug)]
pub enum ScopeError {
    /// Failed to spawn a kubernetes secret.
    CreateSecret{ registry: Address, id: String, err: kube::Error },
    /// Failed to spawn the Kubernetes job
    CreateJob{ name: String, version: Version, id: String, err: kube::Error },
}
impl Display for ScopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ScopeError::*;
        match self {
            CreateSecret { registry, id, .. }   => write!(f, "Failed to create a Docker registry secret with ID '{id}' for registry '{registry}'"),
            CreateJob { name, version, id, .. } => write!(f, "Failed to launch package {}:{} as Kubernetes job with ID '{}'", name, version, id),
        }
    }
}
impl Error for ScopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ScopeError::*;
        match self {
            CreateSecret { err, .. } => Some(err),
            CreateJob { err, .. }    => Some(err),
        }
    }
}

/// Defines errors that may occur when working with the Handle.
#[derive(Debug)]
pub enum HandleError {
    /// Failed to terminate the pod.
    TerminatePod{ id: String, err: kube::Error },
    /// Failed to wait for the pod to become Ready.
    WaitReady{ id: String, err: kube::runtime::wait::Error },
    /// Failed to pull the image on the Kubernetes side.
    PullImage{ id: String, err: Option<String> },
    /// Failed to read the pod's logs.
    ReadLogs{ id: String, err: kube::Error },
}
impl Display for HandleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use HandleError::*;
        match self {
            TerminatePod { id, .. } => write!(f, "Failed to terminate pod '{id}'"),
            WaitReady{ id, .. }     => write!(f, "Failed to wait for pod '{id}' to become ready"),
            PullImage{ id, err }    => write!(f, "Failed to pull the image for pod '{}'{}", id, if let Some(message) = err { format!(": {message}") } else { String::new() }),
            ReadLogs{ id, .. }      => write!(f, "Failed to read logs of pod '{id}'"),
        }
    }
}
impl Error for HandleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use HandleError::*;
        match self {
            TerminatePod{ err, .. } => Some(err),
            WaitReady{ err, .. }    => Some(err),
            PullImage{ .. }         => None,
            ReadLogs{ err, .. }     => Some(err),
        }
    }
}





/***** HELPER FUNCTIONS *****/
/// Ensures that the `crane` executable is downloaded at the given location.
/// 
/// # Arguments
/// - `path`: The path to put the `crane` executable.
/// - `temp_dir`: Some (already existing!) directory to download intermediary files and unpacking them and such.
/// 
/// # Errors
/// This function errors if we faield to find _and_ download the file.
async fn ensure_crane_exe(path: impl AsRef<Path>, temp_dir: impl AsRef<Path>) -> Result<(), CraneError> {
    let path     : &Path = path.as_ref();
    let temp_dir : &Path = temp_dir.as_ref();
    debug!("Ensuring `crate` executable exists at '{}'...", path.display());

    // Resolve where to get the executable from
    #[cfg(target_arch = "x86_64")]
    const URL: &str = CRANE_TAR_URL_X86_64;
    #[cfg(target_arch = "aarch64")]
    const URL: &str = CRANE_TAR_URL_ARM64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported non-x86_64, non-ARM64 architecture");

    // Check if it already exists, that's nice then
    if path.exists() {
        debug!("Executable '{}' found, marked as present", path.display());
        return Ok(());
    }
    debug!("Executable '{}' not found, marked as missing", path.display());

    // Otherwise, we should attempt to download the crane executable's tarball
    let tar_path: PathBuf = temp_dir.join("go-containerregistry_Linux.tar.gz");
    debug!("Downloading '{}' to '{}'...", URL, tar_path.display());
    if let Err(err) = download_file_async(URL, &tar_path, DownloadSecurity::all(&CRANE_TAR_CHECKSUM), None).await {
        return Err(CraneError::DownloadCraneTar { from: URL, to: tar_path, err });
    }

    // Unpack the tarball
    let dir_path: PathBuf = temp_dir.join("go-containerregistry_Linux");
    debug!("Unpacking '{}' to '{}'...", tar_path.display(), dir_path.display());
    if let Err(err) = unarchive_async(&tar_path, &dir_path).await {
        return Err(CraneError::UnpackCraneTar{ from: tar_path, to: dir_path, err });
    }

    // Move the directory's crane executable to the target location
    let crane_path: PathBuf = dir_path.join("crane");
    debug!("Extracting '{}' to '{}'...", crane_path.display(), path.display());
    if let Err(err) = tfs::copy(&crane_path, path).await {
        return Err(CraneError::MoveCrane{ from: crane_path, to: path.into(), err });
    }
    // Make it executable, too
    if let Err(err) = set_executable(path) {
        return Err(CraneError::MakeCraneExecutable{ path: path.into(), err });
    }

    // Finally, delete the tar and directory
    if let Err(err) = tfs::remove_dir_all(&dir_path).await { warn!("Failed to remove extracted tarball folder '{}': {}", dir_path.display(), err); }
    if let Err(err) = tfs::remove_file(&tar_path).await { warn!("Failed to remove downloaded tarball '{}': {}", tar_path.display(), err); }

    // Done!
    debug!("Successfully downloaded `crane` executable to {}", path.display());
    Ok(())
}



/// Creates a Kubernetes secret description file that we use to create a Docker registry secret.
/// 
/// # Arguments
/// - `registry`: The [`Address`] of the registry to login to.
/// - `auth`: The [`RegistryAuth`] that describes what kind of secret to add.
/// 
/// # Returns
/// A tuple of the ID of the secret and the actual [`Secret`] struct describing it.
fn create_k8s_registry_secret(registry: impl AsRef<Address>, auth: RegistryAuth) -> (String, Secret) {
    // Generate an identifier for this secret
    let registry: &Address = registry.as_ref();
    let id: String = format!("docker-registry-{}", rand::thread_rng().sample_iter(Uniform::new(0, 26 + 10)).take(8).map(|i: u8| if i < 10 { (i + b'0') as char } else { (i - 10 + b'a') as char }).collect::<String>());

    // Create a base64-encoded variation of the Docker config
    let docker_config: String = match auth {
        RegistryAuth::Basic(basic) => {
            // Create the Base64-encoded username/password
            let bbasic: String = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", basic.username, basic.password));

            // Use that to create the base64-encoded config
            base64::engine::general_purpose::STANDARD.encode(format!("{{ \"auths\": {{ \"{registry}\": {{ \"auth\": \"{bbasic}\" }} }} }}"))
        },
    };

    // Create the Secret
    let secret: Secret = serde_json::from_value(json!({
        // Define the kind of this YAML file
        "apiVersion": "v1",
        "kind": "Secret",

        // Define the name of the secret
        "metadata": {
            "name": id,
        },

        // Now define the secret's contents
        "data": {
            ".dockerconfigjson": docker_config,
        },
        "type": "kubernetes.io/dockerconfigjson",
    })).unwrap();

    // Return the ID and the secret now
    (id, secret)
}

/// Creates a Kubernetes job description file that we use to launch a job.
/// 
/// # Arguments
/// - `einfo`: The [`ExecuteInfo`] struct that describes the job.
/// - `secret`: The name of the secret which we (might) need to download the container.
/// 
/// # Returns
/// A tuple of the ID of this job, and the actual [`Pod`] struct describing the job.
fn create_k8s_pod(einfo: ExecuteInfo, secret: Option<String>) -> (String, Pod) {
    // Generate an identifier for this job by sanitizing the parts we want
    // (Note: jeez Kubernetes is pedantic about its names... Regex that determines what to allow: `[a-z0-9]([-a-z0-9]*[a-z0-9])?`)
    let name: String = einfo.image.name.chars().filter_map(|c| if c >= 'A' && c <= 'Z' { Some((c as u8 - b'A' + b'a') as char) } else if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') { Some(c) } else { None }).collect::<String>();
    let version: String = einfo.image.version.map(|v| v.replace('.', "")).unwrap_or("latest".into());
    let id: String = format!("{}-{}-{}", name, version, rand::thread_rng().sample_iter(Uniform::new(0, 26 + 10)).take(8).map(|i: u8| if i < 10 { (i + b'0') as char } else { (i - 10 + b'a') as char }).collect::<String>());

    // Define the main JSON body
    let mut body: serde_json::Value = json!({
        // Define the kind of this YAML file
        "apiVersion": "v1",
        "kind": "Pod",

        // Define the job ID
        "metadata": {
            "name": id,
        },

        // Now define the rest of the job
        "spec": {
            "containers": [{
                "name": id,
                "image": einfo.image_source.into_registry(),
                "args": einfo.command,
                "env": [{
                    "name": OUTPUT_PREFIX_NAME,
                    "value": "1",
                }],
                "securityContext": {
                    "capabilities": {
                        "drop": ["all"],
                        "add": ["SYS_TIME"],
                    },
                    "privileged": false,
                },
                "imagePullPolicy": "Always",
            }],
        },
    });

    // Potentially add in the secret
    if let Some(secret) = secret {
        body["spec"]["imagePullSecrets"] = json!([{ "name": secret }]);
    }

    // Create the Job
    let pod: Pod = serde_json::from_value(body).unwrap();

    // Now we can generate the struct efficiently using the JSON macro.
    (id, pod)
}





/***** AUXILLARY FUNCTIONS *****/
/// Reads a Kubernetes config file from the given path on the disk.
/// 
/// This file can then be used to configure a Kubernetes client.
/// 
/// # Arguments
/// - `path`: The [`Path`]-like to read the config file from.
/// 
/// # Returns
/// A new [`Config`] that can be used to connect to the instance it describes.
/// 
/// # Errors
/// This function may error if we failed to read the config file or if it was invalid.
pub async fn read_config_async(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path: &Path = path.as_ref();
    debug!("Reading Kubernetes config '{}'...", path.display());

    // Read the file to a string
    let raw: String = match tfs::read_to_string(path).await {
        Ok(raw)  => raw,
        Err(err) => { return Err(ConfigError::FileRead { path: path.into(), err }); },
    };

    // Read it with serde to a Kubeconfig
    let config: Kubeconfig = match serde_yaml::from_str(&raw) {
        Ok(config) => config,
        Err(err)   => { return Err(ConfigError::Parse{ path: path.into(), err }); },
    };

    // Finally, wrap that in an official config
    match Config::from_custom_kubeconfig(config, &KubeConfigOptions::default()).await {
        Ok(config) => Ok(config),
        Err(err)   => Err(ConfigError::Compile{ path: path.into(), err }),
    }
}



/// Resolves the [`ImageSource`] to an [`ImageSource::Registry`].
/// 
/// If we're given an [`ImageSource::Path`], we upload the container to the given registry. Otherwise, we just return as-is.
/// 
/// # Arguments
/// - `image`: The image to push. This will determine its name and tag in the container registry.
/// - `source`: The [`ImageSource`] to resolve.
/// - `registry`: The address of the registry to upload the image to if necessary.
/// - `auth`: Any method of authentication that we need for the registry.
/// - `insecure`: If true, we pass the '--insecure' flag to the `crane` executable (i.e., ignore SSL certs and such).
/// 
/// # Returns
/// Another [`ImageSource`] that is the resolved version of `image`.
/// 
/// # Errors
/// This function may error if the given `image` was an [`ImageSource::Path`], and we failed to upload the image.
pub async fn resolve_image_source(name: impl AsRef<Image>, source: impl Into<ImageSource>, registry: impl AsRef<Address>, auth: Option<RegistryAuth>, insecure: bool) -> Result<ImageSource, ResolveError> {
    let name     : &Image      = name.as_ref();
    let source   : ImageSource = source.into();
    let registry : &Address    = registry.as_ref();
    info!("Resolving image by maybe pushing it to a registry");

    // Only resolve if we're a local file
    let path: PathBuf = match source {
        ImageSource::Path(path)    => path,
        ImageSource::Registry(reg) => {
            debug!("Nothing to resolve (image is already a registry image; {reg})");
            return Ok(ImageSource::Registry(reg));
        },
    };
    debug!("Resolving local image '{}' to a registry image @ '{}'", path.display(), registry);

    // Deduce the path to the registry
    let address: String = format!("{registry}/v2/{}:{}", name.name, if let Some(version) = &name.version { version } else { "latest" });

    // Next, ensure the crane executable exists
    debug!("Ensuring `crane` exists...");
    if let Err(err) = ensure_crane_exe(CRANE_PATH, "/tmp").await { return Err(ResolveError::CraneExe{ err }); }

    // If there is any auth, run the command first
    if let Some(RegistryAuth::Basic(basic)) = auth {
        info!("Using basic auth to login to registry");

        // Prepare the login command in `crane`
        debug!("Logging in to registry as user '{}'...", basic.username);
        let mut cmd: Command = Command::new(CRANE_PATH);
        cmd.args(["auth", "login", "-u"]);
        cmd.arg(basic.username);
        cmd.arg("-p");
        cmd.arg(basic.password);
        cmd.arg(registry.to_string());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Run it
        let output: Output = match cmd.output() {
            Ok(output) => output,
            Err(err)   => { return Err(ResolveError::LaunchLogin { what: cmd, err }); },
        };
        if !output.status.success() { return Err(ResolveError::LoginFailure { registry: registry.clone(), err: Box::new(ResolveError::CommandFailure { what: cmd, status: output.status, stdout: String::from_utf8_lossy(&output.stdout).into(), stderr: String::from_utf8_lossy(&output.stderr).into() }) }); }        
    }

    // Next up, prepare to launch crane with the tarball path
    debug!("Pushing image using `crane`...");
    let mut cmd: Command = Command::new(CRANE_PATH);
    cmd.args(["push", path.display().to_string().as_str()]);
    cmd.arg(&address);
    if insecure { cmd.arg("--insecure"); }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Run it
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(err)   => { return Err(ResolveError::LaunchPush { what: cmd, err }); },
    };
    if !output.status.success() { return Err(ResolveError::PushFailure { path, image: address, err: Box::new(ResolveError::CommandFailure { what: cmd, status: output.status, stdout: String::from_utf8_lossy(&output.stdout).into(), stderr: String::from_utf8_lossy(&output.stderr).into() }) }); }

    // Done
    debug!("Resolved local image '{}' to remote image '{}'", path.display(), address);
    Ok(ImageSource::Registry(address))
}





/***** HELPER STRUCTURES *****/
/// Abstracts over the possible container states.
#[derive(Clone, Debug, EnumDebug)]
pub enum ContainerStateKind {
    /// The container is running
    Running(ContainerStateRunning),
    Waiting(ContainerStateWaiting),
    Terminated(ContainerStateTerminated),
}





/***** AUXILLARY STRUCTURES *****/
/// Defines a struct with K8s-specific options to pass to this API.
#[derive(Clone, Debug)]
pub struct K8sOptions {
    /// The path to the Kubernetes config file to connect with.
    pub config           : PathBuf,
    /// The address of the Docker registry that we push container images to.
    pub registry_address : Address,
}

/// Defines a struct that describes everything we need to know about a job for a Kubernetes task.
#[derive(Clone, Debug)]
pub struct ExecuteInfo {
    /// The image name to use for the container.
    pub image        : Image,
    /// The location where we import (as file) or create (from repo) the image from.
    pub image_source : ImageSource,

    /// The command(s) to pass to Branelet.
    pub command      : Vec<String>,
}

/// Defines methods of authentication for registries.
#[derive(Clone, Debug, EnumDebug)]
pub enum RegistryAuth {
    /// It needs a username and a password.
    Basic(BasicAuth),
}
/// Defines the Docker registry basic authentication scheme.
#[derive(Clone, Debug)]
pub struct BasicAuth {
    /// The username of the user.
    pub username : String,
    /// The password of the user.
    pub password : String,
}





/***** LIBRARY *****/
/// Represents a client for a Kubernetes cluster. Practically acts as a builder for a connection.
#[derive(Clone)]
pub struct Client {
    /// A Kubernetes config to wrap around.
    client : kube::Client,
}

impl Client {
    /// Constructor for the Client.
    /// 
    /// # Arguments
    /// - `config`: The [`Config`] that we use to known to which cluster to connect and how.
    /// 
    /// # Returns
    /// A new Client instance that can be used to connect to the cluster described in the given config.
    /// 
    /// # Errors
    /// This function errors if we failed to create a [`kube::Client`] from the given `config`.
    #[inline]
    pub fn new(config: impl Into<Config>) -> Result<Self, ClientError> {
        let config: Config = config.into();
        debug!("Creating client to cluster '{}'", config.cluster_url);

        // Attempt to create a client from the given config
        let client: kube::Client = match kube::Client::try_from(config) {
            Ok(client) => client,
            Err(err)   => { return Err(ClientError::CreateClient{ err }); },
        };

        // Return ourselves with the client
        Ok(Self {
            client,
        })
    }

    /// Constructor for the Client that parses the Kubernetes config from the given path.
    /// 
    /// # Arguments
    /// - `path`: The [`Path`]-like to parse the Kubernetes config from.
    /// 
    /// # Returns
    /// A new Client instance that can be used to connect to the cluster described in the given config.
    /// 
    /// # Errors
    /// This function may error if we failed to parse the given file or if we failed to create a [`kube::Client`] from the given `config`.
    pub async fn from_path_async(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        // Attempt to load the configuration file
        let config: Config = match read_config_async(path).await {
            Ok(config) => config,
            Err(err)   => { return Err(ClientError::LoadConfig { err }); },
        };

        // Create a client from that
        debug!("Creating client to cluster '{}'", config.cluster_url);
        let client: kube::Client = match kube::Client::try_from(config) {
            Ok(client) => client,
            Err(err)   => { return Err(ClientError::CreateClient { err }); },
        };

        // Return ourselves with the client
        Ok(Self {
            client,
        })
    }



    /// Creates a scope so that we can use to send requests while knowing what kind of resource we're talking about.
    /// 
    /// # Generic arguments
    /// - `R`: The type of [`Resource`] to make this scopes for. This scopes the connection to a particular set of namespace/resources you can do.
    /// 
    /// # Arguments
    /// - `namespace`: The Kubernetes namespace to use for the request.
    /// 
    /// # Returns
    /// A new [`Scope`] representing it.
    #[inline]
    pub fn scope<R: Resource<Scope = NamespaceResourceScope>>(&self, namespace: impl AsRef<str>) -> Scope<R> where R::DynamicType: Default {
        // We create the requested API interface and return that
        let namespace: &str = namespace.as_ref();
        debug!("Creating client scope for resource '{}' and namespace '{}'", type_name::<R>(), namespace);
        Scope {
            api : Api::namespaced(self.client.clone(), namespace),
        }
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Format as a typical struct
        f.debug_struct("Client")
            .field("Client", &"<kube::Client>")
            .finish()
    }
}



/// Represents a client that has a certain resource scope and namespace within a Kubernetes cluster (at least conceptually).
/// 
/// # Generic arguments
/// - `K`: 
#[derive(Debug)]
pub struct Scope<R> {
    /// The [`Api`] abstraction with which we connect.
    api : Api<R>,
}

impl<R: Clone + Debug + DeserializeOwned> Scope<R> {
    /// Attaches to the resources with the given ID, returning a handle for it.
    /// 
    /// # Arguments
    /// - `id`: The name/identifier of the resource to attach to.
    /// 
    /// # Returns
    /// A new [`Handle<R>`] that can be used to manage a resource of that kind.
    pub fn attach(&self, id: impl Into<String>) -> Handle<R> {
        Handle {
            api : self.api.clone(),
            id  : id.into(),
        }
    }
}

impl Scope<Secret> {
    /// Creates a Docker credentials secret in Kubernetes.
    /// 
    /// # Arguments
    /// - `registry`: The address of the registry to connect to.
    /// - `auth`: The method of authenticating with the registry.
    /// 
    /// # Returns
    /// A new [`Handle<Secret>`] struct that can be used to destroy the secret or otherwise manage it.
    /// 
    /// # Errors
    /// This function errors if we failed to connect to the cluster or the cluster failed to create it somehow.
    pub async fn create_registry_secret(&self, registry: impl AsRef<Address>, auth: RegistryAuth) -> Result<Handle<Secret>, ScopeError> {
        let registry: &Address = registry.as_ref();
        info!("Creating Docker registry secret for registry '{registry}' on Kubernetes backend");

        // Prepare the Kubernetes secrets file
        let (id, secret): (String, Secret) = create_k8s_registry_secret(registry, auth);

        // Submit the secret
        debug!("Creating secret '{id}'...");
        if let Err(err) = self.api.create(&PostParams::default(), &secret).await {
            return Err(ScopeError::CreateSecret{ registry: registry.clone(), id, err });
        }

        // // Wait until the pod is created
        // debug!("Waiting for secret '{id}' to be created...");
        // let mut stream = match self.api.watch(&WatchParams::default().fields(&format!("metadata.name={id}")), "0").await {
        //     Ok(stream) => stream.boxed(),
        //     Err(err)   => { return Err(ScopeError::Wait { resource: type_name::<Secret>().into(), id, err }); },
        // };
        // while let Some(item) = stream.try_next().await.map_err(|err| ScopeError::Wait { resource: type_name::<Secret>().into(), id: id.clone(), err })? {
        //     match item {
        //         WatchEvent::Added(_)   => { break; },
        //         WatchEvent::Error(err) => { return Err(ScopeError::CreateFailure { resource: type_name::<Secret>().into(), id, err }); },

        //         // Ignore the rest
        //         _ => {},
        //     }
        // }

        // Done
        info!("Successfully created secret '{id}'");
        Ok(Handle{ api: self.api.clone(), id })
    }
}
impl Scope<Pod> {
    /// Launches a given job in Kubernetes.
    /// 
    /// # Arguments
    /// - `einfo`: The [`ExecuteInfo`] that describes the job to launch.
    /// - `registry_secret`: An optional [`Handle<Secret>`] that, when given, will use the referenced secret when pulling the image for this pod.
    /// 
    /// # Returns
    /// A new [`Handle<Pod>`] struct that can be used to cancel a job or otherwise manage it.
    /// 
    /// # Errors
    /// This function errors if we failed to push the container to the local registry (if it was a file), connect to the cluster or if Kubernetes failed to launch the job.
    pub async fn spawn(&self, einfo: ExecuteInfo, registry_secret: Option<&Handle<Secret>>) -> Result<Handle<Pod>, ScopeError> {
        info!("Spawning package task from '{}' on Kubernetes backend", einfo.image);

        // Assert the container has been uploaded
        if !matches!(einfo.image_source, ImageSource::Registry(_)) { panic!("Non-Registry ImageSource must have been resolved before calling Scope::spawn"); }

        // Prepare the Kubernetes config file.
        let image: Image = einfo.image.clone();
        let (id, pod): (String, Pod) = create_k8s_pod(einfo, registry_secret.map(|handle| handle.id.clone()));

        // Submit the job
        debug!("Launching pod '{id}'...");
        if let Err(err) = self.api.create(&PostParams::default(), &pod).await {
            return Err(ScopeError::CreateJob{ name: image.name, version: image.version.and_then(|v| Version::from_str(&v).ok()).unwrap_or(Version::latest()), id, err });
        }

        // Done
        info!("Successfully spawned job '{id}'");
        Ok(Handle{ api: self.api.clone(), id })
    }
}



/// Represents a resource that is currently present within a Kubernetes cluster.
#[derive(Debug)]
pub struct Handle<R: 'static + Clone + Debug + DeserializeOwned> {
    /// The connection of which we are a part.
    api : Api<R>,
    /// The ID of the resource we manage.
    id  : String,
}

impl<R: 'static + Clone + Debug + DeserializeOwned> Handle<R> {
    /// Detached this handle from the job, not destroying it when we're going down.
    /// 
    /// Note that this will keep the pod running indefinitely, until you [`Scope::attach`] to it again.
    /// 
    /// # Returns
    /// The job ID that you can use to attach to the job again later.
    pub fn detach(mut self) -> String {
        // Get the id
        let id: String = mem::take(&mut self.id);

        // Drop without calling the destructor (which will drop the job) forgetting
        mem::forget(self);
        id
    }

    /// Cancels the job by terminating it (and thus consuming the handle).
    /// 
    /// Note that this function is strongly preferred over simply [`Drop`]ing this handle, for two reasons:
    /// - You can gracefully handle errors occurring when terminating the handle
    /// - We can await the termination happening.
    /// 
    /// In the case of [`Drop`], we have to call [`tokio:spawn()`] since it's not an async function - and this means that, if the main terminates before the task does, we cannot guarantee it completes.
    /// 
    /// # Errors
    /// This function may error if we failed to terminate the job.
    pub async fn terminate(mut self) -> Result<(), HandleError> {
        // Attempt to delete the pod
        debug!("Deleting {} resource '{}'...", type_name::<R>(), self.id);
        if let Err(err) = self.api.delete(&self.id, &DeleteParams::default()).await {
            return Err(HandleError::TerminatePod{ id: mem::take(&mut self.id), err });
        }

        // Now drop ourselves without calling the destructor
        mem::forget(self);
        Ok(())
    }



    /// Returns the ID in this handle.
    /// 
    /// Note that you should use this for debugging purposes only. All management should go through the `Handle`.
    #[inline]
    pub fn id(&self) -> &str { &self.id }
}
impl<R: 'static + Clone + Debug + DeserializeOwned> Drop for Handle<R> {
    fn drop(&mut self) {
        // Take what we need from self
        let api: Api<R> = self.api.clone();
        let id: String = mem::take(&mut self.id);

        // Spawn a task that does this for us in the background
        // However, there is no guarantee that any tasks running here will actually complete before `main()` does. This is probably fine within the context of `brane-job`, but annoying in CLI situations. Thus, [`Handle::terminate()`] should be preferred wherever possible.
        tokio::spawn(async move {
            debug!("Deleting {} resource '{}'...", type_name::<R>(), id);
            if let Err(err) = api.delete(&id, &DeleteParams::default()).await {
                warn!("{}", HandleError::TerminatePod{ id, err }.trace());
            }
        });
    }
}

impl Handle<Pod> {
    /// Blocks the thread until the pod reports it is ready.
    /// 
    /// # Errors
    /// This function may error if we failed to connect to the cluster or if we failed to await the given pod.
    pub async fn wait_ready(&self) -> Result<(), HandleError> {
        // Wait until the container gets its first state (i.e., it is scheduled, or at least attempted)
        debug!("Waiting for pod '{}' to reach 'Ready'...", self.id);
        let mut pod: Pod = loop {
            // Wait until the a state is returned
            match await_condition(self.api.clone(), &self.id, |obj: Option<&Pod>| {
                if let Some(pod) = obj {
                    if let Some(status) = &pod.status {
                        if let Some(statuses) = &status.container_statuses {
                            match statuses.len().cmp(&1) {
                                Ordering::Greater => { warn!("Pod '{}' has more than one containers (assumption falsified)", self.id); return statuses[0].state.is_some(); },
                                Ordering::Equal   => { return statuses[0].state.is_some(); },
                                Ordering::Less    => {},
                            }
                        }
                    }
                }

                // If we didn't return, one of the above is not present
                false
            }).await {
                Ok(Some(pod)) => { break pod; },
                Ok(None)      => { continue; },
                Err(err)      => { return Err(HandleError::WaitReady { id: self.id.clone(), err }); },
            }
        };

        // Now match on the state found in the pod
        let mut times: usize = 1;
        loop {
            // Match the most recent state
            let status : ContainerStatus = pod.status.unwrap().container_statuses.unwrap().swap_remove(0);
            let state  : ContainerState  = status.state.unwrap();
            match (state.running, state.waiting, state.terminated) {
                (Some(_), None, None) => {
                    // It's definitely ready at this point
                    info!("Pod '{}' reached 'Ready'", self.id);
                    return Ok(());
                },

                (None, Some(_), None) => {
                    // Consider if the pod was terminated before, since that might indicate errors
                    if let Some(ContainerState{ terminated: Some(terminated), .. }) = status.last_state {
                        // Consider why the POD was terminated
                        if let Some(reason) = &terminated.reason {
                            if reason == "ImagePullBackOff" {
                                return Err(HandleError::PullImage{ id: self.id.clone(), err: terminated.message });
                            }
                        }

                        // Otherwise, we assume it's some other kind of backoff we won't care about until we join
                        info!("Pod '{}' is terminated (which is a kind of ready)", self.id);
                        if let Some(reason) = terminated.reason { debug!("Pod '{}' is terminated because of {}{}", self.id, reason, if let Some(message) = terminated.message { format!(": {message}") } else { String::new() }) }
                        return Ok(());
                    }

                    // Otherwise, the POD is waiting after a non-terminated; let us assume this means it needs some more cooking time
                    info!("Pod '{}' is waiting after something else than termination; assuming it needs more time", self.id);
                },

                (None, None, Some(terminated)) => {
                    // Otherwise, we assume it's some other kind of backoff we won't care about until we join
                    info!("Pod '{}' is terminated (which is a kind of ready)", self.id);
                    if let Some(reason) = terminated.reason { debug!("Pod '{}' is terminated because of {}{}", self.id, reason, if let Some(message) = terminated.message { format!(": {message}") } else { String::new() }) }
                    return Ok(());
                },

                _ => { panic!("Assumption that only one of running, waiting, terminated is active falsified"); }
            }

            // If we made it this far, then we have to wait until the wait becomes something else
            times += 1;
            debug!("Waiting for pod '{}' to reach 'Ready' (x{})...", self.id, times);
            pod = loop {
                // Wait until the a state is returned
                match await_condition(self.api.clone(), &self.id, |obj: Option<&Pod>| {
                    if let Some(pod) = obj {
                        if let Some(status) = &pod.status {
                            if let Some(statuses) = &status.container_statuses {
                                // Check there is a container to get the status of
                                match statuses.len().cmp(&1) {
                                    Ordering::Greater => {
                                        warn!("Pod '{}' has more than one containers (assumption falsified)", self.id);
                                        return statuses[0].state.is_some();
                                    },
                                    Ordering::Equal => {
                                        if let Some(state) = &statuses[0].state {
                                            // Match the state to discover if we can return (that is, any state that is not a wait after a non-terminated)
                                            match (&state.running, &state.waiting, &state.terminated) {
                                                (Some(_), None, None) |
                                                (None, None, Some(_)) => { return true; },
                                                (None, Some(_), None) => { return matches!(&statuses[0].last_state, Some(ContainerState{ terminated: Some(_), .. })) },

                                                _ => { panic!("Assumption that only one of running, waiting, terminated is active falsified"); },
                                            }
                                        }
                                    },
                                    Ordering::Less => {},
                                }
                            }
                        }
                    }
    
                    // If we didn't return, one of the above is not present
                    false
                }).await {
                    Ok(Some(pod)) => { break pod; },
                    Ok(None)      => { continue; },
                    Err(err)      => { return Err(HandleError::WaitReady { id: self.id.clone(), err }); },
                }
            };
        }
    }

    /// Waits until the pod's job is completed.
    /// 
    /// # Returns
    /// A tuple with the return code, stdout and stderr of the pod, respectively.
    /// 
    /// # Errors
    /// This function may error if we failed to connect to the cluster or if we failed to follow the given pod (because it does not exist, for example).
    pub async fn join(self) -> Result<(i32, String, String), HandleError> {
        // Wait until the POD completes running
        debug!("Waiting until pod '{}' terminates...", self.id);
        let pod: Pod = loop {
            // Wait until the pod reports terminated, for whatever reason
            match await_condition(self.api.clone(), &self.id, |obj: Option<&Pod>| {
                if let Some(pod) = obj {
                    if let Some(status) = &pod.status {
                        if let Some(statuses) = &status.container_statuses {
                            match statuses.len().cmp(&1) {
                                Ordering::Greater => { warn!("Pod '{}' has more than one containers (assumption falsified)", self.id); if let Some(state) = &statuses[0].state { return state.terminated.is_some(); } },
                                Ordering::Equal   => { if let Some(state) = &statuses[0].state { return state.terminated.is_some(); } },
                                Ordering::Less    => {},
                            }
                        }
                    }
                }

                // If we didn't return, one of the above is not present
                false
            }).await {
                Ok(Some(pod)) => { break pod; },
                Ok(None)      => { continue; },
                Err(err)      => { return Err(HandleError::WaitReady { id: self.id.clone(), err }); },
            }
        };

        // Get the termination code (the unwraps are safe because we include them in the conditions above)
        let terminate: ContainerStateTerminated = pod.status.unwrap().container_statuses.unwrap().swap_remove(0).state.unwrap().terminated.unwrap();

        // Attach to the POD and collect the logs for the duration of its runtime
        debug!("Reading pod '{}' logs", self.id);
        let mut stdout: String = String::new();
        let mut stderr: String = String::new();
        let mut stream = match self.api.log_stream(&self.id, &LogParams::default()).await {
            Ok(stream) => stream,
            Err(err)   => { return Err(HandleError::ReadLogs{ id: self.id.clone(), err }); },
        };
        while let Some(entry) = stream.try_next().await.map_err(|err| HandleError::ReadLogs { id: self.id.clone(), err })? {
            // Do we really not have any way to distinguish? That's actually a little unfortunate :/

            // OK, let's do it ourselves then - we adapt branelet to simply prefix its messages with what is necessary
            let entry: Cow<str> = String::from_utf8_lossy(&entry);
            for line in entry.lines() {
                if line.len() >= OUTPUT_PREFIX.len() && &line[..OUTPUT_PREFIX.len()] == OUTPUT_PREFIX {
                    stdout.push_str(&line[OUTPUT_PREFIX.len()..]);
                    stdout.push('\n');
                } else {
                    stderr.push_str(line);
                    stderr.push('\n');
                }
            }
        }

        // Now we can delete ourselves
        let id: String = self.id.clone();
        if let Err(err) = self.terminate().await { warn!("{}", err.trace()); };

        // Done!
        debug!("Joined pod '{}' (which returned status {})", id, terminate.exit_code);
        Ok((terminate.exit_code, stdout, stderr))
    }
}
