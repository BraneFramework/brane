//  DOCKER.rs
//    by Lut99
//
//  Created:
//    19 Sep 2022, 14:57:17
//  Last edited:
//    08 Feb 2024, 15:15:18
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines functions that interact with the local Docker daemon.
//

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64ct::{Base64, Encoding};
use bollard::container::{
    Config, CreateContainerOptions, LogOutput, LogsOptions, RemoveContainerOptions, StartContainerOptions, WaitContainerOptions,
};
use bollard::image::{CreateImageOptions, ImportImageOptions, RemoveImageOptions, TagImageOptions};
use bollard::models::{DeviceRequest, EndpointSettings, HostConfig};
pub use bollard::{API_DEFAULT_VERSION, Docker};
use brane_exe::FullValue;
use enum_debug::EnumDebug;
use futures_util::StreamExt as _;
use futures_util::stream::TryStreamExt as _;
use hyper::body::Body;
use log::debug;
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use specifications::container::{Image, VolumeBind};
use specifications::data::{AccessKind, DataName};
use specifications::package::Capability;
use tokio::fs::{self as tfs, File as TFile};
use tokio::io::{self as tio, AsyncReadExt as _, AsyncWriteExt as _};
use tokio_tar::Archive;
use tokio_util::codec::{BytesCodec, FramedRead};

pub use crate::errors::DockerError as Error;
use crate::errors::{ClientVersionParseError, ExecuteError};


/***** CONSTANTS *****/
/// Defines the prefix to the Docker image tar's manifest config blob (which contains the image digest)
pub(crate) const MANIFEST_CONFIG_PREFIX: &str = "blobs/sha256/";

/// Defines an _alternative_ postfix to the Docker image tar's manifest config blob (which contains the image digest).
///
/// This one is actually used in saved images.
pub(crate) const MANIFEST_CONFIG_POSTFIX: &str = ".json";





/***** HELPER STRUCTS *****/
/// The layout of a Docker manifest file.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct DockerImageManifest {
    /// The config string that contains the digest as the path of the config file
    #[serde(rename = "Config")]
    config: String,
}





/***** AUXILLARY STRUCTS *****/
/// Defines a wrapper around ClientVersion that allows it to be parsed.
#[derive(Clone, Copy, Debug)]
pub struct ClientVersion(pub bollard::ClientVersion);
impl FromStr for ClientVersion {
    type Err = ClientVersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Find the dot to split on
        let dot_pos: usize = match s.find('.') {
            Some(pos) => pos,
            None => {
                return Err(ClientVersionParseError::MissingDot { raw: s.into() });
            },
        };

        // Split it
        let major: &str = &s[..dot_pos];
        let minor: &str = &s[dot_pos + 1..];

        // Attempt to parse each of them as the appropriate integer type
        let major: usize = match usize::from_str(major) {
            Ok(major) => major,
            Err(err) => {
                return Err(ClientVersionParseError::IllegalMajorNumber { raw: s.into(), err });
            },
        };
        let minor: usize = match usize::from_str(minor) {
            Ok(minor) => minor,
            Err(err) => {
                return Err(ClientVersionParseError::IllegalMinorNumber { raw: s.into(), err });
            },
        };

        // Done, return the value
        Ok(ClientVersion(bollard::ClientVersion { major_version: major, minor_version: minor }))
    }
}



/// Defines a serializer for the ImageSource.
#[derive(Debug)]
pub struct ImageSourceSerializer<'a> {
    source: &'a ImageSource,
}
impl Display for ImageSourceSerializer<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ImageSource::*;
        match self.source {
            Path(path) => write!(f, "Path<{}>", path.to_string_lossy()),
            Registry(source) => write!(f, "Registry<{source}>"),
        }
    }
}

/// Defines the source of an image (either a file or from a repo).
#[derive(Clone, Debug, EnumDebug)]
pub enum ImageSource {
    /// It's a file, and this is the path to load.
    Path(PathBuf),
    /// It's in a remote registry, and this is it.
    Registry(String),
}

impl ImageSource {
    /// Checks whether this source is a file.
    ///
    /// # Returns
    /// True if we are [`ImageSource::Path`], or false otherwise.
    pub fn is_path(&self) -> bool { matches!(self, Self::Path(_)) }

    /// Provides access to the internal path.
    ///
    /// # Returns
    /// A reference to the internal [`PathBuf`].
    ///
    /// # Panics
    /// This function panics if we are not the [`ImageSource::Path`] we assumed we were.
    pub fn path(&self) -> &Path {
        if let Self::Path(path) = self {
            path
        } else {
            panic!("Cannot unwrap an ImageSource::{} as an ImageSource::Path", self.variant());
        }
    }

    /// Provides mutable access to the internal path.
    ///
    /// # Returns
    /// A mutable reference to the internal [`PathBuf`].
    ///
    /// # Panics
    /// This function panics if we are not the [`ImageSource::Path`] we assumed we were.
    pub fn path_mut(&mut self) -> &mut PathBuf {
        if let Self::Path(path) = self {
            path
        } else {
            panic!("Cannot unwrap an ImageSource::{} as an ImageSource::Path", self.variant());
        }
    }

    /// Takes ownership of the internal path.
    ///
    /// # Returns
    /// The internal [`PathBuf`].
    ///
    /// # Panics
    /// This function panics if we are not the [`ImageSource::Path`] we assumed we were.
    pub fn into_path(self) -> PathBuf {
        if let Self::Path(path) = self {
            path
        } else {
            panic!("Cannot unwrap an ImageSource::{} as an ImageSource::Path", self.variant());
        }
    }

    /// Checks whether this source is a registry.
    ///
    /// # Returns
    /// True if we are [`ImageSource::Registry`], or false otherwise.
    pub fn is_registry(&self) -> bool { matches!(self, Self::Registry(_)) }

    /// Provides access to the internal address.
    ///
    /// # Returns
    /// A reference to the internal [`String`] address.
    ///
    /// # Panics
    /// This function panics if we are not the [`ImageSource::Registry`] we assumed we were.
    pub fn registry(&self) -> &str {
        if let Self::Registry(addr) = self {
            addr
        } else {
            panic!("Cannot unwrap an ImageSource::{} as an ImageSource::Registry", self.variant());
        }
    }

    /// Provides mutable access to the internal address.
    ///
    /// # Returns
    /// A mutable reference to the internal [`String`] address.
    ///
    /// # Panics
    /// This function panics if we are not the [`ImageSource::Registry`] we assumed we were.
    pub fn registry_mut(&mut self) -> &mut String {
        if let Self::Registry(addr) = self {
            addr
        } else {
            panic!("Cannot unwrap an ImageSource::{} as an ImageSource::Registry", self.variant());
        }
    }

    /// Takes ownership of the internal address.
    ///
    /// # Returns
    /// The internal [`String`] address.
    ///
    /// # Panics
    /// This function panics if we are not the [`ImageSource::Registry`] we assumed we were.
    pub fn into_registry(self) -> String {
        if let Self::Registry(addr) = self {
            addr
        } else {
            panic!("Cannot unwrap an ImageSource::{} as an ImageSource::Registry", self.variant());
        }
    }

    /// Returns a formatter for the ImageSource that can serialize it in a deterministic manner. This method should be preferred if `ImageSource::from_str()` should read it.
    #[inline]
    pub fn serialize(&self) -> ImageSourceSerializer { ImageSourceSerializer { source: self } }
}

impl Display for ImageSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ImageSource::*;
        match self {
            Path(path) => write!(f, "{}", path.display()),
            Registry(from) => write!(f, "{from}"),
        }
    }
}

impl<S: AsRef<str>> From<S> for ImageSource {
    fn from(value: S) -> Self {
        let value: &str = value.as_ref();

        // Attempt to parse it using the wrappers first
        if value.len() > 5 && &value[..5] == "Path<" && &value[value.len() - 1..] == ">" {
            return Self::Path(value[5..value.len() - 1].into());
        }
        if value.len() > 9 && &value[..9] == "Registry<" && &value[value.len() - 1..] == ">" {
            return Self::Registry(value[9..value.len() - 1].into());
        }

        // If not, then check if it's a path that exists
        let path: PathBuf = PathBuf::from(value);
        if path.exists() {
            return Self::Path(path);
        }

        // Otherwise, we interpret it is a registry
        Self::Registry(value.into())
    }
}
impl Serialize for ImageSource {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize().to_string())
    }
}
impl<'de> Deserialize<'de> for ImageSource {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Define the visitor
        struct ImageSourceVisitor;
        impl Visitor<'_> for ImageSourceVisitor {
            type Value = ImageSource;

            fn expecting(&self, f: &mut Formatter) -> FResult { write!(f, "an image source (as file or repository)") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ImageSource::from(v))
            }
        }

        // Simply do the call
        deserializer.deserialize_str(ImageSourceVisitor)
    }
}
impl FromStr for ImageSource {
    type Err = std::convert::Infallible;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> { Ok(Self::from(s)) }
}

impl AsRef<ImageSource> for ImageSource {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&ImageSource> for ImageSource {
    #[inline]
    fn from(value: &ImageSource) -> Self { value.clone() }
}
impl From<&mut ImageSource> for ImageSource {
    #[inline]
    fn from(value: &mut ImageSource) -> Self { value.clone() }
}



/// Defines the (type of) network ot which a container should connect.
#[derive(Clone, Debug)]
pub enum Network {
    /// Use no network.
    None,

    /// Use a bridged network (Docker's default).
    Bridge,
    /// Use the host network directly.
    Host,
    /// Connect to a specific other container (with the given name/ID).
    Container(String),
    /// Connect to a network with the given name.
    Custom(String),
}

impl Display for Network {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Network::*;
        match self {
            None => write!(f, "none"),

            Bridge => write!(f, "bridge"),
            Host => write!(f, "host"),
            Container(name) => write!(f, "container:{name}"),
            Custom(name) => write!(f, "{name}"),
        }
    }
}

impl From<Network> for String {
    #[inline]
    fn from(value: Network) -> Self { format!("{value}") }
}
impl From<&Network> for String {
    #[inline]
    fn from(value: &Network) -> Self { format!("{value}") }
}



/// Collects information we need to know to connect to the (local) Docker daemon.
#[derive(Clone, Debug)]
pub struct DockerOptions {
    /// The path to the socket with which we connect.
    pub socket:  PathBuf,
    /// The client API version we use.
    pub version: ClientVersion,
}
impl AsRef<DockerOptions> for DockerOptions {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl AsMut<DockerOptions> for DockerOptions {
    #[inline]
    fn as_mut(&mut self) -> &mut Self { self }
}
impl From<&DockerOptions> for DockerOptions {
    #[inline]
    fn from(value: &DockerOptions) -> Self { value.clone() }
}
impl From<&mut DockerOptions> for DockerOptions {
    #[inline]
    fn from(value: &mut DockerOptions) -> Self { value.clone() }
}

/// Collects information we need to perform a container call.
#[derive(Clone, Debug)]
pub struct ExecuteInfo {
    /// The name of the container-to-be.
    pub name: String,
    /// The image name to use for the container.
    pub image: Image,
    /// The location where we import (as file) or create (from repo) the image from.
    pub image_source: ImageSource,

    /// The command(s) to pass to Branelet.
    pub command: Vec<String>,
    /// The extra mounts we want to add, if any (this includes any data folders).
    pub binds: Vec<VolumeBind>,
    /// The extra device requests we want to add, if any (e.g., GPUs).
    pub capabilities: HashSet<Capability>,
    /// The netwok to connect the container to.
    pub network: Network,
}
impl ExecuteInfo {
    /// Constructor for the ExecuteInfo.
    ///
    /// # Arguments
    /// - `name`: The name of the container-to-be.
    /// - `image`: The image name to use for the container.
    /// - `image_source`: The location where we import (as file) or create (from repo) the image from if it's not already loaded.
    /// - `command`: The command(s) to pass to Branelet.
    /// - `binds`: The extra mounts we want to add, if any (this includes any data folders).
    /// - `capabilities`: The extra device requests we want to add, if any (e.g., GPUs).
    /// - `network`: The netwok to connect the container to.
    ///
    /// # Returns
    /// A new ExecuteInfo instance populated with the given values.
    #[inline]
    pub fn new(
        name: impl Into<String>,
        image: impl Into<Image>,
        image_source: impl Into<ImageSource>,
        command: Vec<String>,
        binds: Vec<VolumeBind>,
        capabilities: HashSet<Capability>,
        network: Network,
    ) -> Self {
        ExecuteInfo { name: name.into(), image: image.into(), image_source: image_source.into(), command, binds, capabilities, network }
    }
}





/***** HELPER FUNCTIONS *****/
/// Preprocesses a single argument from either an IntermediateResult or a Data to whatever is needed for their access kind and any mounts.
///
/// # Arguments
/// - `data_dir`: The directory where all real datasets live.
/// - `results_dir`: The directory where to mount results from.
/// - `binds`: The list of VolumeBinds to which we will add while preprocessing.
/// - `inputs`: The list of inputs to resolve the name in.
/// - `name`: The name of the argument.
/// - `value`: The FullValue to preprocess.
///
/// # Returns
/// Nothing explicitly, but does add to the list of binds and overwrites the value of the given FullValue with any other one if necessary.
///
/// # Errors
/// This function errors if we didn't know the input set or if we failed to create new volume binds.
fn preprocess_arg(
    data_dir: Option<impl AsRef<Path>>,
    results_dir: impl AsRef<Path>,
    binds: &mut Vec<VolumeBind>,
    input: &HashMap<DataName, AccessKind>,
    name: impl AsRef<str>,
    value: &mut FullValue,
) -> Result<(), ExecuteError> {
    let data_dir: Option<&Path> = data_dir.as_ref().map(|d| d.as_ref());
    let results_dir: &Path = results_dir.as_ref();
    let name: &str = name.as_ref();

    // Match on its type to find its data name
    let data_name: DataName = match value {
        // The Data and IntermediateResult is why we're here
        FullValue::Data(name) => DataName::Data(name.into()),
        FullValue::IntermediateResult(name) => DataName::IntermediateResult(name.into()),

        // Some types might need recursion
        FullValue::Array(values) => {
            for (i, v) in values.iter_mut().enumerate() {
                preprocess_arg(data_dir, results_dir, binds, input, format!("{name}[{i}]"), v)?;
            }
            return Ok(());
        },
        FullValue::Instance(_, props) => {
            for (n, v) in props {
                preprocess_arg(data_dir, results_dir, binds, input, format!("{name}.{n}"), v)?;
            }
            return Ok(());
        },

        // Otherwise, we don't have to preprocess
        _ => {
            return Ok(());
        },
    };
    debug!("Resolving argument '{}' ({})", name, data_name.variant());

    // Get the method of access for this data type
    let access: &AccessKind = match input.get(&data_name) {
        Some(access) => access,
        None => {
            return Err(ExecuteError::UnknownData { name: data_name });
        },
    };

    // Match on that to replace the value and generate a binding (possibly)
    match access {
        AccessKind::File { path } => {
            // If this is an intermediate result, patch the path with the results directory
            let src_dir: PathBuf = if data_name.is_intermediate_result() {
                results_dir.join(path)
            } else if let Some(data_dir) = data_dir {
                data_dir.join(data_name.name()).join(path)
            } else {
                path.clone()
            };

            // Generate the container path
            let dst_dir: PathBuf = PathBuf::from("/data").join(data_name.name());

            // Generate a volume bind with that
            binds.push(match VolumeBind::new_readonly(src_dir, &dst_dir) {
                Ok(bind) => bind,
                Err(err) => {
                    return Err(ExecuteError::VolumeBindError { err });
                },
            });

            // Replace the argument
            *value = FullValue::String(dst_dir.to_string_lossy().to_string());
        },
    }

    // OK
    Ok(())
}



/// Creates a container with the given image and starts it (non-blocking after that).
///
/// # Arguments
/// - `docker`: The Docker instance to use for accessing the container.
/// - `info`: The ExecuteInfo describing what to launch and how.
///
/// # Returns
/// The name of the container such that it can be waited on later.
///
/// # Errors
/// This function may error for many reasons, which usually means that the container failed to be created or started (wow!).
async fn create_and_start_container(docker: &Docker, info: &ExecuteInfo) -> Result<String, Error> {
    // Generate unique (temporary) container name
    let container_name: String = format!("{}-{}", info.name, &uuid::Uuid::new_v4().to_string()[..6]);
    let create_options = CreateContainerOptions { name: &container_name, platform: None };

    // Extract device requests from the capabilities
    #[allow(clippy::unnecessary_filter_map)]
    let device_requests: Vec<DeviceRequest> = info
        .capabilities
        .iter()
        .filter_map(|c| match c {
            // We need a CUDA-enabled GPU
            Capability::CudaGpu => {
                debug!("Requesting CUDA GPU");
                Some(DeviceRequest {
                    driver: Some("nvidia".into()),
                    count: Some(1),
                    capabilities: Some(vec![vec!["gpu".into()]]),
                    ..Default::default()
                })
            },
        })
        .collect();

    // Combine the properties in the execute info into a HostConfig
    let host_config = HostConfig {
        binds: Some(
            info.binds
                .iter()
                .map(|b| {
                    debug!("Binding '{}' (host) -> '{}' (container)", b.host.display(), b.container.display());
                    b.docker().to_string()
                })
                .collect(),
        ),
        network_mode: Some(info.network.clone().into()),
        privileged: Some(false),
        device_requests: Some(device_requests),
        ..Default::default()
    };

    // Create the container confic
    let create_config =
        Config { image: Some(info.image.name()), cmd: Some(info.command.clone()), host_config: Some(host_config), ..Default::default() };

    // Run it with that config
    debug!("Launching container with name '{}' (image: {})...", info.name, info.image.name());
    if let Err(reason) = docker.create_container(Some(create_options), create_config).await {
        return Err(Error::CreateContainerError { name: info.name.clone(), image: Box::new(info.image.clone()), err: reason });
    }
    debug!(" > Container created");
    match docker.start_container(&container_name, None::<StartContainerOptions<String>>).await {
        Ok(_) => {
            debug!(" > Container '{}' started", container_name);
            Ok(container_name)
        },
        Err(reason) => Err(Error::StartError { name: info.name.clone(), image: Box::new(info.image.clone()), err: reason }),
    }
}

/// Waits for the given container to complete.
///
/// # Arguments
/// - `docker`: The Docker instance to use for accessing the container.
/// - `name`: The name of the container to wait on.
/// - `image`: The image that was run (used for debugging).
/// - `keep_container`: Whether to keep the container around after it's finished or not.
///
/// # Returns
/// The return code of the docker container, its stdout and its stderr (in that order).
///
/// # Errors
/// This function may error for many reasons, which usually means that the container is unknown or the Docker engine is unreachable.
async fn join_container(docker: &Docker, name: &str, keep_container: bool) -> Result<(i32, String, String), Error> {
    // Wait for the container to complete
    if let Err(reason) = docker.wait_container(name, None::<WaitContainerOptions<String>>).try_collect::<Vec<_>>().await {
        return Err(Error::WaitError { name: name.into(), err: reason });
    }

    // Get stdout and stderr logs from container
    let logs_options = Some(LogsOptions::<String> { stdout: true, stderr: true, ..Default::default() });
    let log_outputs = match docker.logs(name, logs_options).try_collect::<Vec<LogOutput>>().await {
        Ok(out) => out,
        Err(reason) => {
            return Err(Error::LogsError { name: name.into(), err: reason });
        },
    };

    // Collect them in one string per output channel
    let mut stderr = String::new();
    let mut stdout = String::new();
    for log_output in log_outputs {
        match log_output {
            LogOutput::StdErr { message } => stderr.push_str(String::from_utf8_lossy(&message).as_ref()),
            LogOutput::StdOut { message } => stdout.push_str(String::from_utf8_lossy(&message).as_ref()),
            _ => {
                continue;
            },
        }
    }

    // Get the container's exit status by inspecting it
    let code = returncode_container(docker, name).await?;

    // Don't leave behind any waste: remove container (but only if told to do so!)
    if !keep_container {
        remove_container(docker, name).await?;
    }

    // Return the return data of this container!
    Ok((code, stdout, stderr))
}

/// Returns the exit code of a container is (hopefully) already stopped.
///
/// # Arguments
/// - `docker`: The Docker instance to use for accessing the container.
/// - `name`: The container's name.
///
/// # Returns
/// The exit-/returncode that was returned by the container.
///
/// # Errors
/// This function errors if the Docker daemon could not be reached, such a container did not exist, could not be inspected or did not have a return code (yet).
async fn returncode_container(docker: &Docker, name: impl AsRef<str>) -> Result<i32, Error> {
    let name: &str = name.as_ref();

    // Do the inspect call
    let info = match docker.inspect_container(name, None).await {
        Ok(info) => info,
        Err(reason) => {
            return Err(Error::InspectContainerError { name: name.into(), err: reason });
        },
    };

    // Try to get the execution state from the container
    let state = match info.state {
        Some(state) => state,
        None => {
            return Err(Error::ContainerNoState { name: name.into() });
        },
    };

    // Finally, try to get the exit code itself
    match state.exit_code {
        Some(code) => Ok(code as i32),
        None => Err(Error::ContainerNoExitCode { name: name.into() }),
    }
}

/// Tries to remove the docker container with the given name.
///
/// # Arguments
/// - `docker`: An already connected local instance of Docker.
/// - `name`: The name of the container to remove.
///
/// # Errors
/// This function errors if we failed to remove it.
async fn remove_container(docker: &Docker, name: impl AsRef<str>) -> Result<(), Error> {
    let name: &str = name.as_ref();

    // Set the options
    let remove_options = Some(RemoveContainerOptions { force: true, ..Default::default() });

    // Attempt the removal
    match docker.remove_container(name, remove_options).await {
        Ok(_) => Ok(()),
        Err(reason) => Err(Error::ContainerRemoveError { name: name.into(), err: reason }),
    }
}

/// Tries to import the image at the given path into the given Docker instance.
///
/// # Arguments
/// - `docker`: An already connected local instance of Docker.
/// - `image`: The image to pull.
/// - `source`: Path to the image to import.
///
/// # Returns
/// Nothing on success, or an ExecutorError otherwise.
async fn import_image(docker: &Docker, image: impl Into<Image>, source: impl AsRef<Path>) -> Result<(), Error> {
    let image: Image = image.into();
    let source: &Path = source.as_ref();
    let options = ImportImageOptions { quiet: true };

    // Try to read the file
    let file = match TFile::open(source).await {
        Ok(handle) => handle,
        Err(reason) => {
            return Err(Error::ImageFileOpenError { path: PathBuf::from(source), err: reason });
        },
    };

    // If successful, open the byte with a FramedReader, freezing all the chunk we read
    let byte_stream = FramedRead::new(file, BytesCodec::new()).map(|r| {
        let bytes = r.unwrap().freeze();
        Ok::<_, Error>(bytes)
    });

    // Finally, wrap it in a HTTP body and send it to the Docker API
    let body = Body::wrap_stream(byte_stream);
    if let Err(err) = docker.import_image(options, body, None).try_collect::<Vec<_>>().await {
        return Err(Error::ImageImportError { path: PathBuf::from(source), err });
    }

    // Tag it with the appropriate name & version
    let options = Some(TagImageOptions { repo: image.name.clone(), tag: image.version.clone().unwrap() });
    match docker.tag_image(image.digest.as_ref().unwrap(), options).await {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::ImageTagError { image: Box::new(image), source: source.to_string_lossy().to_string(), err }),
    }
}

/// Pulls a new image from the given Docker image ID / URL (?) and imports it in the Docker instance.
///
/// # Arguments
/// - `docker`: An already connected local instance of Docker.
/// - `image`: The image to pull.
/// - `source`: The `repo/image[:tag]` to pull it from.
///
/// # Errors
/// This function errors if we failed to pull the image, e.g., the Docker engine did not know where to find it, or there was no internet.
async fn pull_image(docker: &Docker, image: impl Into<Image>, source: impl Into<String>) -> Result<(), Error> {
    let image: Image = image.into();
    let source: String = source.into();

    // Define the options for this image
    let options = Some(CreateImageOptions { from_image: source.clone(), ..Default::default() });

    // Try to create it
    if let Err(err) = docker.create_image(options, None, None).try_collect::<Vec<_>>().await {
        return Err(Error::ImagePullError { source, err });
    }

    // Set the options
    let options: Option<TagImageOptions<_>> = Some(if let Some(version) = &image.version {
        TagImageOptions { repo: image.name.clone(), tag: version.clone() }
    } else {
        TagImageOptions { repo: image.name.clone(), ..Default::default() }
    });

    // Now tag it
    match docker.tag_image(&source, options).await {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::ImageTagError { image: Box::new(image), source, err }),
    }
}





/***** AUXILLARY FUNCTIONS *****/
/// Creates a new connection to the local Docker daemon.
///
/// # Arguments
/// - `opts`: The DockerOptions that contains information on how we can connect to the local daemon.
///
/// # Returns
/// A new `Docker`-instance that may be used in some of the other functions in this module.
///
/// # Errors
/// This function errors if we could not connect to the local daemon.
pub fn connect_local(opts: impl AsRef<DockerOptions>) -> Result<Docker, Error> {
    let opts: &DockerOptions = opts.as_ref();

    // Connect to docker
    #[cfg(unix)]
    match Docker::connect_with_unix(&opts.socket.to_string_lossy(), 900, &opts.version.0) {
        Ok(res) => Ok(res),
        Err(reason) => Err(Error::ConnectionError { path: opts.socket.clone(), version: opts.version.0, err: reason }),
    }
    #[cfg(windows)]
    match Docker::connect_with_named_pipe(&opts.socket.to_string_lossy(), 900, &opts.version.0) {
        Ok(res) => Ok(res),
        Err(reason) => Err(Error::ConnectionError { path: opts.socket.clone(), version: opts.version.0, err: reason }),
    }
    #[cfg(not(any(unix, windows)))]
    compile_error!("Non-Unix, non-Windows OS not supported.");
}

/// Helps any VM aiming to use Docker by preprocessing the given list of arguments and function result into a list of bindings (and resolving the the arguments while at it).
///
/// # Arguments
/// - `args`: The arguments to resolve / generate bindings for.
/// - `input`: A list of input datasets & intermediate results to the current task.
/// - `result`: The result to also generate a binding for if it is present.
/// - `data_dir`: The directory where all real datasets live.
/// - `results_dir`: The directory where all temporary results are/will be stored.
///
/// # Returns
/// A list of VolumeBindings that define which folders have to be mounted to the container how.
///
/// # Errors
/// This function errors if datasets / results are unknown to us.
pub async fn preprocess_args(
    args: &mut HashMap<String, FullValue>,
    input: &HashMap<DataName, AccessKind>,
    result: &Option<String>,
    data_dir: Option<impl AsRef<Path>>,
    results_dir: impl AsRef<Path>,
) -> Result<Vec<VolumeBind>, ExecuteError> {
    let data_dir: Option<&Path> = data_dir.as_ref().map(|r| r.as_ref());
    let results_dir: &Path = results_dir.as_ref();

    // Then, we resolve the input datasets using the runtime index
    let mut binds: Vec<VolumeBind> = vec![];
    for (name, value) in args {
        preprocess_arg(data_dir, results_dir, &mut binds, input, name, value)?;
    }

    // Also make sure the result directory is alive and kicking
    if let Some(result) = result {
        // The source path will be `<results folder>/<name>`
        let src_path: PathBuf = results_dir.join(result);
        // The container-relevant path will be: `/result` (nice and easy)
        let ref_path: PathBuf = PathBuf::from("/result");

        // Now make sure the source path exists and is a new, empty directory
        if src_path.exists() {
            if !src_path.is_dir() {
                return Err(ExecuteError::ResultDirNotADir { path: src_path });
            }
            if let Err(err) = tfs::remove_dir_all(&src_path).await {
                return Err(ExecuteError::ResultDirRemoveError { path: src_path, err });
            }
        }
        if let Err(err) = tfs::create_dir_all(&src_path).await {
            return Err(ExecuteError::ResultDirCreateError { path: src_path, err });
        }

        // Add a volume bind for that
        binds.push(match VolumeBind::new_readwrite(src_path, ref_path) {
            Ok(bind) => bind,
            Err(err) => {
                return Err(ExecuteError::VolumeBindError { err });
            },
        });
    }

    // Done, return the binds
    Ok(binds)
}

/// Given an `image.tar` file, extracts the Docker digest (i.e., image ID) from it and returns it.
///
/// # Arguments
/// - `path`: The `image.tar` file to extract the digest from.
///
/// # Returns
/// The image's digest as a string. Does not include `sha:...`.
///
/// # Errors
/// This function errors if the given image.tar could not be read or was in an incorrect format.
pub async fn get_digest(path: impl AsRef<Path>) -> Result<String, Error> {
    // Convert the Path-like to a Path
    let path: &Path = path.as_ref();

    // Try to open the given file
    let handle: TFile = match TFile::open(path).await {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::ImageTarOpenError { path: path.to_path_buf(), err });
        },
    };

    // Wrap it as an Archive
    let mut archive: Archive<TFile> = Archive::new(handle);

    // Go through the entries
    let mut entries = match archive.entries() {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::ImageTarEntriesError { path: path.to_path_buf(), err });
        },
    };
    while let Some(entry) = entries.next().await {
        // Make sure the entry is legible
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                return Err(Error::ImageTarEntryError { path: path.to_path_buf(), err });
            },
        };

        // Check if the entry is the manifest.json
        let entry_path = match entry.path() {
            Ok(path) => path.to_path_buf(),
            Err(err) => {
                return Err(Error::ImageTarIllegalPath { path: path.to_path_buf(), err });
            },
        };
        if entry_path == PathBuf::from("manifest.json") {
            // Try to read it
            let mut manifest: Vec<u8> = vec![];
            if let Err(err) = entry.read_to_end(&mut manifest).await {
                return Err(Error::ImageTarManifestReadError { path: path.to_path_buf(), entry: entry_path, err });
            };

            // Try to parse it with serde
            let mut manifest: Vec<DockerImageManifest> = match serde_json::from_slice(&manifest) {
                Ok(manifest) => manifest,
                Err(err) => {
                    return Err(Error::ImageTarManifestParseError { path: path.to_path_buf(), entry: entry_path, err });
                },
            };

            // Get the first and only entry from the vector
            let manifest: DockerImageManifest = if manifest.len() == 1 {
                manifest.pop().unwrap()
            } else {
                return Err(Error::ImageTarIllegalManifestNum { path: path.to_path_buf(), entry: entry_path, got: manifest.len() });
            };

            // Now, try to strip the filesystem part and add sha256:
            let digest = if manifest.config.starts_with(MANIFEST_CONFIG_PREFIX) {
                let mut digest = String::from("sha256:");
                digest.push_str(&manifest.config[MANIFEST_CONFIG_PREFIX.len()..]);
                digest
            } else if manifest.config.ends_with(MANIFEST_CONFIG_POSTFIX) {
                let config_len: usize = manifest.config.len();
                let mut digest = String::from("sha256:");
                digest.push_str(&manifest.config[..config_len - MANIFEST_CONFIG_PREFIX.len()]);
                digest
            } else {
                return Err(Error::ImageTarIllegalDigest { path: path.to_path_buf(), entry: entry_path, digest: manifest.config });
            };

            // We found the digest! Set it, then return
            return Ok(digest);
        }
    }

    // No manifest found :(
    Err(Error::ImageTarNoManifest { path: path.to_path_buf() })
}

/// Given an already downloaded container, computes the SHA-256 hash of it.
///
/// # Arguments
/// - `container_path`: The path to the container image file to hash.
///
/// # Returns
/// The hash, as a `sha2::Digest`.
///
/// # Errors
/// This function may error if we failed to read the given file.
pub async fn hash_container(container_path: impl AsRef<Path>) -> Result<String, Error> {
    let container_path: &Path = container_path.as_ref();
    debug!("Hashing image file '{}'...", container_path.display());

    // Attempt to open the file
    let mut handle: tfs::File = match tfs::File::open(container_path).await {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::ImageTarOpenError { path: container_path.into(), err });
        },
    };

    // Read through it in chunks
    let mut hasher: Sha256 = Sha256::new();
    let mut buf: [u8; 1024 * 16] = [0; 1024 * 16];
    loop {
        // Read the next chunk
        let n_bytes: usize = match handle.read(&mut buf).await {
            Ok(n_bytes) => n_bytes,
            Err(err) => {
                return Err(Error::ImageTarReadError { path: container_path.into(), err });
            },
        };
        // Stop if we read nothing
        if n_bytes == 0 {
            break;
        }

        // Hash that
        hasher.update(&buf[..n_bytes]);
    }
    let result: String = Base64::encode_string(&hasher.finalize());
    debug!("Image file '{}' hash: '{}'", container_path.display(), result);

    // Done
    Ok(result)
}

/// Tries to import/pull the given image if it does not exist in the local Docker instance.
///
/// # Arguments
/// - `docker`: An already connected local instance of Docker.
/// - `image`: The Docker image name, version & potential digest to pull.
/// - `source`: Where to get the image from should it not be present already.
///
/// # Errors
/// This function errors if it failed to ensure the image existed (i.e., import or pull failed).
pub async fn ensure_image(docker: &Docker, image: impl Into<Image>, source: impl Into<ImageSource>) -> Result<(), Error> {
    let image: Image = image.into();
    let source: ImageSource = source.into();

    // Abort if image is already loaded
    match docker.inspect_image(&image.docker().to_string()).await {
        Ok(_) => {
            debug!("Image '{}' already exists in Docker deamon.", image.docker());
            return Ok(());
        },
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, message: _ }) => {
            debug!("Image '{}' doesn't exist in Docker daemon.", image.docker());
        },
        Err(err) => {
            return Err(Error::ImageInspectError { image: Box::new(image), err });
        },
    }

    // Otherwise, import it if it is described or pull it
    match source {
        ImageSource::Path(path) => {
            debug!(" > Importing file '{}'...", path.display());
            import_image(docker, image, path).await
        },

        ImageSource::Registry(source) => {
            debug!(" > Pulling image '{}'...", image);
            pull_image(docker, image, source).await
        },
    }
}

/// Saves an already pulled image to some file on disk.
///
/// # Arguments
/// - `docker`: An already connected local instance of Docker.
/// - `image`: The Docker image name, version & potential digest of the image to write to disk.
/// - `target`: The location to write the image to.
pub async fn save_image(docker: &Docker, image: impl Into<Image>, target: impl AsRef<Path>) -> Result<(), Error> {
    let image: Image = image.into();
    let target: &Path = target.as_ref();
    debug!(
        "Saving image {}{} to '{}'...",
        image.name,
        if let Some(version) = &image.version { format!(":{version}") } else { String::new() },
        target.display()
    );

    // Open the output file
    let mut handle: tio::BufWriter<tfs::File> = match tfs::File::create(target).await {
        Ok(handle) => tio::BufWriter::new(handle),
        Err(err) => {
            return Err(Error::ImageFileCreateError { path: target.into(), err });
        },
    };

    // Decide the name of the image
    let name: String = if let Some(digest) = image.digest {
        digest
    } else {
        format!("{}{}", image.name, if let Some(version) = image.version { format!(":{version}") } else { String::new() })
    };

    // Read the image tar as raw bytes from the Daemon
    let mut total: usize = 0;
    let mut stream = docker.export_image(&name);
    while let Some(chunk) = stream.next().await {
        // Unwrap the chunk
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                return Err(Error::ImageExportError { name, err });
            },
        };
        debug!("Next chunk: {} bytes", chunk.len());

        // Write it to the file
        if let Err(err) = handle.write(&chunk).await {
            return Err(Error::ImageFileWriteError { path: target.into(), err });
        }
        debug!("Write OK");
        total += chunk.len();
    }
    println!("Total downloaded size: {total} bytes");

    // Finish the stream & the handle
    if let Err(err) = handle.flush().await {
        return Err(Error::ImageFileShutdownError { path: target.into(), err });
    }
    if let Err(err) = handle.shutdown().await {
        return Err(Error::ImageFileShutdownError { path: target.into(), err });
    }

    // Done
    Ok(())
}





/***** LIBRARY *****/
/// Launches the given job and returns its name so it can be tracked.
///
/// Note that this function makes its own connection to the local Docker daemon.
///
/// # Arguments
/// - `opts`: The DockerOptions that contains information on how we can connect to the local daemon.
/// - `exec`: The ExecuteInfo that describes the job to launch.
///
/// # Returns
/// The name of the container such that it can be waited on later.
///
/// # Errors
/// This function errors for many reasons, some of which include not being able to connect to Docker or the container failing (to start).
pub async fn launch(opts: impl AsRef<DockerOptions>, exec: ExecuteInfo) -> Result<String, Error> {
    // Connect to docker
    let docker: Docker = connect_local(opts)?;

    // Either import or pull image, if not already present
    ensure_image(&docker, &exec.image, &exec.image_source).await?;

    // Start container, return immediately (propagating any errors that occurred)
    create_and_start_container(&docker, &exec).await
}

/// Joins the container with the given name, i.e., waits for it to complete and returns its results.
///
/// # Arguments
/// - `opts`: The DockerOptions that contains information on how we can connect to the local daemon.
/// - `name`: The name of the container to wait for.
/// - `keep_container`: If true, then will not remove the container after it has been launched. This is very useful for debugging.
///
/// # Returns
/// The return code of the docker container, its stdout and its stderr (in that order).
///
/// # Errors
/// This function may error for many reasons, which usually means that the container is unknown or the Docker engine is unreachable.
pub async fn join(opts: impl AsRef<DockerOptions>, name: impl AsRef<str>, keep_container: bool) -> Result<(i32, String, String), Error> {
    let name: &str = name.as_ref();

    // Connect to docker
    let docker: Docker = connect_local(opts)?;

    // And now wait for it
    join_container(&docker, name, keep_container).await
}

/// Launches the given container and waits until its completed.
///
/// Note that this function makes its own connection to the local Docker daemon.
///
/// # Arguments
/// - `opts`: The DockerOptions that contains information on how we can connect to the local daemon.
/// - `exec`: The ExecuteInfo describing what to launch and how.
/// - `keep_container`: If true, then will not remove the container after it has been launched. This is very useful for debugging.
///
/// # Returns
/// The return code of the docker container, its stdout and its stderr (in that order).
///
/// # Errors
/// This function errors for many reasons, some of which include not being able to connect to Docker or the container failing.
pub async fn run_and_wait(opts: impl AsRef<DockerOptions>, exec: ExecuteInfo, keep_container: bool) -> Result<(i32, String, String), Error> {
    // This next bit's basically launch but copied so that we have a docker connection of our own.
    // Connect to docker
    let docker: Docker = connect_local(opts)?;

    // Either import or pull image, if not already present
    ensure_image(&docker, &exec.image, &exec.image_source).await?;

    // Start container, return immediately (propagating any errors that occurred)
    let name: String = create_and_start_container(&docker, &exec).await?;

    // And now wait for it
    join_container(&docker, &name, keep_container).await
}

/// Tries to return the (IP-)address of the container with the given name.
///
/// Note that this function makes a separate connection to the local Docker instance.
///
/// # Arguments
/// - `opts`: The DockerOptions that contains information on how we can connect to the local daemon.
/// - `name`: The name of the container to fetch the address of.
///
/// # Returns
/// The address of the container as a string on success, or an ExecutorError otherwise.
pub async fn get_container_address(opts: impl AsRef<DockerOptions>, name: impl AsRef<str>) -> Result<String, Error> {
    let name: &str = name.as_ref();

    // Try to connect to the local instance
    let docker: Docker = connect_local(opts)?;

    // Try to inspect the container in question
    let container = match docker.inspect_container(name.as_ref(), None).await {
        Ok(data) => data,
        Err(reason) => {
            return Err(Error::InspectContainerError { name: name.into(), err: reason });
        },
    };

    // Get the networks of this container
    let networks: HashMap<String, EndpointSettings> = container.network_settings.and_then(|n| n.networks).unwrap_or_default();

    // Next, get the address of the first network and try to return that
    if let Some(network) = networks.values().next() {
        let ip = network.ip_address.clone().unwrap_or_default();
        if ip.is_empty() { Ok(String::from("127.0.0.1")) } else { Ok(ip) }
    } else {
        Err(Error::ContainerNoNetwork { name: name.into() })
    }
}

/// Tries to remove the docker image with the given name.
///
/// Note that this function makes a separate connection to the local Docker instance.
///
/// # Arguments
/// - `opts`: The DockerOptions that contains information on how we can connect to the local daemon.
/// - `name`: The name of the image to remove.
///
/// # Errors
/// This function errors if removing the image failed. Reasons for this may be if the image did not exist, the Docker engine was not reachable, or ...
pub async fn remove_image(opts: impl AsRef<DockerOptions>, image: &Image) -> Result<(), Error> {
    // Try to connect to the local instance
    let docker: Docker = connect_local(opts)?;

    // Check if the image still exists
    let info = docker.inspect_image(&image.name()).await;
    if info.is_err() {
        // It doesn't (or we can't reach it), but either way, easy
        return Ok(());
    }

    // Set the options to remove
    let remove_options = Some(RemoveImageOptions { force: true, ..Default::default() });

    // Now we can try to remove the image
    let info = info.unwrap();
    match docker.remove_image(info.id.as_ref().unwrap(), remove_options, None).await {
        Ok(_) => Ok(()),
        Err(reason) => Err(Error::ImageRemoveError { image: Box::new(image.clone()), id: info.id.clone().unwrap(), err: reason }),
    }
}
