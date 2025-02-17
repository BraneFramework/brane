use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::common::{CallPattern, Parameter, Type};
use crate::package::{Capability, PackageKind};
use crate::version::Version;


/***** CUSTOM TYPES *****/
type Map<T> = std::collections::HashMap<String, T>;





/***** ERRORS *****/
/// Defines error(s) for the VolumeBind struct.
#[derive(Debug)]
pub enum VolumeBindError {
    /// The given path is not an absolute path.
    PathNotAbsolute { path: PathBuf },
}

impl Display for VolumeBindError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use VolumeBindError::*;
        match self {
            PathNotAbsolute { path } => write!(f, "Given path '{}' is not absolute", path.display()),
        }
    }
}

impl std::error::Error for VolumeBindError {}



/// Collect errors relating to the LocalContainer specification.
#[derive(Debug)]
pub enum LocalContainerInfoError {
    /// Could not open the target file
    FileOpenError { path: PathBuf, err: std::io::Error },
    /// Could not parse the target file
    FileParseError { err: serde_yaml::Error },

    /// Could not create the target file
    FileCreateError { path: PathBuf, err: std::io::Error },
    /// Could not write to the given writer
    FileWriteError { err: serde_yaml::Error },
}

impl Display for LocalContainerInfoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            LocalContainerInfoError::FileOpenError { path, err } => write!(f, "Could not open local container file '{}': {}", path.display(), err),
            LocalContainerInfoError::FileParseError { err } => write!(f, "Could not read & parse local container file: {err}"),

            LocalContainerInfoError::FileCreateError { path, err } => {
                write!(f, "Could not create local container file '{}': {}", path.display(), err)
            },
            LocalContainerInfoError::FileWriteError { err } => write!(f, "Could not serialize & write local container file: {err}"),
        }
    }
}

impl Error for LocalContainerInfoError {}



/// Collects errors relating to the Container specification.
#[derive(Debug)]
pub enum ContainerInfoError {
    /// Could not open the target file
    FileReadError { path: PathBuf, err: std::io::Error },
    /// Could not parse the target file
    ParseError { err: serde_yaml::Error },

    /// Could not create the target file
    FileCreateError { path: PathBuf, err: std::io::Error },
    /// Could not write to the given writer
    FileWriteError { err: serde_yaml::Error },
}

impl Display for ContainerInfoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            ContainerInfoError::FileReadError { path, err } => write!(f, "Could not open & read container file '{}': {}", path.display(), err),
            ContainerInfoError::ParseError { err } => write!(f, "Could not parse container file YAML: {err}"),

            ContainerInfoError::FileCreateError { path, err } => write!(f, "Could not create container file '{}': {}", path.display(), err),
            ContainerInfoError::FileWriteError { err } => write!(f, "Could not serialize & write container file: {err}"),
        }
    }
}

impl Error for ContainerInfoError {}





/***** SPECIFICATIONS *****/
/// A special struct that prints a given VolumeBindOption as a Docker-compatible string.
#[derive(Debug)]
pub struct VolumeBindOptionDockerDisplay<'a> {
    /// The VolumeBindOption to show.
    option: &'a VolumeBindOption,
}

impl Display for VolumeBindOptionDockerDisplay<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use VolumeBindOption::*;
        match self.option {
            ReadOnly => write!(f, "ro"),
        }
    }
}


/// Defines possible options for a Docker volume binding.
#[derive(Clone, Debug)]
pub enum VolumeBindOption {
    /// The volume is read-only.
    ReadOnly,
}

impl VolumeBindOption {
    /// Returns a formatter that writes a Docker-compatible version of this VolumeBindOption.
    #[inline]
    pub fn docker(&self) -> VolumeBindOptionDockerDisplay { VolumeBindOptionDockerDisplay { option: self } }
}



/// A special struct that prints a given VolumeBind as a Docker-compatible string.
#[derive(Debug)]
pub struct VolumeBindDockerDisplay<'a> {
    /// The VolumeBind to show.
    bind: &'a VolumeBind,
}

impl Display for VolumeBindDockerDisplay<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(
            f,
            "{}:{}{}",
            self.bind.host.display(),
            self.bind.container.display(),
            if !self.bind.options.is_empty() {
                format!(":{}", self.bind.options.iter().map(|o| o.docker().to_string()).collect::<Vec<String>>().join(","))
            } else {
                String::new()
            }
        )
    }
}


/// Defines a single Docker volume binding.
#[derive(Clone, Debug)]
pub struct VolumeBind {
    /// The source location, on the host.
    pub host:      PathBuf,
    /// The target location, on the container.
    pub container: PathBuf,
    /// Any options for the bind.
    pub options:   Vec<VolumeBindOption>,
}

impl VolumeBind {
    /// Constructor for VolumeBind that does not initialize it with special options.
    ///
    /// # Arguments
    /// - `host`: The path to the host folder. Note that this path must be absolute.
    /// - `container`: The path to the container folder. Note that this path must be absolute.
    /// - `options`: The VolumeBindOptions that further customize the bind(s).
    ///
    /// # Returns
    /// A new VolumeBind instance.
    ///
    /// # Errors
    /// This function may error if either of the given paths is not actually absolute.
    pub fn new(host: impl Into<PathBuf>, container: impl Into<PathBuf>, options: Vec<VolumeBindOption>) -> Result<Self, VolumeBindError> {
        let host: PathBuf = host.into();
        let container: PathBuf = container.into();

        // Sanity check both paths are absolute
        if !host.is_absolute() {
            return Err(VolumeBindError::PathNotAbsolute { path: host });
        }
        if !container.is_absolute() {
            return Err(VolumeBindError::PathNotAbsolute { path: container });
        }

        // Add them
        Ok(Self { host, container, options })
    }

    /// Constructor for VolumeBind that initializes it as a read-only bind.
    ///
    /// # Arguments
    /// - `host`: The path to the host folder. Note that this path must be absolute.
    /// - `container`: The path to the container folder. Note that this path must be absolute.
    ///
    /// # Returns
    /// A new VolumeBind instance.
    ///
    /// # Errors
    /// This function may error if either of the given paths is not actually absolute.
    #[inline]
    pub fn new_readonly(host: impl Into<PathBuf>, container: impl Into<PathBuf>) -> Result<Self, VolumeBindError> {
        Self::new(host, container, vec![VolumeBindOption::ReadOnly])
    }

    /// Constructor for VolumeBind that initializes it as a read/write bind.
    ///
    /// # Arguments
    /// - `host`: The path to the host folder. Note that this path must be absolute.
    /// - `container`: The path to the container folder. Note that this path must be absolute.
    ///
    /// # Returns
    /// A new VolumeBind instance.
    ///
    /// # Errors
    /// This function may error if either of the given paths is not actually absolute.
    #[inline]
    pub fn new_readwrite(host: impl Into<PathBuf>, container: impl Into<PathBuf>) -> Result<Self, VolumeBindError> {
        Self::new(host, container, vec![])
    }

    /// Returns a formatter that writes a Docker-compatible version of this VolumeBindOption.
    #[inline]
    pub fn docker(&self) -> VolumeBindDockerDisplay { VolumeBindDockerDisplay { bind: self } }
}



/// Serializes an Image to a way that Docker likes.
#[derive(Debug)]
pub struct ImageDockerFormatter<'a> {
    /// The image to format
    image: &'a Image,
}
impl Display for ImageDockerFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(
            f,
            "{}",
            if let Some(digest) = &self.image.digest {
                digest[7..].into()
            } else {
                format!("{}{}", self.image.name, if let Some(version) = &self.image.version { format!(":{version}") } else { String::new() })
            }
        )
    }
}

/// Specifies the name of an Image, possibly with digest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    /// The name/label of the image.
    pub name:    String,
    /// The version/label of the image, if any.
    pub version: Option<String>,
    /// If we know a digest of the image, this field tells us it.
    pub digest:  Option<String>,
}

impl Image {
    /// Constructor for the Image that instantiates it with the given name.
    ///
    /// # Arguments
    /// - `name`: The name/label of the image.
    /// - `digest`: The digest of the image if this is already known.
    ///
    /// # Returns
    /// A new Image instance.
    #[inline]
    pub fn new(name: impl Into<String>, version: Option<impl Into<String>>, digest: Option<impl Into<String>>) -> Self {
        Self { name: name.into(), version: version.map(|v| v.into()), digest: digest.map(|d| d.into()) }
    }

    /// Returns the name-part of the Image (i.e., the name + version).
    #[inline]
    pub fn name(&self) -> String { format!("{}{}", self.name, if let Some(version) = &self.version { format!(":{version}") } else { String::new() }) }

    /// Returns the digest-part of the Image.
    #[inline]
    pub fn digest(&self) -> Option<&str> { self.digest.as_deref() }

    /// Returns the Docker-compatible serialization of this Image.
    ///
    /// # Returns
    /// An ImageDockerFormatter which handles the formatting.
    #[inline]
    pub fn docker(&self) -> ImageDockerFormatter { ImageDockerFormatter { image: self } }
}

impl Display for Image {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(
            f,
            "{}{}{}",
            self.name,
            if let Some(version) = &self.version { format!(":{version}") } else { String::new() },
            if let Some(digest) = &self.digest { format!("@{digest}") } else { String::new() }
        )
    }
}

impl AsRef<Image> for Image {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&Image> for Image {
    #[inline]
    fn from(value: &Image) -> Self { value.clone() }
}
impl From<&mut Image> for Image {
    #[inline]
    fn from(value: &mut Image) -> Self { value.clone() }
}

impl From<String> for Image {
    fn from(s: String) -> Self { Self::from(s.as_str()) }
}
impl From<&String> for Image {
    fn from(s: &String) -> Self { Self::from(s.as_str()) }
}
impl From<&str> for Image {
    fn from(s: &str) -> Self {
        // First, split between digest and rest, if any '@' is present
        let (rest, digest): (&str, Option<&str>) = if let Some(idx) = s.rfind('@') { (&s[..idx], Some(&s[idx + 1..])) } else { (s, None) };

        // Next, search if there is a version or something
        let (name, version): (&str, Option<&str>) = if let Some(idx) = s.rfind(':') { (&rest[..idx], Some(&rest[idx + 1..])) } else { (rest, None) };

        // We can combine those in an Image
        Image { name: name.into(), version: version.map(|s| s.into()), digest: digest.map(|s| s.into()) }
    }
}



/// Specifies the contents of a contaienr info YAML file that is inside the container itself.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalContainerInfo {
    /// The name of the package
    pub name: String,
    /// The kind of the package
    pub kind: PackageKind,
    /// The entrypoint to the package
    pub entrypoint: Entrypoint,
    /// The list of actions that this package can do.
    pub actions: Map<Action>,
    /// The list of types that are declared in this package.
    pub types: Map<Type>,
}

impl LocalContainerInfo {
    /// Constructor for the LocalContainerInfo that constructs it from the given path.
    ///
    /// **Generic types**
    ///  * `P`: The Path-like type of the path given.
    ///
    /// **Arguments**
    ///  * `path`: the Path to read the new LocalContainerInfo from.
    ///
    /// **Returns**  
    /// A new LocalContainerInfo on success, or else a LocalContainerInfoError.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, LocalContainerInfoError> {
        // Convert the path-like to a Path
        let path = path.as_ref();

        // Open the file to read it
        let handle = match File::open(path) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(LocalContainerInfoError::FileOpenError { path: path.to_path_buf(), err });
            },
        };

        // Do the parsing with from_reader()
        Self::from_reader(handle)
    }

    /// Constructor for the LocalContainerInfo that constructs it from the given reader.
    ///
    /// **Generic types**
    ///  * `R`: The type of the reader, which implements Read.
    ///
    /// **Arguments**
    ///  * `reader`: The reader to read from. Will be consumed.
    ///
    /// **Returns**  
    /// A new LocalContainerInfo on success, or else a LocalContainerInfoError.
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, LocalContainerInfoError> {
        // Simply pass to serde
        match serde_yaml::from_reader(reader) {
            Ok(result) => Ok(result),
            Err(err) => Err(LocalContainerInfoError::FileParseError { err }),
        }
    }

    /// Writes the LocalContainerInfo to the given location.
    ///
    /// **Generic types**
    ///  * `P`: The Path-like type of the given target location.
    ///
    /// **Arguments**
    ///  * `path`: The target location to write to the LocalContainerInfo to.
    ///
    /// **Returns**  
    /// Nothing on success, or a LocalContainerInfoError otherwise.
    pub fn to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), LocalContainerInfoError> {
        // Convert the path-like to a path
        let path = path.as_ref();

        // Open a file
        let handle = match File::create(path) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(LocalContainerInfoError::FileCreateError { path: path.to_path_buf(), err });
            },
        };

        // Use ::to_write() to deal with the actual writing
        self.to_writer(handle)
    }

    /// Writes the LocalContainerInfo to the given writer.
    ///
    /// **Generic types**
    ///  * `W`: The type of the writer, which implements Write.
    ///
    /// **Arguments**
    ///  * `writer`: The writer to write to. Will be consumed.
    ///
    /// **Returns**  
    /// Nothing on success, or a LocalContainerInfoError otherwise.
    pub fn to_writer<W: Write>(&self, writer: W) -> Result<(), LocalContainerInfoError> {
        // Simply write with serde
        match serde_yaml::to_writer(writer, self) {
            Ok(()) => Ok(()),
            Err(err) => Err(LocalContainerInfoError::FileWriteError { err }),
        }
    }
}

impl From<ContainerInfo> for LocalContainerInfo {
    fn from(container_info: ContainerInfo) -> Self {
        Self {
            name: container_info.name,
            kind: container_info.kind,
            entrypoint: container_info.entrypoint,
            actions: container_info.actions,
            types: container_info.types.unwrap_or_default(),
        }
    }
}
impl From<&ContainerInfo> for LocalContainerInfo {
    fn from(container_info: &ContainerInfo) -> Self {
        Self {
            name: container_info.name.clone(),
            kind: container_info.kind,
            entrypoint: container_info.entrypoint.clone(),
            actions: container_info.actions.clone(),
            types: container_info.types.as_ref().cloned().unwrap_or_default(),
        }
    }
}



/// Specifies the contents of a container info YAML file. Note that this is only the file the user creates.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerInfo {
    /// The name/programming ID of this package.
    pub name: String,
    /// The version of this package.
    pub version: Version,
    /// The kind of this package.
    pub kind: PackageKind,
    /// The list of owners of this package.
    pub owners: Option<Vec<String>>,
    /// A short description of the package.
    pub description: Option<String>,

    /// The functions that this package supports.
    pub actions:    Map<Action>,
    /// The entrypoint of the image
    pub entrypoint: Entrypoint,
    /// The types that this package adds.
    pub types:      Option<Map<Type>>,

    /// The base image to use for the package image.
    pub base: Option<String>,
    /// The dependencies, as install commands for sudo apt-get install -y <...>
    pub dependencies: Option<Vec<String>>,
    /// Any environment variables that the user wants to be set
    pub environment: Option<Map<String>>,
    /// The list of additional files to copy to the image
    pub files: Option<Vec<String>>,
    /// An extra script to run to initialize the working directory
    pub initialize: Option<Vec<String>>,
    /// An extra set of commands that will be run _before_ the workspace is copied over. Useful for non-standard general dependencies.
    pub install: Option<Vec<String>>,
    /// An extra set of commands that will be run _after_ the workspace is copied over. Useful for preprocessing or unpacking things.
    #[serde(alias = "postinstall", alias = "post-install", alias = "post_install")]
    pub unpack: Option<Vec<String>>,
}

impl ContainerInfo {
    /// **Edited: now returning ContainerInfoErrors.**
    ///
    /// Returns a ContainerInfo by constructing it from the file at the given path.
    ///
    /// **Generic types**
    ///  * `P`: The Path-like type of the given target location.
    ///
    /// **Arguments**
    ///  * `path`: The path to the container info file.
    ///
    /// **Returns**  
    /// The newly constructed ContainerInfo instance on success, or a ContainerInfoError upon failure.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<ContainerInfo, ContainerInfoError> {
        // Convert the path-like to a path
        let path = path.as_ref();

        // Read the contents in one go
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) => {
                return Err(ContainerInfoError::FileReadError { path: path.to_path_buf(), err });
            },
        };

        // Delegate the actual parsing to from_string
        ContainerInfo::from_string(contents)
    }

    /// **Edited: now returning ContainerInfoErrors.**
    ///
    /// Returns a ContainerInfo by constructing it from the given Reader with YAML text.
    ///
    /// **Arguments**
    ///  * `r`: The reader with the contents of the raw YAML file.
    ///
    /// **Returns**  
    /// The newly constructed ContainerInfo instance on success, or a ContainerInfoError upon failure.
    pub fn from_reader<R: Read>(r: R) -> Result<ContainerInfo, ContainerInfoError> {
        match serde_yaml::from_reader(r) {
            Ok(result) => Ok(result),
            Err(err) => Err(ContainerInfoError::ParseError { err }),
        }
    }

    /// **Edited: now returning ContainerInfoErrors.**
    ///
    /// Returns a ContainerInfo by constructing it from the given string of YAML text.
    ///
    /// **Arguments**
    ///  * `contents`: The text contents of a raw YAML file.
    ///
    /// **Returns**  
    /// The newly constructed ContainerInfo instance on success, or a ContainerInfoError upon failure.
    pub fn from_string(contents: String) -> Result<ContainerInfo, ContainerInfoError> {
        match serde_yaml::from_str(&contents) {
            Ok(result) => Ok(result),
            Err(err) => Err(ContainerInfoError::ParseError { err }),
        }
    }

    /// Writes the ContainerInfo to the given location.
    ///
    /// **Generic types**
    ///  * `P`: The Path-like type of the given target location.
    ///
    /// **Arguments**
    ///  * `path`: The target location to write to the LocalContainerInfo to.
    ///
    /// **Returns**  
    /// Nothing on success, or a ContainerInfoError otherwise.
    pub fn to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), ContainerInfoError> {
        // Convert the path-like to a path
        let path = path.as_ref();

        // Open a file
        let handle = match File::create(path) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(ContainerInfoError::FileCreateError { path: path.to_path_buf(), err });
            },
        };

        // Use ::to_write() to deal with the actual writing
        self.to_writer(handle)
    }

    /// Writes the ContainerInfo to the given writer.
    ///
    /// **Generic types**
    ///  * `W`: The type of the writer, which implements Write.
    ///
    /// **Arguments**
    ///  * `writer`: The writer to write to. Will be consumed.
    ///
    /// **Returns**  
    /// Nothing on success, or a ContainerInfoError otherwise.
    pub fn to_writer<W: Write>(&self, writer: W) -> Result<(), ContainerInfoError> {
        // Simply write with serde
        match serde_yaml::to_writer(writer, self) {
            Ok(()) => Ok(()),
            Err(err) => Err(ContainerInfoError::FileWriteError { err }),
        }
    }
}



/// Defines the YAML of an action in a package.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    pub requirements: Option<HashSet<Capability>>,
    pub command: Option<ActionCommand>,
    pub description: Option<String>,
    pub endpoint: Option<ActionEndpoint>,
    pub pattern: Option<CallPattern>,
    pub input: Option<Vec<Parameter>>,
    pub output: Option<Vec<Parameter>>,
}



/// Defines the YAML of a command within an action in a package.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionCommand {
    pub args:    Vec<String>,
    pub capture: Option<String>,
}



/// Defines the YAML of a remote OAS action.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionEndpoint {
    pub method: Option<String>,
    pub path:   String,
}



/// Defines the YAML of the entry point to a package (in terms of function).
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entrypoint {
    pub kind:    String,
    pub exec:    String,
    pub content: Option<String>,
    pub delay:   Option<u64>,
}
