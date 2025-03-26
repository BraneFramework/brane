//  PACKAGE.rs
//    by Lut99
//
//  Created:
//    01 Mar 2023, 09:45:11
//  Last edited:
//    01 Mar 2023, 09:45:26
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the `package.yml` file and related structs.
//

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Result;
use chrono::{DateTime, Utc};
use enum_debug::EnumDebug;
// use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value as JValue;
use serde_with::skip_serializing_none;
use strum::{EnumIter, IntoEnumIterator};
use uuid::Uuid;

use crate::common::{Function, Type};
use crate::container::ContainerInfo;
use crate::version::Version;


/***** CUSTOM TYPES *****/
/// Shorthand for a map with String keys.
type Map<T> = std::collections::HashMap<String, T>;





/***** ERRORS *****/
/// Lists the errors that can occur for the [`PackageKind`] enum
#[derive(Debug, thiserror::Error)]
pub enum PackageKindError {
    /// We tried to convert a string to a [`PackageKind`] but failed
    #[error("'{}' is not a valid package type; possible types are {}", skind, Self::get_package_kinds())]
    IllegalKind { skind: String },
}

impl PackageKindError {
    /// Static helper that collects a list of possible package kinds.
    ///
    /// **Returns**  
    /// A string list of the possible package kinds to enter.
    fn get_package_kinds() -> String {
        let mut kinds = String::new();
        for kind in PackageKind::iter() {
            if !kinds.is_empty() {
                kinds += ", ";
            }
            kinds += &format!("'{kind}'");
        }
        kinds
    }
}

/// Lists the error for parsing a [`Capability`] from a string.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityParseError {
    /// An unknown capability was given.
    #[error("Unknown capability '{raw}'")]
    UnknownCapability { raw: String },
}


/// Lists the errors that can occur for the [`PackageInfo`] struct
#[derive(Debug, thiserror::Error)]
pub enum PackageInfoError {
    /// We could not parse a given yaml string as a [`PackageInfo`]
    #[error("Cannot construct PackageInfo object from YAML string")]
    IllegalString { source: serde_yaml::Error },
    /// We could not parse a given yaml file as a [`PackageInfo`]
    #[error("Cannot construct PackageInfo object from YAML file '{}'", path.display())]
    IllegalFile { path: PathBuf, source: serde_yaml::Error },
    /// We could not parse a given set of JSON-encoded [`PackageInfo`]s
    #[error("Cannot construct PackageInfo object from JSON value")]
    IllegalJsonValue { source: serde_json::Error },
    /// Could not open the file we wanted to load
    #[error("Error while trying to read PackageInfo file '{}'", path.display())]
    IOError { path: PathBuf, source: std::io::Error },

    /// Could not create the target file
    #[error("Could not create package info file '{}'", path.display())]
    FileCreateError { path: PathBuf, source: std::io::Error },
    /// Could not write to the given writer
    #[error("Could not serialize & write package info file")]
    FileWriteError { source: serde_yaml::Error },
}

/// Lists the errors that can occur for the [`PackageIndex`] struct
#[derive(Debug, thiserror::Error)]
pub enum PackageIndexError {
    /// A package/version combination has already been loaded into the [`PackageIndex`]
    #[error("Encountered duplicate version {version} of package '{name}'")]
    DuplicatePackage { name: String, version: String },
    /// Could not parse a version string as one
    #[error("Could not parse version string '{raw}' in package.yml of package '{package}' to a Version")]
    IllegalVersion { package: String, raw: String, source: semver::Error },

    /// We could not do a request to some server to get a JSON file
    #[error("Could not send a request to '{url}'")]
    RequestFailed { url: String, source: reqwest::Error },
    /// A HTTP request returned a non-200 status code
    #[error("Request sent to '{url}' returned status {status}")]
    ResponseNot200 { url: String, status: reqwest::StatusCode },
    /// Coult not parse a given remote JSON file as a [`PackageIndex`]
    #[error("Cannot construct PackageIndex object from JSON file at '{url}'")]
    IllegalJsonFile { url: String, source: reqwest::Error },

    /// Could not parse a given reader with JSON data as a [`PackageIndex`]
    #[error("Cannot construct PackageIndex object from JSON reader")]
    IllegalJsonReader { source: serde_json::Error },
    /// Could not correct parse the JSON as a list of [`PackageInfo`] structs
    #[error("Cannot parse list of PackageInfos")]
    IllegalPackageInfos { source: PackageInfoError },
    /// Could not open the file we wanted to load
    #[error("Error while trying to read PackageIndex file '{}'", path.display())]
    IOError { path: PathBuf, source: std::io::Error },
}


/***** AUXILLARY *****/
/// Enum that lists possible package types
#[derive(Debug, Deserialize, Clone, Copy, EnumIter, Eq, PartialEq, Serialize)]
pub enum PackageKind {
    /// The package is an executable package (wrapping some other language or code)
    #[serde(rename = "ecu")]
    Ecu,
    /// The package is an external DSL function
    #[serde(rename = "dsl")]
    Dsl,
    /// The package is an CWL job(?)
    #[serde(rename = "cwl")]
    Cwl,
}

impl PackageKind {
    /// Returns a more understandable name for the `PackageKind`s.
    pub fn pretty(&self) -> &str {
        match self {
            PackageKind::Ecu => "code package",
            PackageKind::Dsl => "BraneScript/Bakery package",
            PackageKind::Cwl => "CWL package",
        }
    }
}

impl std::str::FromStr for PackageKind {
    type Err = PackageKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Convert to lowercase
        let ls = s.to_lowercase();

        // Match
        match ls.as_str() {
            "ecu" => Ok(PackageKind::Ecu),
            "dsl" => Ok(PackageKind::Dsl),
            "cwl" => Ok(PackageKind::Cwl),
            _ => Err(PackageKindError::IllegalKind { skind: ls }),
        }
    }
}

impl std::convert::From<PackageKind> for String {
    fn from(value: PackageKind) -> String { String::from(&value) }
}

impl std::convert::From<&PackageKind> for String {
    fn from(value: &PackageKind) -> String {
        match value {
            PackageKind::Ecu => String::from("ecu"),
            PackageKind::Dsl => String::from("dsl"),
            PackageKind::Cwl => String::from("cwl"),
        }
    }
}

impl std::fmt::Display for PackageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", String::from(self)) }
}



/// Defines if the package has any additional requirements on the system it will run.
#[derive(Clone, Copy, Deserialize, EnumDebug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// The package requires access to a CUDA GPU
    CudaGpu,
}

impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Capability::*;
        match self {
            CudaGpu => write!(f, "cuda_gpu"),
        }
    }
}

impl AsRef<Capability> for Capability {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}

impl FromStr for Capability {
    type Err = CapabilityParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cuda_gpu" => Ok(Self::CudaGpu),

            _ => Err(CapabilityParseError::UnknownCapability { raw: s.into() }),
        }
    }
}





/***** LIBRARY *****/
/// The PackageInfo struct, which might be used alongside a Docker container to define its metadata.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageInfo {
    /// The created timestamp of the package.
    pub created: DateTime<Utc>,
    /// The identifier of this package, as an Uuid.
    pub id:      Uuid,
    /// The digest of the resulting image. As long as the image has not been generated, is None.
    pub digest:  Option<String>,

    /// The name/programming ID of this package.
    pub name: String,
    /// The version of this package.
    pub version: Version,
    /// The kind of this package.
    pub kind: PackageKind,
    /// The list of owners of this package.
    pub owners: Vec<String>,
    /// A short description of the package.
    pub description: String,

    /// Whether or not the functions in this package run detached (i.e., asynchronous).
    pub detached:  bool,
    /// The functions that this package supports.
    pub functions: Map<Function>,
    /// The types that this package adds.
    pub types:     Map<Type>,
}

#[allow(unused)]
impl PackageInfo {
    /// Constructor for the `PackageInfo`.
    ///
    /// **Arguments**
    ///  * `name`: The name/programming ID of this package.
    ///  * `version`: The version of this package.
    ///  * `kind`: The kind of this package.
    ///  * `owners`: The list of owners of this package.
    ///  * `description`: A short description of the package.
    ///  * `detached`: Whether or not the functions in this package run detached (i.e., asynchronous).
    ///  * `functions`: The functions that this package supports.
    ///  * `types`: The types that this package adds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        version: Version,
        kind: PackageKind,
        owners: Vec<String>,
        description: String,
        detached: bool,
        functions: Map<Function>,
        types: Map<Type>,
    ) -> PackageInfo {
        // Generate new ID & note the time
        let id = Uuid::new_v4();
        let created = Utc::now();

        // Return the package
        PackageInfo { created, id, digest: None, name, version, kind, owners, description, detached, functions, types }
    }

    /// **Edited: changed to return appropriate errors. Also added docstring.**
    ///
    /// Constructor for the `PackageInfo` that tries to construct it from the file at the given location.
    ///
    /// **Arguments**
    ///  * `path`: The path to load.
    ///
    /// **Returns**  
    /// The new `PackageInfo` upon success, or a [`PackageInfoError`] detailling why if it failed.
    pub fn from_path(path: PathBuf) -> Result<PackageInfo, PackageInfoError> {
        // Read the file first
        let contents = fs::read_to_string(&path).map_err(|source| PackageInfoError::IOError { path: path.clone(), source })?;

        // Next, delegate actual reading to from_string
        match PackageInfo::from_string(contents) {
            Err(PackageInfoError::IllegalString { source }) => Err(PackageInfoError::IllegalFile { path: path.clone(), source }),
            x => x,
        }
    }

    /// **Edited: changed to return appropriate errors. Also added docstring.**
    ///
    /// Constructor for the `PackageInfo` that tries to deserialize it.
    ///
    /// **Arguments**
    ///  * `contents`: The string that contains the contents for the `PackageInfo`.
    ///
    /// **Returns**  
    /// The new `PackageInfo` upon success, or a [`PackageInfoError`] detailling why if it failed.
    pub fn from_string(contents: String) -> Result<PackageInfo, PackageInfoError> {
        // Try to parse using serde
        serde_yaml::from_str(&contents).map_err(|source| PackageInfoError::IllegalString { source })
    }

    /// Writes the `PackageInfo` to the given location.
    ///
    /// **Generic types**
    ///  * `P`: The Path-like type of the given target location.
    ///
    /// **Arguments**
    ///  * `path`: The target location to write to the `PackageInfo` to.
    ///
    /// **Returns**  
    /// Nothing on success, or a [`PackageInfoError`] otherwise.
    pub fn to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), PackageInfoError> {
        // Convert the path-like to a path
        let path = path.as_ref();

        // Open a file
        let handle = File::create(path).map_err(|source| PackageInfoError::FileCreateError { path: path.to_path_buf(), source })?;

        // Use ::to_write() to deal with the actual writing
        self.to_writer(handle)
    }

    /// Writes the [`PackageInfo`] to the given writer.
    ///
    /// **Generic types**
    ///  * `W`: The type of the writer, which implements Write.
    ///
    /// **Arguments**
    ///  * `writer`: The writer to write to. Will be consumed.
    ///
    /// **Returns**  
    /// Nothing on success, or a PackageInfoError otherwise.
    pub fn to_writer<W: Write>(&self, writer: W) -> Result<(), PackageInfoError> {
        // Simply write with serde
        serde_yaml::to_writer(writer, self).map_err(|source| PackageInfoError::FileWriteError { source })
    }
}

impl From<ContainerInfo> for PackageInfo {
    fn from(container: ContainerInfo) -> Self {
        // Construct Function descriptions from the Actions
        let mut functions = Map::<Function>::with_capacity(container.actions.len());
        for (action_name, action) in container.actions {
            // Get the return values of the function
            let function_output = action.output.unwrap_or_default();

            // Wrap that in the three parameters needed for a function
            let arguments = action.input.unwrap_or_default();
            let pattern = action.pattern;
            let return_type = match function_output.first() {
                Some(output) => output.data_type.to_string(),
                None => String::from("unit"),
            };

            // Save the function under the original name
            let function = Function::new(arguments, pattern, return_type, action.requirements);
            functions.insert(action_name, function);
        }

        // Put it an other values in the new instance
        PackageInfo::new(
            container.name,
            container.version,
            container.kind,
            container.owners.unwrap_or_default(),
            container.description.unwrap_or_default(),
            container.entrypoint.kind == *"service",
            functions,
            container.types.unwrap_or_default(),
        )
    }
}

impl From<&ContainerInfo> for PackageInfo {
    fn from(container: &ContainerInfo) -> Self {
        // Construct Function descriptions from the Actions
        let mut functions = Map::<Function>::with_capacity(container.actions.len());
        for (action_name, action) in &container.actions {
            // Get the return values of the function
            let function_output = action.output.clone().unwrap_or_default();

            // Wrap that in the three parameters needed for a function
            let arguments = action.input.clone().unwrap_or_default();
            let pattern = action.pattern.clone();
            let return_type = match function_output.first() {
                Some(output) => output.data_type.to_string(),
                None => String::from("unit"),
            };

            // Save the function under the original name
            let function = Function::new(arguments, pattern, return_type, action.requirements.clone());
            functions.insert(action_name.clone(), function);
        }

        // Put it and other clones in the new instance
        PackageInfo::new(
            container.name.clone(),
            container.version,
            container.kind,
            match container.owners.as_ref() {
                Some(owners) => owners.clone(),
                None => Vec::new(),
            },
            match container.description.as_ref() {
                Some(description) => description.clone(),
                None => String::new(),
            },
            container.entrypoint.kind == *"service",
            functions,
            match container.types.as_ref() {
                Some(types) => types.clone(),
                None => Map::new(),
            },
        )
    }
}



/// Collects multiple [`PackageInfo`]s into one database, called the package index.
#[derive(Debug, Clone, Default)]
pub struct PackageIndex {
    /// The list of packages stored in the index.
    pub packages: Map<PackageInfo>,
    /// Cache of the standard 'latest' packages so we won't have to search every time.
    pub latest:   Map<(Version, String)>,
}

impl PackageIndex {
    /// Constructor for the `PackageIndex` that initializes it to having no packages.
    #[inline]
    pub fn empty() -> Self { PackageIndex::new(Map::<PackageInfo>::new()) }

    /// Constructor for the `PackageIndex`.
    ///
    /// **Arguments**
    ///  * `packages`: The map of packages to base this index on. Each key should be `<name>-<version>` (i.e., every package version is a separate entry).
    pub fn new(packages: Map<PackageInfo>) -> Self {
        // Compute the latest versions for each package
        let mut latest: Map<(Version, String)> = Map::with_capacity(packages.len());
        for (key, package) in &packages {
            // Check if the package name has already been added
            if !latest.contains_key(&package.name) {
                latest.insert(package.name.clone(), (package.version, key.clone()));
                continue;
            }

            // Check if the existing version is later or not
            let latest_package: &mut (Version, String) = latest.get_mut(&package.name).unwrap();
            if package.version >= latest_package.0 {
                // It is; update the version to point to the latest version of this package
                latest_package.0 = package.version;
                latest_package.1.clone_from(key);
            }
        }

        // Create the index with the packages and the latest version cache
        PackageIndex { packages, latest }
    }

    /// Tries to construct a new PackageIndex from the application file at the given path.
    ///
    /// **Arguments**
    ///  * `path`: Path to the application file.
    ///
    /// **Returns**  
    /// The new `PackageIndex` if it all went fine, or a [`PackageIndexError`] if it didn't.
    pub fn from_path(path: &Path) -> Result<Self, PackageIndexError> {
        // Try to open the referenced file
        let file = File::open(path).map_err(|source| PackageIndexError::IOError { path: PathBuf::from(path), source })?;

        // Wrap it in a bufreader and go to from_reader
        let buf_reader = BufReader::new(file);
        PackageIndex::from_reader(buf_reader)
    }

    /// Tries to construct a new `PackageIndex` from the given reader.
    ///
    /// **Arguments**
    ///  * `r`: The reader that contains the data to construct the `PackageIndex` from.
    ///
    /// **Returns**  
    /// The new `PackageIndex` if it all went fine, or a [`PackageIndexError`] if it didn't.
    pub fn from_reader<R: Read>(r: R) -> Result<Self, PackageIndexError> {
        // Try to parse using serde
        let value = serde_json::from_reader(r).map_err(|source| PackageIndexError::IllegalJsonReader { source })?;

        // Delegate the parsed JSON struct to the from_value one
        PackageIndex::from_value(value)
    }

    /// Tries to construct a new `PackageIndex` from a JSON file at the given URL.
    ///
    /// **Arguments**
    ///  * `url`: The location of the JSON file to parse.
    ///
    /// **Returns**  
    /// The new `PackageIndex` if it all went fine, or a [`PackageIndexError`] if it didn't.
    pub async fn from_url(url: &str) -> Result<Self, PackageIndexError> {
        // try to get the file
        let json = match reqwest::get(url).await {
            Ok(response) => {
                if response.status() == reqwest::StatusCode::OK {
                    // We have the request; now try to get it as json
                    response.json().await.map_err(|source| PackageIndexError::IllegalJsonFile { url: url.to_string(), source })?
                } else {
                    return Err(PackageIndexError::ResponseNot200 { url: url.to_string(), status: response.status() });
                }
            },
            Err(reason) => {
                return Err(PackageIndexError::RequestFailed { url: url.to_string(), source: reason });
            },
        };

        // Done; pass the rest to the from_value() function
        PackageIndex::from_value(json)
    }

    /// Tries to construct a new `PackageIndex` from the given JSON-parsed value.
    ///
    /// **Arguments**
    ///  * `v`: The JSON root value of the tree to parse.
    ///
    /// **Returns**  
    /// The new `PackageIndex` if it all went fine, or a [`PackageIndexError`] if it didn't.
    pub fn from_value(v: JValue) -> Result<Self, PackageIndexError> {
        // Parse the known packages from the list of json values
        let known_packages: Vec<PackageInfo> = serde_json::from_value(v)
            .map_err(|source| PackageIndexError::IllegalPackageInfos { source: PackageInfoError::IllegalJsonValue { source } })?;

        // Construct the package index from the list of packages
        PackageIndex::from_packages(known_packages)
    }

    /// Tries to construct a new `PackageIndex` from a list of [`PackageInfo`]s.
    ///
    /// **Arguments**
    ///  * `known_packages`: List of [`PackageInfo`]s to incorporate in the `PackageIndex`.
    ///
    /// **Returns**  
    /// The new `PackageIndex` if it all went fine, or a [`PackageIndexError`] if it didn't.
    pub fn from_packages(known_packages: Vec<PackageInfo>) -> Result<Self, PackageIndexError> {
        // Construct the list of packages and of versions
        let mut packages = Map::<PackageInfo>::new();
        for package in known_packages {
            // Compute the key for this package
            let key = format!("{}-{}", package.name, package.version);
            if packages.contains_key(&key) {
                return Err(PackageIndexError::DuplicatePackage { name: package.name.clone(), version: package.version.to_string() });
            }
            packages.insert(key, package.clone());
        }

        // We have collected the list so we're done!
        Ok(PackageIndex::new(packages))
    }

    /// Returns the package with the given name and (optional) version.
    ///
    /// **Arguments**
    ///  * `name`: The name of the package.
    ///  * `version`: The version of the package to get. If omitted, uses the latest version known to the `PackageIndex`.
    ///
    /// **Returns**  
    /// An (immuteable) reference to the package if it exists, or else None.
    pub fn get(&self, name: &str, version: Option<&Version>) -> Option<&PackageInfo> {
        // Resolve the package version
        let version = match version {
            Some(version) => {
                if version.is_latest() {
                    match self.get_latest_version(name) {
                        Some(version) => version,
                        None => {
                            return None;
                        },
                    }
                } else {
                    version
                }
            },
            None => match self.get_latest_version(name) {
                Some(version) => version,
                None => {
                    return None;
                },
            },
        };

        // Try to return the package info matching to this name/version pair
        self.packages.get(&format!("{name}-{version}"))
    }

    /// Returns the latest version of the given package.
    ///
    /// **Arguments**
    ///  * `name`: The name of the package.
    ///
    /// **Returns**  
    /// An (immuteable) reference to the version if this package if known, or else None.
    #[inline]
    fn get_latest_version(&self, name: &str) -> Option<&Version> { self.latest.get(name).map(|(version, _)| version) }
}
