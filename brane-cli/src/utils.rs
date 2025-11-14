//  UTILS.rs
//    by Lut99
//
//  Created:
//    21 Feb 2022, 14:43:30
//  Last edited:
//    11 Apr 2023, 15:35:16
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains useful utilities used throughout the brane-cli package.
//

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use specifications::package::PackageKind;
use specifications::version::AliasedFunctionVersion;

// use crate::{MIN_DOCKER_VERSION, MIN_BUILDX_VERSION};
use crate::errors::UtilError;


/***** HELPER ENUMS *****/
/// If a dependency is not met, this enum lists which one and why not.
#[derive(Debug, thiserror::Error)]
pub enum DependencyError {
    /// Docker cannot be reached
    #[error("Local Docker instance cannot be reached (is Docker installed and running?)")]
    DockerNotInstalled,
    /// Docker has a too low version
    #[error("Docker version is {got}, but Brane requires version {expected} or later")]
    DockerMinNotMet { got: semver::Version, expected: semver::Version },

    /// The Buildkit plugin is not installed for Docker
    #[error("Local Docker instance does not have the Buildkit plugin installed")]
    BuildkitNotInstalled,
    /// The Buildkit plugin has an incorrect version
    #[error("Buildkit plugin for Docker version is {got}, but Brane requires version {expected} or later")]
    BuildKitMinNotMet { got: semver::Version, expected: semver::Version },
}

/***** UTILITIES *****/
/// **Edited: Now returning UtilErrors.**
///
/// Checks the runtime dependencies of brane-cli (Docker + BuildKit)
///
/// **Returns**  
/// Nothing if the dependencies are met, a DependencyError if it wasn't, or a UtilError if we couldn't determine.
pub async fn check_dependencies() -> Result<Result<(), DependencyError>, UtilError> {
    // We checked all the runtime dependencies! (:sweat:)
    Ok(Ok(()))
}



/// **Edited: now returning CliErrors.**
///
/// Tries to determine the package file in the pulled repository.
///
/// TODO: This is rather dumb, why does it not just check the contents of the file?
///
/// **Arguments**
///  * `dir`: The directory the is the root of a package.
///
/// **Returns**  
/// A PathBuf pointing to what we think is the package file, or else a CliError if we could not determine it or something went wrong.
pub fn determine_file(dir: &Path) -> Result<PathBuf, UtilError> {
    // Open an iterator over the directory's files
    let files = fs::read_dir(dir).map_err(|source| UtilError::DirectoryReadError { dir: dir.to_path_buf(), source })?;

    // Iterate through them
    for file in files {
        // Make sure this file is valid
        let file = file.map_err(|source| UtilError::DirectoryReadError { dir: dir.to_path_buf(), source })?;

        // Compare the filename with anything we know
        let file_name = String::from(file.file_name().to_string_lossy()).to_lowercase();
        if file.path().is_file()
            && (file_name.eq("container.yml") || file_name.eq("container.yaml") || file_name.ends_with(".bk") || file_name.ends_with(".cwl"))
        {
            return Ok(PathBuf::from(file_name));
        }
    }

    Err(UtilError::UndeterminedPackageFile { dir: dir.to_path_buf() })
}



/// **Edited: not taking a context anymore, returning CliErrors and a PackageKind instead of a string.**
///
/// Tries to deduce the package kind from the given file.
///
/// **Arguments**
///  * `path`: Path to file from which we'd like to deduce the kind.
///
/// **Returns**  
/// The PackageKind if we could deduce it, or some sort of CliError if we could not or something went wrong.
pub fn determine_kind(path: &Path) -> Result<PackageKind, UtilError> {
    // See if the filename convention allows us to choose a package kind
    if let Some(file) = path.file_name() {
        let filename = String::from(file.to_string_lossy()).to_lowercase();
        if filename.eq("container.yml") || filename.eq("container.yaml") {
            // It's a code package, likely
            return Ok(PackageKind::Ecu);
        }
    }
    // See if the extension allows us to choose a package kind
    if let Some(extension) = path.extension() {
        let extension = String::from(extension.to_string_lossy()).to_lowercase();
        if extension.eq("bk") {
            // It's a Bakery / DSL package
            return Ok(PackageKind::Dsl);
        }
    }

    // For CWL we need to look inside the file
    let mut file_content = String::new();
    {
        // Open the file
        let mut handle = File::open(path).map_err(|source| UtilError::PackageFileOpenError { file: path.to_path_buf(), source })?;

        // Read the entire file to the string
        handle.read_to_string(&mut file_content).map_err(|source| UtilError::PackageFileReadError { file: path.to_path_buf(), source })?;
    }

    // Check if the content contains a keywords that allow us to say which package it is
    if file_content.contains("cwlVersion") {
        return Ok(PackageKind::Cwl);
    }

    // Could not determine the package
    Err(UtilError::UndeterminedPackageKind { file: path.to_path_buf() })
}



/// **Edited: uses dirs instead of appdirs and returns UtilErrors when it goes wrong.**
///
/// Returns the path of the configuration directory. Is guaranteed to be an absolute path when it returns successfully (but _not_ that it also exists!).
///
/// **Returns**  
/// The path of the Brane configuration directory if successful, or a UtilError otherwise.
pub fn get_config_dir() -> Result<PathBuf, UtilError> {
    // Try to get the user directory
    let user = dirs::config_dir().ok_or_else(|| UtilError::UserConfigDirNotFound)?;

    // Simply append Brane's path and return
    Ok(user.join("brane"))
}

/// Makes sure that Brane's config directory exists and then returns its path.
///
/// **Arguments**
///  * `create`: If true, creates the directory if it does not exist; if false, throws an error.
///
/// **Returns**  
/// The path of the Brane configuration directory if successful, or a UtilError otherwise.
pub fn ensure_config_dir(create: bool) -> Result<PathBuf, UtilError> {
    // Get the brane directory
    let config_dir: PathBuf = get_config_dir()?;

    // Check if the brane directory exists
    if !config_dir.exists() {
        // Either create it if told to do so, or error
        if create {
            fs::create_dir_all(&config_dir).map_err(|source| UtilError::BraneConfigDirCreateError { path: config_dir.clone(), source })?;
        } else {
            return Err(UtilError::BraneConfigDirNotFound { path: config_dir });
        }
    }

    // Done, return the path
    Ok(config_dir)
}

/// **Edited: Now returns UtilErrors.**
///
/// Returns the location of the history file for Brane.
///
/// **Returns**  
/// The path of the HistoryFile or a UtilError otherwise.
pub fn get_history_file() -> Result<PathBuf, UtilError> {
    // Get the config dir
    let config_dir = get_config_dir()?;

    // Add the path and return
    Ok(config_dir.join("repl_history.txt"))
}

/// Makes sure that the history file exists and then returns its path.
///
/// **Arguments**
///  * `create`: If true, creates the directory if it does not exist; if false, throws an error.
///
/// **Returns**  
/// The path of the HistoryFile or a UtilError otherwise.
pub fn ensure_history_file(create: bool) -> Result<PathBuf, UtilError> {
    // Get the path to the history file
    let history_file = get_history_file()?;

    // Make sure it exists
    if !history_file.exists() {
        // Either create it if told to do so, or error
        if create {
            // Make sure the config directory exists
            ensure_config_dir(create)?;

            // Now create the file
            File::create(&history_file).map_err(|source| UtilError::HistoryFileCreateError { path: history_file.clone(), source })?;
        } else {
            return Err(UtilError::HistoryFileNotFound { path: history_file });
        }
    }

    // Done
    Ok(history_file)
}



/// Returns the general data directory based on the user's home folder.
///
/// **Arguments**
///  * `create`: If set to true, creates the missing file and directories instead of throwing errors.
///
/// **Returns**  
/// A PathBuf with the absolute path that is guaranteed to exist, or an UtilError otherwise.
pub fn get_data_dir() -> Result<PathBuf, UtilError> {
    // Try to get the user directory
    let user = dirs::data_local_dir().ok_or_else(|| UtilError::UserLocalDataDirNotFound)?;

    // Join the Brane directory and done
    Ok(user.join("brane"))
}

/// Makes sure that Brane's data directory exists, and then returns its path.
///
/// **Arguments**
///  * `create`: If true, creates the directory if it does not exist; if false, throws an error.
///
/// **Returns**  
/// A PathBuf with the absolute path that is guaranteed to exist, or an UtilError otherwise.
pub fn ensure_data_dir(create: bool) -> Result<PathBuf, UtilError> {
    // Get the data directory
    let data_dir = get_data_dir()?;

    // Check if the brane directory exists
    if !data_dir.exists() {
        // Either create it if told to do so, or error
        if create {
            fs::create_dir_all(&data_dir).map_err(|source| UtilError::BraneDataDirCreateError { path: data_dir.clone(), source })?;
        } else {
            return Err(UtilError::BraneDataDirNotFound { path: data_dir });
        }
    }

    // Done (get_data_dir() is already absolute)
    Ok(data_dir)
}

/// **Edited: Changed to return UtilErrors.**
///
/// Returns the general package directory based on the user's home folder.  
/// Basically, tries to resolve the folder '~/.local/share/brane/packages`.  
/// Note that this does not mean that this directory exists.
///
/// **Returns**  
/// A PathBuf with an absolute path to the packages dir, or an UtilError otherwise.
pub fn get_packages_dir() -> Result<PathBuf, UtilError> {
    // Get the data directory
    let data_dir = get_data_dir()?;

    // Append the packages directory and done
    Ok(data_dir.join("packages"))
}

/// Makes sure that Brane's packages directory exists, and then returns its path.  
/// Basically, tries to resolve the folder '~/.local/share/brane/packages`.
///
/// **Arguments**
///  * `create`: If set to true, creates the missing file and directories instead of throwing errors.
///
/// **Returns**  
/// A PathBuf with the absolute path that is guaranteed to exist, or an UtilError otherwise.
pub fn ensure_packages_dir(create: bool) -> Result<PathBuf, UtilError> {
    // Get the packages directory
    let packages_dir = get_packages_dir()?;

    // Make sure it exists
    if !packages_dir.exists() {
        // Either create it if told to do so, or error
        if create {
            // Make sure the data directory exists
            ensure_data_dir(create)?;

            // Now create the directory
            fs::create_dir(&packages_dir).map_err(|source| UtilError::BranePackageDirCreateError { path: packages_dir.clone(), source })?;
        } else {
            return Err(UtilError::BranePackageDirNotFound { path: packages_dir });
        }
    }

    // Done, since the packages directory is always canonicalized
    Ok(packages_dir)
}

/// Returns the general data directory based on the user's home folder.  
/// Basically, tries to resolve the folder `~/.local/share/brane/data`.  
/// Note that this does not mean that this directory exists.
///
/// # Returns
/// A PathBuf with an absolute path to the data directory.
///
/// # Errors
/// This functions fails if we failed to get the Brane data directory (no confusion at all lol).
pub fn get_datasets_dir() -> Result<PathBuf, UtilError> {
    // Get the data directory (the global one)
    let data_dir = get_data_dir()?;

    // Append the dataset directory and done is Cees.
    Ok(data_dir.join("data"))
}

/// Makes sure that Brane's dataset directory exists, and then returns its path.  
/// Basically, tries to resolve the folder `~/.local/share/brane/data`.
///
/// # Arguments
/// - `create`: If set to true, creates the missing directories instead of throwing errors.
///
/// # Returns
/// A PathBuf with the absolute path to the datasets directory that is also guaranteed to exist.
///
/// # Errors
/// This function errors if we failed to get the Brane data directory (no confusion at all, lol) or the directory did not exist (if `create` is false) / was not accessible.
pub fn ensure_datasets_dir(create: bool) -> Result<PathBuf, UtilError> {
    // Get the data directory
    let data_dir: PathBuf = get_datasets_dir()?;

    // Make sure it exists
    if !data_dir.exists() {
        // Either create it if told to do so, or error
        if create {
            // Make sure the parent directory exists, then create this directory
            ensure_data_dir(create)?;
            fs::create_dir(&data_dir).map_err(|source| UtilError::BraneDatasetsDirCreateError { path: data_dir.clone(), source })?;
        } else {
            return Err(UtilError::BraneDatasetsDirNotFound { path: data_dir });
        }
    }

    // Done, since the dataset directory is already canonicalized
    Ok(data_dir)
}

/// **Edited: Now returning UtilErrors.**
///
/// Gets the directory where we likely stored the package.  
/// If the given version is omitted, just returns the package directory for this name.  
/// If the given version is latest, tries to find the latest version directory to return that; otherwise, errors that there are no versions to choose from.  
/// Does not guarantee that the directory also exists; check ensure_package_dir() for that.
///
/// **Arguments**
///  * `name`: The name of the package we want to get the directory from.
///  * `version`: The version of the package. Is optional to have a package directory that ignores versions.
///
/// **Returns**  
/// A PathBuf with the directory if successfull, or an UtilError otherwise.
pub fn get_package_dir(name: &str, version: Option<AliasedFunctionVersion>) -> Result<PathBuf, UtilError> {
    // Try to get the general package directory + the name of the package
    let packages_dir = get_packages_dir()?;
    let package_dir = packages_dir.join(name);

    // If there is no version, return the parent package dir (without version)
    let version = match version {
        Some(version) => version,
        None => return Ok(package_dir),
    };

    // Otherwise, resolve the version number if its 'latest'
    let version = match version {
        AliasedFunctionVersion::Latest => brane_tsk::local::get_package_versions(name, &package_dir)
            .map_err(|source| UtilError::VersionsError { source })?
            .into_iter()
            .max()
            .expect("We need at least one version in order to take the latest"),
        AliasedFunctionVersion::Version(version) => version.clone(),
    };

    // Return the path with the version appended to it
    Ok(package_dir.join(version.to_string()))
}

/// Makes sure that the package directory for the given name/version pair exists, then returns the path to it.  
/// If the given version is omitted, just returns the package directory for this name.  
/// If the given version is latest, tries to find the latest version directory to return that; otherwise, always errors (regardless of 'create').
///
/// **Arguments**
///  * `name`: The name of the package we want to get the directory from.
///  * `version`: The version of the package. Is optional to have a package directory without any nested versions.
///  * `create`: If set to true, creates the missing file and directories instead of throwing errors.
///
/// **Returns**  
/// A PathBuf with the directory if successfull, or an UtilError otherwise.
pub fn ensure_package_dir(name: &str, version: Option<&AliasedFunctionVersion>, create: bool) -> Result<PathBuf, UtilError> {
    // Retrieve the path for this version
    let package_dir = get_package_dir(name, version.cloned())?;

    // Make sure it exists
    if !package_dir.exists() {
        // Before we decide what to do, match on whether we have a version (to return more accurate errors)
        match version {
            Some(version) => {
                // Either create it if told to do so, or error
                if create {
                    // Make sure the packages directory exists
                    ensure_packages_dir(create)?;

                    // Now create the directory
                    fs::create_dir_all(&package_dir).map_err(|source| UtilError::VersionDirCreateError {
                        package: name.to_string(),
                        version: version.clone(),
                        path: package_dir.clone(),
                        source,
                    })?;
                } else {
                    return Err(UtilError::VersionDirNotFound { package: name.to_string(), version: version.clone(), path: package_dir });
                }
            },

            None => {
                // Either create it if told to do so, or error
                if create {
                    // Make sure the packages directory exists
                    ensure_packages_dir(create)?;

                    // Now create the directory
                    fs::create_dir_all(&package_dir).map_err(|source| UtilError::PackageDirCreateError {
                        package: name.to_string(),
                        path: package_dir.clone(),
                        source,
                    })?;
                } else {
                    return Err(UtilError::PackageDirNotFound { package: name.to_string(), path: package_dir });
                }
            },
        }
    }

    // It's alright
    Ok(package_dir)
}

/// Gets the directory where we likely stored a dataset.  
/// Does not guarantee that the directory also exists; check `ensure_dataset_dir()` for that.
///
/// # Generic arguments
/// - `S`: The &str-like `name` of the dataset to generate the path for.
///
/// # Arguments
/// - `name`: The name of the dataset we want to get the path of.
///
/// # Returns
/// A PathBuf with the (absolute path to the) directory.
///
/// # Errors
/// This function may error if we failed to get the parent datasets directory (see `get_datasets_dir()`).
pub fn get_dataset_dir<S: AsRef<str>>(name: S) -> Result<PathBuf, UtilError> {
    // Try to get the general package directory + the name of the package
    let datasets_dir = get_datasets_dir()?;
    let dataset_dir = datasets_dir.join(name.as_ref());

    // That seems about right
    Ok(dataset_dir)
}

/// Makes sure that the dataset directory for the given dataset exists, then returns the path to it.
///
/// # Generic arguments
/// - `S`: The &str-like `name` of the dataset to generate the path for.
///
/// # Arguments
/// - `name`: The name of the dataset we want to get/create the directory for.
/// - `create`: If set to true, creates the missing directories instead of throwing errors.
///
/// # Returns
/// A PathBuf with the directory.
///
/// # Errors
/// This function may error if we failed to get the parent datasets directory (see `get_datasets_dir()`) or if we failed to verify/create the dataset.
pub fn ensure_dataset_dir<S: AsRef<str>>(name: S, create: bool) -> Result<PathBuf, UtilError> {
    // Retrieve the path for this version
    let data_dir = get_dataset_dir(name.as_ref())?;

    // Make sure it exists
    if !data_dir.exists() {
        // Either create it if told to do so, or error
        if create {
            // Make sure the parent directory exists
            ensure_datasets_dir(create)?;

            // Now create the directory
            fs::create_dir_all(&data_dir).map_err(|source| UtilError::BraneDatasetDirCreateError {
                name: name.as_ref().into(),
                path: data_dir.clone(),
                source,
            })?;
        } else {
            return Err(UtilError::BraneDatasetDirNotFound { name: name.as_ref().into(), path: data_dir });
        }
    }

    // It's alright
    Ok(data_dir)
}

/// Gets the directory where we store instance definitions.
///
/// Does not guarantee that the directory exists. Check 'ensure_instances_dir()` for that.
///
/// # Returns
/// The path to the directory where we shall/have store(d) instance definitions.
///
/// # Errors
/// This function may error if we failed to get the Brane configuration directory.
pub fn get_instances_dir() -> Result<PathBuf, UtilError> {
    // Try to get the config directory
    let config_dir: PathBuf = get_config_dir()?;

    // Return that plus 'instances' (not rocket science, I know)
    Ok(config_dir.join("instances"))
}

/// Gets the directory where we store instance definitions and ensures it exists.
///
/// # Arguments
/// - `create`: If given, ensures it exists by attempting to create it. If set to false, then this function will error if it does not exist instead.
///
/// # Returns
/// The path to the directory where we shall/have store(d) instance definitions. You can assume the directory exists if this happens.
///
/// # Errors
/// This function errors if we failed to get the Brane configuration directory or if we failed to create any directory required.
pub fn ensure_instances_dir(create: bool) -> Result<PathBuf, UtilError> {
    // Retrieve the path
    let instances_dir: PathBuf = get_instances_dir()?;

    // Make sure it exists
    if !instances_dir.exists() {
        // Either create it if told to do so, or error
        if create {
            // Make sure the parent exists first
            ensure_config_dir(create)?;

            // Now create our directory
            fs::create_dir(&instances_dir).map_err(|source| UtilError::BraneInstancesDirCreateError { path: instances_dir.clone(), source })?;
        } else {
            return Err(UtilError::BraneInstancesDirNotFound { path: instances_dir });
        }
    }

    // Otherwise, robert's your father's brother
    Ok(instances_dir)
}

/// Gets the directory where we store the instance definition for the given instance.
///
/// Does not guarantee that the directory exists. Check 'ensure_instance_dir()` for that.
///
/// # Arguments
/// - `name`: The name of the instance for which to get the directory.
///
/// # Returns
/// The path to the directory where we shall/have store(d) instance's definition.
///
/// # Errors
/// This function may error if we failed to get the Brane configuration directory.
pub fn get_instance_dir(name: impl AsRef<str>) -> Result<PathBuf, UtilError> {
    // Try to get the general instances directory
    let instances_dir: PathBuf = get_instances_dir()?;

    // Return that plus the name (not rocket science, I know)
    Ok(instances_dir.join(name.as_ref()))
}

/// Gets the directory where we store the instance definition for the given instance and ensures it exists.
///
/// # Arguments
/// - `name`: The name of the instance for which to get the directory.
/// - `create`: If given, ensures it exists by attempting to create it. If set to false, then this function will error if it does not exist instead.
///
/// # Returns
/// The path to the directory where we shall/have store(d) instance definition. You can assume the directory exists if this happens.
///
/// # Errors
/// This function errors if we failed to get the Brane configuration directory or if we failed to create any directory required.
pub fn ensure_instance_dir(name: impl AsRef<str>, create: bool) -> Result<PathBuf, UtilError> {
    let name: &str = name.as_ref();

    // Retrieve the path
    let instance_dir: PathBuf = get_instance_dir(name)?;

    // Make sure it exists
    if !instance_dir.exists() {
        // Either create it if told to do so, or error
        if create {
            // Make sure the parent exists first
            ensure_instances_dir(create)?;

            // Now create our directory
            fs::create_dir(&instance_dir).map_err(|source| UtilError::BraneInstanceDirCreateError {
                path: instance_dir.clone(),
                name: name.into(),
                source,
            })?;
        } else {
            return Err(UtilError::BraneInstanceDirNotFound { path: instance_dir, name: name.into() });
        }
    }

    // Otherwise, robert's your father's brother
    Ok(instance_dir)
}

/// Returns the path for the softlink that points to the active instance directory.
///
/// # Returns
/// The path to the softlink. Note that if this is returned, no guarantees are made about its existance.
///
/// # Errors
/// This function may error if we failed to get the Brane configuration directory.
pub fn get_active_instance_link() -> Result<PathBuf, UtilError> {
    // Get the configuration directory
    let config_dir: PathBuf = get_config_dir()?;

    // Simply return that with the file's path
    Ok(config_dir.join("active_instance"))
}



/// Returns an equivalent string to the given one, except that the first letter is capitalized.
///
/// **Arguments**
///  * `s`: The string to capitalize.
///
/// **Returns**  
/// A copy of the given string with the first letter in uppercase.
pub fn uppercase_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().chain(c).collect(),
    }
}



/// Checks whether the given string is a valid name for Bakery.
///
/// **Arguments**
///  * `name`: The name to check.
///
/// **Returns**  
/// Nothing if the name is valid, or a UtilError otherwise.
pub fn assert_valid_bakery_name(name: &str) -> Result<(), UtilError> {
    if name.chars().all(|c| c.is_alphanumeric() || c == '_') { Ok(()) } else { Err(UtilError::InvalidBakeryName { name: name.to_string() }) }
}
