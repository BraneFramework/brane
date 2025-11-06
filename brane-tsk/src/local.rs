//  LOCAL.rs
//    by Lut99
//
//  Created:
//    18 Nov 2022, 14:46:51
//  Last edited:
//    22 May 2023, 13:39:32
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines functions for collecting local package & data indices.
//

use std::fs::{self, DirEntry, File, ReadDir};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde_json::json;
use specifications::data::{DataIndex, DataInfo};
use specifications::package::{PackageIndex, PackageInfo};
use specifications::version::ConcreteFunctionVersion;

pub use crate::errors::LocalError as Error;


/***** AUXILLARY FUNCTIONS *****/
/// Collects a list of versions in the given package directory.
///
/// # Arguments
/// - `package_dir`: The package directory to search. This function assumes it already exists.
/// - `package_name`: The name of the package we search the directory of (used for debugging purposes).
///
/// # Returns
/// The list of Versions found in the given package directory, or a PackageError if we couldn't.
pub fn get_package_versions(package_name: &str, package_dir: &Path) -> Result<Vec<ConcreteFunctionVersion>, Error> {
    // Get the list of available versions
    let version_dirs = fs::read_dir(package_dir).map_err(|source| Error::PackageDirReadError { path: package_dir.to_path_buf(), source })?;

    // Convert the list of strings into a version
    let mut versions: Vec<ConcreteFunctionVersion> = Vec::new();
    for dir in version_dirs {
        let dir_path = match dir {
            Ok(dir) => dir.path(),
            Err(source) => return Err(Error::PackageDirReadError { path: package_dir.to_path_buf(), source }),
        };

        // Next, check if it's a 'package dir' by checking for the files we need
        if !dir_path.join("package.yml").exists() {
            // It's not a version folder
            continue;
        }

        // Try to parse the filename as a version number
        let dir_name = match dir_path.file_name() {
            Some(value) => value.to_string_lossy().to_string(),
            None => {
                return Err(Error::UnreadableVersionEntry { path: dir_path });
            },
        };
        let version = ConcreteFunctionVersion::from_str(&dir_name).map_err(|source| Error::IllegalVersionEntry {
            package: package_name.to_string(),
            version: dir_name,
            source,
        })?;

        // Push it to the list and try again
        versions.push(version);
    }
    if versions.is_empty() {
        return Err(Error::NoVersions { package: package_name.to_string() });
    }

    // Done! Return it
    Ok(versions)
}





/***** LIBRARY *****/
/// Returns the an index of locally available packages and their versions.
///
/// # Arguments
/// - `packages_path`: The path to the directory that we read the packages from.
///
/// # Returns
/// A PackageIndex if we could retrieve it, or a PackageError if we failed.
///
/// # Errors
/// This function may error if we failed to read the local packages folder or if the packages folder was incorrectly laid out.
pub fn get_package_index(packages: impl AsRef<Path>) -> Result<PackageIndex, Error> {
    let packages_path: &Path = packages.as_ref();

    // Open an iterator to the list of files
    let package_dirs = fs::read_dir(packages_path).map_err(|source| Error::PackagesDirReadError { path: packages_path.into(), source })?;

    // Start iterating through all the packages
    let mut packages = vec![];
    for package in package_dirs {
        let package = package.map_err(|source| Error::PackagesDirReadError { path: packages_path.into(), source })?;

        // Make sure it's a directory
        let package_path = package.path();
        if !package_path.is_dir() {
            continue;
        }

        // Read the versions inside the package directory and add each of them separately
        let package_name = package_path.file_name().unwrap().to_string_lossy();
        let versions = get_package_versions(&package_name, &package_path)?;
        for version in versions {
            // Get the path of this version
            let version_path = package_path.join(version.to_string());

            // Try to read the propery package info
            let package_file = version_path.join("package.yml");
            match PackageInfo::from_path(package_file.clone()) {
                Ok(package_info) => {
                    packages.push(package_info);
                },
                Err(source) => {
                    return Err(Error::InvalidPackageYml { package: package_name.to_string(), path: package_file, source });
                },
            }
        }
    }

    // Generate the package index from the collected list of packages
    PackageIndex::from_value(json!(packages)).map_err(|source| Error::PackageIndexError { source })
}



/// Returns the an index of locally available datasets.
///
/// # Arguments
/// - `datasets_path`: The path to the directory that we read the packages from.
///
/// # Returns
/// A [`DataIndex`] if we could retrieve it, or an [`Error`] if we failed.
///
/// # Errors
/// This function may error if we failed to read the local data folder or if the data folder was incorrectly laid out.
pub fn get_data_index(datasets_path: impl AsRef<Path>) -> Result<DataIndex, Error> {
    let datasets_path: &Path = datasets_path.as_ref();

    // Start reading the directory
    let dirs: ReadDir = fs::read_dir(datasets_path).map_err(|source| Error::DatasetsReadError { path: datasets_path.into(), source })?;

    // Read it and iterate over all of the nested directories
    let mut infos: Vec<DataInfo> = Vec::with_capacity(16);
    for d in dirs {
        // Unwrap the entry
        let d: DirEntry = d.map_err(|source| Error::DatasetsReadError { path: datasets_path.into(), source })?;

        // If it's a directory, tentatively try to find a 'data.yml' file in there
        let d_path: PathBuf = d.path();
        let info_path: PathBuf = d_path.join("data.yml");
        if d_path.is_dir() && info_path.exists() {
            // Attempt to open the file
            let handle = File::open(&info_path).map_err(|source| Error::DataInfoOpenError { path: info_path.clone(), source })?;

            // Attempt to parse it
            let info: DataInfo = serde_yaml::from_reader(handle).map_err(|source| Error::DataInfoReadError { path: info_path, source })?;

            // Add it to the index
            infos.push(info);
        }
    }

    // Return a newly constructed info with it
    DataIndex::from_infos(infos).map_err(|source| Error::DataIndexError { source })
}
