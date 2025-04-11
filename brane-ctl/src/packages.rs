//  PACKAGES.rs
//    by Lut99
//
//  Created:
//    06 Dec 2022, 11:57:11
//  Last edited:
//    10 Mar 2023, 16:49:17
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements subcommands relating to packages.
//

use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::{self, DirEntry, ReadDir};
use std::path::PathBuf;
use std::str::FromStr;

use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, NodeKind, NodeSpecificConfig};
use brane_tsk::docker;
use specifications::version::Version;
use tracing::{debug, info, warn};

pub use crate::errors::PackagesError as Error;


/***** LIBRARY *****/
/// Attempts to hash the given container for use in policies.
///
/// # Arguments
/// - `node_config_path`: The path to the node config file that contains environment settings for this node.
///
/// # Returns
/// Nothing directly, but does print the hash to `stdout`.
///
/// # Errors
/// This function errors if we failed to find the given image or if we failed to hash the file.
pub async fn hash(node_config_path: impl Into<PathBuf>, image: impl Into<String>) -> Result<(), Error> {
    let node_config_path: PathBuf = node_config_path.into();
    let image: String = image.into();
    info!("Computing hash for image '{}'...", image);

    // Load the node config file
    debug!("Loading node config file '{}'...", node_config_path.display());
    let node_config: NodeConfig = NodeConfig::from_path(&node_config_path).map_err(|source| Error::NodeConfigLoadError { source })?;
    let packages_path: PathBuf = match node_config.node {
        NodeSpecificConfig::Central(node) => node.paths.packages,
        NodeSpecificConfig::Worker(node) => node.paths.packages,
        NodeSpecificConfig::Proxy(_) => return Err(Error::UnsupportedNode { what: "compute a package hash", kind: NodeKind::Proxy }),
    };

    // Attempt to resolve the image
    debug!("Resolving image...");
    let mut image_path: PathBuf = PathBuf::from(&image);
    if image_path.exists() {
        if !image_path.is_file() {
            return Err(Error::FileNotAFile { path: image_path });
        }
    } else {
        // It needs more work

        // Split the image into a name and possible version number
        let (name, version): (String, Version) =
            Version::from_package_pair(&image).map_err(|source| Error::IllegalNameVersionPair { raw: image, source })?;

        // Start reading the packages directory
        let entries: ReadDir =
            fs::read_dir(&packages_path).map_err(|source| Error::DirReadError { what: "packages", path: packages_path.clone(), source })?;
        let mut file: Option<(PathBuf, Version)> = None;
        for (i, entry) in entries.enumerate() {
            // Unwrap the entry
            let entry: DirEntry =
                entry.map_err(|source| Error::DirEntryReadError { what: "packages", entry: i, path: packages_path.clone(), source })?;

            // Attempt to analyse the filename by parsing it as a (name, version) pair
            let entry_name: OsString = entry.file_name();
            let entry_name: Cow<str> = entry_name.to_string_lossy();
            let dash_pos: usize = match entry_name.find('-') {
                Some(pos) => pos,
                None => {
                    warn!("Missing dash ('-') in file '{}' (skipping)", entry.path().display());
                    continue;
                },
            };
            let dot_pos: usize = match entry_name.rfind('.') {
                Some(pos) => pos,
                None => {
                    warn!("Missing extension dot ('.') in file '{}' (skipping)", entry.path().display());
                    continue;
                },
            };
            let ename: &str = &entry_name[..dash_pos];
            let eversion: &str = &entry_name[dash_pos + 1..dot_pos];

            // Attempt to parse the eversion
            let eversion: Version = match Version::from_str(eversion) {
                Ok(eversion) => eversion,
                Err(err) => {
                    warn!("File '{}' has illegal version number '{}': {} (skipping)", entry.path().display(), eversion, err);
                    continue;
                },
            };

            // Check if this package checks out
            if name == ename {
                // Only write it if the version makes sense
                if version.is_latest() {
                    // Check if it's 'latest' too or the highest
                    if eversion.is_latest() || file.is_none() || eversion > file.as_ref().unwrap().1 {
                        let is_latest: bool = eversion.is_latest();
                        file = Some((entry.path(), eversion));
                        if is_latest {
                            break;
                        }
                    }
                } else if version == eversion {
                    // Always accept it and stop searching
                    file = Some((entry.path(), eversion));
                    break;
                }
            }
        }

        // Fail if we didn't find any
        if let Some((path, _)) = file {
            image_path = path;
        } else {
            return Err(Error::UnknownImage { path: packages_path, name, version });
        }
    }

    // With the image resolved, hash it
    debug!("Hashing image '{}'...", image_path.display());
    let hash: String = docker::hash_container(&image_path).await.map_err(|source| Error::HashError { source })?;

    // Write it
    println!("{hash}");

    // Done
    Ok(())
}
