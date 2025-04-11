//  UNPACK.rs
//    by Lut99
//
//  Created:
//    28 Mar 2023, 10:26:05
//  Last edited:
//    28 Mar 2023, 10:58:36
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements functions that can unpack internal files.
//

use std::fs;
use std::path::{Path, PathBuf};

use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, NodeKind};
use tracing::{debug, info};

pub use crate::errors::UnpackError as Error;
use crate::spec::ResolvableNodeKind;


/***** LIBRARY *****/
/// Unpacks the target Docker Compose file that we embedded in this executable.
///
/// # Arguments
/// - `kind`: The NodeKind that determines the specific file to unpack to.
/// - `fix_dirs`: Whether to fix missing directories.
/// - `path`: The path to write the new file to.
/// - `node_config_path`: The path to the `node.yml` file.
///
/// # Errors
/// This function errors if we failed to read the `node.yml` file, or failed to write the builtin one.
pub fn compose(kind: ResolvableNodeKind, fix_dirs: bool, path: impl AsRef<Path>, node_config_path: impl AsRef<Path>) -> Result<(), Error> {
    let path: &Path = path.as_ref();
    let node_config_path: &Path = node_config_path.as_ref();
    info!("Extracting Docker Compose file for '{}' to '{}'", kind, path.display());

    // Resolve the kind, if necessary
    let kind: NodeKind = match kind.0 {
        Some(kind) => kind,
        None => {
            debug!("Resolving node kind using '{}'...", node_config_path.display());

            // Load the node config file to resolve the kind
            let node_config: NodeConfig = NodeConfig::from_path(node_config_path).map_err(|source| Error::NodeConfigError { source })?;

            // Return the kind
            node_config.node.kind()
        },
    };

    // Resolve the path
    let path: PathBuf = path.to_string_lossy().replace("$NODE", &kind.to_string()).into();

    // Check if the target directory exists
    if let Some(parent) = path.parent() {
        debug!("Asserting target directory '{}' exists...", parent.display());

        // Assert it exists
        if !parent.exists() {
            // Either fix or fail
            if fix_dirs {
                fs::create_dir_all(parent).map_err(|source| Error::TargetDirCreateError { path: parent.into(), source })?;
            } else {
                return Err(Error::TargetDirNotFound { path: parent.into() });
            }
        }

        // Assert it is a directory
        if !parent.is_dir() {
            return Err(Error::TargetDirNotADir { path: parent.into() });
        }
    }

    // Get the correct file
    let compose: &str = match kind {
        NodeKind::Central => include_str!("../../docker-compose-central.yml"),
        NodeKind::Worker => include_str!("../../docker-compose-worker.yml"),
        NodeKind::Proxy => include_str!("../../docker-compose-proxy.yml"),
    };

    // Attempt to write it
    debug!("Writing file to '{}'...", path.display());
    fs::write(&path, compose).map_err(|source| Error::FileWriteError { what: "Docker Compose", path, source })?;

    // OK, done
    Ok(())
}
