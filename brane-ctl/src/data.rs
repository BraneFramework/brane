use std::path::{Path, PathBuf};

use anyhow::Context;
use brane_cfg::info::Info as _;
use brane_cfg::node::NodeConfig;
use brane_shr::fs::copy_dir_recursively_async;
use specifications::data::AssetInfo;
use tracing::{debug, error};

fn try_canonicalize(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}


/// Ensures that a directory exists. Contrary to create_dir(_all). This function does not error if
/// a directory already exists.
fn ensure_dir(path: impl AsRef<Path>) -> std::io::Result<()> {
    match std::fs::create_dir_all(path) {
        // All errors except already exists are still valid
        Err(e) if matches!(e.kind(), std::io::ErrorKind::AlreadyExists) => Ok(()),
        x => x,
    }
}

pub async fn import(node_config_path: PathBuf, source_asset_manifest_path: PathBuf, copy: bool) -> anyhow::Result<()> {
    debug!("Loading node config file '{}'...", node_config_path.display());
    let mut node_config =
        NodeConfig::from_path(&node_config_path).with_context(|| format!("Could not load node config from: {}", node_config_path.display()))?;

    node_config.node.resolve_paths(node_config_path.parent().expect("Could not determine parent directory of node.yml"));

    let Some(node_config) = node_config.node.try_into_worker() else {
        error!("Provided node config is not a worker node config");
        return Ok(());
    };

    // Determine all source paths
    let mut asset_info = AssetInfo::from_path(&source_asset_manifest_path).context("Could not load asset info")?;
    let source_asset_dir_path = source_asset_manifest_path.parent().unwrap();
    let source_access_manifest_path = match &asset_info.access {
        specifications::data::AccessKind::File { path } => path.clone(),
    };
    let source_access_fs_path = try_canonicalize(source_asset_dir_path.join(&source_access_manifest_path));

    // Determine all target paths
    let target_data_dir_path = node_config.paths.data.as_path();
    let target_asset_dir_path = target_data_dir_path.join(&asset_info.name);
    let target_asset_manifest_path = target_asset_dir_path.join("data.yml");

    let data_dir_name =
        source_access_fs_path.canonicalize().map(|v| v.file_name().and_then(|v| v.to_str()).unwrap_or("data").to_owned()).unwrap_or("data".into());

    let target_access_manifest_path = if copy { PathBuf::from(".").join(&data_dir_name) } else { source_access_fs_path.clone() };

    let target_access_fs_path = if copy { target_asset_dir_path.join(&data_dir_name) } else { source_access_fs_path.clone() };

    ensure_dir(target_data_dir_path).with_context(|| format!("Failed to ensure directory: {}", target_data_dir_path.display()))?;

    // Create new asset directory
    match std::fs::create_dir(&target_asset_dir_path) {
        Err(e) if matches!(e.kind(), std::io::ErrorKind::AlreadyExists) => {
            // TODO: Push up the error
            panic!("Directory already exists");
        },
        e => e,
    }
    .context("Could not create data dir")?;

    // Copy over data
    if copy {
        debug!("Copying over data from source access path to target access path");
        copy_dir_recursively_async(&source_access_fs_path, &target_access_fs_path).await.context("Could not copy over asset data")?;
    }

    // We change the location for the data access in the assetinfo and write that to the new
    // manifest location
    match &mut asset_info.access {
        specifications::data::AccessKind::File { path } => {
            *path = target_access_manifest_path;
        },
    }
    asset_info.to_path(&target_asset_manifest_path).context("Could not write updated manifest")?;
    debug!("Wrote new manifest to {}", target_asset_manifest_path.display());

    // TODO: Probably better to remove the dir if an error occurs after create_dir

    Ok(())
}
