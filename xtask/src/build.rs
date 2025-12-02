//! Module with all things related to building Brane targets.
use std::collections::HashSet;
use std::env::consts::{ARCH, OS};

use anyhow::Context as _;
use tracing::{info, warn};

use crate::registry::{BuildFuncInfo, REGISTRY};
use crate::utilities::{ensure_dir_with_cachetag, get_cargo_target_directory};

/// Build all given targets for the current operating system and architecture.
/// # Arguments
/// - `targets`: A list of targets to build.
///
/// Note that a target can be both a package name (e.g. 'brane-ctl') or a group name (e.g.
/// 'binaries').
pub fn build(targets: &[String]) -> anyhow::Result<()> {
    let build_targets: HashSet<_> = targets
        .iter()
        .flat_map(|target| {
            let mut found = REGISTRY.search_for_system(target, OS, ARCH).peekable();

            if found.peek().is_none() {
                warn!("Target {target} did not match any known targets for your system");
            }

            found
        })
        .collect();

    let target_dir = get_cargo_target_directory().context("Could not get cargo target directory")?;
    ensure_dir_with_cachetag(target_dir.join("release")).context("Could not create release directory")?;

    for target in build_targets {
        info!("Building {target}", target = target.package_name);
        (target.build_command)(BuildFuncInfo { out_dir: target_dir.clone() })?
    }

    Ok(())
}
