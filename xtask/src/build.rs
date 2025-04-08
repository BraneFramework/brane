//! Module with all things related to building Brane targets.
use std::collections::HashSet;
use std::env::consts::{ARCH, OS};
use std::path::PathBuf;

use crate::registry::{self, BuildFuncInfo};

/// Build all given targets for the current operating system and architecture.
/// # Arguments
/// - `targets`: A list of targets to build.
///
/// Note that a target can be both a package name (e.g. 'brane-ctl') or a group name (e.g.
/// 'binaries').
pub fn build(targets: &[String]) -> anyhow::Result<()> {
    let registry = registry::registry();
    let build_targets: HashSet<_> = targets
        .iter()
        .flat_map(|target| {
            let mut found = registry.search_for_system(target, OS, ARCH).peekable();

            if found.peek().is_none() {
                eprintln!("Warning: Target {target} did not match any known targets for your system");
            }

            found
        })
        .collect();

    for target in build_targets {
        eprintln!("Building {target}", target = target.package_name);
        (target.build_command)(BuildFuncInfo { out_dir: PathBuf::from("./target/release") })?
    }

    Ok(())
}
