use std::collections::HashSet;
use std::env::consts::{ARCH, OS};
use std::path::PathBuf;

use crate::registry::{self, BuildFuncInfo, build_registry};

pub fn build(targets: &[String]) -> anyhow::Result<()> {
    let registry = registry::REGISTRY.get_or_init(build_registry);
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
        (target.build_command)(BuildFuncInfo { target_arch: String::from(std::env::consts::ARCH), out_dir: PathBuf::from("./target/release") })?
    }

    Ok(())
}
