//! Module containing all logic needed for generating completions from the clap CLI interface for
//! all workspace members.
use std::env::consts::{ARCH, OS};
use std::fs::File;
use std::path::Path;

use anyhow::Context as _;
use clap::ValueEnum;
use clap_complete::{Generator, Shell};

use crate::registry::{self, Target};
use crate::utilities::ensure_dir_with_cachetag;

pub(crate) fn generate(target: Option<Target>, shell: Option<Shell>) -> anyhow::Result<()> {
    let out_dir = Path::new("./target/completions");
    ensure_dir_with_cachetag(out_dir).context("Could not ensure dir with cachetag")?;

    let shells_to_do = match shell {
        Some(shell) => &[shell][..],
        None => Shell::value_variants(),
    };

    let targets_to_do = match target {
        Some(target) => &[target][..],
        None => &registry::registry().list_targets(OS, ARCH).cloned().collect::<Vec<_>>(),
    };

    for shell in shells_to_do {
        for target in targets_to_do {
            let Some(mut command) = target.command.clone() else { continue };
            let bin_name = command.get_name().to_owned();
            let mut file = File::create(out_dir.join(shell.file_name(&bin_name)))
                .with_context(|| format!("Could not open/create completions file for {bin_name}"))?;
            clap_complete::generate(*shell, &mut command, &bin_name, &mut file);
        }
    }

    Ok(())
}
