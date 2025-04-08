//! Module containing all logic needed for generating completions from the clap CLI interface for
//! all workspace members.
use std::env::consts::{ARCH, OS};
use std::fs::File;
use std::path::Path;

use anyhow::Context as _;
use clap::{Command, ValueEnum};
use clap_complete::{Generator, Shell};

use crate::registry::{self, Target};

pub(crate) fn generate_by_target(target: Option<Target>, shell: Option<Shell>, destination: impl AsRef<Path>) -> anyhow::Result<()> {
    let destination = destination.as_ref();

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
            let Some(command) = target.command.clone() else { continue };
            generate(command, shell, destination)?
        }
    }

    Ok(())
}

pub(crate) fn generate(mut command: Command, shell: &Shell, destination: impl AsRef<Path>) -> anyhow::Result<()> {
    let destination = destination.as_ref();

    let bin_name = command.get_name().to_owned();
    let mut file = File::create(destination.join(shell.file_name(&bin_name)))
        .with_context(|| format!("Could not open/create completions file for {bin_name}"))?;
    clap_complete::generate(*shell, &mut command, &bin_name, &mut file);

    Ok(())
}
