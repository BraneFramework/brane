use std::env::consts::{ARCH, OS};
use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap_complete::{Generator, Shell, generate};

use crate::registry;

pub(crate) fn completions(force: bool) -> anyhow::Result<()> {
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;

    for (shell, location) in [
        (Shell::Bash, base_dir.data_local_dir().join("bash-completion/completions")),
        (Shell::Fish, base_dir.data_local_dir().join("fish/vendor_completions.d")),
        (Shell::Zsh, base_dir.data_local_dir().join("zsh/site-functions")),
    ] {
        if !location.exists() {
            if force {
                std::fs::create_dir_all(&location).context("Attempted to create completion directory")?;
            } else {
                bail!("Completion directory for {shell} does not exist, and command was not ran with --force");
            }
        }

        // We do not need completions for the binaries ran inside the images, as we cannot
        // auto-complete those anyway.
        for target in registry::registry().search_for_system("binaries", OS, ARCH) {
            let Some(mut command) = target.command else {
                continue;
            };

            let bin_name = command.get_name().to_owned();

            let completion_filename = shell.file_name(&bin_name);

            let path = location.join(completion_filename);
            tracing::debug!("Creating {path:?}");
            let mut file = File::create(path).context("Attempted to create completion file")?;
            generate(shell, &mut command, bin_name, &mut file);
        }
    }

    Ok(())
}

pub(crate) fn binaries(force: bool) -> anyhow::Result<()> {
    let target_directory = PathBuf::from("./target/release");

    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;

    let dest_dir = base_dir.executable_dir().context("Could not determine the directories in which to install")?;
    if !dest_dir.exists() {
        if force {
            std::fs::create_dir_all(dest_dir).context("Could not create required directories for installing the binaries")?;
        } else {
            bail!("Executable directory '{exec_dir}' does not exist, and was ran without --force", exec_dir = dest_dir.display());
        }
    }

    for target in registry::registry().search_for_system("binaries", OS, ARCH) {
        let Some(command) = target.command else {
            continue;
        };

        let bin_name = command.get_name().to_owned();
        let src_path = target_directory.join(&bin_name);

        eprintln!("{src_path:?} -> {dest_dir:?}");
        std::fs::copy(src_path, dest_dir.join(&bin_name))
            .with_context(|| format!("Unable to install binaries in '{exec_dir}'", exec_dir = dest_dir.display()))?;
    }

    Ok(())
}
