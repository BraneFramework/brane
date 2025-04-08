//! Module containing all logic to install Brane locally.
use std::env::consts::{ARCH, OS};
use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap_complete::{Generator, Shell, generate};

use crate::registry;
use crate::utilities::{CopyError, copy};

pub fn completion_locations() -> anyhow::Result<[(Shell, PathBuf); 3]> {
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;

    Ok([
        (Shell::Bash, base_dir.data_local_dir().join("bash-completion/completions")),
        (Shell::Fish, base_dir.data_local_dir().join("fish/vendor_completions.d")),
        (Shell::Zsh, base_dir.data_local_dir().join("zsh/site-functions")),
    ])
}

pub(crate) fn completions(parents: bool, force: bool) -> anyhow::Result<()> {
    let completion_locations = completion_locations().expect("Could not get completion locations");

    for (shell, location) in completion_locations {
        if !location.exists() {
            if parents {
                std::fs::create_dir_all(&location).context("Attempted to create completion directory")?;
            } else {
                bail!("Completion directory for {shell} does not exist, and command was not ran with --parents (-p)");
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

            if !force && path.exists() {
                eprintln!("File: {path} already exists and --force (-f) was not provided, skipping", path = path.display());
            } else {
                let mut file = File::create(path).context("Attempted to create completion file")?;
                generate(shell, &mut command, bin_name, &mut file);
            }
        }
    }

    Ok(())
}

pub(crate) fn binaries(parents: bool, force: bool) -> anyhow::Result<()> {
    let target_directory = PathBuf::from("./target/release");
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;
    let dest_dir = base_dir.executable_dir().context("Could not determine the directories in which to install")?;

    for target in registry::registry().search_for_system("binaries", OS, ARCH) {
        let Some(command) = target.command else { continue };

        let bin_name = command.get_name().to_owned();
        let src_path = target_directory.join(&bin_name);

        tracing::debug!("Copying: {src_path:?} -> {dest_dir:?}");
        let dest_path = dest_dir.join(&bin_name);

        match copy(src_path, dest_path, force, parents) {
            Ok(_) => (),
            Err(ref err @ CopyError::FileAlreadyExists { .. }) => eprintln!("{err}, Skipping"),
            _ => {},
        }
    }

    Ok(())
}

pub(crate) fn manpages(parents: bool, force: bool) -> anyhow::Result<()> {
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;
    let dest_dir = base_dir.data_local_dir().join("man/man1");

    if !dest_dir.exists() {
        if parents {
            std::fs::create_dir_all(&dest_dir).context("Could not create man page target directory")?;
        } else {
            anyhow::bail!("target directory did not exist and --parents (-p) was not provided");
        }
    }

    for target in registry::registry().search_for_system("binaries", OS, ARCH) {
        let Some(command) = target.command else { continue };

        crate::man::generate_recursively(command, &dest_dir, true, force)?;
    }

    Ok(())
}
