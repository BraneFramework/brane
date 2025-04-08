//! Module containing all logic to install Brane locally.
use std::env::consts::{ARCH, OS};
use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap_complete::{Generator, Shell, generate};
use tracing::{debug, info, warn};

use crate::registry;
use crate::utilities::{CopyError, SubCommandIter, copy};

/// Provides a map for the various user locations where shell completions are stored.
pub fn completion_locations() -> anyhow::Result<[(Shell, PathBuf); 3]> {
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;

    Ok([
        (Shell::Bash, base_dir.data_local_dir().join("bash-completion/completions")),
        (Shell::Fish, base_dir.data_local_dir().join("fish/vendor_completions.d")),
        (Shell::Zsh, base_dir.data_local_dir().join("zsh/site-functions")),
    ])
}

/// Installs the completion files in the relevant user directories
///
/// # Arguments
/// - parents: Creates the relevant directories if they don't exist yet
/// - force: overwrite files if they already exist
pub(crate) fn completions(parents: bool, force: bool) -> anyhow::Result<()> {
    info!("Installing completions");
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
            debug!("Creating {path:?}");

            if !force && path.exists() {
                warn!("File: {path} already exists and --force (-f) was not provided, skipping.", path = path.display());
            } else {
                let mut file = File::create(path).context("Attempted to create completion file")?;
                generate(shell, &mut command, bin_name, &mut file);
            }
        }
    }

    Ok(())
}

/// Installs the Brane binaries in the relevant user directories
///
/// # Arguments
/// - parents: Creates the relevant directories if they don't exist yet
/// - force: overwrite files if they already exist
pub(crate) fn binaries(parents: bool, force: bool) -> anyhow::Result<()> {
    info!("Installing binaries");
    let target_directory = PathBuf::from("./target/release");
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;
    let dest_dir = base_dir.executable_dir().context("Could not determine the directories in which to install")?;

    for target in registry::registry().search_for_system("binaries", OS, ARCH) {
        let Some(command) = target.command else { continue };

        let bin_name = command.get_name().to_owned();
        let src_path = target_directory.join(&bin_name);

        let dest_path = dest_dir.join(&bin_name);
        debug!("Installing to {}", dest_path.display());

        match copy(src_path, dest_path, force, parents) {
            Ok(_) => (),
            Err(ref err @ CopyError::FileAlreadyExists { .. }) => warn!("{err}, Skipping"),
            _ => {},
        }
    }

    Ok(())
}

/// Installs the Brane man pages in the relevant usre directories
///
/// # Arguments
/// - parents: Creates the relevant directories if they don't exist yet
/// - force: overwrite files if they already exist
pub(crate) fn manpages(parents: bool, force: bool) -> anyhow::Result<()> {
    info!("Installing manpages");
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to install")?;
    let dest_dir = base_dir.data_local_dir().join("man/man1");

    if !dest_dir.exists() {
        if parents {
            debug!("Creating directory {}", dest_dir.display());
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

/// Uninstall Brane from all installation locations we could have installed.
///
/// Note that Brane does not know if those files are actually created by Brane, so if something
/// else is stored at any location Brane will install, that file will be deleted.
pub(crate) fn uninstall() -> anyhow::Result<()> {
    info!("Uninstalling Brane");
    let base_dir = directories::BaseDirs::new().context("Could not determine directories in which to uninstall")?;

    // Removing binaries
    let dest_dir = base_dir.executable_dir().context("Could not determine the directories in which to uninstall")?;
    for target in registry::registry().search("binaries") {
        let path = dest_dir.join(target.output_name);

        if path.exists() {
            debug!("Removing file {}", path.display());
            std::fs::remove_file(&path).with_context(|| format!("Unable to remove: {}", path.display()))?;
        }
    }

    // Removing completion files
    for target in registry::registry().search("binaries") {
        let Some(command) = target.command else { continue };

        for (shell, directory) in completion_locations().context("Could not get completion locations")? {
            let path = directory.join(shell.file_name(command.get_name()));

            if path.exists() {
                debug!("Removing file {}", path.display());
                std::fs::remove_file(&path).with_context(|| format!("Unable to remove: {}", path.display()))?;
            }
        }
    }

    // Removing man page files
    let data_dir = base_dir.data_local_dir();
    let man_dir = data_dir.join("man/man1/");
    for target in registry::registry().search("binaries") {
        let Some(command) = target.command else { continue };

        for command in SubCommandIter::new(command) {
            let man = clap_mangen::Man::new(command.clone());
            let mut filename = man.get_filename();

            let path = man_dir.join(&filename);
            if path.exists() {
                debug!("Removing file {}", path.display());
                std::fs::remove_file(&path).with_context(|| format!("Unable to remove: {}", path.display()))?;
            }

            filename.push_str(".gz");
            let path = man_dir.join(&filename);
            if path.exists() {
                debug!("Removing file {}", path.display());
                std::fs::remove_file(&path).with_context(|| format!("Unable to remove: {}", path.display()))?;
            }
        }
    }

    Ok(())
}
