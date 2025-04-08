//! Module containing logic to create manpages for all workspace members using the clap CLI.
use std::env::consts::{ARCH, OS};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Command;

use crate::registry::{self, Target};
use crate::utilities::SubCommandIter;

/// Generates all man pages for all commands (and subcommands) that are part of the given target.
///
/// # Arguments:
/// - target: Either a package name or a group name for which to generate the man pages
/// - destination: The location where to store the man pages
/// - compressed: Whether or not to compress the man pages using gzip encoding
/// - force: Overwrites the old files if they already exist
pub(crate) fn generate_by_target(target: Option<Target>, destination: impl AsRef<Path>, compressed: bool, force: bool) -> anyhow::Result<()> {
    let targets = match target {
        Some(target) => &[target][..],
        None => &registry::registry().list_targets(OS, ARCH).cloned().collect::<Vec<_>>(),
    };

    for target in targets {
        // clap will ensure the target contains a command if a target is specified
        let Some(command) = target.clone().command else {
            continue;
        };

        generate_recursively(command, destination.as_ref(), compressed, force)?;
    }

    Ok(())
}

/// Generate all man pages for a certain commands and its subcommands
///
/// Note: that this function **does** attempt to generate the man pages for the potential
/// subcommands. If this behaviour is desired use [`generate`] instead.
///
/// # Arguments:
/// - command: What `Command` to generate the man page for
/// - destination: The location where to store the man pages
/// - compressed: Whether or not to compress the man pages using gzip encoding
/// - force: Overwrites the old files if they already exist
pub(crate) fn generate_recursively(command: Command, destination: impl AsRef<Path>, compressed: bool, force: bool) -> anyhow::Result<()> {
    let destination = destination.as_ref();

    for command in SubCommandIter::new(command) {
        match generate(command, destination, compressed, force) {
            Ok(()) => (),
            Err(err @ ManGenerateError::FileExists { .. }) => eprintln!("{err}, skipping"),
            e @ Err(_) => return e.context("Could not generate man file"),
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManGenerateError {
    #[error("Man page file {path}, already exists")]
    FileExists { path: PathBuf },
    #[error("Could not render man page at: {path}", path = path.display())]
    ManError { source: std::io::Error, path: PathBuf },

    #[error("Could not create man page file: {path}", path = path.display())]
    FsCreateError { source: std::io::Error, path: PathBuf },
}

/// Generate a single man page for the given command.
///
/// Note: that this function **does not** attempt to generate the man pages for the potential
/// subcommands. If this behaviour is desired use [`generate_recursively`] instead.
///
/// # Arguments:
/// - command: What `Command` to generate the man page for
/// - destination: The location where to store the man pages
/// - compressed: Whether or not to compress the man pages using gzip encoding
/// - force: Overwrites the old files if they already exist
pub(crate) fn generate(command: Command, destination: impl AsRef<Path>, compressed: bool, force: bool) -> Result<(), ManGenerateError> {
    let destination = destination.as_ref();

    let man = clap_mangen::Man::new(command.clone());
    let mut filename = man.get_filename();

    if compressed {
        filename.push_str(".gz");
    }

    let path = destination.join(filename);

    if !force && path.exists() {
        return Err(ManGenerateError::FileExists { path: path.clone() });
    }

    let mut buffer = BufWriter::new(std::fs::File::create(&path).map_err(|source| ManGenerateError::FsCreateError { source, path: path.clone() })?);

    if compressed {
        let mut encoder = flate2::write::GzEncoder::new(buffer, flate2::Compression::default());
        man.render(&mut encoder).map_err(|source| ManGenerateError::ManError { source, path: path.clone() })?;
    } else {
        man.render(&mut buffer).map_err(|source| ManGenerateError::ManError { source, path: path.clone() })?;
    }

    Ok(())
}
