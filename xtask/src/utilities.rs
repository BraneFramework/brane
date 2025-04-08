#![allow(dead_code)]
//! Module containing several utility functions to use in xtask.
use std::env::consts::*;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use tar::Builder;
use tokio::fs::File;
use tokio::io::BufReader;

/// Format the name of a binary as used in the GitHub release.
pub fn format_release_binary_name(name: &str) -> String { format!("{name}-{os}-{arch}{suffix}", os = OS, arch = ARCH, suffix = EXE_SUFFIX) }

/// Format the name of a binary as stored after compilation. It will handle the OS-dependent
/// suffixes, e.g. '.exe' for Windows.
pub fn format_src_binary_name(name: &str) -> String { format!("{name}{suffix}", suffix = EXE_SUFFIX) }

/// Format the name of a library as used in the GitHub release.
pub fn format_release_library_name(name: &str) -> String {
    format!("{prefix}{name}-{os}-{arch}{suffix}.gz", os = OS, arch = ARCH, prefix = DLL_PREFIX, suffix = DLL_SUFFIX)
}

/// Format the name of a library as stored after compilation. It will handle OS-dependent prefixes
/// and suffixes.
pub fn format_src_library_name(name: &str) -> String { format!("{prefix}{name}{suffix}", prefix = DLL_PREFIX, suffix = DLL_SUFFIX) }

/// Compress a file using Gzip encoding.
pub async fn compress_file(path: impl AsRef<Path>, dest: impl AsRef<Path>) -> anyhow::Result<()> {
    let path = path.as_ref();
    let dest = dest.as_ref();
    let file = File::open(path).await.with_context(|| format!("Could not open source file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let dest = File::create(dest).await.with_context(|| format!("Could not open destination file: {}", dest.display()))?;
    let mut encoder = async_compression::tokio::write::GzipEncoder::new(dest);

    tokio::io::copy(&mut reader, &mut encoder).await?;
    Ok(())
}

/// Create a .tar.gz compressed archive from a list of files. Inside the archive, a directory will
/// be created named `archive_name`, without the '.tar.gz' extension. Inside that directory, or
/// given files will be stored in a flat structure.
pub fn create_tar_gz(archive_name: impl AsRef<Path>, files: impl IntoIterator<Item = PathBuf>) -> anyhow::Result<()> {
    let archive_name = archive_name.as_ref();
    let file = std::io::BufWriter::new(std::fs::File::create(archive_name).context("Couldn't create the archive")?);
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = Builder::new(encoder);

    let dirname: PathBuf = archive_name
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Could not get filename from archive"))?
        .to_string_lossy()
        .strip_suffix(".tar.gz")
        .ok_or_else(|| anyhow::anyhow!("Could not extract directory name from archive name"))?
        .into();

    eprintln!("Creating archive: {dirname:?}");

    for file in files {
        let filename = file
            .as_path()
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Could not find filename"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Could not decode filename as UTF-8"))?;

        archive.append_path_with_name(file.as_path(), dirname.join(filename)).context("Could not add file to archive")?;
    }

    archive.finish().context("Could not finish writing archive")?;

    Ok(())
}

/// Ensure that a given directory contains a CACHEDIR.TAG. If the directory does not yet exist, the
/// function will create the directory. The most 'parent' newly created directory will store the
/// CACHEDIR.TAG. If no directories have to be created, it will try to create a CACHEDIR.TAG in the
/// requested directory.
pub fn ensure_dir_with_cachetag(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let path = path.as_ref();
    let absolute_path = std::env::current_dir().context("Could not get current directory")?.join(path);

    if absolute_path.exists() {
        if !absolute_path.is_dir() {
            anyhow::bail!("Output directory location exists, but is not a directory");
        }

        // FIXME: Do proper check
        if !absolute_path.join("CACHEDIR.TAG").exists() {
            // TODO: if a cachetag exists in the provided relative path, we don't have to create a new
            // cachetag
            std::fs::write(absolute_path.join("CACHEDIR.TAG"), "Signature: 8a477f597d28d172789f06886806bc55\n# Created by brane-xtask")?;
        }

        return Ok(());
    }

    let mut cursor = absolute_path.parent().unwrap();
    let mut child = absolute_path.as_path();
    loop {
        if cursor.exists() {
            // Since our child did not yet exist (by virtue that we ended up in this iteration of
            // the loop), we have found the most ancient directory to be created
            std::fs::create_dir(child).with_context(|| format!("Could not create new directory {path}", path = child.display()))?;

            std::fs::write(child.join("CACHEDIR.TAG"), "Signature: 8a477f597d28d172789f06886806bc55\n# Created by brane-xtask")
                .context("Could not create CACHEDIR.TAG")?;
            break;
        }

        child = cursor;
        cursor = cursor.parent().unwrap();
    }

    std::fs::create_dir_all(absolute_path).context("Could not create all remaining directories")?;

    Ok(())
}


/// Iterator that iterates over all man pages that could be generated from this clap::Command
/// For reference, clap::Commands can contain subcommands, recursively, which all can have their
/// own man page.
///
/// The order of this iterator is in-order
// TODO: This iterator is made entirely out of too many allocations
pub struct SubCommandIter {
    // Yeah, we should not allocate here
    todo: Vec<clap::Command>,
}

impl SubCommandIter {
    pub fn new(command: clap::Command) -> Self { Self { todo: vec![command] } }
}

impl Iterator for SubCommandIter {
    type Item = clap::Command;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.todo.pop();

        if let Some(ref item) = item {
            let subcommands = item.get_subcommands().cloned().map(|command| {
                // Add the super-commands name as a prefix
                let subcommand_name = command.get_name();
                let supercommand_name = item.get_name();
                let new_name = format!("{supercommand_name}-{subcommand_name}");
                command.name(new_name)
            });

            self.todo.extend(subcommands);
        }

        item.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CopyError {
    #[error("Could not create directories")]
    FsDirCreate { source: std::io::Error },
    #[error("Could not copy file")]
    FsCopy { source: std::io::Error },

    #[error("Parent directory: {parent} does not exist and --parents (-p) was not provided")]
    MissingParentDirectory { parent: PathBuf },

    #[error("\"Directory\": {parent} in which to install is not a directory")]
    ParentNotDirectory { parent: PathBuf },
    #[error("File {path} already exists and --force (-f) was not provided")]
    FileAlreadyExists { path: PathBuf },
}

/// This function is basically a wrapper around std::fs::copy, but it wraps some logic around
/// creating directories, force overwriting existing files.
///
/// # Arguments:
/// - src: The source path of the file
/// - dest: The destination path of the *file*,
///   Note: do not supply the directory as often done in commands like `cp(1)`
/// - force: In case the destination already exists, overwrite the file anyway
/// - parents: Create directories in the path towards dest, akin to `mkdir -p`
#[inline(always)]
pub(crate) fn copy(src: impl AsRef<Path>, dest: impl AsRef<Path>, force: bool, parents: bool) -> Result<(), CopyError> {
    let dest = dest.as_ref();

    let dest_dir = dest.parent().unwrap();

    if !dest_dir.exists() {
        if parents {
            std::fs::create_dir_all(dest_dir).map_err(|source| CopyError::FsDirCreate { source })?;
        } else {
            return Err(CopyError::MissingParentDirectory { parent: dest_dir.to_path_buf() });
        }
    } else if !dest_dir.is_dir() {
        return Err(CopyError::ParentNotDirectory { parent: dest_dir.to_path_buf() });
    }

    let exists = dest.exists();

    if !force && exists {
        return Err(CopyError::FileAlreadyExists { path: dest.to_path_buf() });
    }

    std::fs::copy(src, dest).map_err(|source| CopyError::FsCopy { source })?;

    Ok(())
}
