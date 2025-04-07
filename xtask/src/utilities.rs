use std::env::consts::*;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use tar::Builder;
use tokio::fs::File;
use tokio::io::BufReader;

pub fn format_release_binary_name(name: &str) -> String { format!("{name}-{os}-{arch}{suffix}", os = OS, arch = ARCH, suffix = EXE_SUFFIX) }

pub fn format_src_binary_name(name: &str) -> String { format!("{name}{suffix}", suffix = EXE_SUFFIX) }

pub fn format_release_library_name(name: &str) -> String {
    format!("{prefix}{name}-{os}-{arch}{suffix}.gz", os = OS, arch = ARCH, prefix = DLL_PREFIX, suffix = DLL_SUFFIX)
}

pub fn format_src_library_name(name: &str) -> String { format!("{prefix}{name}{suffix}", prefix = DLL_PREFIX, suffix = DLL_SUFFIX) }

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
