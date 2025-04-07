use std::env::consts::*;
use std::path::PathBuf;

use anyhow::Context;

use crate::registry;
use crate::utilities::{compress_file, create_tar_gz, format_release_binary_name, format_src_binary_name, format_src_library_name};

pub(crate) async fn create_github_package() -> anyhow::Result<()> {
    eprintln!("Creating a package for: {os} {arch}", os = OS, arch = ARCH);

    let registry = registry::registry();

    let src_dir = PathBuf::from("target/release");
    let dst_dir = PathBuf::from("target/package/release");

    if !dst_dir.exists() {
        std::fs::create_dir_all(&dst_dir).context("Could not create all dirs leading up to destination dir")?
    }

    // CREATE BINARIES
    for (src, dst) in registry
        .search_for_system("binaries", OS, ARCH)
        .map(|target| (format_src_binary_name(&target.output_name), format_release_binary_name(&target.output_name)))
    {
        std::fs::copy(src_dir.join(&src), dst_dir.join(&dst)).with_context(|| format!("Could not copy over file: {src}"))?;
    }

    // CREATE LIBRARIES
    for target in registry.search_for_system("library", OS, ARCH) {
        compress_file(src_dir.join(format_src_library_name(&target.output_name)), dst_dir.join(format_src_library_name(&target.output_name)))
            .await
            .with_context(|| format!("Could not compress {library_name}", library_name = target.output_name))?;
    }

    // CREATE CENTRAL INSTANCE ARCHIVE
    let central_instance_dst = format!("central-instance-{arch}.tar.gz", arch = ARCH);
    let files: Vec<_> = registry.search_for_system("central", OS, ARCH).map(|target| src_dir.join(target.output_name)).collect();
    create_tar_gz(dst_dir.join(&central_instance_dst), files).context("Could not create 'central-instance' tar archive")?;

    // CREATE WORKER INSTANCE ARCHIVE
    let worker_instance_dst = format!("worker-instance-{arch}.tar.gz", arch = ARCH);
    let files: Vec<_> = registry.search_for_system("worker", OS, ARCH).map(|target| src_dir.join(target.output_name)).collect();
    create_tar_gz(dst_dir.join(&worker_instance_dst), files).context("Could not create 'worker-instance' tar archive")?;

    Ok(())
}
