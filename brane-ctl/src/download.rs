//  DOWNLOAD.rs
//    by Lut99
// 
//  Created:
//    20 Feb 2023, 14:59:16
//  Last edited:
//    20 Feb 2023, 17:45:50
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements functions for dealing with the `download` subcommand.
// 

use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::{self, DirEntry, ReadDir};
use std::path::{Path, PathBuf};

use console::{style, Style};
use enum_debug::EnumDebug as _;
use log::{debug, info, warn};
use specifications::version::Version;
use tempfile::TempDir;

use brane_shr::fs::{download_file_async, move_path_async, unarchive_async, DownloadSecurity};

pub use crate::errors::DownloadError as Error;
use crate::spec::{Arch, DownloadServicesSubcommand};


/***** HELPER FUNCTIONS *****/
/// Downloads either the central or the worker images (which depends solely on the tar name).
/// 
/// # Arguments
/// - `address`: The address of the file to download.
/// - `path`: The path to the directory where the image files will _eventually_ end up in.
/// - `tar_name`: The base name of the tarball file, which is also the name if the directory inside it etc.
/// - `force`: If given, overwrites images if they are already there.
/// 
/// # Errors
/// This function may error if we failed to reach GitHub, we failed to establish HTTPS or we failed to somehow write the file / create missing directories (if enabled).
async fn download_brane_services(address: impl AsRef<str>, path: impl AsRef<Path>, tar_name: impl AsRef<str>, force: bool) -> Result<(), Error> {
    let address  : &str  = address.as_ref();
    let path     : &Path = path.as_ref();
    let tar_name : &str  = tar_name.as_ref();

    // Create a temporary directory to download the tar file to.
    debug!("Creating temporary directory...");
    let temp: TempDir = match TempDir::new() {
        Ok(temp) => temp,
        Err(err) => { return Err(Error::TempDirError { err }); },
    };
    let tar_path: PathBuf = temp.path().join(format!("{}.tar.gz", tar_name));

    // Download it
    if let Err(err) = download_file_async(address, &tar_path, DownloadSecurity::https(), Some(Style::new().green().bold())).await {
        // Don't call the destructor of `TempDir`, since it's much easier to debug if it lives after creation
        // SAFETY: This is OK because for our committed version, the destructor of `TempDir` only destroys the directory itself using a normal `std::fs::remove_dir_all()` call, and so nothing will explode if that does not happen.
        // (see https://docs.rs/tempfile/3.3.0/src/tempfile/dir.rs.html#403-407)
        std::mem::forget(temp);
        return Err(Error::DownloadError { address: address.into(), path: tar_path, err });
    }

    // Extract the folder to the same temporary directory
    println!("Unpacking {}...", style(format!("{}.tar.gz", tar_name)).bold().green());
    let dir_path: PathBuf = temp.path().join("services");
    if let Err(err) = unarchive_async(&tar_path, &dir_path).await {
        // Don't call the destructor of `TempDir`, since it's much easier to debug if it lives after creation
        // SAFETY: This is OK because for our committed version, the destructor of `TempDir` only destroys the directory itself using a normal `std::fs::remove_dir_all()` call, and so nothing will explode if that does not happen.
        // (see https://docs.rs/tempfile/3.3.0/src/tempfile/dir.rs.html#403-407)
        std::mem::forget(temp);
        return Err(Error::UnarchiveError{ tar: tar_path, target: dir_path, err });
    }
    // Be sure to do the folder inside the archive
    let dir_path: PathBuf = dir_path.join(tar_name);

    // Now copy the images in that folder to the target directory
    let entries: ReadDir = match fs::read_dir(&dir_path) {
        Ok(entries) => entries,
        Err(err)    => {
            // Don't call the destructor of `TempDir`, since it's much easier to debug if it lives after creation
            // SAFETY: This is OK because for our committed version, the destructor of `TempDir` only destroys the directory itself using a normal `std::fs::remove_dir_all()` call, and so nothing will explode if that does not happen.
            // (see https://docs.rs/tempfile/3.3.0/src/tempfile/dir.rs.html#403-407)
            std::mem::forget(temp);
            return Err(Error::ReadDirError{ path: dir_path, err });
        },
    };
    let mut i: usize = 0;
    for entry in entries {
        // Unwrap the entry
        let entry: DirEntry = match entry {
            Ok(entry) => entry,
            Err(err)  => {
                // Don't call the destructor of `TempDir`, since it's much easier to debug if it lives after creation
                // SAFETY: This is OK because for our committed version, the destructor of `TempDir` only destroys the directory itself using a normal `std::fs::remove_dir_all()` call, and so nothing will explode if that does not happen.
                // (see https://docs.rs/tempfile/3.3.0/src/tempfile/dir.rs.html#403-407)
                std::mem::forget(temp);
                return Err(Error::ReadEntryError{ path: dir_path, entry: i, err });
            },
        };

        // Check if we like it based on its path
        let entry_path: PathBuf = entry.path();
        if !entry_path.exists() {
            warn!("Not copying '{}' to output directory (does not exist)", entry_path.display());
            continue;
        }
        if !entry_path.is_file() {
            warn!("Not copying '{}' to output directory (not a file)", entry_path.display());
            continue;
        }

        // Now make sure it's a tar file
        let entry_name: OsString = entry.file_name();
        let entry_name: Cow<str> = entry_name.to_string_lossy();
        if !entry_name.ends_with(".tar") {
            warn!("Not copying '{}' to output directory (not ending in '.tar')", entry_path.display());
            continue;
        }

        // If we made it this far, we can copy
        let out_path: PathBuf = path.join(entry_name.as_ref());
        if force || !out_path.exists() {
            debug!("Moving '{}' to '{}'...", entry_path.display(), out_path.display());
            if let Err(err) = move_path_async(&entry_path, &out_path).await {
                // Don't call the destructor of `TempDir`, since it's much easier to debug if it lives after creation
                // SAFETY: This is OK because for our committed version, the destructor of `TempDir` only destroys the directory itself using a normal `std::fs::remove_dir_all()` call, and so nothing will explode if that does not happen.
                // (see https://docs.rs/tempfile/3.3.0/src/tempfile/dir.rs.html#403-407)
                std::mem::forget(temp);
                return Err(Error::MoveError{ source: entry_path, target: out_path, err });
            }
        }

        // Don't forget to increment the index
        i += 1;
    }

    // Done! If we haven't forgotten the temporary directory by now, moving out of scope will delete it for us
    Ok(())
}





/***** LIBRARY *****/
/// Downloads the service images to the local machine from the GitHub repo.
/// 
/// # Arguments
/// - `fix_dirs`: Whether to fix missing directories or error instead.
/// - `path`: The path of the folder to download the service images to.
/// - `version`: The version of the images to download.
/// - `arch`: The architecture for which to download the images.
/// - `force`: If given, overwrites images if they are already there.
/// - `kind`: The kind of images to download (e.g., central, worker or auxillary).
/// 
/// # Errors
/// This function may error if we failed to reach GitHub, we failed to establish HTTPS or we failed to somehow write the file / create missing directories (if enabled).
pub async fn services(fix_dirs: bool, path: impl AsRef<Path>, arch: Arch, version: Version, force: bool, kind: DownloadServicesSubcommand) -> Result<(), Error> {
    let path: &Path = path.as_ref();
    info!("Downloading {} service images...", kind.variant());

    // Fix the missing directories, if any.
    if !path.exists() {
        if !fix_dirs { return Err(Error::DirNotFound { what: "output", path: path.into() }); }
        if let Err(err) = fs::create_dir_all(path) { return Err(Error::DirCreateError { what: "output", path: path.into(), err }); }
    }
    if !path.is_dir() { return Err(Error::DirNotADir { what: "output", path: path.into() }); }

    // Now match on what we are downloading
    match kind {
        DownloadServicesSubcommand::Central => {
            // Resolve the address to use
            let address: String = if version.is_latest() {
                format!("https://github.com/epi-project/brane/releases/latest/download/instance-{}.tar.gz", arch.brane())
            } else {
                format!("https://github.com/epi-project/brane/releases/download/v{}/instance-{}.tar.gz", version, arch.brane())
            };
            debug!("Will download from: {}", address);

            // Hand it over the shared code
            download_brane_services(address, path, format!("instance-{}", arch.brane()), force).await?;
        },

        DownloadServicesSubcommand::Worker => {
            // Resolve the address to use
            let address: String = if version.is_latest() {
                format!("https://github.com/epi-project/brane/releases/latest/download/worker-instance-{}.tar.gz", arch.brane())
            } else {
                format!("https://github.com/epi-project/brane/releases/download/v{}/worker-instance-{}.tar.gz", version, arch.brane())
            };
            debug!("Will download from: {}", address);

            // Hand it over the shared code
            download_brane_services(address, path, format!("worker-instance-{}", arch.brane()), force).await?;
        },

        DownloadServicesSubcommand::Auxillary => {

        },
    }

    // Done!
    println!("Successfully downloaded {} services to {}", kind.variant().to_string().to_lowercase(), style(path.display()).bold().green());
    Ok(())
}
