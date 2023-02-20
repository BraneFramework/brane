//  DOWNLOAD.rs
//    by Lut99
// 
//  Created:
//    20 Feb 2023, 14:59:16
//  Last edited:
//    20 Feb 2023, 15:56:58
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements functions for dealing with the `download` subcommand.
// 

use std::fs;
use std::path::{Path, PathBuf};

use console::Style;
use enum_debug::EnumDebug as _;
use log::{debug, info};
use specifications::version::Version;
use tempfile::TempDir;

use brane_shr::fs::{download_file_async, DownloadSecurity};

pub use crate::errors::DownloadError as Error;
use crate::spec::{Arch, DownloadServicesSubcommand};


/***** HELPER FUNCTIONS *****/
/// Downloads either the central or the worker images (which depends solely on the tar name).
/// 
/// # Arguments
/// - `address`: The address of the file to download.
/// - `path`: The path to the directory where the image files will _eventually_ end up in.
/// 
/// # Errors
/// This function may error if we failed to reach GitHub, we failed to establish HTTPS or we failed to somehow write the file / create missing directories (if enabled).
async fn download_brane_services(address: impl AsRef<str>, path: impl AsRef<Path>) -> Result<(), Error> {
    let address : &str  = address.as_ref();
    let path    : &Path = path.as_ref();

    // Download it
    if let Err(err) = download_file_async(address, path, DownloadSecurity::https(), Some(Style::new().green().bold())).await {
        return Err(Error::DownloadError { address: address.into(), path: path.into(), err });
    }



    // Done!
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
/// - `kind`: The kind of images to download (e.g., central, worker or auxillary).
/// 
/// # Errors
/// This function may error if we failed to reach GitHub, we failed to establish HTTPS or we failed to somehow write the file / create missing directories (if enabled).
pub async fn services(fix_dirs: bool, path: impl AsRef<Path>, arch: Arch, version: Version, kind: DownloadServicesSubcommand) -> Result<(), Error> {
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

            // Attempt to download the tar to a temporary directory
            debug!("Creating temporary directory...");
            let temp: TempDir = match TempDir::new() {
                Ok(temp) => temp,
                Err(err) => { return Err(Error::TempDirError { err }); },
            };
            let tar_path: PathBuf = temp.path().join(format!("instance-{}.tar.gz", arch.brane()));

            // Hand it over the shared code
            download_brane_services(address, tar_path, path).await?;
        },
    }

    // Done!
    Ok(())
}
