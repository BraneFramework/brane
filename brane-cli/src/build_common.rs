//  BUILD COMMON.rs
//    by Lut99
//
//  Created:
//    21 Feb 2022, 12:32:28
//  Last edited:
//    19 Apr 2023, 11:19:54
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains common macros, constants and functions between the
//!   different
//

use std::fs;
use std::path::Path;
use std::process::Command;

use specifications::arch::Arch;

use crate::errors::BuildError;


/***** COMMON MACROS *****/
/// Wrapper around write! that returns BuildErrors instead of standard format errors.
macro_rules! write_build {
    ($($e:expr),*) => {
        write!($($e),*).map_err(|err| BuildError::DockerfileStrWriteError{ err })
    }
}

/// Wrapper around writeln! that returns BuildErrors instead of standard format errors.
macro_rules! writeln_build {
    ($($e:expr),*) => {
        writeln!($($e),*).map_err(|err| BuildError::DockerfileStrWriteError{ err })
    }
}





/***** COMMON CONSTANTS */
/// The URL which we use to pull the latest branelet executable from.
pub const BRANELET_URL: &str =
    concat!("https://github.com/braneframework/brane/releases/download/", concat!("v", env!("CARGO_PKG_VERSION")), "/branelet");





/***** COMMON FUNCTIONS *****/
/// **Edited: now returning BuildErrors. Also leaving .lock removal to the main handle function.**
///
/// Cleans the resulting build directory from the build files (but only if the build files should be removed).
///
/// **Arguments**
///  * `package_dir`: The directory to clean (we assume this has been canonicalized and thus exists).
///  * `files`: The files to remove from the build directory.
///
/// **Returns**  
/// Nothing - although this function will print BuildErrors as warnings to stderr using the logger.
pub fn clean_directory(package_dir: &Path, files: Vec<&str>) {
    // Remove the build files
    for file in files {
        let file = package_dir.join(file);
        if file.is_file() {
            if let Err(err) = fs::remove_file(&file) {
                warn!("{}", BuildError::FileCleanupError { path: file, err });
            }
        } else if file.is_dir() {
            if let Err(err) = fs::remove_dir_all(&file) {
                warn!("{}", BuildError::DirCleanupError { path: file, err });
            }
        } else {
            warn!("To-be-cleaned file '{}' is neither a file nor a directory", file.display());
        }
    }
}



/// Builds the docker image in the given package directory.
///
/// # Generic types
///  - `P`: The Path-like type of the container directory path.
///
/// # Arguments
///  - `arch`: The architecture for which to build this image.
///  - `package_dir`: The build directory for this image. We expect the actual image files to be under ./container.
///  - `tag`: Tag to give to the image so we can find it later (probably just `<package name>:<package version>`)
///
/// # Errors
/// This function fails if Buildx could not be test-ran, it could not run the Docker build command or the Docker build command did not return a successfull exit code.
pub fn build_docker_image<P: AsRef<Path>>(arch: Arch, package_dir: P, tag: String) -> Result<(), BuildError> {
    // Prepare the command to check for buildx (and launch the buildx image, presumably)
    let mut command = Command::new("docker");
    command.arg("buildx");
    let buildx = match command.output() {
        Ok(buildx) => buildx,
        Err(err) => {
            return Err(BuildError::BuildKitLaunchError { command: format!("{command:?}"), err });
        },
    };
    // Check if it was successfull
    if !buildx.status.success() {
        return Err(BuildError::BuildKitError {
            command: format!("{command:?}"),
            code:    buildx.status.code().unwrap_or(-1),
            stdout:  String::from_utf8_lossy(&buildx.stdout).to_string(),
            stderr:  String::from_utf8_lossy(&buildx.stdout).to_string(),
        });
    }

    // Next, launch the command to actually build the image
    let mut command = Command::new("docker");
    command.arg("buildx");
    command.arg("build");
    command.arg("--output");
    command.arg("type=docker,dest=image.tar");
    command.arg("--tag");
    command.arg(tag);
    command.arg("--platform");
    command.arg(format!("linux/{}", arch.docker()));
    command.arg("--build-arg");
    command.arg(format!("BRANELET_ARCH={}", arch.brane()));
    command.arg("--build-arg");
    command.arg(format!("JUICEFS_ARCH={}", arch.juicefs()));
    command.arg(".");
    command.current_dir(package_dir);
    let output = match command.status() {
        Ok(output) => output,
        Err(err) => {
            return Err(BuildError::ImageBuildLaunchError { command: format!("{command:?}"), err });
        },
    };
    // Check if it was successfull
    if !output.success() {
        return Err(BuildError::ImageBuildError { command: format!("{command:?}"), code: output.code().unwrap_or(-1) });
    }

    // Done! :D
    Ok(())
}
