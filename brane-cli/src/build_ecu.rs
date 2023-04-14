use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;

use console::style;
use dialoguer::Confirm;
use fs_extra::dir::CopyOptions;
use path_clean::clean as clean_path;

use brane_shr::fs::FileLock;
use specifications::arch::Arch;
use specifications::container::{ContainerInfo, LocalContainerInfo};
use specifications::package::PackageInfo;

use crate::build_common::{BRANELET_URL, build_docker_image, clean_directory};
use crate::errors::BuildError;
use crate::utils::ensure_package_dir;


/***** BUILD FUNCTIONS *****/
/// # Arguments
///  - `arch`: The architecture to compile this image for.
///  - `context`: The directory to copy additional files (executable, working directory files) from.
///  - `file`: Path to the package's main file (a container file, in this case).
///  - `branelet_path`: Optional path to a custom branelet executable. If left empty, will pull the standard one from Github instead.
///  - `keep_files`: Determines whether or not to keep the build files after building.
///  - `convert_crlf`: If true, will not ask to convert CRLF files but instead just do it.
/// 
/// # Errors
/// This function may error for many reasons.
pub async fn handle(
    arch: Arch,
    context: PathBuf,
    file: PathBuf,
    branelet_path: Option<PathBuf>,
    keep_files: bool,
    convert_crlf: bool,
) -> Result<(), BuildError> {
    debug!("Building ecu package from container file '{}'...", file.display());
    debug!("Using {} as build context", context.display());

    // Read the package into a ContainerInfo.
    let handle = match File::open(&file) {
        Ok(handle) => handle,
        Err(err)   => { return Err(BuildError::ContainerInfoOpenError{ file, err }); }
    };
    let reader = BufReader::new(handle);
    let document = match ContainerInfo::from_reader(reader) {
        Ok(document) => document,
        Err(err)     => { return Err(BuildError::ContainerInfoParseError{ file, err }); }
    };

    // Prepare package directory
    let package_dir = match ensure_package_dir(&document.name, Some(&document.version), true) {
        Ok(package_dir) => package_dir,
        Err(err)        => { return Err(BuildError::PackageDirError{ err }); }
    };

    // Lock the directory, build, unlock the directory
    {
        let _lock = match FileLock::lock(&document.name, &document.version, package_dir.join(".lock")) {
            Ok(lock) => lock,
            Err(err) => { return Err(BuildError::LockCreateError{ name: document.name, err }); },
        };
        build(arch, document, context, &package_dir, branelet_path, keep_files, convert_crlf).await?;
    };

    // Done
    Ok(())
}



/// Actually builds a new Ecu package from the given file(s).
/// 
/// # Arguments
///  - `arch`: The architecture to compile this image for.
///  - `document`: The ContainerInfo document describing the package.
///  - `context`: The directory to copy additional files (executable, working directory files) from.
///  - `package_dir`: The package directory to use as the build folder.
///  - `branelet_path`: Optional path to a custom branelet executable. If left empty, will pull the standard one from Github instead.
///  - `keep_files`: Determines whether or not to keep the build files after building.
///  - `convert_crlf`: If true, will not ask to convert CRLF files but instead just do it.
/// 
/// # Errors
/// This function may error for many reasons.
async fn build(
    arch: Arch,
    document: ContainerInfo,
    context: PathBuf,
    package_dir: &Path,
    branelet_path: Option<PathBuf>,
    keep_files: bool,
    convert_crlf: bool,
) -> Result<(), BuildError> {
    // Analyse files for Windows line endings
    let unixify_files: Vec<PathBuf> = find_crlf_files(&document, &context, convert_crlf)?;
    if !unixify_files.is_empty() { debug!("Files to convert: {}", unixify_files.iter().map(|p| format!("'{}'", p.display())).collect::<Vec<String>>().join(", ")); }

    // Prepare the build directory
    let dockerfile = generate_dockerfile(&document, &context, unixify_files, branelet_path.is_some())?;
    prepare_directory(
        &document,
        dockerfile,
        branelet_path,
        &context,
        package_dir,
    )?;
    debug!("Successfully prepared package directory.");

    // Build Docker image
    let tag = format!("{}:{}", document.name, document.version);
    debug!("Building image '{}' in directory '{}'", tag, package_dir.display());
    match build_docker_image(arch, package_dir, tag) {
        Ok(_) => {
            println!(
                "Successfully built version {} of container (ECU) package {}.",
                style(&document.version).bold().cyan(),
                style(&document.name).bold().cyan(),
            );

            // Create a PackageInfo and resolve the hash
            let mut package_info = PackageInfo::from(document);
            match brane_tsk::docker::get_digest(package_dir.join("image.tar")).await {
                Ok(digest) => { package_info.digest = Some(digest); },
                Err(err)   => { return Err(BuildError::DigestError{ err }); }
            }

            // Write it to package directory
            let package_path = package_dir.join("package.yml");
            if let Err(err) = package_info.to_path(package_path) {
                return Err(BuildError::PackageFileCreateError{ err });
            }
    
            // // Check if previous build is still loaded in Docker
            // let image_name = format!("{}:{}", package_info.name, package_info.version);
            // if let Err(e) = docker::remove_image(&image_name).await { return Err(BuildError::DockerCleanupError{ image: image_name, err }); }
    
            // // Upload the 
            // let image_name = format!("localhost:50050/library/{}", image_name);
            // if let Err(e) = docker::remove_image(&image_name).await { return Err(BuildError::DockerCleanupError{ image: image_name, err }); }
    
            // Remove all non-essential files.
            if !keep_files { clean_directory(package_dir, vec![ "Dockerfile", "container" ]); }
        },

        Err(err) => {
            // Print the error first
            eprintln!("{err}");

            // Print some output message, and then cleanup
            println!(
                "Failed to build version {} of container (ECU) package {}. See error output above.",
                style(&document.version).bold().cyan(),
                style(&document.name).bold().cyan(),
            );
            
            // Remove the build files if not told to keep them
            if !keep_files {
                if let Err(err) = fs::remove_dir_all(package_dir) { return Err(BuildError::CleanupError{ path: package_dir.to_path_buf(), err }); }
            }
        }
    }

    // Done
    Ok(())
}

/// Searches the files defined in the given document for any CRLF line endings (since we will have to translate that to Unix line endings if it's a script).
/// 
/// # Arguments
/// - `document`: The ContainerInfo describing which files to check.
/// - `context`: The directory to copy additional files (executable, working directory files) from.
/// - `convert_crlf`: If true, will not ask to convert CRLF files but instead just do it.
/// 
/// # Returns
/// A list of paths of files to convert.
fn find_crlf_files(document: &ContainerInfo, context: impl AsRef<Path>, convert_crlf: bool) -> Result<Vec<PathBuf>, BuildError> {
    debug!("Searching for files with CRLF line endings...");

    // We only have to do anything if there are files defined
    if let Some(files) = &document.files {
        let context: &Path = context.as_ref();

        // Iterate over the available files
        let mut to_unixify: Vec<PathBuf> = Vec::with_capacity(files.len());
        'files: for f in files {
            // Resolve the file's path
            let file_path: PathBuf = context.join(f);
            let file_path: PathBuf = match fs::canonicalize(&file_path) {
                Ok(source) => source,
                Err(err)   => { return Err(BuildError::WdSourceFileCanonicalizeError{ path: file_path, err }); }
            };

            // Attempt to open it
            let mut handle: File = match File::open(&file_path) {
                Ok(handle) => handle,
                Err(err)   => { warn!("Failed to open file '{}' to check if it has CRLF line endings: {} (assuming it has none)", file_path.display(), err); continue; },
            };

            // Read the first 512 bytes, at most
            let mut buffer: [ u8; 512 ] = [ 0; 512 ];
            let n_bytes: usize = match handle.read(&mut buffer) {
                Ok(n_bytes) => n_bytes,
                Err(err)    => { warn!("Failed to read file '{}' to check if it has CRLF line endings: {} (assuming it has none)", file_path.display(), err); continue; },
            };

            // Analyse them for either ASCII or UTF-8 validity
            let sbuffer: &str = match str::from_utf8(&buffer[..n_bytes]) {
                Ok(text) => text,
                Err(err) => { warn!("First 512 bytes of file '{}' are not valid UTF-8: {} (assuming it has no CRLF line endings)", file_path.display(), err); continue; },
            };

            // Now assert we don't see CRLF
            let mut carriage_return: bool = false;
            for c in sbuffer.chars() {
                // Match the character
                if c == '\r' {
                    carriage_return = true;
                } else if c == '\n' && carriage_return {
                    // It's a CRLF all right!
                    if convert_crlf {
                        // We are given permission a-priori, so just add it
                        info!("Marking file '{}' as having CRLF line-endings", file_path.display());
                        to_unixify.push(file_path);
                        continue 'files;
                    } else {
                        // We ask the user for permission first
                        println!("File {} may be written in Windows-style line endings. Do you want to convert it to Unix-style?", style(file_path.display()).bold().cyan());
                        println!("(You may run into issues if you don't, but it should only be done for text files)");
                        println!();
                        let consent: bool = match Confirm::new().interact() {
                            Ok(consent) => consent,
                            Err(err)    => { warn!("Failed to ask the user (you!) for consent to convert CRLF to LF: {err}"); continue 'files; }
                        };

                        // Now only add it if we have it
                        if consent {
                            info!("Marking file '{}' as having CRLF line-endings", file_path.display());
                            to_unixify.push(file_path);
                        }
                        continue 'files;
                    }

                } else {
                    // It's not a carriage return anymore
                    carriage_return = false;
                }
            }

            // Otherwise, it's not CRLF
            debug!("Marking file '{}' as having LF line-endings (no action required)", file_path.display());
        }

        // Return the list of found files
        Ok(to_unixify)
    } else {
        // Nothing to do
        Ok(vec![])
    }
}

/// **Edited: now returning BuildErrors.**
/// 
/// Generates a new DockerFile that can be used to build the package into a Docker container.
/// 
/// **Arguments**
///  * `document`: The ContainerInfo describing the package to build.
///  * `context`: The directory to find the executable in.
///  * `unixify_files`: A list of files we have to convert from CRLF to LF before we add it to the Dockerfile.
///  * `override_branelet`: Whether or not to override the branelet executable. If so, assumes the new one is copied to the temporary build folder by the time the DockerFile is run.
/// 
/// **Returns**  
/// A String that is the new DockerFile on success, or a BuildError otherwise.
fn generate_dockerfile(
    document: &ContainerInfo,
    context: &Path,
    unixify_files: Vec<PathBuf>,
    override_branelet: bool,
) -> Result<String, BuildError> {
    let mut contents = String::new();

    // Get the base image from the document
    let base = document.base.clone().unwrap_or_else(|| String::from("ubuntu:20.04"));

    // Add default heading
    writeln_build!(contents, "# Generated by Brane")?;
    writeln_build!(contents, "FROM {}", base)?;

    // Set the architecture build args
    writeln_build!(contents, "ARG BRANELET_ARCH")?;
    writeln_build!(contents, "ARG JUICEFS_ARCH")?;

    // Add environment variables
    if let Some(environment) = &document.environment {
        for (key, value) in environment {
            writeln_build!(contents, "ENV {}={}", key, value)?;
        }
    }

    // Add dependencies; write the apt-get RUN command with space for packages
    if base.starts_with("alpine") {
        write_build!(contents, "RUN apk add --no-cache ")?;
    } else {
        write_build!(contents, "RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-change-held-packages --allow-downgrades ")?;
    }
    // Default dependencies
    write_build!(contents, "fuse iptables dos2unix ")?;
    // Custom dependencies
    if let Some(dependencies) = &document.dependencies {
        for dependency in dependencies {
            write_build!(contents, "{} ", dependency)?;
        }
    }
    writeln_build!(contents)?;

    // Add the branelet executable
    if override_branelet {
        // It's the custom in the temp dir
        writeln_build!(contents, "ADD ./container/branelet /branelet")?;
    } else {
        // It's the prebuild one
        writeln_build!(contents, "ADD {}-$BRANELET_ARCH /branelet", BRANELET_URL)?;
    }
    // Always make it executable
    writeln_build!(contents, "RUN chmod +x /branelet")?;

    // Add the pre-installation script
    if let Some(install) = &document.install {
        for line in install {
            writeln_build!(contents, "RUN {}", line)?;
        }
    }

    // // Add JuiceFS
    // writeln_build!(contents, "RUN mkdir /data")?;
    // writeln_build!(contents, "ADD https://github.com/juicedata/juicefs/releases/download/v0.12.1/juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz /juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz")?;
    // writeln_build!(contents, "RUN tar -xzvf /juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz \\")?;
    // writeln_build!(contents, " && rm /LICENSE /README.md /README_CN.md /juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz")?;

    // Copy the package files
    writeln_build!(contents, "ADD ./container/wd.tar.gz /opt")?;
    writeln_build!(contents, "WORKDIR /opt/wd")?;

    // Copy the entrypoint executable
    let entrypoint = clean_path(&document.entrypoint.exec);
    if entrypoint.contains("..") { return Err(BuildError::UnsafePath{ path: entrypoint }); }
    let entrypoint = context.join(entrypoint);
    if !entrypoint.exists() || !entrypoint.is_file() { return Err(BuildError::MissingExecutable{ path: entrypoint }); }
    writeln_build!(contents, "RUN chmod +x /opt/wd/{}", &document.entrypoint.exec)?;

    // Rework the marked files from CRLF to LF
    if !unixify_files.is_empty() {
        let max_i: usize = unixify_files.len() - 1;
        write_build!(contents, "RUN ")?;
        for (i, file) in unixify_files.into_iter().enumerate() {
            if i > 0 { write_build!(contents, " && ")?; }
            write_build!(contents, "{}", file.display())?;
            if i < max_i { write_build!(contents, " \\")?; }
            writeln_build!(contents)?;
        }
    }

    // Add the post-installation script
    if let Some(install) = &document.unpack {
        for line in install {
            writeln_build!(contents, "RUN {}", line)?;
        }
    }

    // Finally, add branelet as the entrypoint
    writeln_build!(contents, "ENTRYPOINT [\"/branelet\"]")?;

    // Done!
    debug!("Using DockerFile:\n\n{}\n{}\n{}\n\n", (0..80).map(|_| '-').collect::<String>(), &contents, (0..80).map(|_| '-').collect::<String>());
    Ok(contents)
}

/// **Edited: now returning BuildErrors.**
/// 
/// Prepares the build directory for building the package.
/// 
/// **Arguments**
///  * `document`: The ContainerInfo document carrying metadata about the package.
///  * `dockerfile`: The generated DockerFile that will be used to build the package.
///  * `branelet_path`: The optional branelet path in case we want it overriden.
///  * `context`: The directory to copy additional files (executable, working directory files) from.
///  * `package_info`: The generated PackageInfo from the ContainerInfo document.
///  * `package_dir`: The directory where we can build the package and store it once done.
/// 
/// **Returns**  
/// Nothing if the directory was created successfully, or a BuildError otherwise.
fn prepare_directory(
    document: &ContainerInfo,
    dockerfile: String,
    branelet_path: Option<PathBuf>,
    context: &Path,
    package_dir: &Path,
) -> Result<(), BuildError> {
    // Write Dockerfile to package directory
    let file_path = package_dir.join("Dockerfile");
    debug!("Writing Dockerfile to '{}'...", file_path.display());
    match File::create(&file_path) {
        Ok(ref mut handle) => {
            if let Err(err) = write!(handle, "{dockerfile}") {
                return Err(BuildError::DockerfileWriteError{ path: file_path, err });
            }
        },
        Err(err)   => { return Err(BuildError::DockerfileCreateError{ path: file_path, err }); }
    };



    // Create the container directory
    let container_dir = package_dir.join("container");
    if !container_dir.exists() {
        if let Err(err) = fs::create_dir(&container_dir) {
            return Err(BuildError::ContainerDirCreateError{ path: container_dir, err });
        }
    }

    // Copy custom branelet binary to package directory if needed
    if let Some(branelet_path) = branelet_path {
        // Try to resole the branelet's path
        let source = match std::fs::canonicalize(&branelet_path) {
            Ok(source) => source,
            Err(err)   => { return Err(BuildError::BraneletCanonicalizeError{ path: branelet_path, err }); }
        };
        let target = container_dir.join("branelet");
        debug!("Copying custom branelet '{}' to '{}'...", source.display(), target.display());
        if let Err(err) = fs::copy(&source, &target) {
            return Err(BuildError::BraneletCopyError{ source, target, err });
        }
    }

    // Create a workdirectory and make sure it's empty
    let wd = container_dir.join("wd");
    if wd.exists() {
        if let Err(err) = fs::remove_dir_all(&wd) {
            return Err(BuildError::WdClearError{ path: wd, err });
        } 
    }
    if let Err(err) = fs::create_dir(&wd) {
        return Err(BuildError::WdCreateError{ path: wd, err });
    }

    // Write the local_container.yml to the container directory
    let local_container_path = wd.join("local_container.yml");
    debug!("Writing local_container.yml '{}'...", local_container_path.display());
    let local_container_info = LocalContainerInfo::from(document);
    if let Err(err) = local_container_info.to_path(&local_container_path) {
        return Err(BuildError::LocalContainerInfoCreateError{ err });
    }

    // Copy any other files marked in the ecu document
    if let Some(files) = &document.files {
        for file_path in files {
            debug!("Preparing file '{file_path}'...");

            // Make sure the target path is safe (does not escape the working directory)
            let target = clean_path(file_path);
            if target.contains("..") { return Err(BuildError::UnsafePath{ path: target }) }
            let target = wd.join(target);

            // Create the target folder if it does not exist
            let target_dir: &Path = target.parent().unwrap_or_else(|| panic!("Target file '{}' for package info file does not have a parent; this should never happen!", target.display()));
            if !target_dir.exists() {
                debug!("Creating folder '{}'...", target_dir.display());
                if let Err(err) = fs::create_dir_all(target_dir) { return Err(BuildError::WdDirCreateError{ path: target_dir.into(), err }); };
            }

            // Canonicalize the target itself
            let target = match fs::canonicalize(target.parent().unwrap_or_else(|| panic!("Target file '{}' for package info file does not have a parent; this should never happen!", target.display()))) {
                Ok(target_dir) => target_dir.join(target.file_name().unwrap_or_else(|| panic!("Target file '{}' for package info file does not have a file name; this should never happen!", target.display()))),
                Err(err)       => { return Err(BuildError::WdSourceFileCanonicalizeError{ path: target, err }); }
            };

            // Resolve the source folder
            let source = match fs::canonicalize(context.join(file_path)) {
                Ok(source) => source,
                Err(err)   => { return Err(BuildError::WdTargetFileCanonicalizeError{ path: target, err }); }
            };

            // Switch whether it's a directory or a file
            if source.is_dir() {
                // Copy everything inside the folder
                debug!("Copying DIRECTORY '{}' to '{}'...", source.display(), target.display());
                let mut copy_options = CopyOptions::new();
                copy_options.copy_inside = true;
                if let Err(err) = fs_extra::dir::copy(&source, &target, &copy_options) { return Err(BuildError::WdDirCopyError{ source, target, err }); }
            } else {
                // Copy only the file
                debug!("Copying FILE '{}' to '{}'...", source.display(), target.display());
                if let Err(err) = fs::copy(&source, &target) { return Err(BuildError::WdFileCopyError{ source, target, err }); }
            }

            // Done
        }
    }

    // Archive the working directory
    debug!("Archiving working directory '{}'...", container_dir.display());
    let mut command = Command::new("tar");
    command.arg("-zcf");
    command.arg("wd.tar.gz");
    command.arg("wd");
    command.current_dir(&container_dir);
    let output = match command.output() {
        Ok(output) => output,
        Err(err)   => { return Err(BuildError::WdCompressionLaunchError{ command: format!("{command:?}"), err }); }
    };
    if !output.status.success() {
        return Err(BuildError::WdCompressionError{ command: format!("{command:?}"), code: output.status.code().unwrap_or(-1), stdout: String::from_utf8_lossy(&output.stdout).to_string(), stderr: String::from_utf8_lossy(&output.stderr).to_string() });
    }

    // We're done with the working directory zip!
    Ok(())
}
