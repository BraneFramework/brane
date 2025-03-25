use std::fmt::Write as FmtWrite;
use std::fs::{self, DirEntry, File, ReadDir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;

use brane_shr::fs::FileLock;
use console::style;
use dialoguer::Confirm;
use path_clean::clean as clean_path;
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
        Err(err) => {
            return Err(BuildError::ContainerInfoOpenError { file, err });
        },
    };
    let document = match ContainerInfo::from_reader(handle) {
        Ok(document) => document,
        Err(err) => {
            return Err(BuildError::ContainerInfoParseError { file, err });
        },
    };

    // Prepare package directory
    let package_dir = match ensure_package_dir(&document.name, Some(&document.version), true) {
        Ok(package_dir) => package_dir,
        Err(err) => {
            return Err(BuildError::PackageDirError { err });
        },
    };

    // Lock the directory, build, unlock the directory
    {
        let _lock = match FileLock::lock(&document.name, document.version, package_dir.join(".lock")) {
            Ok(lock) => lock,
            Err(err) => {
                return Err(BuildError::LockCreateError { name: document.name, err });
            },
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
    // Prepare the build directory
    let dockerfile = generate_dockerfile(&document, &context, branelet_path.is_some())?;
    prepare_directory(&document, dockerfile, branelet_path, &context, package_dir, convert_crlf)?;
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
                Ok(digest) => {
                    package_info.digest = Some(digest);
                },
                Err(err) => {
                    return Err(BuildError::DigestError { err });
                },
            }

            // Write it to package directory
            let package_path = package_dir.join("package.yml");
            if let Err(err) = package_info.to_path(package_path) {
                return Err(BuildError::PackageFileCreateError { err });
            }

            // // Check if previous build is still loaded in Docker
            // let image_name = format!("{}:{}", package_info.name, package_info.version);
            // if let Err(e) = docker::remove_image(&image_name).await { return Err(BuildError::DockerCleanupError{ image: image_name, err }); }

            // // Upload the
            // let image_name = format!("localhost:50050/library/{}", image_name);
            // if let Err(e) = docker::remove_image(&image_name).await { return Err(BuildError::DockerCleanupError{ image: image_name, err }); }

            // Remove all non-essential files.
            if !keep_files {
                clean_directory(package_dir, vec!["Dockerfile", "container"]);
            }
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
                if let Err(err) = fs::remove_dir_all(package_dir) {
                    return Err(BuildError::CleanupError { path: package_dir.to_path_buf(), err });
                }
            }
        },
    }

    // Done
    Ok(())
}

/// Generates a new DockerFile that can be used to build the package into a Docker container.
///
/// **Arguments**
///  * `document`: The ContainerInfo describing the package to build.
///  * `context`: The directory to find the executable in.
///  * `override_branelet`: Whether or not to override the branelet executable. If so, assumes the new one is copied to the temporary build folder by the time the DockerFile is run.
///
/// **Returns**  
/// A String that is the new DockerFile on success, or a BuildError otherwise.
fn generate_dockerfile(document: &ContainerInfo, context: &Path, override_branelet: bool) -> Result<String, BuildError> {
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
        write_build!(
            contents,
            "RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-change-held-packages --allow-downgrades "
        )?;
    }
    // Default dependencies
    write_build!(contents, "fuse iptables ")?;
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
    if entrypoint.to_string_lossy().contains("..") {
        return Err(BuildError::UnsafePath { path: entrypoint });
    }
    let entrypoint = context.join(entrypoint);
    if !entrypoint.exists() || !entrypoint.is_file() {
        return Err(BuildError::MissingExecutable { path: entrypoint });
    }
    writeln_build!(contents, "RUN chmod +x /opt/wd/{}", &document.entrypoint.exec)?;

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

/// Prepares the build directory for building the package.
///
/// **Arguments**
///  * `document`: The ContainerInfo document carrying metadata about the package.
///  * `dockerfile`: The generated DockerFile that will be used to build the package.
///  * `branelet_path`: The optional branelet path in case we want it overriden.
///  * `context`: The directory to copy additional files (executable, working directory files) from.
///  * `package_info`: The generated PackageInfo from the ContainerInfo document.
///  * `package_dir`: The directory where we can build the package and store it once done.
/// - `convert_crlf`: If true, will not ask to convert CRLF files but instead just do it.
///
/// **Returns**  
/// Nothing if the directory was created successfully, or a BuildError otherwise.
fn prepare_directory(
    document: &ContainerInfo,
    dockerfile: String,
    branelet_path: Option<PathBuf>,
    context: &Path,
    package_dir: &Path,
    convert_crlf: bool,
) -> Result<(), BuildError> {
    // Write Dockerfile to package directory
    let file_path = package_dir.join("Dockerfile");
    debug!("Writing Dockerfile to '{}'...", file_path.display());
    match File::create(&file_path) {
        Ok(ref mut handle) => {
            if let Err(err) = write!(handle, "{dockerfile}") {
                return Err(BuildError::DockerfileWriteError { path: file_path, err });
            }
        },
        Err(err) => {
            return Err(BuildError::DockerfileCreateError { path: file_path, err });
        },
    };

    // Create the container directory
    let container_dir = package_dir.join("container");
    if !container_dir.exists() {
        if let Err(err) = fs::create_dir(&container_dir) {
            return Err(BuildError::ContainerDirCreateError { path: container_dir, err });
        }
    }

    // Copy custom branelet binary to package directory if needed
    if let Some(branelet_path) = branelet_path {
        // Try to resole the branelet's path
        let source = match std::fs::canonicalize(&branelet_path) {
            Ok(source) => source,
            Err(err) => {
                return Err(BuildError::BraneletCanonicalizeError { path: branelet_path, err });
            },
        };
        let target = container_dir.join("branelet");
        debug!("Copying custom branelet '{}' to '{}'...", source.display(), target.display());
        if let Err(err) = fs::copy(&source, &target) {
            return Err(BuildError::BraneletCopyError { source, target, err });
        }
    }

    // Create a workdirectory and make sure it's empty
    let wd = container_dir.join("wd");
    if wd.exists() {
        if let Err(err) = fs::remove_dir_all(&wd) {
            return Err(BuildError::WdClearError { path: wd, err });
        }
    }
    if let Err(err) = fs::create_dir(&wd) {
        return Err(BuildError::WdCreateError { path: wd, err });
    }

    // Write the local_container.yml to the container directory
    let local_container_path = wd.join("local_container.yml");
    debug!("Writing local_container.yml '{}'...", local_container_path.display());
    let local_container_info = LocalContainerInfo::from(document);
    if let Err(err) = local_container_info.to_path(&local_container_path) {
        return Err(BuildError::LocalContainerInfoCreateError { err });
    }

    // Copy any other files marked in the ecu document
    if let Some(mut files) = document.files.as_ref().map(|files| files.iter().map(PathBuf::from).collect::<Vec<PathBuf>>()) {
        while let Some(file) = files.pop() {
            // Make sure the target path is safe (does not escape the working directory)
            let target = clean_path(&file);
            if target.to_string_lossy().contains("..") {
                return Err(BuildError::UnsafePath { path: target });
            }
            let target = wd.join(target);

            // Create the target folder if it does not exist
            let target_dir: &Path = target.parent().unwrap_or_else(|| {
                panic!("Target file '{}' for package info file does not have a parent; this should never happen!", target.display())
            });
            if !target_dir.exists() {
                debug!("Creating folder '{}'...", target_dir.display());
                if let Err(err) = fs::create_dir_all(target_dir) {
                    return Err(BuildError::WdDirCreateError { path: target_dir.into(), err });
                };
            }

            // Canonicalize the target itself. We do some handwaving with the parent to ensure that the thing we are canonicalizing exists, after which we can add the filename again (which is sure not to escape anymore).
            let target = match fs::canonicalize(target.parent().unwrap_or_else(|| {
                panic!("Target file '{}' for package info file does not have a parent; this should never happen!", target.display())
            })) {
                Ok(target_dir) => target_dir.join(target.file_name().unwrap_or_else(|| {
                    panic!("Target file '{}' for package info file does not have a file name; this should never happen!", target.display())
                })),
                Err(err) => {
                    return Err(BuildError::WdSourceFileCanonicalizeError { path: target, err });
                },
            };

            // Resolve the source folder
            let source = match fs::canonicalize(if file.is_relative() { context.join(file) } else { file }) {
                Ok(source) => source,
                Err(err) => {
                    return Err(BuildError::WdTargetFileCanonicalizeError { path: target, err });
                },
            };

            // Switch whether it's a directory or a file
            if source.is_dir() {
                // Recurse into the directory
                debug!("Recursing into directory '{}'...", source.display());
                let entries: ReadDir = match fs::read_dir(&source) {
                    Ok(entries) => entries,
                    Err(err) => {
                        return Err(BuildError::WdDirReadError { path: source, err });
                    },
                };

                // For speedz, reserve as much new files as we know
                let size_hint: (usize, Option<usize>) = entries.size_hint();
                files.reserve(size_hint.1.unwrap_or(size_hint.0));

                // Iterate over the entries to add them
                for entry in entries {
                    // Unpack the entry
                    let entry: DirEntry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            return Err(BuildError::WdDirEntryError { path: source, err });
                        },
                    };

                    // Add it to the list of todos
                    files.push(entry.path());
                }

                // Now continue with the nested entry
                continue;
            } else {
                // Copy only the file
                debug!("Copying file '{}' to '{}'...", source.display(), target.display());
                if let Err(err) = fs::copy(&source, &target) {
                    return Err(BuildError::WdFileCopyError { source, target, err });
                }

                // Analyse if we have to CRLF-to-LF this file
                {
                    let mut lf_path: PathBuf = target.clone();
                    lf_path.set_file_name(format!(
                        "{}.crlf",
                        lf_path
                            .file_name()
                            .unwrap_or_else(|| panic!("Unexpected no filename in just-copied file '{}'", lf_path.display()))
                            .to_string_lossy()
                    ));
                    {
                        // Open the file
                        debug!("Analyzing if '{}' has Windows-style (CRLF) line endings...", target.display());
                        let mut handle: File = match File::open(&target) {
                            Ok(handle) => handle,
                            Err(err) => {
                                return Err(BuildError::WdFileOpenError { path: target, err });
                            },
                        };

                        // Read the first 512 bytes of a file - but we use a larger buffer to avoid reallocation later on
                        let mut buffer: [u8; 16384] = [0; 16384];
                        let mut buffer_len: usize = match handle.read(&mut buffer[..512]) {
                            Ok(len) => len,
                            Err(err) => {
                                return Err(BuildError::WdFileReadError { path: target, err });
                            },
                        };

                        // Check if it's valid UTF-8
                        let sbuffer: &str = match std::str::from_utf8(&buffer[..buffer_len]) {
                            Ok(sbuffer) => sbuffer,
                            Err(err) => {
                                debug!(
                                    "First 512 bytes of file '{}' are not valid UTF-8: {} (assuming it does not need CRLF -> LF conversion)",
                                    target.display(),
                                    err
                                );
                                continue;
                            },
                        };

                        // Now search for the \r\n pattern
                        let mut has_crlf: bool = false;
                        let mut saw_cr: bool = false;
                        for c in sbuffer.chars() {
                            if c == '\r' {
                                saw_cr = true;
                            } else if c == '\n' && saw_cr {
                                has_crlf = true;
                                break;
                            } else {
                                saw_cr = false;
                            }
                        }

                        // Continue if it was not found
                        if !has_crlf {
                            debug!(
                                "First 512 bytes of file '{}' does not have any CRLF line endings (assuming it does not need CRLF -> LF conversion)",
                                target.display()
                            );
                            continue;
                        }
                        debug!("Found CRLF line endings in valid UTF-8 file '{}'", target.display());

                        // Ask the user for confirmation, if necessary
                        if !convert_crlf {
                            println!(
                                "It looks like file {} has Windows-style line endings (CRLF). Do you want to convert it to Unix-style (LF)?",
                                style(source.display()).bold().cyan()
                            );
                            println!("(You want to if this is a text file, but not if it's a raw binary file)");
                            println!();
                            match Confirm::new().with_prompt("Convert CRLF to LF?").interact() {
                                Ok(consent) => {
                                    if !consent {
                                        debug!("Not converting file '{}' from CRLF -> LF because the user (you!) told us not to", target.display());
                                        continue;
                                    }
                                },
                                Err(err) => {
                                    return Err(BuildError::WdConfirmationError { err });
                                },
                            };
                            println!();
                        }

                        // Otherwise, we open a second file to write the converted version to
                        debug!("Writing LF version of file '{}' to '{}'...", target.display(), lf_path.display());
                        let mut lf_handle: File = match File::create(&lf_path) {
                            Ok(handle) => handle,
                            Err(err) => {
                                return Err(BuildError::WdFileCreateError { path: lf_path, err });
                            },
                        };

                        // Write the conversion, buffered
                        let mut lf_buffer: [u8; 16384] = [0; 16384];
                        let mut lf_buffer_len: usize = 0;
                        while buffer_len > 0 {
                            // Write the bytes in the input buffer to the output buffer, omitting '\r' in '\r\n' where necessary
                            saw_cr = false;
                            for c in &buffer[..buffer_len] {
                                let c: char = *c as char;

                                // If we have a buffered carriage return, write it unless it is superceded by a newline
                                if saw_cr && c != '\n' {
                                    lf_buffer[lf_buffer_len] = b'\r';
                                    lf_buffer_len += 1;
                                }
                                saw_cr = false;

                                // Write this character always, unless it's a carriage return - buffer it in that case
                                if c != '\r' {
                                    lf_buffer[lf_buffer_len] = c as u8;
                                    lf_buffer_len += 1;
                                } else {
                                    saw_cr = true;
                                }
                            }
                            // Write any leftover carriage return
                            if saw_cr {
                                lf_buffer[lf_buffer_len] = b'\r';
                                lf_buffer_len += 1;
                            }

                            // Now write the new buffer to the thing
                            if let Err(err) = lf_handle.write(&lf_buffer[..lf_buffer_len]) {
                                return Err(BuildError::WdFileWriteError { path: lf_path, err });
                            }
                            lf_buffer_len = 0;

                            // Refresh the input buffer
                            buffer_len = match handle.read(&mut buffer) {
                                Ok(len) => len,
                                Err(err) => {
                                    return Err(BuildError::WdFileReadError { path: target, err });
                                },
                            };
                        }
                    }

                    // When we're done, shuffle the files around
                    debug!("Moving '{}' -> '{}'", lf_path.display(), target.display());
                    if let Err(err) = fs::remove_file(&target) {
                        return Err(BuildError::WdFileRemoveError { path: target, err });
                    }
                    if let Err(err) = fs::rename(&lf_path, &target) {
                        return Err(BuildError::WdFileRenameError { source: lf_path, target, err });
                    }
                }
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
        Err(err) => {
            return Err(BuildError::WdCompressionLaunchError { command: format!("{command:?}"), err });
        },
    };
    if !output.status.success() {
        return Err(BuildError::WdCompressionError {
            command: format!("{command:?}"),
            code:    output.status.code().unwrap_or(-1),
            stdout:  String::from_utf8_lossy(&output.stdout).to_string(),
            stderr:  String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    // We're done with the working directory zip!
    Ok(())
}
