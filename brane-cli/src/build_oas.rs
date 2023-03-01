use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use brane_oas::{self, build};
use console::style;
use openapiv3::OpenAPI;

use specifications::arch::Arch;
use specifications::package::{PackageKind, PackageInfo};
use specifications::version::Version;

use crate::build_common::{BRANELET_URL, build_docker_image, clean_directory, LockHandle};
use crate::errors::BuildError;
use crate::utils::ensure_package_dir;


/***** BUILD FUNCTIONS *****/
/// # Arguments
///  - `arch`: The architecture to compile this image for.
///  - `context`: The directory to copy additional files (executable, working directory files) from.
///  - `file`: Path to the package's main file (a container file, in this case).
///  - `branelet_path`: Optional path to a custom branelet executable. If left empty, will pull the standard one from Github instead.
///  - `keep_files`: Determines whether or not to keep the build files after building.
/// 
/// # Errors
/// This function may error for many reasons.
pub async fn handle(
    arch: Arch,
    context: PathBuf,
    file: PathBuf,
    branelet_path: Option<PathBuf>,
    keep_files: bool,
) -> Result<(), BuildError> {
    debug!("Building oas package from OAS Document '{}'...", file.display());
    debug!("Using {} as build context", context.display());

    // Read the package into an OasDocument
    let document = match brane_oas::parse_oas_file(&file) {
        Ok(document) => document,
        Err(err)     => { return Err(BuildError::OasDocumentParseError{ file, err }); }
    };

    // Prepare package directory
    let package_info = create_package_info(&document)?;
    let package_dir = match ensure_package_dir(&package_info.name, Some(&package_info.version), true) {
        Ok(package_dir) => package_dir,
        Err(err)        => { return Err(BuildError::PackageDirError{ err }); }
    };

    // Lock the directory, build, unlock the directory
    {
        let _lock = LockHandle::lock(&package_info.name, package_dir.join(".lock"))?;
        build(arch, document, package_info, &package_dir, branelet_path, keep_files).await?;
    };

    // Done
    Ok(())
}

/// **Edited: now returning BuildErrors.**
/// 
/// Tries to build a PackageInfo from an OpenAPI document.
/// 
/// **Arguments**
///  * `document`: The OpenAPI document to try and convert.
/// 
/// **Returns**  
/// The newly constructed PackageInfo upon success, or a BuildError otherwise.
fn create_package_info(
    document: &OpenAPI,
) -> Result<PackageInfo, BuildError> {
    // Collect some metadata from the document
    let name = document.info.title.to_lowercase().replace(' ', "-");
    let version = match Version::from_str(&document.info.version) {
        Ok(version) => version,
        Err(err)    => { return Err(BuildError::VersionParseError{ err }); }
    };
    let description = document.info.description.clone().unwrap_or_default();

    // Try to build the functions
    let (functions, types) = match build::build_oas_functions(document) {
        Ok(result) => result,
        Err(err)   => { return Err(BuildError::PackageInfoFromOpenAPIError{ err }); }
    };

    // With the collected info, build and return the new PackageInfo
    Ok(PackageInfo::new(
        name,
        version,
        PackageKind::Oas,
        vec![],
        description,
        false,
        functions,
        types,
    ))
}



/// Actually builds a new Ecu package from the given file(s).
/// 
/// # Arguments
///  - `arch`: The architecture to compile this image for.
///  - `document`: The OpenAPI document describing the package.
///  - `package_dir`: The package directory to use as the build folder.
///  - `package_info`: The PackageInfo document also describing the package, but in a package-kind-oblivious way.
///  - `branelet_path`: Optional path to a custom branelet executable. If left empty, will pull the standard one from Github instead.
///  - `keep_files`: Determines whether or not to keep the build files after building.
/// 
/// # Errors
/// This function may error for many reasons.
async fn build(
    arch: Arch,
    document: OpenAPI,
    package_info: PackageInfo,
    package_dir: &Path,
    branelet_path: Option<PathBuf>,
    keep_files: bool,
) -> Result<(), BuildError> {
    // Prepare package directory.
    let dockerfile = generate_dockerfile(branelet_path.is_some())?;
    prepare_directory(
        &document,
        dockerfile,
        branelet_path,
        package_dir
    )?;
    debug!("Successfully prepared package directory.");

    // // Build Docker image.
    // let tag = format!("{}:{}", package_info.name, package_info.version);
    // build_docker_image(&package_dir, tag)?;

    // Build Docker image
    let tag = format!("{}:{}", package_info.name, package_info.version);
    debug!("Building image '{}' in directory '{}'", tag, package_dir.display());
    match build_docker_image(arch, package_dir, tag) {
        Ok(_) => {
            println!(
                "Successfully built version {} of Web API (OAS) package {}.",
                style(&package_info.version).bold().cyan(),
                style(&package_info.name).bold().cyan(),
            );

            // Resolve the digest of the package info
            let mut package_info = package_info;
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
                "Failed to built version {} of Web API (OAS) package {}. See error output above.",
                style(&package_info.version).bold().cyan(),
                style(&package_info.name).bold().cyan(),
            );
            if let Err(err) = fs::remove_dir_all(package_dir) { return Err(BuildError::CleanupError{ path: package_dir.to_path_buf(), err }); }
        }
    }

    // Done
    Ok(())
}

/// **Edited: now returning BuildErrors + removing oas_file argument since it wasn't used.**
/// 
/// Generates a new DockerFile that can be used to build the package into a Docker container.
/// 
/// **Arguments**
///  * `document`: The OpenAPI document describing the package to build.
///  * `override_branelet`: Whether or not to override the branelet executable. If so, assumes the new one is copied to the temporary build folder by the time the DockerFile is run.
/// 
/// **Returns**  
/// A String that is the new DockerFile on success, or a BuildError otherwise.
fn generate_dockerfile(
    override_branelet: bool,
) -> Result<String, BuildError> {
    let mut contents = String::new();

    // Add default heading
    writeln_build!(contents, "# Generated by Brane")?;
    writeln_build!(contents, "FROM alpine")?;

    // Set the architecture build arg
    writeln_build!(contents, "ARG BRANELET_ARCH")?;
    writeln_build!(contents, "ARG JUICEFS_ARCH")?;

    // Add dependencies
    writeln_build!(contents, "RUN apk add --no-cache iptables")?;

    // Add the branelet executable
    if override_branelet {
        writeln_build!(contents, "ADD ./container/branelet /branelet")?;
    } else {
        writeln_build!(contents, "ADD {}-$BRANELET_ARCH /branelet", BRANELET_URL)?;
    }
    writeln_build!(contents, "RUN chmod +x /branelet")?;

    // Add JuiceFS
    writeln_build!(contents, "RUN mkdir /data")?;
    writeln_build!(contents, "ADD https://github.com/juicedata/juicefs/releases/download/v0.12.1/juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz /juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz")?;
    writeln_build!(contents, "RUN tar -xzvf /juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz \\")?;
    writeln_build!(contents, " && rm /LICENSE /README.md /README_CN.md /juicefs-0.12.1-linux-$JUICEFS_ARCH.tar.gz")?;

    // Copy files
    writeln_build!(contents, "ADD ./container/wd.tar.gz /opt")?;
    writeln_build!(contents, "WORKDIR /opt/wd")?;

    // Finally, set the branelet as entrypoint
    writeln_build!(contents, "ENTRYPOINT [\"/branelet\"]")?;

    // Done
    debug!("Using DockerFile:\n\n{}\n{}\n{}\n\n", (0..80).map(|_| '-').collect::<String>(), &contents, (0..80).map(|_| '-').collect::<String>());
    Ok(contents)
}

/// **Edited: now returning BuildErrors + acceping OpenAPI document instead of path to it.**
/// 
/// Prepares the build directory for building the package.
/// 
/// **Arguments**
///  * `document`: The OpenAPI document carrying metadata about the package.
///  * `dockerfile`: The generated DockerFile that will be used to build the package.
///  * `branelet_path`: The optional branelet path in case we want it overriden.
///  * `package_info`: The generated PackageInfo from the ContainerInfo document.
///  * `package_dir`: The directory where we can build the package and store it once done.
/// 
/// **Returns**  
/// Nothing if the directory was created successfully, or a BuildError otherwise.
fn prepare_directory(
    document: &OpenAPI,
    dockerfile: String,
    branelet_path: Option<PathBuf>,
    package_dir: &Path,
) -> Result<(), BuildError> {
    // Write the Dockerfile to the package directory
    let file_path = package_dir.join("Dockerfile");
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

    // Copy custom branelet binary to container directory if needed
    if let Some(branelet_path) = branelet_path {
        // Try to resole the branelet's path
        let source = match std::fs::canonicalize(&branelet_path) {
            Ok(source) => source,
            Err(err)   => { return Err(BuildError::BraneletCanonicalizeError{ path: branelet_path, err }); }
        };
        let target = container_dir.join("branelet");
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

    // Write the OpenAPI document to the working directory
    let openapi_path = wd.join("document.yml");
    match File::create(&openapi_path) {
        Ok(ref mut handle) => {
            // Try to serialize the document
            let to_write = match serde_yaml::to_string(&document) {
                Ok(to_write) => to_write,
                Err(err)     => { return Err(BuildError::OpenAPISerializeError{ err }); }
            };
            if let Err(err) = write!(handle, "{to_write}") {
                return Err(BuildError::OpenAPIFileWriteError{ path: openapi_path, err });
            }
        },
        Err(err)   => { return Err(BuildError::OpenAPIFileCreateError{ path: openapi_path, err }); }
    };

    // Archive the working directory
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
