use crate::{docker, packages};
use anyhow::{Context, Result};
use brane_oas::{self, build};
use console::style;
use openapiv3::OpenAPI;
use specifications::package::PackageInfo;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::{fmt::Write as FmtWrite, path::Path};

const BRANELET_URL: &str = concat!(
    "https://github.com/onnovalkering/brane/releases/download/",
    concat!("v", env!("CARGO_PKG_VERSION")),
    "/branelet"
);

const JUICE_URL: &str =
    "https://github.com/juicedata/juicefs/releases/download/v0.12.1/juicefs-0.12.1-linux-amd64.tar.gz";

///
///
///
pub async fn handle(
    context: PathBuf,
    file: PathBuf,
    branelet_path: Option<PathBuf>,
) -> Result<()> {
    let context = fs::canonicalize(context)?;
    debug!("Using {:?} as build context", context);

    // Prepare OpenAPI document.
    let oas_file = context.join(file);
    let oas_document = brane_oas::parse_oas_file(&oas_file)?;

    // Prepare package directory.
    let dockerfile = generate_dockerfile(&oas_document, branelet_path.is_some())?;
    let package_info = create_package_info(&oas_document)?;
    let package_dir = packages::get_package_dir(&package_info.name, Some(&package_info.version))?;
    prepare_directory(&oas_file, dockerfile, branelet_path, &package_info, &package_dir)?;

    debug!("Successfully prepared package directory.");

    // Build Docker image.
    let tag = format!("{}:{}", package_info.name, package_info.version);
    build_docker_image(&package_dir, tag)?;

    // Build Docker image
    let tag = format!("{}:{}", package_info.name, package_info.version);
    let result = build_docker_image(&package_dir, tag);

    if result.is_ok() {
        println!(
            "Successfully built version {} of Web API (OAS) package {}.",
            style(&package_info.version).bold().cyan(),
            style(&package_info.name).bold().cyan(),
        );    

        // Check if previous build is still loaded in Docker
        let image_name = format!("{}:{}", package_info.name, package_info.version);
        docker::remove_image(&image_name).await?;

        let image_name = format!("localhost:5000/library/{}", image_name);
        docker::remove_image(&image_name).await?;

        fs::remove_file(package_dir.join(".lock"))
            .context("Failed to delete '.lock' file in package directory.")?;
    } else {
        println!(
            "Failed to built version {} of Web API (OAS) package {}. See error output above.",
            style(&package_info.version).bold().cyan(),
            style(&package_info.name).bold().cyan(),
        );

        fs::remove_dir_all(package_dir)
            .context("Failed to delete package directory after failed build.")?;
    }    

    Ok(())
}

///
///
///
fn create_package_info(oas_document: &OpenAPI) -> Result<PackageInfo> {
    let name = oas_document.info.title.to_lowercase().replace(" ", "-");
    let version = oas_document.info.version.clone();
    let description = oas_document.info.description.clone();

    let (functions, types) = build::build_oas_functions(&oas_document)?;

    let package_info = PackageInfo::new(
        name,
        version,
        description,
        false,
        String::from("oas"),
        Some(functions),
        Some(types),
    );

    Ok(package_info)
}

///
///
///
fn generate_dockerfile(
    _oas_document: &OpenAPI,
    override_branelet: bool,
) -> Result<String> {
    let mut contents = String::new();

    // Add default heading
    writeln!(contents, "# Generated by Brane")?;
    writeln!(contents, "FROM alpine")?;

    // Add dependencies
    writeln!(contents, "RUN apk add --no-cache iptables")?;

    // Add default branelet
    if override_branelet {
        writeln!(contents, "ADD branelet branelet")?;
    } else {
        writeln!(contents, "ADD {} branelet", BRANELET_URL)?;
        writeln!(contents, "RUN chmod +x branelet")?;
    }

    writeln!(contents, "ADD {} juicefs.tar.gz", JUICE_URL)?;
    writeln!(
        contents,
        "RUN tar -xzf juicefs.tar.gz && rm juicefs.tar.gz && mkdir /data"
    )?;

    // Copy files
    writeln!(contents, "ADD wd.tar.gz /opt")?;
    writeln!(contents, "WORKDIR /opt/wd")?;
    writeln!(contents, "ENTRYPOINT [\"/branelet\"]")?;

    Ok(contents)
}

///
///
///
fn prepare_directory(
    oas_file: &Path,
    dockerfile: String,
    branelet_path: Option<PathBuf>,
    package_info: &PackageInfo,
    package_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(&package_dir)?;
    debug!("Created {:?} as package directory", package_dir);

    File::create(&package_dir.join(".lock"))
        .context("Failed to create '.lock' file inside package directory")?;

    // Write Dockerfile to package directory
    let mut buffer = File::create(package_dir.join("Dockerfile"))?;
    write!(buffer, "{}", dockerfile)?;

    // Write package.yml to package directory
    let mut buffer = File::create(package_dir.join("package.yml"))?;
    write!(buffer, "{}", serde_yaml::to_string(&package_info)?)?;

    // Copy custom branelet binary to package directory
    if let Some(branelet_path) = branelet_path {
        fs::copy(fs::canonicalize(branelet_path)?, package_dir.join("branelet"))?;
    }

    // Create the working directory and copy required files.
    let wd = package_dir.join("wd");
    if !wd.exists() {
        fs::create_dir(&wd)?;
    }

    // Always copy these two files, required by convention
    fs::copy(oas_file, wd.join("document.yml"))?;
    fs::copy(package_dir.join("package.yml"), wd.join("package.yml"))?;

    // Archive the working directory and remove the original.
    let output = Command::new("tar")
        .arg("-zcf")
        .arg("wd.tar.gz")
        .arg("wd")
        .current_dir(&package_dir)
        .output()
        .expect("Couldn't run 'tar' command.");

    if !output.status.success() {
        return Err(anyhow!("Failed to prepare working directory archive."));
    }

    let output = Command::new("rm")
        .arg("-rf")
        .arg("wd")
        .current_dir(&package_dir)
        .output()
        .expect("Couldn't run 'rm' command.");

    if !output.status.success() {
        warn!("Failed to cleanup working directory.");
    }

    Ok(())
}

///
///
///
fn build_docker_image(
    package_dir: &Path,
    tag: String,
) -> Result<()> {
    let buildx = Command::new("docker")
        .arg("buildx")
        .output()
        .expect("Couldn't run 'docker' command.");

    if !buildx.status.success() {
        return Err(anyhow!(
            "Failed to build Docker image. Is BuildKit enabled (see documentation)?"
        ));
    }

    let output = Command::new("docker")
        .arg("buildx")
        .arg("build")
        .arg("--output")
        .arg("type=docker,dest=image.tar")
        .arg("--tag")
        .arg(tag)
        .arg(".")
        .current_dir(&package_dir)
        .status()
        .expect("Couldn't run 'docker' command.");

    if !output.success() {
        return Err(anyhow!(
            "Failed to build Docker image. See Docker output above for more information."
        ));
    }

    Ok(())
}
