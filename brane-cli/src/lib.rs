#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
#[macro_use]
extern crate prettytable;
#[macro_use]
extern crate lazy_static;

pub mod build_ecu;
pub mod build_oas;
pub mod docker;
pub mod packages;
pub mod registry;
pub mod repl;
pub mod run;
pub mod test;
pub mod utils;

use anyhow::Result;
use semver::Version;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::{
    fs::{self, File},
    path::Path,
};

const MIN_DOCKER_VERSION: &str = "19.0.0";

///
///
///
pub fn check_dependencies() -> Result<()> {
    let output = Command::new("docker").arg("--version").output()?;
    let version = String::from_utf8_lossy(&output.stdout[15..17]);

    let version = Version::parse(&format!("{}.0.0", version))?;
    let minimum = Version::parse(MIN_DOCKER_VERSION)?;

    if version < minimum {
        return Err(anyhow!("Installed Docker doesn't meet the minimum requirement."));
    }

    Ok(())
}

///
///
///
pub fn determine_file(context: &Path) -> Result<PathBuf> {
    let files = fs::read_dir(context)?;
    for file in files {
        let file_name = file?.file_name();
        let file_name = file_name.into_string().unwrap();

        if file_name == "container.yml"
            || file_name == "container.yaml"
            || file_name.ends_with(".bk")
            || file_name.ends_with(".cwl")
        {
            return Ok(PathBuf::from(file_name));
        }
    }

    Err(anyhow!(
        "Cannot determine suitable build file in: {:?}. Please use the --file option.",
        context
    ))
}

///
///
///
pub fn determine_kind(
    context: &Path,
    file: &Path,
) -> Result<String> {
    /* TIM */
    let file = String::from(file.file_name().unwrap().to_string_lossy());
    /*******/

    if file.starts_with("container.y") {
        return Ok(String::from("ecu"));
    }

    if file.ends_with(".bk") {
        return Ok(String::from("dsl"));
    }

    // For CWL and OAS we need to look inside the file
    /* TIM */
    let file2 = File::open(context.join(&file));
    if let Err(reason) = file2 {
        let code = reason.raw_os_error().unwrap_or(-1);
        eprintln!("Could not open package file '{}': {}.", context.join(file).to_string_lossy(), reason);
        std::process::exit(code);
    }
    let mut file = file2.ok().unwrap();
    // let mut file = File::open(context.join(file))?;
    /*******/
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)?;

    if file_content.contains("cwlVersion") {
        return Ok(String::from("cwl"));
    }

    if file_content.contains("openapi") {
        return Ok(String::from("oas"));
    }

    Err(anyhow!(
        "Cannot determine target package kind based on: {:?}. Please use the --kind option.",
        file
    ))
}
