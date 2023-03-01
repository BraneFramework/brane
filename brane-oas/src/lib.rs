#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
#[macro_use]
extern crate maplit;

use anyhow::{Context, Result};
pub use openapiv3::OpenAPI;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub mod build;
pub mod execute;
pub mod resolver;

pub use execute::execute;

///
///
///
pub fn parse_oas_file<P: Into<PathBuf>>(oas_file: P) -> Result<OpenAPI> {
    let oas_file: PathBuf = oas_file.into();
    let extension = oas_file.extension().unwrap_or_default();
    let extension = extension.to_string_lossy().to_ascii_lowercase();

    let oas_file = File::open(&oas_file).with_context(|| format!("Failed to open OAS file: {oas_file:?}"))?;

    let oas_reader = BufReader::new(&oas_file);
    match extension.as_str() {
        "yaml" | "yml" => {
            serde_yaml::from_reader(oas_reader).with_context(|| format!("Failed to parse file as OAS: {oas_file:?}"))
        }
        "json" => {
            serde_json::from_reader(oas_reader).with_context(|| format!("Failed to parse file as OAS: {oas_file:?}"))
        }
        _ => bail!("Couldn't determine if OAS file is in JSON or YAML format. Please check the file extension."),
    }
}
