/* VERSION.rs
 *   by Lut99
 *
 * Created:
 *   08 May 2022, 13:31:16
 * Last edited:
 *   23 May 2022, 20:50:07
 * Auto updated?
 *   Yes
 *
 * Description:
 *   Implements version queriers for the Brane framework.
**/

use std::str::FromStr;

use reqwest::{Response, StatusCode};
use specifications::arch::Arch;
use specifications::version::Version;
use tracing::debug;

use crate::errors::VersionError;
use crate::instance::InstanceInfo;


/***** HELPER STRUCTS *****/
/// Struct that is used in querying the local CLI.
#[derive(Debug)]
struct LocalVersion {
    /// The architecture as reported by `uname -m`
    arch:    Arch,
    /// The version as reported by the env
    version: Version,
}

impl LocalVersion {
    /// Constructor for the RemoteVersion.
    ///
    /// Queries the CARGO_PKG_VERSION environment variable for the version.
    ///
    /// # Returns
    /// A new LocalVersion instance on success, or else a VersionError.
    fn new() -> Result<Self, VersionError> {
        // Parse the env
        let version = Version::from_str(env!("CARGO_PKG_VERSION"))
            .map_err(|source| VersionError::VersionParseError { raw: env!("CARGO_PKG_VERSION").to_string(), source })?;

        // Done, return the struct
        Ok(Self { arch: Arch::HOST, version })
    }
}



/// Struct that is used in querying the remote CLI.
#[derive(Debug)]
struct RemoteVersion {
    /// The architecture as reported by the remote
    _arch:   Arch,
    /// The version as downloaded from the remote
    version: Version,
}

impl RemoteVersion {
    /// Constructor for the RemoteVersion.
    ///
    /// Queries the remote host as stored in the Brane registry login file (get_config_dir()/registry.yml) for its version number.
    ///
    /// # Returns
    /// A new RemoteVersion instance on success, or else a VersionError.
    async fn new() -> Result<Self, VersionError> {
        debug!("Retrieving remote version number");

        // Try to get the registry file path
        debug!(" > Reading registy.yml...");
        let config: InstanceInfo = InstanceInfo::from_active_path().map_err(|source| VersionError::InstanceInfoError { source })?;

        // Pass to the other constructor
        Self::from_instance_info(config).await
    }

    /// Constructor for the RemoteVersion, which creates it from a given IdentityFile.
    ///
    /// # Arguments
    /// - `info`: The InstanceInfo file to use to find the remote registry's properties.
    ///
    /// # Returns
    /// A new RemoteVersion instance on success, or else a VersionError.
    async fn from_instance_info(info: InstanceInfo) -> Result<Self, VersionError> {
        // Use reqwest for the API call
        debug!(" > Querying...");
        let mut url: String = info.api.to_string();
        url.push_str("/version");
        let response: Response = reqwest::get(&url).await.map_err(|source| VersionError::RequestError { url: url.clone(), source })?;
        if response.status() != StatusCode::OK {
            return Err(VersionError::RequestFailure { url, status: response.status() });
        }
        let version_body: String = response.text().await.map_err(|source| VersionError::RequestBodyError { url: url.clone(), source })?;

        // Try to parse the version
        debug!(" > Parsing remote version...");
        let version = Version::from_str(&version_body).map_err(|source| VersionError::VersionParseError { raw: version_body, source })?;

        // Done!
        debug!("Remote version number: {}", &version);
        Ok(Self { _arch: Arch::X86_64, version })
    }
}





/***** HANDLERS *****/
/// Returns the local architecture (without any extra text).
pub fn handle_local_arch() -> Result<(), VersionError> {
    // Get the local version and print it
    println!("{}", LocalVersion::new()?.arch);

    // Done
    Ok(())
}

/// Returns the local version (without any extra text).
pub fn handle_local_version() -> Result<(), VersionError> {
    // Get the local version and print it
    println!("{}", LocalVersion::new()?.version);

    // Done
    Ok(())
}



/// Returns the local architecture (without any extra text).
pub async fn handle_remote_arch() -> Result<(), VersionError> {
    // Get the remote version and print it
    println!("<TBD>");

    // Done
    Ok(())
}

/// Returns the local version (without any extra text).
pub async fn handle_remote_version() -> Result<(), VersionError> {
    // Get the remote version and print it
    println!("{}", RemoteVersion::new().await?.version);

    // Done
    Ok(())
}



/// Returns both the local and possible remote version numbers with some pretty formatting.
pub async fn handle() -> Result<(), VersionError> {
    // Get the local version first and immediately print
    let local = LocalVersion::new()?;
    println!();
    println!("Brane CLI client");
    println!(" - Version      : v{}", local.version);
    println!(" - Architecture : {}", local.arch);
    println!();

    // If the registry file exists, then also do the remote
    let active_instance_exists: bool = InstanceInfo::active_instance_exists().map_err(|source| VersionError::InstanceInfoExistsError { source })?;
    if active_instance_exists {
        // Get the registry file from it
        let config = InstanceInfo::from_active_path().map_err(|source| VersionError::InstanceInfoError { source })?;

        // Print the URL
        println!("Remote Brane instance at '{}'", &config.api);

        // Get the version
        let remote = RemoteVersion::from_instance_info(config).await?;
        println!(" - Version      : v{}", remote.version);
        println!(" - Architecture : <TBD>");
        println!();
    }

    // Done
    Ok(())
}
