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

use std::path::PathBuf;
use std::str::FromStr;

use log::debug;
use reqwest::{Response, StatusCode};

use specifications::arch::Arch;
use specifications::identity::{IdentityFile, IdentityFileError};
use specifications::version::Version;

use crate::errors::{UtilError, VersionError};
use crate::utils::{get_config_dir, get_login_file};


/***** HELPER STRUCTS *****/
/// Struct that is used in querying the local CLI.
#[derive(Debug)]
struct LocalVersion {
    /// The architecture as reported by `uname -m`
    arch    : Arch,
    /// The version as reported by the env
    version : Version,
}

impl LocalVersion {
    /// Constructor for the RemoteVersion.
    /// 
    /// Queries the CARGO_PKG_VERSION environment variable for the version.
    /// 
    /// # Returns
    /// A new LocalVersion instance on success, or else a VersionError.
    fn new() -> Result<Self, VersionError> {
        // Parse the architecture
        let arch = match Arch::host() {
            Ok(arch) => arch,
            Err(err) => { return Err(VersionError::HostArchError{ err }); }
        };

        // Parse the env
        let version = match Version::from_str(env!("CARGO_PKG_VERSION")) {
            Ok(version) => version,
            Err(err)    => { return Err(VersionError::VersionParseError{ raw: env!("CARGO_PKG_VERSION").to_string(), err }); }
        };

        // Done, return the struct
        Ok(Self {
            arch,
            version,
        })
    }
    
}



/// Struct that is used in querying the remote CLI.
#[derive(Debug)]
struct RemoteVersion {
    /// The architecture as reported by the remote
    _arch   : Arch,
    /// The version as downloaded from the remote
    version : Version,
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
        let config: IdentityFile = match get_login_file() {
            Ok(config) => config,
            Err(err)   => { return Err(VersionError::IdentityFileError{ err }); }
        };

        // Pass to the other constructor
        Self::from_identity_file(config).await
    }

    /// Constructor for the RemoteVersion, which creates it from a given IdentityFile.
    /// 
    /// # Arguments
    /// - `config`: The IdentityFile file to use to find the remote registry's properties.
    /// 
    /// # Returns
    /// A new RemoteVersion instance on success, or else a VersionError.
    async fn from_identity_file(config: IdentityFile) -> Result<Self, VersionError> {
        // Use reqwest for the API call
        debug!(" > Querying...");
        let mut url: String = config.api_service.to_string(); url.push_str("/version");
        let response: Response = match reqwest::get(&url).await {
            Ok(version) => version,
            Err(err)    => { return Err(VersionError::RequestError{ url, err }); }
        };
        if response.status() != StatusCode::OK {
            return Err(VersionError::RequestFailure{ url, status: response.status() });
        }
        let version_body: String = match response.text().await {
            Ok(body) => body,
            Err(err) => { return Err(VersionError::RequestBodyError{ url, err }); }
        };

        // Try to parse the version
        debug!(" > Parsing remote version...");
        let version = match Version::from_str(&version_body) {
            Ok(version) => version,
            Err(err)    => { return Err(VersionError::VersionParseError{ raw: version_body, err }); }  
        };

        // Done!
        debug!("Remote version number: {}", &version);
        Ok(Self {
            _arch : Arch::x86_64,
            version,
        })
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
    let config_file: PathBuf = match get_config_dir() {
        Ok(dir)  => dir.join("registry.yml"),
        Err(err) => { return Err(VersionError::ConfigDirError{ err }); }
    };
    if config_file.exists() {
        // Get the registry file from it
        let config = match IdentityFile::from_path(&config_file) {
            Ok(config)                                    => config,
            Err(IdentityFileError::FileNotFound { path }) => { return Err(VersionError::IdentityFileError{ err: UtilError::IdentityFileNotFound { path } }); }
            Err(err)                                      => { return Err(VersionError::IdentityFileError{ err: UtilError::IdentityFileError{ err } }); }
        };

        // Print the URL
        println!("Remote Brane instance at '{}'", &config.api_service);
        
        // Get the version
        let remote = RemoteVersion::from_identity_file(config).await?;
        println!(" - Version      : v{}", remote.version);
        println!(" - Architecture : <TBD>");
        println!();
    }

    // Done
    Ok(())
}
