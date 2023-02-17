//  GENERATE.rs
//    by Lut99
// 
//  Created:
//    21 Nov 2022, 15:40:47
//  Last edited:
//    17 Feb 2023, 14:22:58
//  Auto updated?
//    Yes
// 
//  Description:
//!   Handles commands relating to node.yml generation.
// 

use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

use console::style;
use enum_debug::EnumDebug as _;
use futures_util::stream::StreamExt as _;
use hex_literal::hex;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use rand::Rng as _;
use rand::distributions::Alphanumeric;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use brane_cfg::infra::{InfraFile, InfraLocation};
use brane_cfg::backend::{BackendFile, Credentials};
use brane_cfg::node::{CentralConfig, CentralKafkaTopics, CentralNames, CentralPaths, CentralPorts, CentralServices, CommonNames, CommonPaths, CommonPorts, CommonServices, NodeConfig, NodeKindConfig, WorkerConfig, WorkerNames, WorkerPaths, WorkerPorts, WorkerServices};
use brane_cfg::policies::{ContainerPolicy, PolicyFile, UserPolicy};
use specifications::address::Address;
use specifications::package::Capability;

pub use crate::errors::GenerateError as Error;
use crate::spec::{GenerateBackendSubcommand, GenerateNodeSubcommand, HostnamePair, LocationPair};
use crate::utils::resolve_config_path;


/***** CONSTANTS *****/
/// Checksun for the `cfssl` executable.
const CHECKSUM_CFSSL: [u8; 32] = hex!("16b42bfc592dc4d0ba1e51304f466cae7257edec13743384caf4106195ab6047");

/// Checksun for the `cfssljson` executable.
const CHECKSUM_CFSSLJSON: [u8; 32] = hex!("3b26c85877e2233684216ec658594be474954bc62b6f08780b369e234ccc67c9");





/***** HELPER FUNCTIONS ******/
/// Ensures that the directory where the given file lives exists.
/// 
/// # Arguments
/// - `path`: The path of the file who's directory we want to ensure.
/// - `fix_dirs`: If true, will generate missing directories. If false, will throw errors when a directory (tree) is missing instead.
/// 
/// # Returns
/// Nothing, but after it returns without error it can be assumed that the directories exist.
fn ensure_dir_of(path: impl AsRef<Path>, fix_dirs: bool) -> Result<(), Error> {
    let path: &Path = path.as_ref();

    // Get the directory name of the path
    let dir: &Path = match path.parent() {
        Some(dir) => dir,
        None      => { panic!("Cannot ensure directory of '{}' which has no parent (did you mean to use `ensure_dir()`?)", path.display()); },  
    };

    // Assert it exists
    if !dir.exists() {
        // Error if we don't have to fix it
        if !fix_dirs { return Err(Error::DirNotFound{ path: dir.into() }); };

        // Create it if we're asked to
        if let Err(err) = fs::create_dir_all(dir) {
            return Err(Error::DirCreateError{ path: dir.into(), err });
        }
    }
    // If it does but is a file, error
    if !dir.is_dir() { return Err(Error::DirNotADir{ path: dir.into() }); }

    // Directory should now exist as a directory
    Ok(())
}

/// Ensures that the given directoryexists.
/// 
/// # Arguments
/// - `path`: The path of the directory we want to ensure.
/// - `fix_dirs`: If true, will generate missing directories. If false, will throw errors when a directory (tree) is missing instead.
/// 
/// # Returns
/// Nothing, but after it returns without error it can be assumed that the directory exist.
fn ensure_dir(path: impl AsRef<Path>, fix_dirs: bool) -> Result<(), Error> {
    let path: &Path = path.as_ref();

    // Assert it exists
    if !path.exists() {
        // Error if we don't have to fix it
        if !fix_dirs { return Err(Error::DirNotFound{ path: path.into() }); };

        // Create it if we're asked to
        if let Err(err) = fs::create_dir_all(path) {
            return Err(Error::DirCreateError{ path: path.into(), err });
        }
    }
    // If it does but is a file, error
    if !path.is_dir() { return Err(Error::DirNotADir{ path: path.into() }); }

    // Directory should now exist as a directory
    Ok(())
}

/// Makes the given path canonical, casting the error for convenience.
/// 
/// # Arguments
/// - `path`: The path to make canonical.
/// 
/// # Returns
/// The same path but canonical.
/// 
/// # Errors
/// This function errors if we failed to make the path canonical (i.e., something did not exist).
#[inline]
fn canonicalize(path: impl AsRef<Path>) -> Result<PathBuf, Error> {
    let path: &Path = path.as_ref();
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(err) => Err(Error::CanonicalizeError{ path: path.into(), err }),
    }
}

/// Function that writes the standard node.yml header to the given writer.
/// 
/// # Arguments
/// - `writer`: The Writer to write to.
/// 
/// # Returns
/// Nothing, but does update the given writer with the standard header.
/// 
/// # Errors
/// This function errors if we failed to write.
fn write_node_header(writer: &mut impl Write) -> Result<(), std::io::Error> {
    // Simply call write repeatedly
    writeln!(writer, "# NODE.yml")?;
    writeln!(writer, "#   generated by branectl v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# This file defines the environment of the local node.")?;
    writeln!(writer, "# Edit this file to change service properties. Some require a restart")?;
    writeln!(writer, "# of the service (typically any 'ports' or 'topics' related setting), but most")?;
    writeln!(writer, "# will be reloaded dynamically by the services themselves.")?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# For an overview of what you can do in this file, refer to")?;
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/node.md")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
    Ok(())
}

/// Function that takes a location ID and tries to make it a bit better.
/// 
/// Note that this function should be used for human-readable names only that don't have to be made unique.
/// 
/// # Arguments
/// - `id`: The identifier to beautify.
/// 
/// # Returns
/// A new string that might be the same, or be that but prettier.
fn beautify_id(id: impl AsRef<str>) -> String {
    // Replace underscores and dashes with spaces
    let id: String = id.as_ref().replace(['-', '_'], " ");

    // Capitalize each word
    let id: String = id.split(' ').map(|w| if !w.is_empty() { let mut chars = w.chars(); format!("{}{}", chars.next().unwrap().to_uppercase(), chars.collect::<String>()) } else { String::new() }).collect::<Vec<String>>().join(" ");

    // Return
    id
}

/// Function that writes the standard infra.yml header to the given writer.
/// 
/// # Arguments
/// - `writer`: The Writer to write to.
/// 
/// # Returns
/// Nothing, but does update the given writer with the standard header.
/// 
/// # Errors
/// This function errors if we failed to write.
fn write_infra_header(writer: &mut impl Write) -> Result<(), std::io::Error> {
    // Simply call write repeatedly
    writeln!(writer, "# INFRA.yml")?;
    writeln!(writer, "#   generated by branectl v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# This file defines the nodes part of this Brane instance.")?;
    writeln!(writer, "# Edit this file to change the location of nodes and relevant services.")?;
    writeln!(writer, "# This file is loaded lazily, so changing it typically does not require a")?;
    writeln!(writer, "# restart.")?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# For an overview of what you can do in this file, refer to")?;
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/infra.md")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
    Ok(())
}

/// Function that writes the standard backend.yml header to the given writer.
/// 
/// # Arguments
/// - `writer`: The Writer to write to.
/// 
/// # Returns
/// Nothing, but does update the given writer with the standard header.
/// 
/// # Errors
/// This function errors if we failed to write.
fn write_backend_header(writer: &mut impl Write) -> Result<(), std::io::Error> {
    // Simply call write repeatedly
    writeln!(writer, "# BACKEND.yml")?;
    writeln!(writer, "#   generated by branectl v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# This file defines how the delegate service may connect to the compute backend.")?;
    writeln!(writer, "# Edit this file to change how, where and with what credentials to connect. You")?;
    writeln!(writer, "# can also use it to define properties advertised about the backend for this")?;
    writeln!(writer, "# domain.")?;
    writeln!(writer, "# This file is loaded lazily, so changing it typically does not require a")?;
    writeln!(writer, "# restart.")?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# For an overview of what you can do in this file, refer to")?;
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/backend.md")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
    Ok(())
}

/// Function that writes the standard policies.yml header to the given writer.
/// 
/// # Arguments
/// - `writer`: The Writer to write to.
/// 
/// # Returns
/// Nothing, but does update the given writer with the standard header.
/// 
/// # Errors
/// This function errors if we failed to write.
fn write_policy_header(writer: &mut impl Write) -> Result<(), std::io::Error> {
    // Simply call write repeatedly
    writeln!(writer, "# POLICIES.yml")?;
    writeln!(writer, "#   generated by branectl v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# This file defines which users are allow to transfer which datasets, and which")?;
    writeln!(writer, "# container is allowed to be run.")?;
    writeln!(writer, "# Note that it's temporary, since this will eventually be taken over be an")?;
    writeln!(writer, "# eFLINT reasoner.")?;
    writeln!(writer, "# This file is loaded lazily, so changing it typically does not require a")?;
    writeln!(writer, "# restart.")?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# For an overview of what you can do in this file, refer to")?;
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/policy.md")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
    Ok(())
}



/// Downloads some executable to the given location.
/// 
/// # Arguments
/// - `what`: Some more human-readable description of what we are downloading.
/// - `remote`: The URL to download the file from.
/// - `local`: The location to download the file to.
/// - `checksum`: The checksum to verify the executable with before running.
/// 
/// # Returns
/// Nothing, except that when it does you can assume a file exists at the given location.
/// 
/// Also keeps the user up-to-date with prints and a progress bar.
/// 
/// # Errors
/// This function may error if we failed to download the file or write it (which may happen if the parent directory of `local` does not exist).
async fn download_exe(what: impl Display, remote: impl AsRef<str>, local: impl AsRef<Path>, checksum: impl AsRef<[u8]>) -> Result<(), Error> {
    let remote   : &str  = remote.as_ref();
    let local    : &Path = local.as_ref();
    let checksum : &[u8] = checksum.as_ref();
    println!("Downloading {}...", style(what).green().bold());

    // Assert the download directory exists
    let dir: Option<&Path> = local.parent();
    if dir.is_some() && !dir.unwrap().exists() { return Err(Error::DirNotFound{ path: dir.unwrap().into() }); }

    // Open the local file
    debug!("Opening output file '{}'...", local.display());
    let mut handle: File = match File::create(local) {
        Ok(handle) => {
            // Prepare the permissions to set by reading the file's metadata
            let mut permissions: Permissions = match handle.metadata() {
                Ok(metadata) => metadata.permissions(),
                Err(err)     => { return Err(Error::FileMetadataError{ what: "temporary binary", path: local.into(), err }); },
            };
            permissions.set_mode(permissions.mode() | 0o100);

            // Set them
            if let Err(err) = handle.set_permissions(permissions) { return Err(Error::FilePermissionsError{ what: "temporary binary", path: local.into(), err }); }

            // Return the handle
            handle
        },
        Err(err)   => { return Err(Error::FileCreateError{ what: "temporary binary", path: local.into(), err }); },
    };

    // Send a request
    debug!("Sending download request to '{}'...", remote);
    let req: reqwest::Response = match reqwest::get(remote).await {
        Ok(req)  => req,
        Err(err) => { return Err(Error::RequestError{ address: remote.into(), err }); },
    };
    if !req.status().is_success() { return Err(Error::RequestFailure{ address: remote.into(), code: req.status(), err: req.text().await.ok() }); }

    // Create the progress bar based on whether if there is a length
    debug!("Downloading...");
    let len: Option<u64> = req.headers().get("Content-Length").and_then(|len| len.to_str().ok()).and_then(|len| u64::from_str(len).ok());
    let prgs: ProgressBar = if let Some(len) = len {
        ProgressBar::new(len).with_style(ProgressStyle::with_template("    {bar:60} {bytes}/{total_bytes} ETA {eta_precise}").unwrap())
    } else {
        ProgressBar::new_spinner().with_style(ProgressStyle::with_template("    {elapsed_precise} {bar:60} {bytes}").unwrap())
    };

    // Download and get the checksum at the _same time_
    let mut hasher = Sha256::new();
    let mut stream = req.bytes_stream();
    while let Some(next) = stream.next().await {
        // Unwrap the result
        let next: _ = match next {
            Ok(next) => next,
            Err(err) => { return Err(Error::DownloadError{ address: remote.into(), err }); },
        };

        // Write it to the file & update the running hash
        if let Err(err) = handle.write(&*next) { return Err(Error::FileWriteError{ what: "temporary binary", path: local.into(), err }); }
        hasher.update(&*next);

        // Update what we've written
        prgs.update(|state| state.set_pos(state.pos() + next.len() as u64));
    }
    let result = hasher.finalize();
    prgs.finish_and_clear();

    // Assert the checksums are the same
    if &result[..] != checksum { return Err(Error::FileChecksumError{ path: local.into(), expected: hex::encode(&result[..]), got: hex::encode(checksum) }); }
    println!("{}{}{}", style(" > Checksum ").dim(), style(hex::encode(&result[..])).green().bold().dim(), style(" OK").dim());

    // Done
    Ok(())
}

/// Writes the given config file to the given location.
/// 
/// # Arguments
/// - `what`: Some more human-readable description of what we are downloading.
/// - `config`: The `Serialize`able type to write.
/// - `path`: The path to write the serializeable type to.
/// 
/// # Returns
/// Nothing, except that when it does you can assume a file exists at the given location.
/// 
/// # Errors
/// This function may error if we failed to serialize or write the given config file.
fn generate_config(what: impl Display, config: impl Serialize, path: impl AsRef<Path>) -> Result<(), Error> {
    let path: &Path = path.as_ref();
    info!("Generating {}...", what);

    // Serialize the config with JSON
    let sconfig: String = match serde_json::to_string_pretty(&config) {
        Ok(sconfig) => sconfig,
        Err(err)    => { return Err(Error::ConfigSerializeError{ err }); },
    };

    // Assert the download directory exists
    let dir: Option<&Path> = path.parent();
    if dir.is_some() && !dir.unwrap().exists() { return Err(Error::DirNotFound{ path: dir.unwrap().into() }); }

    // Open the local file
    debug!("Opening output file '{}'...", path.display());
    let mut handle: File = match File::create(path) {
        Ok(handle) => handle,
        Err(err)   => { return Err(Error::FileCreateError{ what: "config", path: path.into(), err }); },
    };

    // Write it and we're done
    if let Err(err) = write!(handle, "{}", sconfig) { return Err(Error::FileWriteError{ what: "config", path: path.into(), err }); }
    Ok(())
}

/// Generates a CA certificate given the CSR configuration files.
/// 
/// # Arguments
/// - `what`: Some more human-readable description of what we are generating.
/// - `cfssl`: The path to the cfssl binary.
/// - `cfssljson`: The path to the cfssljson binary.
/// - `ca_csr_path`: The path to the file that describes the new certificate.
/// - `path`: The path to write the resulting certificate file to.
/// 
/// # Returns
/// Nothing, except that when it does you can assume a file exists at the given location.
/// 
/// Also keeps the user up-to-date with a neat print.
/// 
/// # Errors
/// This function may error if we failed to call the command or the command itself fails.
fn generate_ca_cert(cfssl: impl AsRef<Path>, cfssljson: impl AsRef<Path>, ca_csr: impl AsRef<Path>, path: impl AsRef<Path>) -> Result<(), Error> {
    let cfssl     : &Path = cfssl.as_ref();
    let cfssljson : &Path = cfssljson.as_ref();
    let ca_csr    : &Path = ca_csr.as_ref();
    let path      : &Path = path.as_ref();
    info!("Generating {}...", style("CA certificate").green().bold());

    // Prepare the command to run
    let mut cmd: Command = Command::new("bash");
    cmd.arg("-c");
    cmd.arg(format!("\"{}\" gencert -initca \"{}\" | \"{}\" -bare \"{}\"", cfssl.display(), ca_csr.display(), cfssljson.display(), path.display()));

    // Run it
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(err)   => { return Err(Error::SpawnError{ cmd, err }); },
    };
    if !output.status.success() { return Err(Error::SpawnFailure{ cmd, status: output.status, err: String::from_utf8_lossy(&output.stderr).into() }); }

    // Done
    Ok(())
}

/// Generates a server certificate given the CSR configuration files.
/// 
/// # Arguments
/// - `what`: Some more human-readable description of what we are generating.
/// - `cfssl`: The path to the cfssl binary.
/// - `cfssljson`: The path to the cfssljson binary.
/// - `ca_cert`: The path to the CA certificate.
/// - `ca_key`: The path to the private CA key.
/// - `ca_config`: The path to the CA config file to use.
/// - `server_csr`: The path to the file that describes the new certificate.
/// - `path`: The path to write the resulting certificate file to.
/// 
/// # Returns
/// Nothing, except that when it does you can assume a file exists at the given location.
/// 
/// Also keeps the user up-to-date with a neat print.
/// 
/// # Errors
/// This function may error if we failed to call the command or the command itself fails.
fn generate_server_cert(cfssl: impl AsRef<Path>, cfssljson: impl AsRef<Path>, ca_cert: impl AsRef<Path>, ca_key: impl AsRef<Path>, ca_config: impl AsRef<Path>, server_csr: impl AsRef<Path>, path: impl AsRef<Path>) -> Result<(), Error> {
    let cfssl      : &Path = cfssl.as_ref();
    let cfssljson  : &Path = cfssljson.as_ref();
    let ca_cert    : &Path = ca_cert.as_ref();
    let ca_key     : &Path = ca_key.as_ref();
    let ca_config  : &Path = ca_config.as_ref();
    let server_csr : &Path = server_csr.as_ref();
    let path       : &Path = path.as_ref();
    info!("Generating {}...", style("server certificate").green().bold());

    // Prepare the command to run
    let mut cmd: Command = Command::new("bash");
    cmd.arg("-c");
    cmd.arg(format!("\"{}\" gencert -ca=\"{}\" -ca-key=\"{}\" -config=\"{}\" -profile=server \"{}\" | \"{}\" -bare \"{}\"", cfssl.display(), ca_cert.display(), ca_key.display(), ca_config.display(), server_csr.display(), cfssljson.display(), path.display()));

    // Run it
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(err)   => { return Err(Error::SpawnError{ cmd, err }); },
    };
    if !output.status.success() { return Err(Error::SpawnFailure{ cmd, status: output.status, err: String::from_utf8_lossy(&output.stderr).into() }); }

    // Done
    Ok(())
}





/***** HELPER STRUCTS *****/
/// Defines the JSON format for the `ca-config.json` file we use to configure `cfssl` in general.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfig {
    /// The toplevel signing struct
    signing : CfsslCaConfigSigning,
}

/// Defines the JSON format for the toplevel map in the `ca-config.json` file.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfigSigning {
    /// Set some default values
    default  : CfsslCaConfigDefault,
    /// Defines the profiles to sign with this certificate.
    profiles : HashMap<String, CfsslCaConfigProfile>,
}

/// Defines the JSON format for the default map in the `ca-config.json` file.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfigDefault {
    /// Sets the default expiry time.
    /// 
    /// We set as string for convenience. If we are ever gonna read this, we should change this to a more elaborate data format.
    expiry : String,
}

/// Defines the JSON format for a profile map in the `ca-config.json` file.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfigProfile {
    /// The list of usages allowed for this profile.
    usages : Vec<String>,
    /// The expiry time.
    /// 
    /// We set as string for convenience. If we are ever gonna read this, we should change this to a more elaborate data format.
    expiry : String,
}



/// Defines the JSON format for the `ca-csr.json` file we use to let `cfssl` generate a CA certificate for us.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaCsr {
    /// The common name for the CA certificate.
    #[serde(rename = "CN")]
    cn    : String,
    /// Defines the key to generate.
    key   : CfsslCsrKey,
    /// The names(?) of the CSR.
    names : Vec<HashMap<String, String>>,
}

/// Defines the JSON format for the `server-csr.json` file we use to let `cfssl` generate a server certificate for us.
#[derive(Clone, Debug, Serialize)]
struct CfsslServerCsr {
    /// The common name for the server certificate.
    #[serde(rename = "CN")]
    cn    : String,
    /// The list of hostnames to generate this certificate for.
    hosts : Vec<String>,
    /// Defines the key to generate.
    key   : CfsslCsrKey,
    /// The names(?) of the CSR.
    names : Vec<HashMap<String, String>>,
}

/// Defines a key for all of the CSR files.
#[derive(Clone, Debug, Serialize)]
struct CfsslCsrKey {
    /// The algorithm used.
    algo : String,
    /// The size of the key, in bits.
    size : usize,
}





/***** LIBRARY *****/
/// Handles generating a new `node.yml` config file for a central _or_ worker node.
/// 
/// # Arguments
/// - `path`: The path to write the central node.yml to.
/// - `hosts`: List of additional hostnames to set in the launched containers.
/// - `proxy`: The address to proxy to, if any (not the address of the proxy service, but rather that of a 'real' proxy).
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `config_path`: The path to the config directory that other paths may use as their base.
/// - `command`: The GenerateSubcommand that contains the specific values to write, as well as whether to write a central or worker node.
/// 
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
/// 
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub fn node(path: impl Into<PathBuf>, hosts: Vec<HostnamePair>, proxy: Option<Address>, fix_dirs: bool, config_path: impl Into<PathBuf>, command: GenerateNodeSubcommand) -> Result<(), Error> {
    let path        : PathBuf = path.into();
    let config_path : PathBuf = config_path.into();
    info!("Generating node.yml for a {}...", match &command { GenerateNodeSubcommand::Central { .. } => { "central node".into() }, GenerateNodeSubcommand::Worker{ location_id, .. } => { format!("worker node with location ID '{}'", location_id) } });

    // Generate the host -> IP map from the pairs.
    let hosts: HashMap<String, IpAddr> = {
        let mut res: HashMap<String, IpAddr> = HashMap::with_capacity(hosts.len());
        for pair in hosts {
            // Ensure it doesn't already exist
            if res.insert(pair.0.clone(), pair.1).is_some() {
                warn!("Duplicate IP given for hostname '{}': using only {}", pair.0, pair.1);
            }
        }
        res
    };

    // Build the NodeConfig
    debug!("Generating node config...");
    let node_config: NodeConfig = match command {
        // Generate the central node
        GenerateNodeSubcommand::Central { infra, certs, packages, prx_name, api_name, drv_name, plr_name, prx_port, api_port, drv_port, plr_cmd_topic, plr_res_topic } => {
            // Resolve any path depending on the '$CONFIG'
            let infra : PathBuf = resolve_config_path(infra, &config_path);
            let certs : PathBuf = resolve_config_path(certs, &config_path);

            // Ensure the directory structure is there
            ensure_dir_of(&infra, fix_dirs)?;
            ensure_dir(&certs, fix_dirs)?;
            ensure_dir(&packages, fix_dirs)?;

            // Generate the config's contents
            NodeConfig {
                hosts,
                proxy,

                names    : CommonNames{ prx : prx_name.clone() },
                paths    : CommonPaths{ certs: canonicalize(certs)?, packages: canonicalize(packages)? },
                ports    : CommonPorts{ prx : SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), prx_port).into() },
                services : CommonServices{ prx : Address::Hostname(format!("http://{}", prx_name), prx_port) },

                node : NodeKindConfig::Central(CentralConfig {
                    names : CentralNames{ api: api_name.clone(), drv: drv_name, plr: plr_name },
                    paths : CentralPaths {
                        infra : canonicalize(infra)?,
                    },
                    ports    : CentralPorts { api: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), api_port).into(), drv: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), drv_port).into() },
                    services : CentralServices{ brokers: vec![ Address::Hostname("aux-kafka".into(), 9092) ], scylla: Address::Hostname("aux-scylla".into(), 9042), api: Address::Hostname(format!("http://{}", api_name), api_port) },
                    topics   : CentralKafkaTopics{ planner_command: plr_cmd_topic, planner_results: plr_res_topic },
                }),
            }
        },

        // Generate the worker node
        GenerateNodeSubcommand::Worker { location_id, backend, policies, certs, packages, data, results, temp_data, temp_results, prx_name, reg_name, job_name, chk_name, prx_port, reg_port, job_port, chk_port } => {
            // Resolve the service names
            let prx_name: String = prx_name.replace("$LOCATION", &location_id);
            let reg_name: String = reg_name.replace("$LOCATION", &location_id);
            let job_name: String = job_name.replace("$LOCATION", &location_id);
            let chk_name: String = chk_name.replace("$LOCATION", &location_id);

            // Resolve any path depending on the '$CONFIG'
            let backend  : PathBuf = resolve_config_path(backend, &config_path);
            let policies : PathBuf = resolve_config_path(policies, &config_path);
            let certs    : PathBuf = resolve_config_path(certs, &config_path);

            // Ensure the directory structure is there
            ensure_dir_of(&backend, fix_dirs)?;
            ensure_dir_of(&policies, fix_dirs)?;
            ensure_dir(&certs, fix_dirs)?;
            ensure_dir(&packages, fix_dirs)?;
            ensure_dir(&data, fix_dirs)?;
            ensure_dir(&results, fix_dirs)?;
            ensure_dir(&temp_data, fix_dirs)?;
            ensure_dir(&temp_results, fix_dirs)?;

            // Generate the config's contents
            NodeConfig {
                hosts,
                proxy,

                names    : CommonNames{ prx: prx_name.clone() },
                paths    : CommonPaths{ certs: canonicalize(resolve_config_path(certs, &config_path))?, packages: canonicalize(resolve_config_path(packages, &config_path))? },
                ports    : CommonPorts{ prx : SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), prx_port).into() },
                services : CommonServices{ prx : Address::Hostname(format!("http://{}", prx_name), prx_port) },

                node : NodeKindConfig::Worker(WorkerConfig {
                    location_id,
                    names : WorkerNames { reg: reg_name.clone(), job: job_name, chk: chk_name.clone() },
                    paths : WorkerPaths {
                        backend      : canonicalize(resolve_config_path(backend, &config_path))?,
                        policies     : canonicalize(resolve_config_path(policies, &config_path))?,
                        data         : canonicalize(data)?,
                        results      : canonicalize(results)?,
                        temp_data    : canonicalize(temp_data)?,
                        temp_results : canonicalize(temp_results)?,
                    },
                    ports    : WorkerPorts { reg: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), reg_port).into(), job: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), job_port).into() },
                    services : WorkerServices { reg: Address::Hostname(format!("https://{}", reg_name), reg_port), chk: Address::Hostname(format!("http://{}", chk_name), chk_port) },
                }),
            }
        },
    };

    // Open the file and write a header to it
    debug!("Writing to '{}'...", path.display());
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err)   => { return Err(Error::FileCreateError{ what: "node.yml", path, err }); },
    };

    // Write the top comment header thingy
    if let Err(err) = write_node_header(&mut handle) { return Err(Error::FileHeaderWriteError{ what: "infra.yml", path, err }); }
    // Write the file itself
    if let Err(err) = node_config.to_writer(handle) { return Err(Error::NodeWriteError{ path, err }); }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}



/// Handles generating root & server certificates for the current domain.
/// 
/// # Arguments
/// - `location_id`: The identifier of the location to generate them for.
/// - `hostname`: The hostname of the location to generate the certificates for.
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path of the directory to write the new certificate files to.
/// - `temp_dir`: The path of the directory where we store the temporary scripts.
/// 
/// # Returns
/// Nothing, but does write several new files to the given directory and updates the user on stdout on success.
/// 
/// # Errors
/// This function may error if I/O errors occur while downloading the auxillary scripts or while writing the files.
pub async fn certs(location_id: impl Into<String>, hostname: impl Into<String>, fix_dirs: bool, path: impl Into<PathBuf>, temp_dir: impl Into<PathBuf>) -> Result<(), Error> {
    let location_id : String  = location_id.into();
    let hostname    : String  = hostname.into();
    let path        : PathBuf = path.into();
    let temp_dir    : PathBuf = temp_dir.into();
    info!("Generating root & server certificates for {} @ {} to '{}'...", location_id, hostname, path.display());

    // Make sure the parent directory exists
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            if !fix_dirs { return Err(Error::DirNotFound { path: parent.into() }); }
            debug!("Creating missing '{}' directory (fix_dirs == true)...", parent.display());
            if let Err(err) = fs::create_dir_all(parent) { return Err(Error::DirCreateError { path: parent.into(), err }); }
        } else if !parent.is_dir() {
            return Err(Error::DirNotADir { path: parent.into() });
        }
    }

    // Make sure the cfssl binary is there
    let cfssl_path: PathBuf = temp_dir.join("cfssl");
    if cfssl_path.exists() {
        if !cfssl_path.is_file() { return Err(Error::FileNotAFile{ path: cfssl_path }); }
        debug!("'{}' already exists", cfssl_path.display());
    } else {
        debug!("'{}' does not exist, downloading...", cfssl_path.display());
        download_exe("cfssl", "https://github.com/cloudflare/cfssl/releases/download/v1.6.3/cfssl_1.6.3_linux_amd64", &cfssl_path, CHECKSUM_CFSSL).await?;
    }

    // Make sure the cfssljson binary is there
    let cfssljson_path: PathBuf = temp_dir.join("cfssljson");
    if cfssljson_path.exists() {
        if !cfssljson_path.is_file() { return Err(Error::FileNotAFile{ path: cfssljson_path }); }
        debug!("'{}' already exists", cfssljson_path.display());
    } else {
        debug!("'{}' does not exist, downloading...", cfssljson_path.display());
        download_exe("cfssljson", "https://github.com/cloudflare/cfssl/releases/download/v1.6.3/cfssljson_1.6.3_linux_amd64", &cfssljson_path, CHECKSUM_CFSSLJSON).await?;
    }

    // Now make sure the generic config JSON is there
    let ca_config_path: PathBuf = temp_dir.join("ca-config.json");
    if ca_config_path.exists() {
        if !ca_config_path.is_file() { return Err(Error::FileNotAFile{ path: ca_config_path }); }
        debug!("'{}' already exists", ca_config_path.display());
    } else {
        debug!("'{}' does not exist, generating...", ca_config_path.display());
        generate_config("CA config", CfsslCaConfig {
            signing : CfsslCaConfigSigning {
                default  : CfsslCaConfigDefault{ expiry: "8760h".into() },
                profiles : HashMap::from([
                    ("server".into(), CfsslCaConfigProfile {
                        usages : vec![ "signing".into(), "key encipherment".into(), "server auth".into() ],
                        expiry : "8760h".into(),
                    }),
                    ("client".into(), CfsslCaConfigProfile {
                        usages : vec![ "signing".into(), "key encipherment".into(), "client auth".into() ],
                        expiry : "8760h".into(),
                    }),
                ]),
            }
        }, &ca_config_path)?;
    }

    // Generate a random ID to avoid* conflicting* repeated files
    let id: String = rand::thread_rng().sample_iter(Alphanumeric).map(|c| char::from(c)).take(3).collect::<String>();

    // Then write the CA config itself (always, since it contains call-specific information)
    let ca_csr_path: PathBuf = temp_dir.join(format!("ca-csr-{}.json", id));
    debug!("Generating '{}'...", ca_csr_path.display());
    generate_config("CA CSR config", CfsslCaCsr {
        cn    : location_id.clone(),
        key   : CfsslCsrKey { algo: "rsa".into(), size: 4096 },
        names : vec![ HashMap::from([ ("".into(), "".into()) ]) ],
    }, &ca_csr_path)?;
    // And the server config
    let server_csr_path: PathBuf = temp_dir.join(format!("server-csr-{}.json", id));
    debug!("Generating '{}'...", server_csr_path.display());
    generate_config("server CSR config", CfsslServerCsr {
        cn    : location_id.clone(),
        hosts : vec![ hostname ],
        key   : CfsslCsrKey { algo: "rsa".into(), size: 4096 },
        names : vec![ HashMap::from([ ("".into(), "".into()) ]) ],
    }, &server_csr_path)?;

    // Now call the `cfssl` binary twice to generate the certificates
    generate_ca_cert(&cfssl_path, &cfssljson_path, ca_csr_path, path.join("ca"))?;
    generate_server_cert(&cfssl_path, &cfssljson_path, path.join("ca.pem"), path.join("ca-key.pem"), ca_config_path, server_csr_path, path.join("server"))?;

    // Done!
    println!("Successfully generated certificates for domain {}", style(location_id).green().bold());
    Ok(())
}



/// Handles generating a new `infra.yml` config file.
/// 
/// # Arguments
/// - `locations`: The locations (i.e., worker nodes) to define.
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path to write the `infra.yml` to.
/// - `names`: The human-friendly names per domain.
/// - `reg_ports`: The registry ports per domain.
/// - `job_ports`: The job ports per domain.
/// 
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
/// 
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub fn infra(locations: Vec<LocationPair<':', String>>, fix_dirs: bool, path: impl Into<PathBuf>, names: Vec<LocationPair<'=', String>>, reg_ports: Vec<LocationPair<'=', u16>>, job_ports: Vec<LocationPair<'=', u16>>) -> Result<(), Error> {
    let path: PathBuf = path.into();
    info!("Generating creds.yml...");

    // Create the locations
    debug!("Generating infrastructure information...");
    let mut locs: HashMap<String, InfraLocation> = HashMap::with_capacity(locations.len());
    for loc in locations {
        locs.insert(loc.0.clone(), InfraLocation {
            name     : beautify_id(loc.0),
            registry : Address::hostname(format!("https://{}", loc.1), 50051),
            delegate : Address::hostname(format!("grpc://{}", loc.1), 50052),
        });
    }

    // Overwrite given values
    for name in names {
        match locs.get_mut(&name.0) {
            Some(loc) => loc.name = name.1,
            None      => { return Err(Error::UnknownLocation{ loc: name.0 }); },
        }
    }
    for port in reg_ports {
        match locs.get_mut(&port.0) {
            Some(loc) => *loc.registry.port_mut() = port.1,
            None      => { return Err(Error::UnknownLocation{ loc: port.0 }); },
        }
    }
    for port in job_ports {
        match locs.get_mut(&port.0) {
            Some(loc) => *loc.delegate.port_mut() = port.1,
            None      => { return Err(Error::UnknownLocation{ loc: port.0 }); },
        }
    }

    // Populate a new InfraFile
    let infra: InfraFile = InfraFile::new(locs);

    // Make sure its directory exists
    debug!("Writing to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;

    // Open the file to write it to
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err)   => { return Err(Error::FileCreateError{ what: "infra.yml", path, err }); },
    };

    // Write the header
    if let Err(err) = write_infra_header(&mut handle) { return Err(Error::FileHeaderWriteError { what: "infra.yml", path, err }); }
    // Write the contents
    if let Err(err) = infra.to_writer(handle) { return Err(Error::InfraWriteError{ path, err }); }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}



/// Handles generating a new `creds.yml` config file.
/// 
/// # Arguments
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path to write the `creds.yml` to.
/// - `capabilities`: A list of Capabilities to advertise for this domain.
/// - `hash_container`: Whether the hashing-containers feature should be enabled or not.
/// - `command`: The command with the type of backend (and associated properties) encoded in it.
/// 
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
/// 
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub fn backend(fix_dirs: bool, path: impl Into<PathBuf>, capabilities: Vec<Capability>, hash_containers: bool, command: GenerateBackendSubcommand) -> Result<(), Error> {
    let path: PathBuf = path.into();
    info!("Generating backend.yml for a {} backend...", command.variant());

    // Create the BackendFile
    debug!("Generating backend information...");
    let backend: BackendFile = match command {
        GenerateBackendSubcommand::Local{ socket, client_version } => {
            // Generate the creds file we want
            BackendFile {
                capabilities    : Some(capabilities.into_iter().collect()),
                hash_containers : Some(hash_containers),
                method          : Credentials::Local{ path: Some(socket), version: client_version.map(|v| (v.0.major_version, v.0.minor_version)) },
            }
        },
    };

    // Make sure its directory exists
    debug!("Writing to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;

    // Open the file to write it to
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err)   => { return Err(Error::FileCreateError{ what: "backend.yml", path, err }); },
    };

    // Write the header
    if let Err(err) = write_backend_header(&mut handle) { return Err(Error::FileHeaderWriteError { what: "backend.yml", path, err }); }
    // Write the contents
    if let Err(err) = backend.to_writer(handle) { return Err(Error::BackendWriteError{ path, err }); }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}

/// Handles generating a new `policies.yml` config file.
/// 
/// # Arguments
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path to write the `policies.yml` to.
/// - `allow_all`: If true, generates default `AllowAll` rules instead of `DenyAll`.
/// 
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
/// 
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub fn policy(fix_dirs: bool, path: impl Into<PathBuf>, allow_all: bool) -> Result<(), Error> {
    let path: PathBuf = path.into();
    info!("Generating policies.yml that {} all...", if allow_all { "allows" } else { "denies" });

    // Create the CredsFile
    debug!("Generating backend information...");
    let policies: PolicyFile = PolicyFile {
        users      : vec![ UserPolicy::AllowAll ],
        containers : vec![ ContainerPolicy::AllowAll ],
    };

    // Make sure its directory exists
    debug!("Writing to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;

    // Open the file to write it to
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err)   => { return Err(Error::FileCreateError{ what: "policies.yml", path, err }); },
    };

    // Write the header
    if let Err(err) = write_policy_header(&mut handle) { return Err(Error::FileHeaderWriteError{ what: "policies.yml", path, err }); }
    // Write the contents
    if let Err(err) = policies.to_writer(handle) { return Err(Error::PolicyWriteError{ path, err }); }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}
