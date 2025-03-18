//  GENERATE.rs
//    by Lut99
//
//  Created:
//    21 Nov 2022, 15:40:47
//  Last edited:
//    01 May 2024, 15:20:56
//  Auto updated?
//    Yes
//
//  Description:
//!   Handles commands relating to node.yml generation.
//

use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{self, File};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use base64ct::Encoding as _;
use brane_cfg::backend::{BackendFile, Credentials};
use brane_cfg::info::Info as _;
use brane_cfg::infra::{InfraFile, InfraLocation};
use brane_cfg::node::{
    self, CentralConfig, CentralPaths, CentralServices, ExternalService, NodeConfig, NodeSpecificConfig, PrivateOrExternalService, PrivateService,
    ProxyPaths, ProxyServices, PublicService, WorkerConfig, WorkerPaths, WorkerServices, WorkerUsecase,
};
use brane_cfg::proxy::{self, ForwardConfig};
use brane_shr::fs::{DownloadSecurity, set_executable};
use console::style;
use diesel::{Connection as _, SqliteConnection};
use diesel_migrations::{FileBasedMigrations, MigrationHarness as _};
use enum_debug::EnumDebug as _;
use jsonwebtoken::jwk::{self, Jwk, JwkSet, KeyAlgorithm, OctetKeyParameters, OctetKeyType, PublicKeyUse};
use log::{debug, info, warn};
use rand::distr::Alphanumeric;
use rand::rngs::OsRng;
use rand::{Rng as _, TryRngCore};
use serde::Serialize;
use specifications::address::Address;
use specifications::package::Capability;
use specifications::policy::generate_policy_token;
use tempfile::TempDir;

pub use crate::errors::GenerateError as Error;
use crate::spec::{GenerateBackendSubcommand, GenerateCertsSubcommand, GenerateNodeSubcommand, Pair};
use crate::utils::resolve_config_path;


/***** STATICS *****/
/// The embedded `cfssl` binary, compiled and/or downloaded by `build.rs`.
const CFSSL_BIN: &[u8] = include_bytes!(env!("CFSSL_PATH"));
/// The embedded `cfssljson` binary, compiled and/or downloaded by `build.rs`.
const CFSSLJSON_BIN: &[u8] = include_bytes!(env!("CFSSLJSON_PATH"));





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
        None => {
            panic!("Cannot ensure directory of '{}' which has no parent (did you mean to use `ensure_dir()`?)", path.display());
        },
    };

    // Assert it exists
    if !dir.exists() {
        // Error if we don't have to fix it
        if !fix_dirs {
            return Err(Error::DirNotFound { path: dir.into() });
        };

        // Create it if we're asked to
        if let Err(err) = fs::create_dir_all(dir) {
            return Err(Error::DirCreateError { path: dir.into(), err });
        }
    }
    // If it does but is a file, error
    if !dir.is_dir() {
        return Err(Error::DirNotADir { path: dir.into() });
    }

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
        if !fix_dirs {
            return Err(Error::DirNotFound { path: path.into() });
        };

        // Create it if we're asked to
        if let Err(err) = fs::create_dir_all(path) {
            return Err(Error::DirCreateError { path: path.into(), err });
        }
    }
    // If it does but is a file, error
    if !path.is_dir() {
        return Err(Error::DirNotADir { path: path.into() });
    }

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
        Err(err) => Err(Error::CanonicalizeError { path: path.into(), err }),
    }
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
    let id: String = id
        .split(' ')
        .map(|w| {
            if !w.is_empty() {
                let mut chars = w.chars();
                format!("{}{}", chars.next().unwrap().to_uppercase(), chars.collect::<String>())
            } else {
                String::new()
            }
        })
        .collect::<Vec<String>>()
        .join(" ");

    // Return
    id
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
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/node.html")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
    Ok(())
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
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/infra.html")?;
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
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/backend.html")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
    Ok(())
}

/// Function that writes the standard proxy.yml header to the given writer.
///
/// # Arguments
/// - `writer`: The Writer to write to.
///
/// # Returns
/// Nothing, but does update the given writer with the standard header.
///
/// # Errors
/// This function errors if we failed to write.
fn write_proxy_header(writer: &mut impl Write) -> Result<(), std::io::Error> {
    // Simply call write repeatedly
    writeln!(writer, "# PROXY.yml")?;
    writeln!(writer, "#   generated by branectl v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# This file defines the settings for the proxy service on this node.")?;
    writeln!(writer, "# This file is loaded eagerly, so changing it requires a restart of the proxy")?;
    writeln!(writer, "# service itself.")?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# For an overview of what you can do in this file, refer to")?;
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/proxy.html")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
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
        Err(err) => {
            return Err(Error::ConfigSerializeError { err });
        },
    };

    // Assert the download directory exists
    let dir: Option<&Path> = path.parent();
    if let Some(dir) = dir {
        if !dir.exists() {
            return Err(Error::DirNotFound { path: dir.into() });
        }
    }

    // Open the local file
    debug!("Opening output file '{}'...", path.display());
    let mut handle: File = match File::create(path) {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::FileCreateError { what: "config", path: path.into(), err });
        },
    };

    // Write it and we're done
    if let Err(err) = write!(handle, "{sconfig}") {
        return Err(Error::FileWriteError { what: "config", path: path.into(), err });
    }
    Ok(())
}

/// Extracts a cfssl(json) embedded binary to the given location.
///
/// # Arguments
/// - `path`: The path to write the resulting binary to.
/// - `cfssljson`: If true, extracts `cfssljson` instead of `cfssl`.
///
/// # Errors
/// This function may error if we failed to write the binaries or make it executable.
fn extract_cfssl(path: impl AsRef<Path>, cfssljson: bool) -> Result<(), Error> {
    let path: &Path = path.as_ref();

    // Attempt to write it
    if let Err(err) = fs::write(path, if !cfssljson { CFSSL_BIN } else { CFSSLJSON_BIN }) {
        return Err(Error::ExtractError { what: if !cfssljson { "cfssl" } else { "cfssljson" }, path: path.into(), err });
    }

    // Make the file executable
    if let Err(err) = set_executable(path) {
        return Err(Error::ExecutableError { err: Box::new(err) });
    }

    // Done
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
    let cfssl: &Path = cfssl.as_ref();
    let cfssljson: &Path = cfssljson.as_ref();
    let ca_csr: &Path = ca_csr.as_ref();
    let path: &Path = path.as_ref();
    info!("Generating CA certificate...");

    // Prepare the command to run
    let mut cmd: Command = Command::new("bash");
    cmd.arg("-c");
    cmd.arg(format!("\"{}\" gencert -initca \"{}\" | \"{}\" -bare \"{}\"", cfssl.display(), ca_csr.display(), cfssljson.display(), path.display()));

    // Run it
    debug!("CA certificate generation command: {:?}", cmd);
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(err) => {
            return Err(Error::SpawnError { cmd, err });
        },
    };
    if !output.status.success() {
        return Err(Error::SpawnFailure { cmd, status: output.status, err: String::from_utf8_lossy(&output.stderr).into() });
    }

    // Done
    Ok(())
}

/// Generates a server certificate given the CSR configuration files.
///
/// # Arguments
/// - `profile`: Whether we are generating a 'client' or a 'server'.
/// - `cfssl`: The path to the cfssl binary.
/// - `cfssljson`: The path to the cfssljson binary.
/// - `ca_cert`: The path to the CA certificate.
/// - `ca_key`: The path to the private CA key.
/// - `ca_config`: The path to the CA config file to use.
/// - `csr_file`: The path to the file that describes the new certificate.
/// - `path`: The path to write the resulting certificate file to.
///
/// # Returns
/// Nothing, except that when it does you can assume a file exists at the given location.
///
/// Also keeps the user up-to-date with a neat print.
///
/// # Errors
/// This function may error if we failed to call the command or the command itself fails.
fn generate_client_server_cert(
    profile: impl AsRef<str>,
    exes: CfsslExecutables<impl AsRef<Path>, impl AsRef<Path>>,
    ca_cert: impl AsRef<Path>,
    ca_key: impl AsRef<Path>,
    ca_config: impl AsRef<Path>,
    csr_file: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> Result<(), Error> {
    let profile: &str = profile.as_ref();
    let cfssl: &Path = exes.cfssl.as_ref();
    let cfssljson: &Path = exes.cfssljson.as_ref();
    let ca_cert: &Path = ca_cert.as_ref();
    let ca_key: &Path = ca_key.as_ref();
    let ca_config: &Path = ca_config.as_ref();
    let csr_file: &Path = csr_file.as_ref();
    let path: &Path = path.as_ref();
    info!("Generating {} certificate...", profile);

    // Prepare the command to run
    let mut cmd: Command = Command::new("bash");
    cmd.arg("-c");
    cmd.arg(format!(
        "\"{}\" gencert -ca=\"{}\" -ca-key=\"{}\" -config=\"{}\" -profile={} \"{}\" | \"{}\" -bare \"{}\"",
        cfssl.display(),
        ca_cert.display(),
        ca_key.display(),
        ca_config.display(),
        profile,
        csr_file.display(),
        cfssljson.display(),
        path.display()
    ));

    // Run it
    debug!("{} certificate generation command: {:?}", profile, cmd);
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(err) => {
            return Err(Error::SpawnError { cmd, err });
        },
    };
    if !output.status.success() {
        return Err(Error::SpawnFailure { cmd, status: output.status, err: String::from_utf8_lossy(&output.stderr).into() });
    }

    // Done
    Ok(())
}





/***** HELPER STRUCTS *****/
/// Combines information about the cfssl executables.
#[derive(Clone, Debug)]
struct CfsslExecutables<P1, P2> {
    /// The main executable
    cfssl:     P1,
    /// The executable that takes the JSON output of the first and generates a .pem certificate out of it
    cfssljson: P2,
}


/// Defines the JSON format for the `ca-config.json` file we use to configure `cfssl` in general.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfig {
    /// The toplevel signing struct
    signing: CfsslCaConfigSigning,
}

/// Defines the JSON format for the toplevel map in the `ca-config.json` file.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfigSigning {
    /// Set some default values
    default:  CfsslCaConfigDefault,
    /// Defines the profiles to sign with this certificate.
    profiles: HashMap<String, CfsslCaConfigProfile>,
}

/// Defines the JSON format for the default map in the `ca-config.json` file.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfigDefault {
    /// Sets the default expiry time.
    ///
    /// We set as string for convenience. If we are ever gonna read this, we should change this to a more elaborate data format.
    expiry: String,
}

/// Defines the JSON format for a profile map in the `ca-config.json` file.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaConfigProfile {
    /// The list of usages allowed for this profile.
    usages: Vec<String>,
    /// The expiry time.
    ///
    /// We set as string for convenience. If we are ever gonna read this, we should change this to a more elaborate data format.
    expiry: String,
}


/// Defines the JSON format for the `ca-csr.json` file we use to let `cfssl` generate a CA certificate for us.
#[derive(Clone, Debug, Serialize)]
struct CfsslCaCsr {
    /// The common name for the CA certificate.
    #[serde(rename = "CN")]
    cn:    String,
    /// Defines the key to generate.
    key:   CfsslCsrKey,
    /// The names(?) of the CSR.
    names: Vec<HashMap<String, String>>,
}

/// Defines the JSON format for the `server-csr.json` file we use to let `cfssl` generate a server certificate for us.
#[derive(Clone, Debug, Serialize)]
struct CfsslClientServerCsr {
    /// The common name for the server certificate.
    #[serde(rename = "CN")]
    cn:    String,
    /// The list of hostnames to generate this certificate for.
    hosts: Vec<String>,
    /// Defines the key to generate.
    key:   CfsslCsrKey,
    /// The names(?) of the CSR.
    names: Vec<HashMap<String, String>>,
}

/// Defines a key for all of the CSR files.
#[derive(Clone, Debug, Serialize)]
struct CfsslCsrKey {
    /// The algorithm used.
    algo: String,
    /// The size of the key, in bits.
    size: usize,
}





/***** LIBRARY *****/
/// Handles generating a new `node.yml` config file for a central _or_ worker node.
///
/// # Arguments
/// - `path`: The path to write the central node.yml to.
/// - `hosts`: List of additional hostnames to set in the launched containers.
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `config_path`: The path to the config directory that other paths may use as their base.
/// - `command`: The GenerateSubcommand that contains the specific values to write, as well as whether to write a central or worker node.
///
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
///
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub fn node(
    path: impl Into<PathBuf>,
    hosts: Vec<Pair<String, ':', IpAddr>>,
    fix_dirs: bool,
    config_path: impl Into<PathBuf>,
    command: GenerateNodeSubcommand,
) -> Result<(), Error> {
    let path: PathBuf = path.into();
    let config_path: PathBuf = config_path.into();
    info!("Generating node.yml for a {}...", match &command {
        GenerateNodeSubcommand::Central { .. } => {
            "central node".into()
        },
        GenerateNodeSubcommand::Worker { location_id, .. } => {
            format!("worker node with location ID '{location_id}'")
        },
        GenerateNodeSubcommand::Proxy { .. } => {
            "proxy node".into()
        },
    });

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
        GenerateNodeSubcommand::Central {
            hostname,
            infra,
            proxy,
            certs,
            packages,
            external_proxy,
            prx_name,
            api_name,
            drv_name,
            plr_name,
            prx_port,
            api_port,
            drv_port,
            plr_port,
        } => {
            // Remove any scheme, paths, ports, whatever from the hostname
            let mut hostname: &str = &hostname;
            if let Some(pos) = hostname.find("://") {
                hostname = &hostname[pos + 3..];
            }
            hostname = hostname.split(':').next().unwrap();
            hostname = hostname.split('/').next().unwrap();

            // Resolve any path depending on the '$CONFIG'
            let infra: PathBuf = resolve_config_path(infra, &config_path);
            let proxy: PathBuf = resolve_config_path(proxy, &config_path);
            let certs: PathBuf = resolve_config_path(certs, &config_path);

            // Ensure the directory structure is there
            ensure_dir_of(&infra, fix_dirs)?;
            ensure_dir_of(&proxy, fix_dirs)?;
            ensure_dir(&certs, fix_dirs)?;
            ensure_dir(&packages, fix_dirs)?;

            // Generate the config's contents
            NodeConfig {
                hostnames: hosts,
                namespace: "brane-central".into(),

                node: NodeSpecificConfig::Central(CentralConfig {
                    paths: CentralPaths {
                        certs:    canonicalize(certs)?,
                        packages: canonicalize(packages)?,

                        infra: canonicalize(infra)?,
                        proxy: if external_proxy.is_some() { None } else { Some(canonicalize(proxy)?) },
                    },

                    services: CentralServices {
                        api: PublicService {
                            name:    api_name.clone(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), api_port).into(),
                            address: Address::Hostname(format!("http://{api_name}"), api_port),

                            external_address: Address::Hostname(format!("http://{hostname}"), api_port),
                        },
                        drv: PublicService {
                            name:    drv_name.clone(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), drv_port).into(),
                            address: Address::Hostname(format!("grpc://{drv_name}"), drv_port),

                            external_address: Address::Hostname(format!("grpc://{hostname}"), drv_port),
                        },
                        plr: PrivateService {
                            name:    plr_name.clone(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), plr_port).into(),
                            address: Address::Hostname(format!("http://{plr_name}"), plr_port),
                        },
                        prx: if let Some(address) = external_proxy {
                            PrivateOrExternalService::External(ExternalService { address })
                        } else {
                            PrivateOrExternalService::Private(PrivateService {
                                name:    prx_name.clone(),
                                bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), prx_port).into(),
                                address: Address::Hostname(format!("http://{prx_name}"), prx_port),
                            })
                        },

                        aux_scylla: PrivateService {
                            name:    "aux-scylla".into(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 9042).into(),
                            address: Address::Hostname("aux-scylla".into(), 9042),
                        },
                    },
                }),
            }
        },

        // Generate the worker node
        GenerateNodeSubcommand::Worker {
            location_id,
            hostname,
            use_cases,
            backend,
            policy_database,
            policy_deliberation_secret,
            policy_expert_secret,
            policy_audit_log,
            proxy,
            certs,
            packages,
            data,
            results,
            temp_data,
            temp_results,
            external_proxy,
            prx_name,
            reg_name,
            job_name,
            chk_name,
            prx_port,
            reg_port,
            job_port,
            chk_port,
        } => {
            // Remove any scheme, paths, ports, whatever from the hostname
            let mut hostname: &str = &hostname;
            if let Some(pos) = hostname.find("://") {
                hostname = &hostname[pos + 3..];
            }
            hostname = hostname.split(':').next().unwrap();
            hostname = hostname.split('/').next().unwrap();

            // Resolve the service names
            let prx_name: String = prx_name.replace("$LOCATION", &location_id);
            let reg_name: String = reg_name.replace("$LOCATION", &location_id);
            let job_name: String = job_name.replace("$LOCATION", &location_id);
            let chk_name: String = chk_name.replace("$LOCATION", &location_id);

            // Resolve any path depending on the '$CONFIG'
            let backend: PathBuf = resolve_config_path(backend, &config_path);
            let policy_deliberation_secret: PathBuf = resolve_config_path(policy_deliberation_secret, &config_path);
            let policy_expert_secret: PathBuf = resolve_config_path(policy_expert_secret, &config_path);
            let policy_audit_log: Option<PathBuf> = policy_audit_log.map(|p| resolve_config_path(p, &config_path));
            let proxy: PathBuf = resolve_config_path(proxy, &config_path);
            let certs: PathBuf = resolve_config_path(certs, &config_path);

            // Ensure the directory structure is there
            ensure_dir_of(&backend, fix_dirs)?;
            ensure_dir_of(&policy_database, fix_dirs)?;
            ensure_dir_of(&policy_deliberation_secret, fix_dirs)?;
            ensure_dir_of(&policy_expert_secret, fix_dirs)?;
            if let Some(policy_audit_log) = &policy_audit_log {
                ensure_dir_of(policy_audit_log, fix_dirs)?;
            }
            ensure_dir_of(&proxy, fix_dirs)?;
            ensure_dir(&certs, fix_dirs)?;
            ensure_dir(&packages, fix_dirs)?;
            ensure_dir(&data, fix_dirs)?;
            ensure_dir(&results, fix_dirs)?;
            ensure_dir(&temp_data, fix_dirs)?;
            ensure_dir(&temp_results, fix_dirs)?;

            // Generate the config's contents
            NodeConfig {
                hostnames: hosts,
                namespace: format!("brane-worker-{location_id}"),

                node: NodeSpecificConfig::Worker(WorkerConfig {
                    name: location_id,

                    usecases: use_cases.into_iter().map(|p| (p.0, WorkerUsecase { api: p.1 })).collect(),

                    paths: WorkerPaths {
                        certs:    canonicalize(certs)?,
                        packages: canonicalize(packages)?,

                        backend: canonicalize(backend)?,
                        policy_database: canonicalize(policy_database)?,
                        policy_deliberation_secret: canonicalize(policy_deliberation_secret)?,
                        policy_expert_secret: canonicalize(policy_expert_secret)?,
                        policy_audit_log: policy_audit_log.map(canonicalize).transpose()?,
                        proxy: if external_proxy.is_some() { None } else { Some(canonicalize(proxy)?) },

                        data: canonicalize(data)?,
                        results: canonicalize(results)?,
                        temp_data: canonicalize(temp_data)?,
                        temp_results: canonicalize(temp_results)?,
                    },

                    services: WorkerServices {
                        reg: PublicService {
                            name:    reg_name.clone(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), reg_port).into(),
                            address: Address::Hostname(format!("https://{reg_name}"), reg_port),

                            external_address: Address::Hostname(format!("https://{hostname}"), reg_port),
                        },
                        job: PublicService {
                            name:    job_name.clone(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), job_port).into(),
                            address: Address::Hostname(format!("grpc://{job_name}"), job_port),

                            external_address: Address::Hostname(format!("grpc://{hostname}"), job_port),
                        },
                        chk: PrivateService {
                            name:    chk_name.clone(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), chk_port).into(),
                            address: Address::Hostname(format!("http://{chk_name}"), chk_port),
                        },
                        prx: if let Some(address) = external_proxy {
                            PrivateOrExternalService::External(ExternalService { address })
                        } else {
                            PrivateOrExternalService::Private(PrivateService {
                                name:    prx_name.clone(),
                                bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), prx_port).into(),
                                address: Address::Hostname(format!("http://{prx_name}"), prx_port),
                            })
                        },
                    },
                }),
            }
        },

        // Generate the proxy node
        GenerateNodeSubcommand::Proxy { hostname, proxy, certs, prx_name, prx_port } => {
            // Remove any scheme, paths, ports, whatever from the hostname
            let mut hostname: &str = &hostname;
            if let Some(pos) = hostname.find("://") {
                hostname = &hostname[pos + 3..];
            }
            hostname = hostname.split(':').next().unwrap();
            hostname = hostname.split('/').next().unwrap();

            // Resolve any path depending on the '$CONFIG'
            let proxy: PathBuf = resolve_config_path(proxy, &config_path);
            let certs: PathBuf = resolve_config_path(certs, &config_path);

            // Assert the directory structure is there
            ensure_dir_of(&proxy, fix_dirs)?;
            ensure_dir(&certs, fix_dirs)?;

            // Populate the NodeConfig
            NodeConfig {
                hostnames: hosts,
                namespace: "brane-proxy".into(),

                node: NodeSpecificConfig::Proxy(node::ProxyConfig {
                    paths: ProxyPaths { proxy: canonicalize(proxy)?, certs: canonicalize(certs)? },

                    services: ProxyServices {
                        prx: PublicService {
                            name:    prx_name.clone(),
                            bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), prx_port).into(),
                            address: Address::Hostname(format!("http://{prx_name}"), prx_port),

                            external_address: Address::Hostname(format!("http://{hostname}"), prx_port),
                        },
                    },
                }),
            }
        },
    };

    // Open the file and write a header to it
    debug!("Writing to '{}'...", path.display());
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::FileCreateError { what: "node.yml", path, err });
        },
    };

    // Write the top comment header thingy
    if let Err(err) = write_node_header(&mut handle) {
        return Err(Error::FileHeaderWriteError { what: "infra.yml", path, err });
    }
    // Write the file itself
    if let Err(err) = node_config.to_writer(handle, true) {
        return Err(Error::FileBodyWriteError { what: "infra.yml", path, err });
    }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}



/// Handles generating root & server certificates for the current domain.
///
/// # Arguments
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path of the directory to write the new certificate files to.
/// - `temp_dir`: The path of the directory where we store the temporary scripts.
/// - `kind`: The kind of certificate(s) to generate.
///
/// # Returns
/// Nothing, but does write several new files to the given directory and updates the user on stdout on success.
///
/// # Errors
/// This function may error if I/O errors occur while downloading the auxillary scripts or while writing the files.
pub async fn certs(fix_dirs: bool, path: impl Into<PathBuf>, temp_dir: impl Into<PathBuf>, mut kind: GenerateCertsSubcommand) -> Result<(), Error> {
    let path: PathBuf = path.into();
    let temp_dir: PathBuf = temp_dir.into();


    /* GENERAL */
    // Don't forget to resolve the hostname
    kind.resolve_hostname();
    info!("Generating {} certificates for {} @ {} to '{}'...", kind.variant(), kind.location_id(), kind.hostname(), path.display());

    // Make sure the target directory exists
    if !path.exists() {
        if !fix_dirs {
            return Err(Error::DirNotFound { path });
        }
        debug!("Creating missing '{}' directory (fix_dirs == true)...", path.display());
        if let Err(err) = fs::create_dir_all(&path) {
            return Err(Error::DirCreateError { path, err });
        }
    } else if !path.is_dir() {
        return Err(Error::DirNotADir { path });
    }

    // Make sure the cfssl binary is there
    let cfssl_path: PathBuf = temp_dir.join("cfssl");
    if cfssl_path.exists() {
        if !cfssl_path.is_file() {
            return Err(Error::FileNotAFile { path: cfssl_path });
        }
        debug!("'{}' already exists", cfssl_path.display());
    } else {
        debug!("'{}' does not exist, extracting...", cfssl_path.display());
        extract_cfssl(&cfssl_path, false)?;
    }

    // Make sure the cfssljson binary is there
    let cfssljson_path: PathBuf = temp_dir.join("cfssljson");
    if cfssljson_path.exists() {
        if !cfssljson_path.is_file() {
            return Err(Error::FileNotAFile { path: cfssljson_path });
        }
        debug!("'{}' already exists", cfssljson_path.display());
    } else {
        debug!("'{}' does not exist, extracting...", cfssljson_path.display());
        extract_cfssl(&cfssljson_path, true)?;
    }

    // Now make sure the generic config JSON is there
    let ca_config_path: PathBuf = temp_dir.join("ca-config.json");
    if ca_config_path.exists() {
        if !ca_config_path.is_file() {
            return Err(Error::FileNotAFile { path: ca_config_path });
        }
        debug!("'{}' already exists", ca_config_path.display());
    } else {
        debug!("'{}' does not exist, generating...", ca_config_path.display());
        generate_config(
            "CA config",
            CfsslCaConfig {
                signing: CfsslCaConfigSigning {
                    default:  CfsslCaConfigDefault { expiry: "8760h".into() },
                    profiles: HashMap::from([
                        ("server".into(), CfsslCaConfigProfile {
                            usages: vec!["signing".into(), "key encipherment".into(), "server auth".into()],
                            expiry: "8760h".into(),
                        }),
                        ("client".into(), CfsslCaConfigProfile {
                            usages: vec!["signing".into(), "key encipherment".into(), "client auth".into()],
                            expiry: "8760h".into(),
                        }),
                    ]),
                },
            },
            &ca_config_path,
        )?;
    }

    // Generate a random ID to avoid* conflicting* repeated files
    let id: String = rand::rng().sample_iter(Alphanumeric).map(char::from).take(3).collect::<String>();

    /* KIND-SPECIFIC */
    match &kind {
        GenerateCertsSubcommand::Server { location_id, hostname } => {
            // Then write the CA config itself (always, since it contains call-specific information)
            let ca_csr_path: PathBuf = temp_dir.join(format!("ca-csr-{id}.json"));
            debug!("Generating '{}'...", ca_csr_path.display());
            generate_config(
                "CA CSR config",
                CfsslCaCsr {
                    cn:    location_id.clone(),
                    key:   CfsslCsrKey { algo: "rsa".into(), size: 4096 },
                    names: vec![HashMap::from([("".into(), "".into())])],
                },
                &ca_csr_path,
            )?;
            // And the server config
            let server_csr_path: PathBuf = temp_dir.join(format!("server-csr-{id}.json"));
            debug!("Generating '{}'...", server_csr_path.display());
            generate_config(
                "server CSR config",
                CfsslClientServerCsr {
                    cn:    location_id.clone(),
                    hosts: vec![hostname.clone()],
                    key:   CfsslCsrKey { algo: "rsa".into(), size: 4096 },
                    names: vec![HashMap::from([("".into(), "".into())])],
                },
                &server_csr_path,
            )?;

            // Now call the `cfssl` binary twice to generate the certificates
            generate_ca_cert(&cfssl_path, &cfssljson_path, ca_csr_path, path.join("ca"))?;
            generate_client_server_cert(
                "server",
                CfsslExecutables { cfssl: &cfssl_path, cfssljson: &cfssljson_path },
                path.join("ca.pem"),
                path.join("ca-key.pem"),
                ca_config_path,
                server_csr_path,
                path.join("server"),
            )?;
        },

        GenerateCertsSubcommand::Client { location_id, hostname, ca_cert, ca_key } => {
            // Generate the client config
            let client_csr_path: PathBuf = temp_dir.join(format!("client-csr-{id}.json"));
            debug!("Generating '{}'...", client_csr_path.display());
            generate_config(
                "client CSR config",
                CfsslClientServerCsr {
                    cn:    location_id.clone(),
                    hosts: vec![hostname.clone()],
                    key:   CfsslCsrKey { algo: "rsa".into(), size: 4096 },
                    names: vec![HashMap::from([("".into(), "".into())])],
                },
                &client_csr_path,
            )?;

            // Assert the input certificate and key are there
            if !ca_cert.exists() {
                return Err(Error::CaCertNotFound { path: ca_cert.clone() });
            }
            if !ca_cert.is_file() {
                return Err(Error::CaCertNotAFile { path: ca_cert.clone() });
            }
            if !ca_key.exists() {
                return Err(Error::CaKeyNotFound { path: ca_cert.clone() });
            }
            if !ca_key.is_file() {
                return Err(Error::CaKeyNotAFile { path: ca_cert.clone() });
            }

            // Generate the key file(s) in a temporary directory
            let certs_dir: PathBuf = temp_dir.join(format!("certs-{id}"));
            if let Err(err) = fs::create_dir_all(&certs_dir) {
                return Err(Error::DirCreateError { path: certs_dir, err });
            }
            generate_client_server_cert(
                "client",
                CfsslExecutables { cfssl: &cfssl_path, cfssljson: &cfssljson_path },
                ca_cert,
                ca_key,
                ca_config_path,
                client_csr_path,
                certs_dir.join("client"),
            )?;

            // Create the output ID file
            let id_path: PathBuf = path.join("client-id.pem");
            debug!("Merging certificate and key into '{}'...", id_path.display());
            let mut output: File = match File::create(&id_path) {
                Ok(output) => output,
                Err(err) => {
                    return Err(Error::FileCreateError { what: "client identity", path: id_path, err });
                },
            };

            // Write the key file into it...
            let key_path: PathBuf = certs_dir.join("client-key.pem");
            let mut key: File = match File::open(&key_path) {
                Ok(key) => key,
                Err(err) => {
                    return Err(Error::FileOpenError { what: "client private key", path: key_path, err });
                },
            };
            if let Err(err) = std::io::copy(&mut key, &mut output) {
                return Err(Error::CopyError { source: key_path, target: id_path, err });
            }

            // And then the certificate file
            let cert_path: PathBuf = certs_dir.join("client.pem");
            let mut cert: File = match File::open(&cert_path) {
                Ok(key) => key,
                Err(err) => {
                    return Err(Error::FileOpenError { what: "client certificate", path: cert_path, err });
                },
            };
            if let Err(err) = std::io::copy(&mut cert, &mut output) {
                return Err(Error::CopyError { source: cert_path, target: id_path, err });
            }

            // Finally, write the CA file as well.
            let out_ca_path: PathBuf = path.join("ca.pem");
            debug!("Copying server CA certificate to '{}'...", out_ca_path.display());
            if let Err(err) = std::fs::copy(ca_cert, &out_ca_path) {
                return Err(Error::CopyError { source: ca_cert.clone(), target: out_ca_path, err });
            }
        },
    }

    // Done!
    println!(
        "Successfully generated {} certificates for domain {}",
        kind.variant().to_string().to_lowercase(),
        style(kind.location_id()).green().bold()
    );
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
pub fn infra(
    locations: Vec<Pair<String, ':', String>>,
    fix_dirs: bool,
    path: impl Into<PathBuf>,
    names: Vec<Pair<String, '=', String>>,
    reg_ports: Vec<Pair<String, '=', u16>>,
    job_ports: Vec<Pair<String, '=', u16>>,
) -> Result<(), Error> {
    let path: PathBuf = path.into();
    info!("Generating creds.yml...");

    // Create the locations
    debug!("Generating infrastructure information...");
    let mut locs: HashMap<String, InfraLocation> = HashMap::with_capacity(locations.len());
    for loc in locations {
        locs.insert(loc.0.clone(), InfraLocation {
            name:     beautify_id(loc.0),
            registry: Address::hostname(format!("https://{}", loc.1), 50051),
            delegate: Address::hostname(format!("grpc://{}", loc.1), 50052),
        });
    }

    // Overwrite given values
    for name in names {
        match locs.get_mut(&name.0) {
            Some(loc) => loc.name = name.1,
            None => {
                return Err(Error::UnknownLocation { loc: name.0 });
            },
        }
    }
    for port in reg_ports {
        match locs.get_mut(&port.0) {
            Some(loc) => *loc.registry.port_mut() = port.1,
            None => {
                return Err(Error::UnknownLocation { loc: port.0 });
            },
        }
    }
    for port in job_ports {
        match locs.get_mut(&port.0) {
            Some(loc) => *loc.delegate.port_mut() = port.1,
            None => {
                return Err(Error::UnknownLocation { loc: port.0 });
            },
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
        Err(err) => {
            return Err(Error::FileCreateError { what: "infra.yml", path, err });
        },
    };

    // Write the header
    if let Err(err) = write_infra_header(&mut handle) {
        return Err(Error::FileHeaderWriteError { what: "infra.yml", path, err });
    }
    // Write the contents
    if let Err(err) = infra.to_writer(handle, true) {
        return Err(Error::FileBodyWriteError { what: "infra.yml", path, err });
    }

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
pub fn backend(
    fix_dirs: bool,
    path: impl Into<PathBuf>,
    capabilities: Vec<Capability>,
    hash_containers: bool,
    command: GenerateBackendSubcommand,
) -> Result<(), Error> {
    let path: PathBuf = path.into();
    info!("Generating backend.yml for a {} backend...", command.variant());

    // Create the BackendFile
    debug!("Generating backend information...");
    let backend: BackendFile = match command {
        GenerateBackendSubcommand::Local { socket, client_version } => {
            // Generate the creds file we want
            BackendFile {
                capabilities: Some(capabilities.into_iter().collect()),
                hash_containers: Some(hash_containers),
                method: Credentials::Local { path: Some(socket), version: client_version.map(|v| (v.0.major_version, v.0.minor_version)) },
            }
        },
    };

    // Make sure its directory exists
    debug!("Writing to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;

    // Open the file to write it to
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::FileCreateError { what: "backend.yml", path, err });
        },
    };

    // Write the header
    if let Err(err) = write_backend_header(&mut handle) {
        return Err(Error::FileHeaderWriteError { what: "backend.yml", path, err });
    }
    // Write the contents
    if let Err(err) = backend.to_writer(handle, true) {
        return Err(Error::FileBodyWriteError { what: "backend.yml", path, err });
    }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}

/// Handles generating a new `policies.db` database.
///
/// # Arguments
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path to write the `policies.db` to.
///
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
///
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub async fn policy_database(fix_dirs: bool, path: PathBuf, branch: String) -> Result<(), Error> {
    info!("Generating policies.db at '{}'...", path.display());

    // First, touch the file alive
    debug!("Creating policy database file '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;
    if let Err(err) = File::create(&path) {
        return Err(Error::FileCreateError { what: "policy database", path, err });
    }

    // Next, fetch the migrations to run
    debug!("Retrieving up-to-date mitigations from 'https://github.com/braneframework/policy-reasoner ({branch})...");
    // NOTE: We're not using `_dir`, but keep it to prevent the directory from being removed once the objects gets dropped
    let (_dir, migrations): (TempDir, FileBasedMigrations) = {
        // Prepare the input URL and output directory
        let url = format!("https://api.github.com/repos/epi-project/policy-reasoner/tarball/{branch}");
        let dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(err) => {
                return Err(Error::TempDirError { err });
            },
        };

        // Download the file
        let tar_path: PathBuf = dir.path().join("repo.tar.gz");
        let dir_path: PathBuf = dir.path().join("repo");
        if let Err(err) = brane_shr::fs::download_file_async(&url, &tar_path, DownloadSecurity { checksum: None, https: true }, None).await {
            return Err(Error::RepoDownloadError { repo: url, target: dir_path, err });
        }
        if let Err(err) = brane_shr::fs::unarchive_async(&tar_path, &dir_path).await {
            return Err(Error::RepoUnpackError { tar: tar_path, target: dir_path, err });
        }
        // Resolve that one weird folder in there
        let dir_path: PathBuf = match brane_shr::fs::recurse_in_only_child_async(&dir_path).await {
            Ok(path) => path,
            Err(err) => {
                return Err(Error::RepoRecurseError { target: dir_path, err });
            },
        };

        // Read that as the migrations
        let migrations: FileBasedMigrations = match FileBasedMigrations::find_migrations_directory_in_path(&dir_path) {
            Ok(migrations) => migrations,
            Err(err) => return Err(Error::MigrationsRetrieve { path: dir_path, err }),
        };
        (dir, migrations)
    };

    // Apply that with diesel
    {
        // Connect to the database
        debug!("Applying migrations...");
        let mut conn: SqliteConnection = match SqliteConnection::establish(&path.display().to_string()) {
            Ok(conn) => conn,
            Err(err) => return Err(Error::DatabaseConnect { path, err }),
        };

        // Attempt to run the migration
        if let Err(err) = conn.run_pending_migrations(migrations) {
            return Err(Error::MigrationsApply { path, err });
        }
    }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}

/// Handles generating a new JWT secret.
///
/// # Arguments
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path to write the `policy_secret.json` to.
/// - `key_id`: Some identifier to use for this key.
/// - `key_alg`: The JWT algorithm that should be used for signing.
///
/// # Errors
/// This function may error if we encountered any I/O errors.
pub fn policy_secret(fix_dirs: bool, path: PathBuf, key_id: String, key_alg: KeyAlgorithm) -> Result<(), Error> {
    info!("Generating policy_secret.json at '{}'...", path.display());

    // Generate a new key with the given properties
    debug!("Generating secret key for {key_alg}...");
    let key: String = match key_alg {
        KeyAlgorithm::HS256 => {
            // Generate a 256-bit, base64-encoded random string of bytes
            // See: <https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1>
            let mut key: [u8; 32] = [0; 32];
            OsRng.try_fill_bytes(&mut key).expect("OsRng should be available and must be able to fill array");
            base64ct::Base64Url::encode_string(&key)
        },

        // Rest is unknown to us
        key_alg => return Err(Error::UnsupportedKeyAlgorithm { key_alg }),
    };

    // Create the to-be-serialized JSON with this
    debug!("Constructing JSON Web Key Set...");
    let secret: JwkSet = JwkSet {
        keys: vec![Jwk {
            common:    jwk::CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_operations: None,
                key_algorithm: Some(key_alg),
                key_id: Some(key_id),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: jwk::AlgorithmParameters::OctetKey(OctetKeyParameters { key_type: OctetKeyType::Octet, value: key }),
        }],
    };

    // Write it to a file
    debug!("Writing secret to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;
    let handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err) => return Err(Error::FileCreateError { what: "policy secret", path, err }),
    };
    if let Err(err) = serde_json::to_writer_pretty(handle, &secret) {
        return Err(Error::FileSerializeError { what: "policy secret", path, err });
    }

    // OK
    println!("Successfully generated {}", style(path.display()).bold().green());
    Ok(())
}

/// Generates a new access token for the checker.
///
/// # Arguments
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path to write the `policy_jwt.json` to.
/// - `secret_path`: The path to the `policy_secret.json` file to use to sign the token with.
/// - `initiator`: The name of the person performing the request, to embed in the token.
/// - `system`: The name or identifier of the node or other entity through which the request is performed, to embed in the token.
/// - `exp`: The duration the token will be valid for.
///
/// # Errors
/// This function may error if we encountered any I/O errors.
pub fn policy_token(fix_dirs: bool, path: PathBuf, secret_path: PathBuf, initiator: String, system: String, exp: Duration) -> Result<(), Error> {
    info!("Generating policy_token.json at '{}'...", path.display());

    // Use the backend to do this
    let token: String = match generate_policy_token(initiator, system, exp, secret_path) {
        Ok(token) => token,
        Err(err) => return Err(Error::TokenGenerate { err }),
    };

    // Finally, write that to a file
    debug!("Writing token to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;
    if let Err(err) = fs::write(&path, token) {
        return Err(Error::FileWriteError { what: "policy token", path, err });
    }

    // OK
    println!("Successfully generated {}", style(path.display()).bold().green());
    Ok(())
}

/// Handles generating a new `proxy.yml` config file.
///
/// # Arguments
/// - `fix_dirs`: if true, will generate missing directories instead of complaining.
/// - `path`: The path to write the `policies.yml` to.
/// - `outgoing_range`: The range of ports to allocate for outgoing connections.
/// - `incoming`: The map of incoming ports to internal destinations to setup for incoming ports.
/// - `forward`: The settings for forwaring traffic to a SOCKS proxy, if enabled.
///
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
///
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub fn proxy(
    fix_dirs: bool,
    path: impl Into<PathBuf>,
    outgoing_range: RangeInclusive<u16>,
    incoming: HashMap<u16, Address>,
    forward: Option<ForwardConfig>,
) -> Result<(), Error> {
    let path: PathBuf = path.into();
    info!("Generating proxy.yml...");

    // Create the BackendFile
    debug!("Generating proxy information...");
    let proxy: proxy::ProxyConfig = proxy::ProxyConfig { outgoing_range, incoming, forward };

    // Make sure its directory exists
    debug!("Writing to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;

    // Open the file to write it to
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::FileCreateError { what: "proxy.yml", path, err });
        },
    };

    // Write the header
    if let Err(err) = write_proxy_header(&mut handle) {
        return Err(Error::FileHeaderWriteError { what: "proxy.yml", path, err });
    }
    // Write the contents
    if let Err(err) = proxy.to_writer(handle, true) {
        return Err(Error::FileBodyWriteError { what: "proxy.yml", path, err });
    }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}
