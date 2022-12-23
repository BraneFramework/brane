//  GENERATE.rs
//    by Lut99
// 
//  Created:
//    21 Nov 2022, 15:40:47
//  Last edited:
//    19 Dec 2022, 11:56:57
//  Auto updated?
//    Yes
// 
//  Description:
//!   Handles commands relating to node.yml generation.
// 

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use console::style;
use enum_debug::EnumDebug as _;
use log::{debug, info, warn};

use brane_cfg::spec::Address;
use brane_cfg::infra::{InfraFile, InfraLocation};
use brane_cfg::creds::{Credentials, CredsFile};
use brane_cfg::node::{CentralConfig, CentralKafkaTopics, CentralNames, CentralPaths, CentralPorts, CentralServices, CommonNames, CommonPaths, CommonPorts, CommonServices, NodeConfig, NodeKindConfig, WorkerConfig, WorkerNames, WorkerPaths, WorkerPorts, WorkerServices};
use brane_cfg::policies::{ContainerPolicy, PolicyFile, UserPolicy};

pub use crate::errors::GenerateError as Error;
use crate::spec::{GenerateCredsSubcommand, GenerateNodeSubcommand, HostnamePair, LocationPair};
use crate::utils::resolve_config_path;


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
    let id: String = id.as_ref().replace('-', " ").replace('_', " ");

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

/// Function that writes the standard creds.yml header to the given writer.
/// 
/// # Arguments
/// - `writer`: The Writer to write to.
/// 
/// # Returns
/// Nothing, but does update the given writer with the standard header.
/// 
/// # Errors
/// This function errors if we failed to write.
fn write_creds_header(writer: &mut impl Write) -> Result<(), std::io::Error> {
    // Simply call write repeatedly
    writeln!(writer, "# CREDS.yml")?;
    writeln!(writer, "#   generated by branectl v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# This file defines how the delegate service may connect to the compute backend.")?;
    writeln!(writer, "# Edit this file to change how, where and with what credentials to connect.")?;
    writeln!(writer, "# This file is loaded lazily, so changing it typically does not require a")?;
    writeln!(writer, "# restart.")?;
    writeln!(writer, "# ")?;
    writeln!(writer, "# For an overview of what you can do in this file, refer to")?;
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/creds.md")?;
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
    writeln!(writer, "# https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/creds.md")?;
    writeln!(writer, "# ")?;
    writeln!(writer)?;
    writeln!(writer)?;

    // And we're done!
    Ok(())
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
        GenerateNodeSubcommand::Worker { location_id, creds, policies, certs, packages, data, results, temp_data, temp_results, prx_name, reg_name, job_name, chk_name, prx_port, reg_port, job_port, chk_port } => {
            // Resolve the service names
            let prx_name: String = prx_name.replace("$LOCATION", &location_id);
            let reg_name: String = reg_name.replace("$LOCATION", &location_id);
            let job_name: String = job_name.replace("$LOCATION", &location_id);
            let chk_name: String = chk_name.replace("$LOCATION", &location_id);

            // Resolve any path depending on the '$CONFIG'
            let creds    : PathBuf = resolve_config_path(creds, &config_path);
            let policies : PathBuf = resolve_config_path(policies, &config_path);
            let certs    : PathBuf = resolve_config_path(certs, &config_path);

            // Ensure the directory structure is there
            ensure_dir_of(&creds, fix_dirs)?;
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
                        creds        : canonicalize(resolve_config_path(creds, &config_path))?,
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
        Err(err)   => { return Err(Error::FileCreateError{ path, err }); },
    };

    // Write the top comment header thingy
    if let Err(err) = write_node_header(&mut handle) { return Err(Error::FileHeaderWriteError { path, err }); }
    // Write the file itself
    if let Err(err) = node_config.to_writer(handle) { return Err(Error::NodeWriteError { path, err }); }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
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
            registry : Address::hostname(format!("http://{}", loc.1), 50051),
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
        Err(err)   => { return Err(Error::FileCreateError { path, err }); },
    };

    // Write the header
    if let Err(err) = write_infra_header(&mut handle) { return Err(Error::FileHeaderWriteError { path, err }); }
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
/// - `command`: The command with the type of backend (and associated properties) encoded in it.
/// 
/// # Returns
/// Nothing, but does write a new file to the given path and updates the user on stdout on success.
/// 
/// # Errors
/// This function may error if I/O errors occur while writing the file.
pub fn creds(fix_dirs: bool, path: impl Into<PathBuf>, command: GenerateCredsSubcommand) -> Result<(), Error> {
    let path: PathBuf = path.into();
    info!("Generating creds.yml for a {} backend...", command.variant());

    // Create the CredsFile
    debug!("Generating backend information...");
    let creds: CredsFile = match command {
        GenerateCredsSubcommand::Local{ socket, client_version } => {
            // Generate the creds file we want
            CredsFile {
                method : Credentials::Local{ path: Some(socket), version: client_version.map(|v| (v.0.major_version, v.0.minor_version)) },
            }
        },
    };

    // Make sure its directory exists
    debug!("Writing to '{}'...", path.display());
    ensure_dir_of(&path, fix_dirs)?;

    // Open the file to write it to
    let mut handle: File = match File::create(&path) {
        Ok(handle) => handle,
        Err(err)   => { return Err(Error::FileCreateError { path, err }); },
    };

    // Write the header
    if let Err(err) = write_creds_header(&mut handle) { return Err(Error::FileHeaderWriteError { path, err }); }
    // Write the contents
    if let Err(err) = creds.to_writer(handle) { return Err(Error::CredsWriteError{ path, err }); }

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
        Err(err)   => { return Err(Error::FileCreateError { path, err }); },
    };

    // Write the header
    if let Err(err) = write_policy_header(&mut handle) { return Err(Error::FileHeaderWriteError { path, err }); }
    // Write the contents
    if let Err(err) = policies.to_writer(handle) { return Err(Error::PolicyWriteError{ path, err }); }

    // Done
    println!("Successfully generated {}", style(path.display().to_string()).bold().green());
    Ok(())
}
