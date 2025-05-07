//  UPGRADE.rs
//    by Lut99
//
//  Created:
//    03 Jul 2023, 13:01:31
//  Last edited:
//    29 Apr 2025, 13:51:21
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements functions for upgrading previous configuration file
//!   layouts to the newer ones.
//

use std::borrow::Cow;
use std::collections::HashMap;
use std::error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::{self, DirEntry};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use brane_cfg::node::{DoublePrivateService, WorkerUsecase};
use brane_shr::input::input;
use console::style;
use log::{debug, info, warn};
use serde::Serialize;
use specifications::address::Host;
use specifications::version::Version;

use crate::old_configs::v1_0_0;
use crate::spec::VersionFix;


/***** CONSTANTS *****/
/// The maximum length of files we consider.
const MAX_FILE_LEN: u64 = 1024 * 1024;





/***** TYPE ALIASES *****/
/// Alias for the closure that parses according to a particular version number.
///
/// Note that this closure returns another closure, which converts the parsed value into an up-to-date version of the file.
type VersionParser<'f1, 'f2, T> = Box<dyn 'f1 + Fn(&str) -> Option<VersionConverter<'f2, T>>>;

/// Alias for the closure that takes a parsed file and converts it to an up-to-date version of the file.
type VersionConverter<'f, T> = Box<dyn 'f + FnOnce(&Path, bool) -> Result<T, Error>>;





/***** ERRORS *****/
/// Describes errors that may occur when upgrading config files.
#[derive(Debug)]
pub enum Error {
    /// Failed to request some input not provided by older files.
    Input { what: &'static str, err: brane_shr::input::Error },
    /// The given path was not found.
    PathNotFound { path: PathBuf },

    /// Failed to read a directory.
    DirRead { path: PathBuf, err: std::io::Error },
    /// Failed to read an entry within a directory.
    DirEntryRead { path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to read a file.
    FileRead { path: PathBuf, err: std::io::Error },
    /// Failed to read the metadata of a file.
    FileMetadataRead { path: PathBuf, err: std::io::Error },

    /// Failed to convert between the infos
    Convert { what: &'static str, version: Version, err: Box<dyn error::Error> },
    /// Failed to serialize the new info.
    Serialize { what: &'static str, err: serde_yaml::Error },
    /// Failed to create a new file.
    FileWrite { path: PathBuf, err: std::io::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            Input { what, .. } => write!(f, "Failed to query the user (you!) for a {what}"),
            PathNotFound { path } => write!(f, "Path '{}' not found", path.display()),

            DirRead { path, .. } => write!(f, "Failed to read directory '{}'", path.display()),
            DirEntryRead { path, entry, .. } => write!(f, "Failed to read entry {} in directory '{}'", entry, path.display()),
            FileRead { path, .. } => write!(f, "Failed to read from file '{}'", path.display()),
            FileMetadataRead { path, .. } => write!(f, "Failed to read metadata of file '{}'", path.display()),

            Serialize { what, .. } => write!(f, "Failed to serialize upgraded {what} file"),
            FileWrite { path, .. } => write!(f, "Failed to write to file '{}'", path.display()),

            Convert { what, version, .. } => write!(f, "Failed to convert v{} {} to v{}", version, what, env!("CARGO_PKG_VERSION")),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            Input { err, .. } => Some(err),
            PathNotFound { .. } => None,

            DirRead { err, .. } => Some(err),
            DirEntryRead { err, .. } => Some(err),
            FileRead { err, .. } => Some(err),
            FileMetadataRead { err, .. } => Some(err),

            Serialize { err, .. } => Some(err),
            FileWrite { err, .. } => Some(err),

            Convert { err, .. } => Some(&**err),
        }
    }
}





/***** HELPER FUNCTIONS *****/
/// Does the heavy lifting in this module by implementing the iteration and trying to upgrade.
///
/// # Arguments
/// - `what`: Some debug-only string that is used to describe the kind of file we are upgrading (e.g., `node.yml`).
/// - `path`: The path fo the file or folder (to scour for files) to upgrade.
/// - `versions`: An ordered list of old BRANE version numbers to closures implementing a parser and a converter, respectively. The parsers are tried in-order.
/// - `dry_run`: Whether to only report which files to upgrade, instead of upgrading them.
/// - `overwrite`: Whether to overwrite the files instead of creating new ones.
///
/// # Errors
/// This function may error if we failed to read from disk.
fn upgrade<T: Serialize>(
    what: &'static str,
    path: impl Into<PathBuf>,
    versions: Vec<(Version, VersionParser<T>)>,
    dry_run: bool,
    overwrite: bool,
) -> Result<(), Error> {
    // Create a queue to parse
    let mut todo: Vec<PathBuf> = vec![path.into()];
    while let Some(path) = todo.pop() {
        debug!("Examining '{}'", path.display());

        // Switch on the type of path
        if path.is_file() {
            debug!("Path '{}' points to a file", path.display());

            // Check if the file is not _too_ large
            match fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.len() >= MAX_FILE_LEN {
                        debug!("Ignoring '{}', since the file is too large (>= {} bytes)", path.display(), MAX_FILE_LEN);
                        continue;
                    }
                },
                Err(err) => {
                    return Err(Error::FileMetadataRead { path, err });
                },
            };
            // Read the file
            let raw: Vec<u8> = match fs::read(&path) {
                Ok(raw) => raw,
                Err(err) => {
                    return Err(Error::FileRead { path, err });
                },
            };
            // Note that non-UTF-8 files are OK, we just ignore them
            let raw: String = match String::from_utf8(raw) {
                Ok(raw) => raw,
                Err(err) => {
                    debug!("Ignoring '{}', since the file contains invalid UTF-8 ({})", path.display(), err);
                    continue;
                },
            };

            // Attempt to parse it with any of the valid files
            for (version, parser) in &versions {
                debug!("Attempting to parse '{}' as v{} {} file...", path.display(), version, what);

                // Attempt to parse the string
                if let Some(converter) = parser(&raw) {
                    debug!("File '{}' is a v{} {} file", path.display(), version, what);

                    // Convert it to another file
                    let parent: Cow<Path> = path
                        .parent()
                        .map(Cow::Borrowed)
                        .unwrap_or_else(|| if path.is_absolute() { Cow::Owned("/".into()) } else { Cow::Owned("./".into()) });
                    if !dry_run && overwrite {
                        // We upgrade in-place
                        println!(
                            "Upgrading file {} from {} to {}...",
                            style(path.display()).green().bold(),
                            style(format!("v{version}")).bold(),
                            style(format!("v{}", env!("CARGO_PKG_VERSION"))).bold()
                        );

                        // Run the upgrade and serialize the resulting file
                        debug!("Converting file...");
                        let new_info: T = converter(parent.as_ref(), true)?;
                        let new_info: String = match serde_yaml::to_string(&new_info) {
                            Ok(info) => info,
                            Err(err) => {
                                return Err(Error::Serialize { what, err });
                            },
                        };

                        // Write the string to the file no sweat
                        debug!("Writing file to '{}'...", path.display());
                        if let Err(err) = fs::write(&path, new_info) {
                            return Err(Error::FileWrite { path, err });
                        }
                        debug!("File '{}' successfully upgraded", path.display());
                    } else if !dry_run && !overwrite {
                        // We upgrade to a new location
                        let new_path: PathBuf = path.with_extension(format!(".yml.{}", env!("CARGO_PKG_VERSION")));
                        println!(
                            "Upgrading file {} to {}, from {} to {}...",
                            style(path.display()).green().bold(),
                            style(new_path.display()).green().bold(),
                            style(format!("v{version}")).bold(),
                            style(format!("v{}", env!("CARGO_PKG_VERSION"))).bold()
                        );

                        // Run the upgrade and serialize the resulting file
                        debug!("Converting file...");
                        let new_info: T = converter(parent.as_ref(), false)?;
                        let new_info: String = match serde_yaml::to_string(&new_info) {
                            Ok(info) => info,
                            Err(err) => {
                                return Err(Error::Serialize { what, err });
                            },
                        };

                        // Write the string to the file no sweat
                        debug!("Writing file to '{}'...", new_path.display());
                        if let Err(err) = fs::write(&new_path, new_info) {
                            return Err(Error::FileWrite { path: new_path, err });
                        }
                        debug!("File '{}' successfully upgraded", path.display());
                    } else {
                        // We don't upgrade, just notify
                        println!(
                            "Found {} {} file that is candidate for upgrading: {}",
                            style(format!("v{version}")).bold(),
                            style(what).bold(),
                            style(path.display()).green().bold()
                        );
                    }
                }
            }
        } else if path.is_dir() {
            debug!("Path '{}' points to a directory", path.display());

            // Collect the entries of this directory and recurse into that
            debug!("Recursing into directory entries...");
            match fs::read_dir(&path) {
                Ok(entries) => {
                    for (i, entry) in entries.enumerate() {
                        // Unwrap the entry
                        let entry: DirEntry = match entry {
                            Ok(entry) => entry,
                            Err(err) => {
                                return Err(Error::DirEntryRead { path, entry: i, err });
                            },
                        };

                        // Add its path to the queue
                        if todo.len() == todo.capacity() {
                            todo.reserve(todo.len());
                        }
                        todo.push(entry.path());
                    }
                },
                Err(err) => {
                    return Err(Error::DirRead { path, err });
                },
            }

            // Continue with the next one
        } else if !path.exists() {
            return Err(Error::PathNotFound { path });
        } else {
            warn!("Given path '{}' is a non-file, non-directory path (skipping)", path.display());
            continue;
        }
    }

    // Done, we've converted all files
    Ok(())
}





/***** LIBRARY *****/
/// Converts old-style `node.yml` files to new-style ones.
///
/// # Arguments
/// - `path`: The path fo the file or folder (to scour for files) to upgrade.
/// - `dry_run`: Whether to only report which files to upgrade, instead of upgrading them.
/// - `overwrite`: Whether to overwrite the files instead of creating new ones.
/// - `version`: Whether to only consider files that are in a particular BRANE version.
///
/// # Errors
/// This function may error if we failed to read from disk.
pub fn node(path: impl Into<PathBuf>, dry_run: bool, overwrite: bool, version: VersionFix) -> Result<(), Error> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use brane_cfg::node::{
        CentralConfig, CentralPaths, CentralServices, NodeConfig, NodeSpecificConfig, PrivateOrExternalService, PrivateService, PublicService,
        WorkerConfig, WorkerPaths, WorkerServices,
    };
    use brane_cfg::proxy::{ForwardConfig, ProxyConfig, ProxyProtocol};
    use specifications::address::Address;
    use v1_0_0::node as v1_0_0;


    let path: PathBuf = path.into();
    info!("Upgrading node.yml files in '{}'...", path.display());

    // Query for missing information first
    let hostname: String = if version.0.is_none() || version.0.unwrap() <= Version::new(1, 0, 0) {
        match input(
            "hostname",
            "Enter the hostname for this node (used to supplement v1.0.0 and older configs)",
            None::<&str>,
            Some(|hostname_str: &String| (!hostname_str.is_empty()).then_some(()).ok_or_else(|| String::from("Hostname cannot be empty"))),
            None::<brane_shr::input::FileHistory>,
        ) {
            Ok(hostname) => hostname,
            Err(err) => {
                return Err(Error::Input { what: "hostname", err });
            },
        }
    } else {
        // It won't be used anyway
        String::new()
    };

    // Construct the list of versions
    let mut versions: Vec<(Version, VersionParser<NodeConfig>)> = vec![(
        Version::new(1, 0, 0),
        Box::new(|raw: &str| -> Option<VersionConverter<NodeConfig>> {
            // Attempt to read it with the file
            let cfg: v1_0_0::NodeConfig = match serde_yaml::from_str(raw) {
                Ok(cfg) => cfg,
                Err(_) => {
                    return None;
                },
            };

            // Return a function for converting it to a new-style function
            let hostname: &str = &hostname;
            Some(Box::new(move |dir: &Path, overwrite: bool| -> Result<NodeConfig, Error> {
                // We must generate a new proxy.yml file, since this was not part of the old spec - this is what the `overwrite` signifies, how to name it
                let proxy_path: PathBuf = if overwrite {
                    dir.join("config").join("proxy.yml")
                } else {
                    dir.join("config").join(format!("proxy.yml.{}", env!("CARGO_PKG_VERSION")))
                };
                let proxy_cfg: ProxyConfig = ProxyConfig {
                    outgoing_range: 4200..=4299,
                    incoming: HashMap::new(),
                    forward: cfg
                        .proxy
                        .map(|a| ForwardConfig { address: Address::from_str(&a.to_string()).unwrap(), protocol: ProxyProtocol::Socks6 }),
                };
                let proxy_cfg: String = match serde_yaml::to_string(&proxy_cfg) {
                    Ok(cfg) => cfg,
                    Err(err) => {
                        return Err(Error::Serialize { what: "proxy.yml", err });
                    },
                };
                if let Err(err) = fs::write(&proxy_path, proxy_cfg) {
                    return Err(Error::FileWrite { path: proxy_path, err });
                }

                // Convert the node, first
                let node: NodeSpecificConfig = match cfg.node {
                    v1_0_0::NodeKindConfig::Central(central) => {
                        // Extract some service info
                        NodeSpecificConfig::Central(CentralConfig {
                            paths: CentralPaths {
                                certs:    cfg.paths.certs,
                                packages: cfg.paths.packages,

                                infra: central.paths.infra,
                                proxy: Some(proxy_path),
                            },

                            services: CentralServices {
                                api: PublicService {
                                    name: central.names.api,
                                    address: Address::from_str(&central.services.api.to_string()).unwrap(),
                                    bind: central.ports.api,
                                    external_address: Address::hostname(format!("http://{hostname}"), central.services.api.port()),
                                },
                                drv: PublicService {
                                    address: Address::hostname(format!("grpc://{}", central.names.drv), central.ports.drv.port()),
                                    name: central.names.drv,
                                    bind: central.ports.drv,
                                    external_address: Address::hostname(format!("grpc://{hostname}"), central.ports.drv.port()),
                                },
                                #[allow(unreachable_code)]
                                plr: PrivateService { name: central.names.plr, address: unimplemented!(), bind: unimplemented!() },
                                prx: PrivateOrExternalService::Private(PrivateService {
                                    address: Address::hostname(format!("http://{}", cfg.names.prx), cfg.ports.prx.port()),
                                    name:    cfg.names.prx,
                                    bind:    cfg.ports.prx,
                                }),

                                aux_scylla: PrivateService {
                                    name:    "aux-scylla".into(),
                                    address: Address::from_str(&central.services.scylla.to_string()).unwrap(),
                                    bind:    SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), central.services.scylla.port()).into(),
                                },
                            },
                        })
                    },

                    v1_0_0::NodeKindConfig::Worker(worker) => NodeSpecificConfig::Worker(WorkerConfig {
                        name: worker.location_id,

                        usecases: HashMap::from([("central".into(), WorkerUsecase { api: Address::from_str(hostname).unwrap() })]),

                        paths: WorkerPaths {
                            certs:    cfg.paths.certs,
                            packages: cfg.paths.packages,

                            backend: worker.paths.backend,
                            policy_database: worker.paths.policies,
                            policy_delib_secret: "NOT YET IMPLEMENTED".into(),
                            policy_store_secret: "NOT YET IMPLEMENTED".into(),
                            policy_audit_log: None,
                            proxy: Some(proxy_path),

                            data: worker.paths.data,
                            results: worker.paths.results,
                            temp_data: worker.paths.temp_data,
                            temp_results: worker.paths.temp_results,
                        },

                        services: WorkerServices {
                            reg: PublicService {
                                name: worker.names.reg,
                                address: Address::from_str(&worker.services.reg.to_string()).unwrap(),
                                bind: worker.ports.reg,
                                external_address: Address::hostname(format!("https://{hostname}"), worker.services.reg.port()),
                            },
                            job: PublicService {
                                address: Address::hostname(format!("grpc://{}", worker.names.job), worker.ports.job.port()),
                                name: worker.names.job,
                                bind: worker.ports.job,
                                external_address: Address::hostname(format!("https://{hostname}"), worker.ports.job.port()),
                            },
                            chk: DoublePrivateService {
                                name:  worker.names.chk,
                                host:  match &worker.services.chk {
                                    v1_0_0::Address::Ipv4(addr, _) => Host::IPv4(*addr),
                                    v1_0_0::Address::Ipv6(addr, _) => Host::IPv6(*addr),
                                    v1_0_0::Address::Hostname(name, _) => Host::Name(name.clone()),
                                },
                                delib: worker.services.chk.port(),
                                store: worker.services.chk.port() + 1,
                            },
                            prx: PrivateOrExternalService::Private(PrivateService {
                                address: Address::hostname(format!("http://{}", cfg.names.prx), cfg.ports.prx.port()),
                                name:    cfg.names.prx,
                                bind:    cfg.ports.prx,
                            }),
                        },
                    }),
                };

                // Generate the Docker Compose namespace
                let namespace: String = match &node {
                    NodeSpecificConfig::Central(_) => "brane-central".into(),
                    NodeSpecificConfig::Worker(worker) => format!("brane-worker-{}", worker.name),
                    NodeSpecificConfig::Proxy(_) => "brane-proxy".into(),
                };

                // Write to the config
                Ok(NodeConfig { namespace, hostnames: cfg.hosts, node })
            }))
        }),
    )];
    // Limit the version to only the given one if applicable
    if let Some(version) = version.0 {
        versions.retain(|(v, _)| v == &version);
    }

    // Call the function that does the heavy lifting
    upgrade::<NodeConfig>("node.yml", path, versions, dry_run, overwrite)
}
