//  LIFETIME.rs
//    by Lut99
//
//  Created:
//    22 Nov 2022, 11:19:22
//  Last edited:
//    07 Mar 2024, 09:55:58
//  Auto updated?
//    Yes
//
//  Description:
//!   Commands that relate to managing the lifetime of the local node.
//

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str::FromStr as _;

use bollard::Docker;
use brane_cfg::info::Info as _;
use brane_cfg::node::{
    CentralConfig, CentralPaths, CentralServices, NodeConfig, NodeKind, NodeSpecificConfig, PrivateOrExternalService, ProxyConfig, ProxyPaths,
    ProxyServices, WorkerConfig, WorkerPaths, WorkerServices,
};
use brane_cfg::proxy;
use brane_tsk::docker::{DockerOptions, ImageSource, ensure_image, get_digest};
use console::style;
use log::{debug, info};
use rand::Rng;
use rand::distr::Alphanumeric;
use serde::{Deserialize, Serialize};
use specifications::container::Image;
use specifications::version::Version;
use strum::IntoEnumIterator;

pub use crate::errors::LifetimeError as Error;
use crate::spec::{LogsOpts, StartOpts, StartSubcommand};

#[derive(Copy, Clone)]
pub enum ServiceKind {
    Central(CentralKind),
    Worker(WorkerKind),
}

impl ServiceKind {
    #[inline]
    pub fn to_service_name(&self) -> &'static str {
        match self {
            Self::Central(central_kind) => central_kind.to_service_name(),
            Self::Worker(worker_kind) => worker_kind.to_service_name(),
        }
    }

    #[inline]
    pub fn to_env_var(&self) -> &'static str {
        match self {
            Self::Central(central_kind) => central_kind.to_env_var(),
            Self::Worker(worker_kind) => worker_kind.to_env_var(),
        }
    }
}

#[derive(strum_macros::EnumIter, Copy, Clone)]
pub enum CentralKind {
    Api,
    Drv,
    Plr,
    Prx,
}

impl CentralKind {
    #[inline]
    pub fn to_service_name(&self) -> &'static str {
        match self {
            Self::Api => "brane-api",
            Self::Drv => "brane-drv",
            Self::Plr => "brane-plr",
            Self::Prx => "brane-prx",
        }
    }

    #[inline]
    pub fn to_env_var(&self) -> &'static str {
        match self {
            Self::Api => "BRANE_API",
            Self::Drv => "BRANE_DRV",
            Self::Plr => "BRANE_PLR",
            Self::Prx => "BRANE_PRX",
        }
    }
}

#[derive(strum_macros::EnumIter, Copy, Clone)]
pub enum WorkerKind {
    Reg,
    Job,
    Chk,
    Prx,
}

impl WorkerKind {
    #[inline]
    pub fn to_service_name(&self) -> &'static str {
        match self {
            Self::Reg => "brane-reg",
            Self::Job => "brane-job",
            Self::Chk => "brane-chk",
            Self::Prx => "brane-prx",
        }
    }

    #[inline]
    pub fn to_env_var(&self) -> &'static str {
        match self {
            Self::Reg => "BRANE_REG",
            Self::Job => "BRANE_JOB",
            Self::Chk => "BRANE_CHK",
            Self::Prx => "BRANE_PRX",
        }
    }
}

/***** HELPER STRUCTS *****/
/// Defines a struct that writes to a valid compose file for overriding hostnames.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ComposeOverrideFile {
    /// The version number to use
    version:  &'static str,
    /// The services themselves
    services: HashMap<&'static str, ComposeOverrideFileService>,
}

/// Defines a struct that defines how a service looks like in a valid compose file for overriding hostnames.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ComposeOverrideFileService {
    /// Defines any additional mounts
    volumes: Vec<String>,
    /// Defines the extra hosts themselves.
    extra_hosts: Vec<String>,
    /// Whether to set any profiles.
    profiles: Vec<String>,
    /// Whether to open any additional ports.
    ports: Vec<String>,
    /// Wheter to set any environment variables
    environment: Vec<String>,
}

/***** HELPER FUNCTIONS *****/
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
    path.canonicalize().map_err(|source| Error::CanonicalizeError { path: path.into(), source })
}

/// Makes the given path join canonical, casting the error for convenience.
///
/// Essentially, if the second path is relative, then it will join them (in the order given) and make the result canonical. Otherwise, just the second path is made canonical.
///
/// # Arguments
/// - `lhs`: The first path to make canonical iff the second path is relative.
/// - `rhs`: The second path to make canonical and potentially join with the first (iff it is relative).
///
/// # Returns
/// The "join" of the paths, but canonical.
///
/// # Errors
/// This function errors if we failed to make the path canonical (i.e., something did not exist).
fn canonicalize_join(lhs: impl AsRef<Path>, rhs: impl AsRef<Path>) -> Result<PathBuf, Error> {
    let lhs: &Path = lhs.as_ref();
    let rhs: &Path = rhs.as_ref();

    // Join them, if necessary
    let path: Cow<Path> = if rhs.is_relative() { Cow::Owned(lhs.join(rhs)) } else { Cow::Borrowed(rhs) };

    // Canonicalize the result
    path.canonicalize().map_err(|source| Error::CanonicalizeError { path: path.into(), source })
}

/// Resolves the given path to replace '$NODE' with the actual node type.
///
/// # Arguments
/// - `path`: The path to resolve.
/// - `node`: Some node-dependent identifier already handled.
///
/// # Returns
/// A new PathBuf that is the same but now without $NODE.
#[inline]
fn resolve_node(path: impl AsRef<Path>, node: impl AsRef<str>) -> PathBuf {
    PathBuf::from(path.as_ref().to_string_lossy().replace("$NODE", node.as_ref()))
}

/// Resolves the given potentially given ImageSource to two possible default values, depending on whether we use DockerHub images or local ones.
///
/// # Arguments
/// - `source`: The ImageSource to resolve.
/// - `local_aux`: Determines whether to resolve a missing ImageSource to a Path source (true) or a Registry source (false).
/// - `svc`: The name of the specific service to resolve this one to if it's missing. Only used if `local_aux` is true.
/// - `img_dir`: The directory to resolve it with if `local_aux` is true.
/// - `image`: The ID of the image to pull from DockerHub we use to resolve the `source` if it's missing. Only used if `local_aux` is false.
///
/// # Returns
/// A new ImageSource that is the same if 'source' was `Some(...)`, or else resolved to a default value.\
fn resolve_aux_svc(
    source: Option<ImageSource>,
    local_aux: bool,
    svc: impl Display,
    img_dir: impl AsRef<Path>,
    image: impl Into<String>,
) -> ImageSource {
    match source {
        Some(source) => source,
        None => {
            if local_aux {
                resolve_image_dir(ImageSource::Path(PathBuf::from(format!("$IMG_DIR/aux-{}.tar", svc))), img_dir)
            } else {
                ImageSource::Registry(image.into())
            }
        },
    }
}

/// Resolves the given ImageSource to replace '$IMG_DIR' with the directory given.
///
/// # Arguments
/// - `source`: The ImageSource to resolve.
/// - `img_dir`: The directory to resolve it with.
///
/// # Returns
/// A new ImageSource that is the same but not with (potentially) $NODE removed.
#[inline]
fn resolve_image_dir(source: impl AsRef<ImageSource>, img_dir: impl AsRef<Path>) -> ImageSource {
    let source: &ImageSource = source.as_ref();
    let img_dir: &Path = img_dir.as_ref();

    // Switch on the source type to do the thing
    match source {
        ImageSource::Path(path) => ImageSource::Path(PathBuf::from(path.to_string_lossy().replace("$IMG_DIR", &img_dir.to_string_lossy()))),
        ImageSource::Registry(source) => ImageSource::Registry(source.replace("$IMG_DIR", &img_dir.to_string_lossy())),
    }
}

/// Resolves the given executable to a sensible executable and a list of arguments.
///
/// # Arguments
/// - `exe`: The executable string to split.
///
/// # Returns
/// A tuple with the executable and a list of additional arguments to call it properly.
///
/// # Errors
/// This function errors if we failed to lex the command.
#[inline]
fn resolve_exe(exe: impl AsRef<str>) -> Result<(String, Vec<String>), Error> {
    shlex::split(exe.as_ref()).map(|mut args| (args.remove(0), args)).ok_or_else(|| Error::ExeParseError { raw: exe.as_ref().into() })
}

/// Resolve the given Docker Compose file either by using the given one, or using the baked-in one.
///
/// # Arguments
/// - `file`: The path given by the user.
/// - `kind`: The kind of this node.
/// - `version`: The Brane version for which we are resolving.
///
/// # Returns
/// A new path which points to a Docker Compose file that exists for sure.
///
/// # Errors
/// This function errors if we failed to verify the given file exists, or failed to unpack the builtin file.
fn resolve_docker_compose_file(file: Option<PathBuf>, kind: NodeKind, mut version: Version) -> Result<PathBuf, Error> {
    // Switch on whether it exists or not
    match file {
        Some(file) => {
            // It does; only verify the file exists
            if !file.exists() {
                return Err(Error::DockerComposeNotFound { path: file });
            }
            if !file.is_file() {
                return Err(Error::DockerComposeNotAFile { path: file });
            }

            // OK
            debug!("Using given file '{}'", file.display());
            Ok(file)
        },

        None => {
            // It does not; unpack the builtins

            // Verify the version matches what we have
            if version.is_latest() {
                version = Version::from_str(env!("CARGO_PKG_VERSION")).unwrap();
            }
            if version != Version::from_str(env!("CARGO_PKG_VERSION")).unwrap() {
                return Err(Error::DockerComposeNotBakedIn { kind, version });
            }

            // Write the target location if it does not yet exist
            let compose_path: PathBuf = PathBuf::from("/tmp").join(format!("docker-compose-{kind}-{version}.yml"));
            if !compose_path.exists() {
                debug!("Unpacking baked-in {} Docker Compose file to '{}'...", kind, compose_path.display());

                // Attempt to open the target location
                let mut handle: File =
                    File::create(&compose_path).map_err(|source| Error::DockerComposeCreateError { path: compose_path.clone(), source })?;

                // Write the correct file to it
                match kind {
                    NodeKind::Central => {
                        write!(handle, "{}", include_str!("../../docker-compose-central.yml"))
                            .map_err(|source| Error::DockerComposeWriteError { path: compose_path.clone(), source })?;
                    },

                    NodeKind::Worker => {
                        write!(handle, "{}", include_str!("../../docker-compose-worker.yml"))
                            .map_err(|source| Error::DockerComposeWriteError { path: compose_path.clone(), source })?;
                    },

                    NodeKind::Proxy => {
                        write!(handle, "{}", include_str!("../../docker-compose-proxy.yml"))
                            .map_err(|source| Error::DockerComposeWriteError { path: compose_path.clone(), source })?;
                    },
                }
            }

            // OK
            debug!("Using baked-in file '{}'", compose_path.display());
            Ok(compose_path)
        },
    }
}

/// Generates some files and directories on the host to make all the canonicalizes happy.
///
/// # Arguments
/// - `node_config`: The [`NodeConfig`] that contains information about where to generate exactly that.
///
/// # Returns
/// This function errors if we failed to generate any of the required files/directories.
fn prepare_host(node_config: &NodeConfig) -> Result<(), Error> {
    // Match on who we're preparing for
    match &node_config.node {
        NodeSpecificConfig::Central(central) => {
            // Nothing to do for a central (yet)
            let CentralConfig {
                paths: CentralPaths { certs: _, packages: _, infra: _, proxy: _ },
                services: CentralServices { api: _, drv: _, plr: _, prx: _, aux_scylla: _ },
            } = central;
            Ok(())
        },

        NodeSpecificConfig::Worker(worker) => {
            // Extract the paths we're interested in
            let WorkerConfig {
                name: _,
                usecases: _,
                paths:
                    WorkerPaths {
                        certs: _,
                        packages: _,
                        backend: _,
                        policy_database: _,
                        policy_deliberation_secret: _,
                        policy_expert_secret: _,
                        policy_audit_log,
                        proxy: _,
                        data: _,
                        results: _,
                        temp_data: _,
                        temp_results: _,
                    },
                services: WorkerServices { reg: _, job: _, chk: _, prx: _ },
            } = worker;

            // Generate an empty log if it doesn't exist
            if let Some(policy_audit_log) = policy_audit_log {
                if !policy_audit_log.exists() {
                    debug!("Generating empty persistent audit log at '{}'...", policy_audit_log.display());
                    File::create(policy_audit_log).map_err(|source| Error::AuditLogCreate { path: policy_audit_log.clone(), source })?;
                }
            }

            // Done
            Ok(())
        },

        NodeSpecificConfig::Proxy(proxy) => {
            // Nothing to do for a proxy (yet)
            let ProxyConfig { paths: ProxyPaths { certs: _, proxy: _ }, services: ProxyServices { prx: _ } } = proxy;
            Ok(())
        },
    }
}

fn get_log_level(service: ServiceKind) -> Option<String> {
    let log_var = format!("{service_name}_LOG", service_name = service.to_env_var());

    match std::env::var(&log_var) {
        Ok(val) => return Some(val),
        // TODO: Could use the trace! macro from error-trace.
        Err(err) => tracing::trace!(
            "Malformed log level set using environment variable `{log_var}`. Falling back to using `BRANE_LOG`, if it is set. Cause: \n{err:#}"
        ),
    };

    match std::env::var("BRANE_LOG") {
        Ok(val) => return Some(val),
        // TODO: Could use the trace! macro from error-trace.
        Err(err) => {
            tracing::trace!("Malformed log level set using environment variable `BRANE_LOG`. Continuing with default logging. Cause: \n{err:#}")
        },
    };

    None
}

/// Generate an additional, temporary `docker-compose.yml` file that adds additional hostnames and/or additional volumes.
///
/// # Arguments
/// - `node_config`: The NodeConfig that contains information about whether to launch a proxy and, if so, how.
/// - `hosts`: The map of hostnames -> IP addresses to include.
/// - `profile_dir`: The profile directory to mount (or not).
///
/// # Returns
/// The path to the generated compose file if it was necessary. If not (i.e., no hosts given), returns `None`.
///
/// # Errors
/// This function errors if we failed to write the file.
fn generate_override_file(node_config: &NodeConfig, hosts: &HashMap<String, IpAddr>, profile_dir: Option<PathBuf>) -> Result<Option<PathBuf>, Error> {
    // Generate the ComposeOverrideFileService
    let svc: ComposeOverrideFileService = ComposeOverrideFileService {
        volumes: if let Some(dir) = profile_dir { vec![format!("{}:/logs/profile", dir.display())] } else { vec![] },
        extra_hosts: hosts.iter().map(|(hostname, ip)| format!("{hostname}:{ip}")).collect(),
        profiles: vec![],
        ports: vec![],
        environment: vec![],
    };

    // Match on the kind of node
    let overridefile: ComposeOverrideFile = match &node_config.node {
        NodeSpecificConfig::Central(node) => {
            let mut services = CentralKind::iter()
                .map(|service| {
                    let mut service_override = svc.clone();

                    println!("Log level?");
                    if let Some(log_level) = get_log_level(ServiceKind::Central(service)) {
                        service_override.environment.push(format!("RUST_LOG={}", log_level));
                        tracing::warn!("Setting loglevel for {} to {}", service.to_service_name(), log_level);
                    } else {
                        tracing::warn!("Leaving loglevel for {} at its default", service.to_service_name());
                    }
                    (service.to_service_name(), service_override)
                })
                .collect::<HashMap<_, _>>();
            {
                // Prepare a proxy service override
                let prx_svc = services.get_mut(CentralKind::Prx.to_service_name()).unwrap();
                if let Some(proxy_path) = &node.paths.proxy {
                    // Open the extra ports

                    // Read the proxy file to find the incoming ports
                    let proxy: proxy::ProxyConfig = proxy::ProxyConfig::from_path(proxy_path).map_err(|source| Error::ProxyReadError { source })?;

                    // Open both the management and the incoming ports now
                    prx_svc.ports.reserve(proxy.incoming.len());
                    for (port, _) in proxy.incoming {
                        prx_svc.ports.push(format!("0.0.0.0:{port}:{port}"));
                    }
                } else {
                    // Otherwise, add it won't start
                    prx_svc.profiles = vec!["donotstart".into()];
                }
            }

            // Generate the override file for this node
            ComposeOverrideFile { version: "3.6", services }
        },

        NodeSpecificConfig::Worker(node) => {
            let mut services = WorkerKind::iter()
                .map(|service| {
                    let mut service_override = svc.clone();

                    if let Some(log_level) = get_log_level(ServiceKind::Worker(service)) {
                        service_override.environment.push(format!("RUST_LOG={}", log_level));
                        println!("Setting loglevel to {log_level}");
                    }
                    (service.to_service_name(), service_override)
                })
                .collect::<HashMap<_, _>>();
            {
                // Prepare a proxy service override
                // Unwrap: This comes from an exhaustive iterator therefore there *MUST* be a
                // checker.
                let prx_svc = services.get_mut(WorkerKind::Prx.to_service_name()).unwrap();
                if let Some(proxy_path) = &node.paths.proxy {
                    // Open the extra ports

                    // Read the proxy file to find the incoming ports
                    let proxy: proxy::ProxyConfig = proxy::ProxyConfig::from_path(proxy_path).map_err(|source| Error::ProxyReadError { source })?;

                    // Open both the management and the incoming ports now
                    prx_svc.ports.reserve(proxy.incoming.len());
                    for (port, _) in proxy.incoming {
                        prx_svc.ports.push(format!("0.0.0.0:{port}:{port}"));
                    }
                } else {
                    // Otherwise, add it won't start
                    prx_svc.profiles = vec!["donotstart".into()];
                }
            }
            {
                // Also a checker override
                // Unwrap: This comes from an exhaustive iterator therefore there *MUST* be a
                // checker.
                let chk_svc = services.get_mut(WorkerKind::Chk.to_service_name()).unwrap();
                if let Some(policy_audit_log) = &node.paths.policy_audit_log {
                    chk_svc.volumes.push(format!("{}:/audit-log.log", policy_audit_log.display()));
                }
            }

            // Generate the override file for this node
            ComposeOverrideFile { version: "3.6", services }
        },

        NodeSpecificConfig::Proxy(node) => {
            // Prepare a proxy service override
            let mut prx_svc: ComposeOverrideFileService = svc;

            // Read the management port
            let manage_port: u16 = node.services.prx.bind.port();
            // Read the proxy file to find the incoming ports
            let proxy: proxy::ProxyConfig = proxy::ProxyConfig::from_path(&node.paths.proxy).map_err(|source| Error::ProxyReadError { source })?;
            // Find the start & stop ports of the outgoing range
            let start: u16 = *proxy.outgoing_range.start();
            let end: u16 = *proxy.outgoing_range.end();

            // Open both the management and the incoming ports now
            prx_svc.ports.reserve(1 + proxy.incoming.len() + 1);
            prx_svc.ports.push(format!("0.0.0.0:{}:{}", manage_port, manage_port));
            for (port, _) in proxy.incoming {
                prx_svc.ports.push(format!("0.0.0.0:{port}:{port}"));
            }
            prx_svc.ports.push(format!("0.0.0.0:{start}-{end}:{start}-{end}"));

            // Generate the override file for this node
            ComposeOverrideFile { version: "3.6", services: HashMap::from([("brane-prx", prx_svc)]) }
        },
    };

    // Attemp to open the file to write that to
    let compose_path: PathBuf = PathBuf::from("/tmp")
        .join(format!("docker-compose-override-{}.yml", rand::rng().sample_iter(&Alphanumeric).take(3).map(char::from).collect::<String>()));
    let handle: File = File::create(&compose_path).map_err(|source| Error::HostsFileCreateError { path: compose_path.clone(), source })?;

    // Now write the map in the correct format
    match serde_yaml::to_writer(handle, &overridefile) {
        Ok(_) => Ok(Some(compose_path)),
        Err(source) => Err(Error::HostsFileWriteError { path: compose_path, source }),
    }
}

/// Loads the given images.
///
/// # Arguments
/// - `docker`: The already connected Docker daemon.
/// - `images`: The map of image name -> image paths to load.
/// - `version`: The Brane version of the images to pull.
///
/// # Returns
/// Nothing, but does load them in the local docker daemon if everything goes alright.
///
/// # Errors
/// This function errors if the given images could not be loaded.
async fn load_images(docker: &Docker, images: HashMap<impl AsRef<str>, ImageSource>, version: &Version) -> Result<(), Error> {
    // Iterate over the images
    for (name, image_source) in images {
        let name: &str = name.as_ref();

        // Determine whether to pull as file or as a repo thing
        let image: Image = match &image_source {
            ImageSource::Path(path) => {
                println!("Loading image {} from file {}...", style(name).green().bold(), style(path.display().to_string()).bold());

                // Load the digest, too
                let digest: String = get_digest(path).await.map_err(|source| Error::ImageDigestError { path: path.into(), source })?;

                // Return it
                Image::new(name, Some(version), Some(digest))
            },

            ImageSource::Registry(source) => {
                println!("Loading image {} from repository {}...", style(name).green().bold(), style(source).bold());
                Image::new(name, Some(version), None::<&str>)
            },
        };

        // Simply rely on ensure_image
        ensure_image(docker, &image, &image_source).await.map_err(|source| Error::ImageLoadError {
            image: Box::new(image),
            image_source: Box::new(image_source),
            source,
        })?;
    }

    // Done
    Ok(())
}

/// Constructs the environment variables for Docker compose.
///
/// # Arguments
/// - `version`: The Brane version to launch.
/// - `node_config_path`: The path of the NodeConfig file to mount.
/// - `node_config`: The NodeConfig to set ports and attach volumes for.
///
/// # Returns
/// A HashMap of environment variables to use for running Docker compose.
///
/// # Errors
/// This function errors if we fail to canonicalize any of the paths in `node_config`.
fn construct_envs(version: &Version, node_config_path: &Path, node_config: &NodeConfig) -> Result<HashMap<&'static str, OsString>, Error> {
    // Set the global ones first
    let mut res: HashMap<&str, OsString> = HashMap::from([
        ("BRANE_VERSION", OsString::from(version.to_string())),
        ("NODE_CONFIG_PATH", canonicalize(node_config_path)?.as_os_str().into()),
    ]);

    // Match on the node kind
    let node_config_dir: &Path = node_config_path.parent().unwrap();
    match &node_config.node {
        NodeSpecificConfig::Central(node) => {
            // Now we do a little ugly something, but we unpack the paths and ports here so that we get compile errors if we add more later on
            let CentralPaths { certs, packages, infra, proxy } = &node.paths;
            let CentralServices { api, drv, plr, prx, aux_scylla: _ } = &node.services;

            // Add the environment variables, which are basically just central-specific paths and ports to mount in the compose file
            res.extend([
                // Names
                ("API_NAME", OsString::from(&api.name.as_str())),
                ("DRV_NAME", OsString::from(&drv.name.as_str())),
                ("PLR_NAME", OsString::from(&plr.name.as_str())),
                // Paths
                ("INFRA", canonicalize_join(node_config_dir, infra)?.as_os_str().into()),
                ("CERTS", canonicalize_join(node_config_dir, certs)?.as_os_str().into()),
                ("PACKAGES", canonicalize_join(node_config_dir, packages)?.as_os_str().into()),
                // Ports
                ("API_PORT", OsString::from(format!("{}", api.bind.port()))),
                ("DRV_PORT", OsString::from(format!("{}", drv.bind.port()))),
            ]);

            // Only add the proxy stuff if given
            if let PrivateOrExternalService::Private(name) = prx {
                res.extend([
                    ("PRX_NAME", OsString::from(&name.name.as_str())),
                    ("PROXY", canonicalize_join(node_config_dir, proxy.as_ref().ok_or(Error::MissingProxyPath)?)?.as_os_str().into()),
                ]);
            }
            if let Some(path) = proxy {
                res.extend([
                    ("PRX_NAME", OsString::from(&prx.try_private().ok_or(Error::MissingProxyService)?.name.as_str())),
                    ("PROXY", canonicalize_join(node_config_dir, path)?.as_os_str().into()),
                ]);
            }
        },

        NodeSpecificConfig::Worker(node) => {
            // Now we do a little ugly something, but we unpack the paths here so that we get compile errors if we add more later on
            let WorkerPaths {
                certs,
                packages,
                backend,
                policy_database,
                policy_deliberation_secret,
                policy_expert_secret,
                // Note: handled by `generate_override_file()`
                policy_audit_log: _,
                proxy,
                data,
                results,
                temp_data,
                temp_results,
            } = &node.paths;
            let WorkerServices { reg, job, chk, prx } = &node.services;

            // Add the environment variables, which are basically just central-specific paths to mount in the compose file
            res.extend([
                // Also add the location ID
                ("LOCATION_ID", OsString::from(&node.name)),
                // Names
                ("REG_NAME", OsString::from(&reg.name.as_str())),
                ("CHK_NAME", OsString::from(&chk.name.as_str())),
                ("JOB_NAME", OsString::from(&job.name.as_str())),
                ("CHK_NAME", OsString::from(&chk.name.as_str())),
                // Paths
                ("BACKEND", canonicalize_join(node_config_dir, backend)?.as_os_str().into()),
                ("POLICY_DB", canonicalize_join(node_config_dir, policy_database)?.as_os_str().into()),
                ("POLICY_DELIBERATION_SECRET", canonicalize_join(node_config_dir, policy_deliberation_secret)?.as_os_str().into()),
                ("POLICY_EXPERT_SECRET", canonicalize_join(node_config_dir, policy_expert_secret)?.as_os_str().into()),
                ("CERTS", canonicalize_join(node_config_dir, certs)?.as_os_str().into()),
                ("PACKAGES", canonicalize_join(node_config_dir, packages)?.as_os_str().into()),
                ("DATA", canonicalize_join(node_config_dir, data)?.as_os_str().into()),
                ("RESULTS", canonicalize_join(node_config_dir, results)?.as_os_str().into()),
                ("TEMP_DATA", canonicalize_join(node_config_dir, temp_data)?.as_os_str().into()),
                ("TEMP_RESULTS", canonicalize_join(node_config_dir, temp_results)?.as_os_str().into()),
                // Ports
                ("CHK_PORT", OsString::from(format!("{}", chk.bind.port()))),
                ("REG_PORT", OsString::from(format!("{}", reg.bind.port()))),
                ("JOB_PORT", OsString::from(format!("{}", job.bind.port()))),
            ]);

            // Only add the proxy stuff if given
            if let PrivateOrExternalService::Private(name) = prx {
                res.extend([
                    ("PRX_NAME", OsString::from(&name.name.as_str())),
                    ("PROXY", canonicalize_join(node_config_dir, proxy.as_ref().ok_or(Error::MissingProxyPath)?)?.as_os_str().into()),
                ]);
            }
            if let Some(path) = proxy {
                res.extend([
                    ("PRX_NAME", OsString::from(&prx.try_private().ok_or(Error::MissingProxyService)?.name.as_str())),
                    ("PROXY", canonicalize_join(node_config_dir, path)?.as_os_str().into()),
                ]);
            }
        },

        NodeSpecificConfig::Proxy(node) => {
            // Now we do a little ugly something, but we unpack the paths and ports here so that we get compile errors if we add more later on
            let ProxyPaths { proxy, certs } = &node.paths;
            let ProxyServices { prx } = &node.services;

            // Add the environment variables for the proxy
            res.extend([
                // Names
                ("PRX_NAME", OsString::from(&prx.name.as_str())),
                // Paths
                ("PROXY", canonicalize_join(node_config_dir, proxy)?.as_os_str().into()),
                ("CERTS", canonicalize_join(node_config_dir, certs)?.as_os_str().into()),
            ]);
        },
    }

    // Done
    debug!("Using environment: {:#?}", res);
    Ok(res)
}

// TODO: Maybe wrap the (extra) arguments as value in the command
enum DockerComposeCommand {
    Up,
    Logs,
}

impl DockerComposeCommand {
    fn to_args(&self) -> Vec<&'static str> {
        match self {
            DockerComposeCommand::Up => vec!["up", "-d"],
            DockerComposeCommand::Logs => vec!["logs", "-f"],
        }
    }
}

/// Runs Docker compose on the given Docker file.
///
/// # Arguments
/// - `compose_verbose`: If given, attempts to enable additional debug prints in the Docker Compose executable.
/// - `exe`: The `docker-compose` executable to run.
/// - `file`: The DockerFile to run.
/// - `project`: The project name to launch the containers for.
/// - `proxyfile`: If given, an additional `docker-compose` file that will add the proxy service.
/// - `overridefile`: If given, an additional `docker-compose` file that overrides the default one with extra hosts and other properties.
/// - `envs`: The map of environment variables to set.
///
/// # Returns
/// Nothing upon success, although obviously the Docker containers do get launched if so.
///
/// # Errors
/// This function fails if we failed to launch the command, or the command itself failed.
fn run_compose(
    compose_verbose: bool,
    exe: (String, Vec<String>),
    command: DockerComposeCommand,
    file: impl AsRef<Path>,
    project: impl AsRef<str>,
    overridefile: Option<PathBuf>,
    envs: HashMap<&'static str, OsString>,
) -> Result<(), Error> {
    let file: &Path = file.as_ref();
    let project: &str = project.as_ref();

    // Start creating the command
    let mut cmd: Command = Command::new(&exe.0);
    cmd.args(&exe.1);
    if compose_verbose {
        cmd.arg("--verbose");
    }
    cmd.args(["-p", project, "-f"]);
    cmd.arg(file.as_os_str());
    if let Some(overridefile) = overridefile {
        cmd.arg("-f");
        cmd.arg(overridefile);
    }
    cmd.args(command.to_args());
    cmd.envs(envs);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Run it
    println!(
        "Running '{}{}' {} on {}...",
        exe.0,
        if !exe.1.is_empty() { format!(" {}", exe.1.join(" ")) } else { String::new() },
        style("up").bold().green(),
        style(file.display()).bold()
    );
    debug!("Command: {:?}", cmd);
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(source) => {
            return Err(Error::JobLaunchError { command: cmd, source });
        },
    };

    if !output.status.success() {
        return Err(Error::JobFailure { command: cmd, status: output.status });
    }

    // Done
    Ok(())
}

/***** LIBRARY *****/
/// Starts the local node by running the given docker-compose file.
///
/// # Arguments
/// - `exe`: The `docker-compose` executable to run.
/// - `file`: The `docker-compose.yml` file to launch.
/// - `node_config_path`: The path to the node config file to potentially override.
/// - `docker_opts`: Configuration for connecting to the local Docker daemon. See `DockerOptions` for more information.
/// - `opts`: Miscellaneous configuration for starting the images. See `StartOpts` for more information.
/// - `command`: The `StartSubcommand` that carries additional information, including which of the node types to launch.
///
/// # Returns
/// Nothing, but does change the local Docker daemon to load and then run the given files.
///
/// # Errors
/// This function errors if we failed to run the `docker-compose` command or if we failed to assert that the given command matches the node kind of the `node.yml` file on disk.
pub async fn start(
    exe: impl AsRef<str>,
    file: Option<PathBuf>,
    node_config_path: impl Into<PathBuf>,
    docker_opts: DockerOptions,
    opts: StartOpts,
    command: StartSubcommand,
) -> Result<(), Error> {
    let exe: &str = exe.as_ref();
    let node_config_path: PathBuf = node_config_path.into();
    info!(
        "Starting node from Docker compose file '{}', defined in '{}'",
        file.as_ref().map(|f| f.display().to_string()).unwrap_or_else(|| "<baked-in>".into()),
        node_config_path.display()
    );

    // Start by loading the node config file
    debug!("Loading node config file '{}'...", node_config_path.display());
    let node_config: NodeConfig = NodeConfig::from_path(&node_config_path).map_err(|source| Error::NodeConfigLoadError { source })?;

    // Resolve the Docker Compose file
    debug!("Resolving Docker Compose file...");
    let file: PathBuf = resolve_docker_compose_file(file, node_config.node.kind(), opts.version)?;

    // Match on the command
    match command {
        StartSubcommand::Central { aux_scylla, brane_prx, brane_api, brane_drv, brane_plr } => {
            // Assert we are building the correct one
            if node_config.node.kind() != NodeKind::Central {
                return Err(Error::UnmatchedNodeKind { got: NodeKind::Central, expected: node_config.node.kind() });
            }

            // Connect to the Docker client
            let docker: Docker = brane_tsk::docker::connect_local(docker_opts).map_err(|source| Error::DockerConnectError { source })?;

            // Generate hosts file
            let overridefile: Option<PathBuf> = generate_override_file(&node_config, &node_config.hostnames, opts.profile_dir)?;

            // Map the images & load them
            if !opts.skip_import {
                let mut images: HashMap<&'static str, ImageSource> = HashMap::from([
                    ("aux-scylla", resolve_aux_svc(aux_scylla, opts.local_aux, "scylla", &opts.image_dir, "scylladb/scylla:4.6.3")),
                    // ("aux-xenon", resolve_image_dir(aux_xenon, &opts.image_dir)),
                    ("brane-api", resolve_image_dir(brane_api, &opts.image_dir)),
                    ("brane-drv", resolve_image_dir(brane_drv, &opts.image_dir)),
                    ("brane-plr", resolve_image_dir(brane_plr, &opts.image_dir)),
                ]);
                if node_config.node.central().services.prx.is_private() {
                    images.insert("brane-prx", resolve_image_dir(brane_prx, &opts.image_dir));
                }
                load_images(&docker, images, &opts.version).await?;
            }

            // Construct the environment variables
            let envs: HashMap<&str, OsString> = construct_envs(&opts.version, &node_config_path, &node_config)?;

            // Launch the docker-compose command
            run_compose(
                opts.compose_verbose,
                resolve_exe(exe)?,
                DockerComposeCommand::Up,
                resolve_node(file, "central"),
                &node_config.namespace,
                overridefile,
                envs,
            )?;
        },

        StartSubcommand::Worker { brane_prx, brane_chk, brane_reg, brane_job } => {
            // Assert we are building the correct one
            if node_config.node.kind() != NodeKind::Worker {
                return Err(Error::UnmatchedNodeKind { got: NodeKind::Worker, expected: node_config.node.kind() });
            }

            // Connect to the Docker client
            let docker: Docker = brane_tsk::docker::connect_local(docker_opts).map_err(|source| Error::DockerConnectError { source })?;

            // Generate some things that we might need before we actually hit run
            prepare_host(&node_config)?;

            // Generate hosts file
            let overridefile: Option<PathBuf> = generate_override_file(&node_config, &node_config.hostnames, opts.profile_dir)?;

            // Map the images & load them
            if !opts.skip_import {
                let mut images: HashMap<&'static str, ImageSource> = HashMap::from([
                    ("brane-chk", resolve_image_dir(brane_chk, &opts.image_dir)),
                    ("brane-reg", resolve_image_dir(brane_reg, &opts.image_dir)),
                    ("brane-job", resolve_image_dir(brane_job, &opts.image_dir)),
                ]);
                if node_config.node.worker().services.prx.is_private() {
                    images.insert("brane-prx", resolve_image_dir(brane_prx, &opts.image_dir));
                }
                load_images(&docker, images, &opts.version).await?;
            }

            // Construct the environment variables
            let envs: HashMap<&str, OsString> = construct_envs(&opts.version, &node_config_path, &node_config)?;

            // Launch the docker-compose command
            run_compose(
                opts.compose_verbose,
                resolve_exe(exe)?,
                DockerComposeCommand::Up,
                resolve_node(file, "worker"),
                &node_config.namespace,
                overridefile,
                envs,
            )?;
        },

        StartSubcommand::Proxy { brane_prx } => {
            // Assert we are building the correct one
            if node_config.node.kind() != NodeKind::Proxy {
                return Err(Error::UnmatchedNodeKind { got: NodeKind::Proxy, expected: node_config.node.kind() });
            }

            // Connect to the Docker client
            let docker: Docker = brane_tsk::docker::connect_local(docker_opts).map_err(|source| Error::DockerConnectError { source })?;

            // Generate hosts file
            let overridefile: Option<PathBuf> = generate_override_file(&node_config, &node_config.hostnames, opts.profile_dir)?;

            // Map the images & load them
            if !opts.skip_import {
                let images: HashMap<&'static str, ImageSource> = HashMap::from([("brane-prx", resolve_image_dir(brane_prx, &opts.image_dir))]);
                load_images(&docker, images, &opts.version).await?;
            }

            // Construct the environment variables
            let envs: HashMap<&str, OsString> = construct_envs(&opts.version, &node_config_path, &node_config)?;

            // Launch the docker-compose command
            run_compose(
                opts.compose_verbose,
                resolve_exe(exe)?,
                DockerComposeCommand::Up,
                resolve_node(file, "proxy"),
                &node_config.namespace,
                overridefile,
                envs,
            )?;
        },
    }

    // Done
    println!("\nSuccessfully launched node of type {}", style(node_config.node.kind()).bold().green());
    Ok(())
}

/// Stops the (currently running) local node.
///
/// This is a very simple command, no more than a wrapper around docker-compose.
///
/// # Arguments
/// - `compose_verbose`: If given, attempts to enable additional debug prints in the Docker Compose executable.
/// - `exe`: The `docker-compose` executable to run.
/// - `file`: The docker-compose file file to use to stop.
/// - `node_config_path`: The path to the node config file that we use to deduce the project name.
///
/// # Returns
/// Nothing, but does change the local Docker daemon to stop the services if they are running.
///
/// # Errors
/// This function errors if we failed to run docker-compose.
pub fn stop(compose_verbose: bool, exe: impl AsRef<str>, file: Option<PathBuf>, node_config_path: impl Into<PathBuf>) -> Result<(), Error> {
    let exe: &str = exe.as_ref();
    let node_config_path: PathBuf = node_config_path.into();
    info!(
        "Stopping node from Docker compose file '{}', defined in '{}'",
        file.as_ref().map(|f| f.display().to_string()).unwrap_or_else(|| "<baked-in>".into()),
        node_config_path.display()
    );

    // Start by loading the node config file
    debug!("Loading node config file '{}'...", node_config_path.display());
    let node_config: NodeConfig = NodeConfig::from_path(&node_config_path).map_err(|source| Error::NodeConfigLoadError { source })?;

    // Resolve the Docker Compose file
    debug!("Resolving Docker Compose file...");
    let file: PathBuf = resolve_docker_compose_file(file, node_config.node.kind(), Version::from_str(env!("CARGO_PKG_VERSION")).unwrap())?;

    // Construct the environment variables
    let envs: HashMap<&str, OsString> = construct_envs(&Version::latest(), &node_config_path, &node_config)?;

    // Resolve the filename and deduce the project name
    let file: PathBuf = resolve_node(file, match node_config.node.kind() {
        NodeKind::Central => "central",
        NodeKind::Worker => "worker",
        NodeKind::Proxy => "proxy",
    });

    // Now launch docker-compose
    let exe: (String, Vec<String>) = resolve_exe(exe)?;
    let mut cmd: Command = Command::new(&exe.0);
    cmd.args(&exe.1);
    if compose_verbose {
        cmd.arg("--verbose");
    }
    cmd.args(["-p", node_config.namespace.as_str(), "-f"]);
    cmd.arg(file.as_os_str());
    cmd.args(["down"]);
    cmd.envs(envs);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Run it
    println!(
        "Running '{}{}' {} on {}...",
        exe.0,
        if !exe.1.is_empty() { format!(" {}", exe.1.join(" ")) } else { String::new() },
        style("down").bold().green(),
        style(file.display()).bold()
    );
    debug!("Command: {:?}", cmd);
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(source) => {
            return Err(Error::JobLaunchError { command: cmd, source });
        },
    };
    if !output.status.success() {
        return Err(Error::JobFailure { command: cmd, status: output.status });
    }

    // Done
    Ok(())
}

pub async fn logs(exe: impl AsRef<str>, file: Option<PathBuf>, node_config_path: impl Into<PathBuf>, opts: LogsOpts) -> Result<(), Error> {
    let exe: &str = exe.as_ref();
    let node_config_path: PathBuf = node_config_path.into();
    info!(
        "Showing logs for node from Docker compose file '{}', defined in '{}'",
        file.as_ref().map(|f| f.display().to_string()).unwrap_or_else(|| "<baked-in>".into()),
        node_config_path.display()
    );

    // Start by loading the node config file
    debug!("Loading node config file '{}'...", node_config_path.display());
    let node_config: NodeConfig = NodeConfig::from_path(&node_config_path).map_err(|source| Error::NodeConfigLoadError { source })?;

    let version = Version::from_str(env!("CARGO_PKG_VERSION")).unwrap();

    // Resolve the Docker Compose file
    debug!("Resolving Docker Compose file...");
    let file: PathBuf = resolve_docker_compose_file(file, node_config.node.kind(), version)?;

    // Construct the environment variables
    let envs: HashMap<&str, OsString> = construct_envs(&version, &node_config_path, &node_config)?;

    // Launch the docker-compose command
    run_compose(
        opts.compose_verbose,
        resolve_exe(exe)?,
        DockerComposeCommand::Logs,
        resolve_node(file, "$NODE"),
        &node_config.namespace,
        None,
        envs,
    )?;

    Ok(())
}
