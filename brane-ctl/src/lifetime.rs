 //  LIFETIME.rs
//    by Lut99
// 
//  Created:
//    22 Nov 2022, 11:19:22
//  Last edited:
//    23 Feb 2023, 16:05:19
//  Auto updated?
//    Yes
// 
//  Description:
//!   Commands that relate to managing the lifetime of the local node.
// 

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use bollard::Docker;
use console::style;
use log::{debug, info};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};

use brane_cfg::node::{CentralPaths, CentralPorts, CommonPaths, NodeConfig, NodeKind, NodeKindConfig, WorkerPaths, WorkerPorts};
use brane_tsk::docker::{ensure_image, get_digest, ImageSource};
use specifications::container::Image;
use specifications::version::Version;

pub use crate::errors::LifetimeError as Error;
use crate::spec::{DockerClientVersion, StartSubcommand};


/***** HELPER STRUCTS *****/
/// Defines a struct that writes to a valid compose file for overriding hostnames.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ComposeOverrideFile {
    /// The version number to use
    version  : &'static str,
    /// The services themselves
    services : HashMap<&'static str, ComposeOverrideFileService>,
}



/// Defines a struct that defines how a service looks like in a valid compose file for overriding hostnames.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ComposeOverrideFileService {
    /// Defines any additional mounts
    volumes: Vec<String>,
    /// Defines the extra hosts themselves.
    extra_hosts: Vec<String>,
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
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(err) => Err(Error::CanonicalizeError{ path: path.into(), err }),
    }
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

/// Resolves the given ImageSource to replace '$MODE' with the actual mode given.
/// 
/// # Arguments
/// - `source`: The ImageSource to resolve.
/// - `mode`: The mode to use. Effectively just a directory nested in `target`.
/// 
/// # Returns
/// A new ImageSource that is the same but not with (potentially) $NODE removed.
#[inline]
fn resolve_mode(source: impl AsRef<ImageSource>, mode: impl AsRef<str>) -> ImageSource {
    let source : &ImageSource = source.as_ref();
    let mode   : &str         = mode.as_ref();

    // Switch on the source type to do the thing
    match source {
        ImageSource::Path(path)       => ImageSource::Path(PathBuf::from(path.to_string_lossy().replace("$MODE", mode))),
        ImageSource::Registry(source) => ImageSource::Registry(source.replace("$MODE", mode)),
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
    shlex::split(exe.as_ref()).map(|mut args| (args.remove(0), args)).ok_or_else(|| Error::ExeParseError{ raw: exe.as_ref().into() })
}

/// Generate an additional, temporary `docker-compose.yml` file that adds additional hostnames and/or additional volumes.
/// 
/// # Arguments
/// - `kind`: The kind of this node.
/// - `hosts`: The map of hostnames -> IP addresses to include.
/// - `profile_dir`: The profile directory to mount (or not).
/// 
/// # Returns
/// The path to the generated compose file if it was necessary. If not (i.e., no hosts given), returns `None`.
/// 
/// # Errors
/// This function errors if we failed to write the file.
fn generate_override_file(kind: NodeKind, hosts: &HashMap<String, IpAddr>, profile_dir: Option<PathBuf>) -> Result<Option<PathBuf>, Error> {
    // Early quit if there's nothing to do
    if hosts.is_empty() { return Ok(None); }

    // Generate the ComposeOverrideFileService
    let svc: ComposeOverrideFileService = ComposeOverrideFileService {
        volumes     : if let Some(dir) = profile_dir { vec![ format!("{}:/logs/profile", dir.display()) ] } else { vec![] },
        extra_hosts : hosts.iter().map(|(hostname, ip)| format!("{}:{}", hostname, ip)).collect(),
    };

    // Generate the ComposeOverrideFile
    let extra_hosts: ComposeOverrideFile = match kind {
        NodeKind::Central =>  ComposeOverrideFile {
            version  : "3.6",
            services : HashMap::from([
                ("brane-prx", svc.clone()),
                ("brane-api", svc.clone()),
                ("brane-drv", svc.clone()),
                ("brane-plr", svc),
            ]),
        },

        NodeKind::Worker =>  ComposeOverrideFile {
            version  : "3.6",
            services : HashMap::from([
                ("brane-prx", svc.clone()),
                ("brane-reg", svc.clone()),
                ("brane-job", svc),
            ]),
        },
    };

    // Attemp to open the file to write that to
    let compose_path: PathBuf = PathBuf::from("/tmp").join(format!("docker-compose-override-{}.yml", rand::thread_rng().sample_iter(&Alphanumeric).take(3).map(char::from).collect::<String>()));
    let handle: File = match File::create(&compose_path) {
        Ok(handle) => handle,
        Err(err)   => { return Err(Error::HostsFileCreateError{ path: compose_path, err }); },  
    };

    // Now write the map in the correct format
    match serde_yaml::to_writer(handle, &extra_hosts) {
        Ok(_)    => Ok(Some(compose_path)),
        Err(err) => Err(Error::HostsFileWriteError{ path: compose_path, err }),
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
    for (name, source) in images {
        let name: &str = name.as_ref();

        // Determine whether to pull as file or as a repo thing
        let image: Image = match &source {
            ImageSource::Path(path) => {
                println!("Loading image {} from file {}...", style(name).green().bold(), style(path.display().to_string()).bold());

                // Load the digest, too
                let digest: String = match get_digest(path).await {
                    Ok(digest) => digest,
                    Err(err)   => { return Err(Error::ImageDigestError{ path: path.into(), err }); },
                };

                // Return it
                Image::new(name, Some(version), Some(digest))
            },

            ImageSource::Registry(source) => {
                println!("Loading image {} from repository {}...", style(name).green().bold(), style(source).bold());
                Image::new(name, Some(version), None::<&str>)
            },
        };

        // Simply rely on ensure_image
        if let Err(err) = ensure_image(docker, &image, &source).await { return Err(Error::ImageLoadError{ image, source, err }); }
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
        NodeKindConfig::Central(central) => {
            // Now we do a little ugly something, but we unpack the paths and ports here so that we get compile errors if we add more later on
            let CommonPaths{ certs, packages } = &node_config.paths;
            let CentralPaths{ infra } = &central.paths;
            let CentralPorts{ api, drv }       = &central.ports;

            // Add the environment variables, which are basically just central-specific paths and ports to mount in the compose file
            res.extend([
                // Names
                ("PRX_NAME", OsString::from(&node_config.names.prx.as_str())),
                ("API_NAME", OsString::from(&node_config.node.central().names.api.as_str())),
                ("DRV_NAME", OsString::from(&node_config.node.central().names.drv.as_str())),
                ("PLR_NAME", OsString::from(&node_config.node.central().names.plr.as_str())),

                // Paths
                ("INFRA", canonicalize(node_config_dir.join(infra))?.as_os_str().into()),
                ("CERTS", canonicalize(node_config_dir.join(certs))?.as_os_str().into()),
                ("PACKAGES", canonicalize(node_config_dir.join(packages))?.as_os_str().into()),
    
                // Ports
                ("API_PORT", OsString::from(format!("{}", api.port()))),
                ("DRV_PORT", OsString::from(format!("{}", drv.port()))),
            ]);
        },

        NodeKindConfig::Worker(worker) => {
            // Now we do a little ugly something, but we unpack the paths here so that we get compile errors if we add more later on
            let CommonPaths{ certs, packages }                                           = &node_config.paths;
            let WorkerPaths{ backend, policies, data, results, temp_data, temp_results } = &worker.paths;
            let WorkerPorts{ reg, job }                                                  = &worker.ports;

            // Add the environment variables, which are basically just central-specific paths to mount in the compose file
            res.extend([
                // Also add the location ID
                ("LOCATION_ID", OsString::from(&worker.location_id)),

                // Names
                ("PRX_NAME", OsString::from(&node_config.names.prx.as_str())),
                ("REG_NAME", OsString::from(&node_config.node.worker().names.reg.as_str())),
                ("JOB_NAME", OsString::from(&node_config.node.worker().names.job.as_str())),
                ("CHK_NAME", OsString::from(&node_config.node.worker().names.chk.as_str())),

                // Paths
                ("BACKEND", canonicalize(node_config_dir.join(backend))?.as_os_str().into()),
                ("POLICIES", canonicalize(node_config_dir.join(policies))?.as_os_str().into()),
                ("CERTS", canonicalize(node_config_dir.join(certs))?.as_os_str().into()),
                ("PACKAGES", canonicalize(node_config_dir.join(packages))?.as_os_str().into()),
                ("DATA", canonicalize(node_config_dir.join(data))?.as_os_str().into()),
                ("RESULTS", canonicalize(node_config_dir.join(results))?.as_os_str().into()),
                ("TEMP_DATA", canonicalize(node_config_dir.join(temp_data))?.as_os_str().into()),
                ("TEMP_RESULTS", canonicalize(node_config_dir.join(temp_results))?.as_os_str().into()),

                // Ports
                ("REG_PORT", OsString::from(format!("{}", reg.port()))),
                ("JOB_PORT", OsString::from(format!("{}", job.port()))),
            ]);
        },
    }

    // Done
    debug!("Using environment: {:#?}", res);
    Ok(res)
}

/// Runs Docker compose on the given Docker file.
/// 
/// # Arguments
/// - `exe`: The `docker-compose` executable to run.
/// - `file`: The DockerFile to run.
/// - `project`: The project name to launch the containers for.
/// - `hostfile`: If given, an additional `docker-compose` file that overrides the default one with extra hosts.
/// - `envs`: The map of environment variables to set.
/// 
/// # Returns
/// Nothing upon success, although obviously the Docker containers do get launched if so.
/// 
/// # Errors
/// This function fails if we failed to launch the command, or the command itself failed.
fn run_compose(exe: (String, Vec<String>), file: impl AsRef<Path>, project: impl AsRef<str>, hostfile: Option<PathBuf>, envs: HashMap<&'static str, OsString>) -> Result<(), Error> {
    let file    : &Path = file.as_ref();
    let project : &str  = project.as_ref();

    // Start creating the command
    let mut cmd: Command = Command::new(exe.0);
    cmd.args(exe.1);
    cmd.args([ "-p", project, "-f" ]);
    cmd.arg(file.as_os_str());
    if let Some(hostfile) = hostfile {
        cmd.arg("-f");
        cmd.arg(hostfile);
    }
    cmd.args([ "up", "-d" ]);
    cmd.envs(envs);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Run it
    println!("Running docker-compose {} on {}...", style("up").bold().green(), style(file.display()).bold());
    debug!("Command: {:?}", cmd);
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(err)   => { return Err(Error::JobLaunchError { command: cmd, err }); },
    };
    if !output.status.success() { return Err(Error::JobFailure { command: cmd, status: output.status }); }

    // Done
    Ok(())
}





/***** LIBRARY *****/
/// Starts the local node by running the given docker-compose file.
/// 
/// # Arguments
/// - `exe`: The `docker-compose` executable to run.
/// - `file`: The `docker-compose.yml` file to launch.
/// - `docker_socket`: The Docker socket path to connect through.
/// - `docker_version`: The Docker client API version to use.
/// - `version`: The Brane version to start.
/// - `node_config_path`: The path to the node config file to potentially override.
/// - `mode`: The mode ('release' or 'debug', typically) to resolve certain image sources with.
/// - `skip_import`: If true, then this command will not import any images.
/// - `profile`: Whether the profile folder should be mounted and, if so, where.
/// - `command`: The `StartSubcommand` that carries additional information, including which of the node types to launch.
/// 
/// # Returns
/// Nothing, but does change the local Docker daemon to load and then run the given files.
/// 
/// # Errors
/// This function errors if we failed to run the `docker-compose` command or if we failed to assert that the given command matches the node kind of the `node.yml` file on disk.
pub async fn start(exe: impl AsRef<str>, file: impl Into<PathBuf>, docker_socket: PathBuf, docker_version: DockerClientVersion, version: Version, node_config_path: impl Into<PathBuf>, mode: String, skip_import: bool, profile_dir: Option<PathBuf>, command: StartSubcommand) -> Result<(), Error> {
    let exe              : &str    = exe.as_ref();
    let file             : PathBuf = file.into();
    let node_config_path : PathBuf = node_config_path.into();
    info!("Starting node from Docker compose file '{}', defined in '{}'", file.display(), node_config_path.display());

    // Start by loading the node config file
    debug!("Loading node config file '{}'...", node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&node_config_path) {
        Ok(config) => config,
        Err(err)   => { return Err(Error::NodeConfigLoadError{ err }); },
    };

    // Match on the command
    match command {
        StartSubcommand::Central{ aux_scylla, aux_kafka, aux_zookeeper, aux_xenon, brane_prx, brane_api, brane_drv, brane_plr } => {
            // Assert we are building the correct one
            if node_config.node.kind() != NodeKind::Central { return Err(Error::UnmatchedNodeKind{ got: NodeKind::Central, expected: node_config.node.kind() }); }

            // Connect to the Docker client
            let docker: Docker = match Docker::connect_with_unix(&docker_socket.to_string_lossy(), 120, &docker_version.0) {
                Ok(docker) => docker,
                Err(err)   => { return Err(Error::DockerConnectError{ socket: docker_socket, version: docker_version.0, err }); },
            };

            // Generate hosts file
            let hostfile: Option<PathBuf> = generate_override_file(node_config.node.kind(), &node_config.hosts, profile_dir)?;

            // Map the images & load them
            if !skip_import {
                let images: HashMap<&'static str, ImageSource> = HashMap::from([
                    ("aux-scylla", aux_scylla),
                    ("aux-kafka", aux_kafka),
                    ("aux-zookeeper", aux_zookeeper),
                    ("aux-xenon", aux_xenon),

                    ("brane-prx", resolve_mode(brane_prx, &mode)),
                    ("brane-api", resolve_mode(brane_api, &mode)),
                    ("brane-drv", resolve_mode(brane_drv, &mode)),
                    ("brane-plr", resolve_mode(brane_plr, &mode)),
                ]);
                load_images(&docker, images, &version).await?;
            }

            // Construct the environment variables
            let envs: HashMap<&str, OsString> = construct_envs(&version, &node_config_path, &node_config)?;

            // Launch the docker-compose command
            run_compose(resolve_exe(exe)?, resolve_node(file, "central"), "brane-central", hostfile, envs)?;
        },

        StartSubcommand::Worker{ brane_prx, brane_reg, brane_job } => {
            // Assert we are building the correct one
            if node_config.node.kind() != NodeKind::Worker  { return Err(Error::UnmatchedNodeKind{ got: NodeKind::Worker, expected: node_config.node.kind() }); }

            // Connect to the Docker client
            let docker: Docker = match Docker::connect_with_unix(&docker_socket.to_string_lossy(), 120, &docker_version.0) {
                Ok(docker) => docker,
                Err(err)   => { return Err(Error::DockerConnectError{ socket: docker_socket, version: docker_version.0, err }); },
            };

            // Generate hosts file
            let hostfile: Option<PathBuf> = generate_override_file(node_config.node.kind(), &node_config.hosts, profile_dir)?;

            // Map the images & load them
            if !skip_import {
                let images: HashMap<&'static str, ImageSource> = HashMap::from([
                    ("brane-prx", resolve_mode(brane_prx, &mode)),
                    ("brane-reg", resolve_mode(brane_reg, &mode)),
                    ("brane-job", resolve_mode(brane_job, &mode)),
                ]);
                load_images(&docker, images, &version).await?;
            }

            // Construct the environment variables
            let envs: HashMap<&str, OsString> = construct_envs(&version, &node_config_path, &node_config)?;

            // Launch the docker-compose command
            run_compose(resolve_exe(exe)?, resolve_node(file, "worker"), format!("brane-worker-{}", node_config.node.worker().location_id), hostfile, envs)?;
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
/// - `exe`: The `docker-compose` executable to run.
/// - `file`: The docker-compose file file to use to stop.
/// - `node_config_path`: The path to the node config file that we use to deduce the project name.
/// 
/// # Returns
/// Nothing, but does change the local Docker daemon to stop the services if they are running.
/// 
/// # Errors
/// This function errors if we failed to run docker-compose.
pub fn stop(exe: impl AsRef<str>, file: impl Into<PathBuf>, node_config_path: impl Into<PathBuf>) -> Result<(), Error> {
    let exe              : &str    = exe.as_ref();
    let file             : PathBuf = file.into();
    let node_config_path : PathBuf = node_config_path.into();
    info!("Stopping node from Docker compose file '{}', defined in '{}'", file.display(), node_config_path.display());

    // Start by loading the node config file
    debug!("Loading node config file '{}'...", node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&node_config_path) {
        Ok(config) => config,
        Err(err)   => { return Err(Error::NodeConfigLoadError{ err }); },
    };

    // Construct the environment variables
    let envs: HashMap<&str, OsString> = construct_envs(&Version::latest(), &node_config_path, &node_config)?;

    // Resolve the filename and deduce the project name
    let file  : PathBuf = resolve_node(file, if node_config.node.kind() == NodeKind::Central { "central" } else { "worker" });
    let pname : String  = format!("brane-{}", match &node_config.node { NodeKindConfig::Central(_) => "central".into(), NodeKindConfig::Worker(node) => format!("worker-{}", node.location_id) });

    // Now launch docker-compose
    let exe: (String, Vec<String>) = resolve_exe(exe)?;
    let mut cmd: Command = Command::new(exe.0);
    cmd.args(exe.1);
    cmd.args([ "-p", pname.as_str(), "-f" ]);
    cmd.arg(file.as_os_str());
    cmd.args([ "down" ]);
    cmd.envs(envs);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Run it
    println!("Running docker-compose {} on {}...", style("down").bold().green(), style(file.display()).bold());
    debug!("Command: {:?}", cmd);
    let output: Output = match cmd.output() {
        Ok(output) => output,
        Err(err)   => { return Err(Error::JobLaunchError { command: cmd, err }); },
    };
    if !output.status.success() { return Err(Error::JobFailure { command: cmd, status: output.status }); }

    // Done
    Ok(())
}
