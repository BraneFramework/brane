//  CLI.rs
//    by Lut99
// 
//  Created:
//    15 May 2023, 11:15:47
//  Last edited:
//    17 May 2023, 12:03:39
//  Auto updated?
//    Yes
// 
//  Description:
//!   An auxillary binary that we can use to test some functionality of
//!   the worker without having to spin up a service and send it requests.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use console::style;
use humanlog::{DebugMode, HumanLogger};
use log::{debug, error, info};

use brane_shr::errors::ErrorTrace as _;
use specifications::address::Address;
use specifications::container::Image;
use specifications::package::PackageInfo;
use specifications::version::Version;

use brane_tsk::docker::ImageSource;
use brane_tsk::k8s::{read_config_async, resolve_image_source, BasicAuth, Client, Config, ExecuteInfo, Handle, Pod, RegistryAuth, Scope, Secret};


/***** ERRORS *****/
/// Errors that may occur when launching a job.
#[derive(Debug)]
pub enum K8sError {
    /// Failed to launch the package.
    LaunchPackage { name: String, version: Version, err: Box<dyn Error> },
    /// Failed to attach to a package.
    AttachPackage { name: String, version: Version, err: Box<dyn Error> },
    /// Failed to join a package.
    JoinPackage { name: String, version: Version, err: Box<dyn Error> },
}
impl Display for K8sError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use K8sError::*;
        match self {
            LaunchPackage { name, version, .. } => write!(f, "Failed to launch package {name}:{version}"),
            AttachPackage { name, version, .. } => write!(f, "Failed to attach to package {name}:{version}"),
            JoinPackage { name, version, .. }   => write!(f, "Failed to join package {name}:{version}"),
        }
    }
}
impl Error for K8sError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use K8sError::*;
        match self {
            LaunchPackage { err, .. } => Some(&**err),
            AttachPackage { err, .. } => Some(&**err),
            JoinPackage { err, .. }   => Some(&**err),
        }
    }
}





/***** HELPER FUNCTIONS *****/
/// Spawns a new task on the Kubernetes backend.
/// 
/// # Arguments
/// - `package`: The already loaded [`PackageInfo`] struct describing the package to run.
/// - `launch`: The [`K8sLaunchArguments`] describing any user-specified parameters to the launch.
/// 
/// # Returns
/// The handles to both the job and the created registry secret (if any).
/// 
/// # Errors
/// This function errors if we failed to spawn the task.
async fn k8s_launch(package: &PackageInfo, launch: K8sLaunchArguments) -> Result<(Handle<Pod>, Option<Handle<Secret>>), K8sError> {
    // Deduce the auth method from the input
    let auth: Option<RegistryAuth> = match (launch.username, launch.password) {
        (Some(username), Some(password)) => Some(RegistryAuth::Basic(BasicAuth{ username, password })),
        (None, None)                     => None,

        // Anything else should never occur
        _ => { unreachable!(); },
    };

    // Load the Kubernetes config file
    let config_path: PathBuf = shellexpand::tilde(&launch.config.to_string_lossy()).as_ref().into();
    debug!("Loading Kubernetes config file '{}'...", config_path.display());
    let config: Config = match read_config_async(&config_path).await {
        Ok(config) => config,
        Err(err)   =>{ return Err(K8sError::LaunchPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); },
    };

    // Attempt to resolve the image file
    debug!("Resolving image source '{}'...", launch.image.display());
    let image: Image = Image::new(&package.name, Some(&package.version), None::<String>);
    let source: ImageSource = match resolve_image_source(&image, ImageSource::Path(launch.image.clone()), launch.registry.clone(), auth.clone(), launch.insecure).await {
        Ok(source) => source,
        Err(err)   => { return Err(K8sError::LaunchPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); },
    };

    // Now connect to the cluster
    debug!("Connecting to cluster...");
    let client: Client = match Client::new(config) {
        Ok(client) => client,
        Err(err)   => { return Err(K8sError::LaunchPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); },
    };

    // Create a secret for the registry
    let secret: Option<Handle<Secret>> = match auth {
        Some(auth) => {
            // Attempt to create the secret
            debug!("Creating Docker registry credential secret...");
            let scope: Scope<Secret> = client.scope("default");
            match scope.create_registry_secret(launch.registry, auth).await {
                Ok(handle) => Some(handle),
                Err(err)   => { return Err(K8sError::LaunchPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); },
            }
        },

        None => None,
    };

    // Launch the job!
    debug!("Spawning job...");
    let scope: Scope<Pod> = client.scope("default");
    let handle: Handle<Pod> = match scope.spawn(ExecuteInfo {
        image,
        image_source : source,

        command : vec![],
    }, secret.as_ref()).await {
        Ok(handle) => handle,
        Err(err)   => { return Err(K8sError::LaunchPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); },
    };

    // Done, return the handles
    Ok((handle, secret))
}

/// Attaches to a given, running pod of the Kubernetes backend by re-creating the handles to it.
/// 
/// # Arguments
/// - `package`: The already loaded [`PackageInfo`] struct describing the package of which we are reaping the results.
/// - `join`: The [`K8sJoinArguments`] that describe the pod to join.
/// 
/// # Returns
/// The handles to both the job and the created registry secret (if any).
/// 
/// # Errors
/// This function errors if we failed to attach to the task.
async fn k8s_attach(package: &PackageInfo, join: &K8sJoinArguments) -> Result<(Handle<Pod>, Option<Handle<Secret>>), K8sError> {
    // Load the Kubernetes config file
    let config_path: PathBuf = shellexpand::tilde(&join.config.to_string_lossy()).as_ref().into();
    debug!("Loading Kubernetes config file '{}'...", config_path.display());
    let config: Config = match read_config_async(&config_path).await {
        Ok(config) => config,
        Err(err)   =>{ return Err(K8sError::AttachPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); },
    };

    // Now connect to the cluster
    debug!("Connecting to cluster...");
    let client: Client = match Client::new(config) {
        Ok(client) => client,
        Err(err)   => { return Err(K8sError::AttachPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); },
    };

    // Attach the pod
    debug!("Attaching resources...");
    let pod: Handle<Pod> = client.scope("default").attach(&join.id);
    // If given, also attach the secret
    let secret: Option<Handle<Secret>> = join.secret.as_ref().map(|id| client.scope("default").attach(id));

    // Done, return the handles
    Ok((pod, secret))
}

/// Joins the given pair of a job and a(n optional) secret.
/// 
/// # Arguments
/// - `package`: The already loaded [`PackageInfo`] struct describing the package of which we are reaping the results.
/// - `job`: The [`Handle<Pod>`] to the job pod itself.
/// - `secret`: The optional [`Handle<Secret>`] to the registry secret. Will be deleted as soon as we saw the POD is ready.
/// 
/// # Returns
/// The exit code, stdout and stderr of the POD when it completes, as a tuple.
/// 
/// # Errors
/// This function errors if we failed to wait for any of the tasks.
async fn k8s_join(package: &PackageInfo, job: Handle<Pod>, secret: Option<Handle<Secret>>) -> Result<(i32, String, String), K8sError> {
    // Begin by waiting until the POD is ready
    if let Err(err) = job.wait_ready().await { return Err(K8sError::JoinPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); }

    // We can dump the secret now
    if let Some(secret) = secret { if let Err(err) = secret.terminate().await { return Err(K8sError::JoinPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }); } }

    // Read the PODs logs, done
    match job.join().await {
        Ok(res)  => Ok(res),
        Err(err) => Err(K8sError::JoinPackage { name: package.name.clone(), version: package.version, err: Box::new(err) }),
    }
}





/***** ARGUMENTS *****/
/// Defines the arguments for this helper binary.
#[derive(Debug, Parser)]
struct Arguments {
    /// Whether to enable trace debugging
    #[clap(long, global=true, help="If given, enables full logging verbosity (implies '--debug')")]
    trace : bool,
    /// Whether to enable debug debugging
    #[clap(long, global=true, help="If given, enables more verbose logging capability")]
    debug : bool,

    /// The subcommand to run
    #[clap(subcommand)]
    subcommand : CliSubcommand,
}

/// Defines the toplevel subcommands.
#[derive(Debug, Subcommand)]
enum CliSubcommand {
    /// Defines everything Kubernetes-related.
    #[clap(name = "k8s", alias = "kubernetes", about = "Groups all subcommands relating to testing Kubernetes.")]
    K8s(K8sArguments),
}

/// Defines the arguments relating to the K8s-subcommand.
#[derive(Debug, Parser)]
struct K8sArguments {
    /// The subcommand to run next.
    #[clap(subcommand)]
    subcommand : K8sSubcommand,
}
/// Defines the subcommands relating to Kubernetes.
#[derive(Debug, Subcommand)]
enum K8sSubcommand {
    /// Pushes an image to a local registry.
    #[clap(name = "push", about = "Pushes a local package (.tar file) to the given remote registry.")]
    Push(K8sPushArguments),

    /// Launches a job with the given parameters.
    #[clap(name = "launch", about = "Launches a given job on the given Kubernetes backend.")]
    Launch(K8sLaunchArguments),
    /// Attaches to a launched job with the given parameters.
    #[clap(name = "join", about = "Joins a launched POD and reaps its results.")]
    Join(K8sJoinArguments),
}

/// Defines the arguments to push a package to a local registry.
#[derive(Debug, Parser)]
struct K8sPushArguments {
    /// Defines the image path to push.
    #[clap(name="PATH", help="The image .tar file to push to the registry.")]
    path     : PathBuf,
    /// Defines the registry address to push to.
    #[clap(name="REGISTRY", help="The address of the registry to push to.")]
    registry : Address,
    /// The tag of the image to push.
    #[clap(name="TAG", help="The tag of the image (given as '<name>:<version>') to push.")]
    tag      : Image,

    /// If given, ignores any certificates and junk when pushing containers.
    #[clap(short, long, help="If given, makes the backend image pusher ignore certificates.")]
    insecure : bool,
    /// The user's username, if using basic auth.
    #[clap(short, long, requires="password", help="If given, use a username/password pair to login to the registry. Note that this one must always appear with '--password'")]
    username : Option<String>,
    /// The user's password, if using basic auth.
    #[clap(short, long, requires="username", help="If given, use a username/password pair to login to the registry. Note that this one must always appear with '--username'")]
    password : Option<String>,
}

/// Defines the arguments to push a package to a local registry.
#[derive(Debug, Parser)]
struct K8sLaunchArguments {
    /// Defines the path to the image to launch.
    #[clap(name="IMAGE_PATH", help="The image .tar file to push to the registry.")]
    image    : PathBuf,
    /// Defines the path to the package.yml to launch.
    #[clap(name="PACKAGE_YML_PATH", help="The package.yml file that describes the container.")]
    package  : PathBuf,
    /// Defines the registry address to push to.
    #[clap(name="REGISTRY", help="The address of the registry to push to.")]
    registry : Address,

    /// Defines the path to the Kubernetes config to use to connect.
    #[clap(short, long, default_value="~/.kube/config", help="The Kubernetes config YAML file that provides which cluster to connect to and how.")]
    config   : PathBuf,
    /// If given, ignores any certificates and junk when pushing containers.
    #[clap(short, long, help="If given, makes the backend image pusher ignore certificates.")]
    insecure : bool,
    /// The user's username, if using basic auth.
    #[clap(short, long, requires="password", help="If given, use a username/password pair to login to the registry. Note that this one must always appear with '--password'")]
    username : Option<String>,
    /// The user's password, if using basic auth.
    #[clap(short, long, requires="username", help="If given, use a username/password pair to login to the registry. Note that this one must always appear with '--username'")]
    password : Option<String>,
}
/// Defines the arguments to push a package to a local registry.
#[derive(Debug, Parser)]
struct K8sJoinArguments {
    /// Defines the path to the package.yml to attach to.
    #[clap(name="PACKAGE_YML_PATH", help="The package.yml file that describes the container.")]
    package : PathBuf,
    /// Defines the ID of the POD to attach to.
    #[clap(name="ID", help="The name/ID of the pod to attach to.")]
    id      : String,

    /// Defines the path to the Kubernetes config to use to connect.
    #[clap(short, long, default_value="~/.kube/config", help="The Kubernetes config YAML file that provides which cluster to connect to and how.")]
    config : PathBuf,
    /// Defines a secret to join as well.
    #[clap(short, long, help="If given, will join a secret with this name, too.")]
    secret : Option<String>,
}





/***** ENTRYPOINT *****/
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Parse the CLI arguments
    let args: Arguments = Arguments::parse();

    // Setup the logger
    if let Err(err) = HumanLogger::terminal(DebugMode::from_flags(args.trace, args.debug)).init() {
        eprintln!("WARNING: Failed to setup logger: {err} (no logging enabled for this session)");
    }
    info!("Initializing {} cli v{}...", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // Match on the subcommand
    match args.subcommand {
        CliSubcommand::K8s(k8s) => match k8s.subcommand {
            K8sSubcommand::Push(push) => {
                info!("Pushing {} to {}...", push.path.display(), push.registry);

                // Deduce the auth method from the input
                let auth: Option<RegistryAuth> = match (push.username, push.password) {
                    (Some(username), Some(password)) => Some(RegistryAuth::Basic(BasicAuth{ username, password })),
                    (None, None)                     => None,

                    // Anything else should never occur
                    _ => { unreachable!(); },
                };

                // Push the image
                let source: ImageSource = match resolve_image_source(&push.tag, ImageSource::Path(push.path.clone()), &push.registry, auth, push.insecure).await {
                    Ok(source) => source,
                    Err(err)   => { error!("{}", err.trace()); std::process::exit(1); },
                };

                // Done!
                println!("Successfully pushed image {} to {}", style(push.path.display()).bold().blue(), style(source.into_registry()).bold().blue());
            },

            K8sSubcommand::Launch(launch) => {
                info!("Launching image {} (package {}) to cluster through registry {}", launch.image.display(), launch.package.display(), launch.registry);

                // Load the package YAML
                debug!("Loading package.yml '{}'...", launch.package.display());
                let package: PackageInfo = match PackageInfo::from_path(launch.package.clone()) {
                    Ok(package) => package,
                    Err(err)    => { error!("{}", err.trace()); std::process::exit(1); },
                };

                // Launch the pod
                let (handle, secret): (Handle<Pod>, Option<Handle<Secret>>) = match k8s_launch(&package, launch).await {
                    Ok(res)  => res,
                    Err(err) => { error!("{}", err.trace()); std::process::exit(1); },
                };

                // Detach the job, since this command only launches it
                println!("Launched package {}{} (as pod '{}')", style(package.name).bold().blue(), if !package.version.is_latest() { format!(":{}", style(package.version).bold().blue()) } else { String::new() }, handle.detach());

                // If there is a secret, also detach that (and mention it)
                if let Some(secret) = secret {
                    println!("{}", style(format!("(Created registry secret '{}' to launch it as well)", secret.detach())).dim());
                }
            },
            K8sSubcommand::Join(join) => {
                info!("Joining pod '{}'{}", join.id, if let Some(secret) = &join.secret { format!(" (and secret '{}')", secret) } else { String::new() });

                // Load the package YAML
                debug!("Loading package.yml '{}'...", join.package.display());
                let package: PackageInfo = match PackageInfo::from_path(join.package.clone()) {
                    Ok(package) => package,
                    Err(err)    => { error!("{}", err.trace()); std::process::exit(1); },
                };

                // Get handles to the pod
                let (handle, secret): (Handle<Pod>, Option<Handle<Secret>>) = match k8s_attach(&package, &join).await {
                    Ok(res)  => res,
                    Err(err) => { error!("{}", err.trace()); std::process::exit(1); },
                };

                // Now join those
                println!("Joining package {}{}...", style(&package.name).bold().blue(), if !package.version.is_latest() { format!(":{}", style(package.version).bold().blue()) } else { String::new() });
                let (code, stdout, stderr): (i32, String, String) = match k8s_join(&package, handle, secret).await {
                    Ok(res)  => res,
                    Err(err) => { error!("{}", err.trace()); std::process::exit(1); },
                };

                // Done!
                println!("Package {}{} returned exit code {}", style(&package.name).bold().blue(), if !package.version.is_latest() { format!(":{}", style(package.version).bold().blue()) } else { String::new() }, style(code).bold().blue());
                println!();
                println!("{}", style("stdout").dim());
                println!("{}", style((0..80).map(|_| '-').collect::<String>()).dim());
                println!("{stdout}");
                println!("{}", style((0..80).map(|_| '-').collect::<String>()).dim());
                println!();
                println!("{}", style("stderr").dim());
                println!("{}", style((0..80).map(|_| '-').collect::<String>()).dim());
                println!("{stderr}");
                println!("{}", style((0..80).map(|_| '-').collect::<String>()).dim());
                println!();
            },
        },
    }

    // Done!
}
