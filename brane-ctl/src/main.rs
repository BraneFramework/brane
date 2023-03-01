//  MAIN.rs
//    by Lut99
// 
//  Created:
//    15 Nov 2022, 09:18:40
//  Last edited:
//    01 Mar 2023, 11:22:23
//  Auto updated?
//    Yes
// 
//  Description:
//!   Entrypoint to the `branectl` executable.
// 

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use humanlog::{DebugMode, HumanLogger};
use log::error;

use brane_cfg::node::ProxyProtocol;
use specifications::address::Address;
use specifications::package::Capability;
use specifications::version::Version;

use brane_ctl::spec::{API_DEFAULT_VERSION, Arch, DockerClientVersion, DownloadServicesSubcommand, GenerateBackendSubcommand, GenerateCertsSubcommand, GenerateNodeSubcommand, HostnamePair, LocationPair, StartDockerOpts, StartOpts, StartSubcommand};
use brane_ctl::{download, generate, lifetime, packages};


/***** ARGUMENTS *****/
/// Defines the toplevel arguments for the `branectl` tool.
#[derive(Debug, Parser)]
#[clap(name = "branectl", about = "The server-side Brane command-line interface.")]
struct Arguments {
    /// If given, prints `info` and `debug` prints.
    #[clap(long, global=true, help = "If given, prints additional information during execution.")]
    debug       : bool,
    /// If given, prints `info`, `debug` and `trace` prints.
    #[clap(long, global=true, conflicts_with = "debug", help = "If given, prints the largest amount of debug information as possible.")]
    trace       : bool,
    /// The path to the node config file to use.
    #[clap(short, long, global=true, default_value = "./node.yml", help = "The 'node.yml' file that describes properties about the node itself (i.e., the location identifier, where to find directories, which ports to use, ...)")]
    node_config : PathBuf,

    /// The subcommand that can be run.
    #[clap(subcommand)]
    subcommand : CtlSubcommand,
}

/// Defines subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
enum CtlSubcommand {
    #[clap(subcommand)]
    Download(Box<DownloadSubcommand>),
    #[clap(subcommand)]
    Generate(Box<GenerateSubcommand>),

    #[clap(subcommand)]
    Packages(Box<PackageSubcommand>),
    #[clap(subcommand)]
    Data(Box<DataSubcommand>),

    #[clap(name = "start", about = "Starts the local node by loading and then launching (already compiled) image files.")]
    Start{
        #[clap(short = 'S', long, default_value = "/var/run/docker.sock", help = "The path of the Docker socket to connect to.")]
        docker_socket  : PathBuf,
        #[clap(short = 'V', long, default_value = API_DEFAULT_VERSION.as_str(), help = "The version of the Docker client API that we use to connect to the engine.")]
        docker_version : DockerClientVersion,
        /// The docker-compose command we run.
        #[clap(short, global=true, long, default_value = "docker compose", help = "The command to use to run Docker Compose.")]
        exe            : String,
        /// The docker-compose file that we start.
        #[clap(short, global=true, long, help = concat!("The docker-compose.yml file that defines the services to start. You can use '$NODE' to match either 'central' or 'worker', depending how we started. If omitted, will use the baked-in counterpart (although that only works for the default version, v", env!("CARGO_PKG_VERSION") , ")."))]
        file           : Option<PathBuf>,

        /// The specific Brane version to start.
        #[clap(short, long, default_value = env!("CARGO_PKG_VERSION"), help = "The Brane version to import.")]
        version : Version,

        /// Sets the '$MODE' variable, which can easily switch the location of compiled binaries.
        #[clap(long, global=true, default_value = "release", conflicts_with = "skip_import", help = "Sets the mode ($MODE) to use in the image flags of the `start` command.")]
        mode        : String,
        /// Whether to skip importing images or not.
        #[clap(long, global=true, help = "If given, skips the import of the images. This is useful if you have already loaded the images in your Docker daemon manually.")]
        skip_import : bool,
        /// The profile directory to mount, if any.
        #[clap(short, long, help = "If given, mounts the '/logs/profile' directories in the instance container(s) to the same (given) directory on the host. Use this to effectively reach the profile files.")]
        profile_dir : Option<PathBuf>,

        /// Defines the possible nodes and associated flags to start.
        #[clap(subcommand)]
        kind : Box<StartSubcommand>,
    },
    #[clap(name = "stop", about = "Stops the local node if it is running.")]
    Stop {
        /// The docker-compose command we run.
        #[clap(short, long, default_value = "docker compose", help = "The command to use to run Docker Compose.")]
        exe  : String,
        /// The docker-compose file that we start.
        #[clap(short, long, help = concat!("The docker-compose.yml file that defines the services to stop. You can use '$NODE' to match either 'central' or 'worker', depending how we started. If omitted, will use the baked-in counterpart (although that only works for the default version, v", env!("CARGO_PKG_VERSION"), ")."))]
        file : Option<PathBuf>,
    },

    #[clap(name = "version", about = "Returns the version of this CTL tool and/or the local node.")]
    Version {
        #[clap(short, long, help = "If given, shows the architecture instead of the version when using '--ctl' or '--node'.")]
        arch : bool,
        #[clap(short, long, help = "Shows the kind of node (i.e., 'central' or 'worker') instead of the version. Only relevant when using '--node'.")]
        kind : bool,
        #[clap(short, long, help = "If given, shows the version of the CTL tool in an easy-to-be-parsed format. Note that, if given in combination with '--node', this one is always reported first.")]
        ctl  : bool,
        #[clap(short, long, help = "If given, shows the local node version in an easy-to-be-parsed format. Note that, if given in combination with '--ctl', this one is always reported second.")]
        node : bool,
    },
}

/// Defines download-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "download", about = "Groups commands that can automatically download stuff from the project's repository.")]
enum DownloadSubcommand {
    #[clap(name = "services", about = "Downloads all of the Brane service images from the GitHub repository to the local machine.")]
    Services {
        /// Whether to create any missing directories or not.
        #[clap(short, long, global=true, help="If given, will automatically create missing directories.")]
        fix_dirs : bool,
        /// The directory to download them to.
        #[clap(short, long, default_value="./target/release", global=true, help="The directory to download the images to. Note: if you leave it at the default, then you won't have to manually specify anything when running 'branectl start'.")]
        path     : PathBuf,

        /// The architecture for which to download the services.
        #[clap(short, long, default_value="$LOCAL", global=true, help="The processor architecture for which to download the images. Specify '$LOCAL' to use the architecture of the current machine.")]
        arch    : Arch,
        /// The version of the services to download.
        #[clap(short, long, default_value=env!("CARGO_PKG_VERSION"), global=true, help="The version of the images to download from GitHub. You can specify 'latest' to download the latest version (but that might be incompatible with this CTL version)")]
        version : Version,
        /// Whether to overwrite existing images or not.
        #[clap(short='F', long, global=true, help="If given, will overwrite services that are already there. Otherwise, these are not overwritten. Note that regardless, a download will still be performed.")]
        force   : bool,

        /// Whether to download the central or the worker VMs.
        #[clap(subcommand)]
        kind : DownloadServicesSubcommand,
    }
}

/// Defines generate-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "generate", about = "Groups commands about (config) generation.")]
enum GenerateSubcommand {
    #[clap(name = "node", about = "Generates a new 'node.yml' file at the location indicated by --node-config.")]
    Node {
        /// Defines one or more additional hostnames to define in the nested Docker container.
        #[clap(short = 'H', long, help = "One or more additional hostnames to set in the spawned Docker containers. Should be given as '<hostname>:<ip>' pairs.")]
        hosts : Vec<HostnamePair>,
        /// Defines any proxy node to proxy control messages through.
        #[clap(long, help = "If given, reroutes all control network traffic for this node through the given proxy.")]
        proxy          : Option<Address>,
        /// Defines the protocol of connecting to the proxy.
        #[clap(long, default_value = "socks5", help = "The manner of connection to the remote proxy. Only has effect if the remote proxy is given (i.e., you specified '--proxy' as well).")]
        proxy_protocol : ProxyProtocol,

        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short='f', long, help = " If given, will generate any missing directories.")]
        fix_dirs    : bool,
        /// Custom config path.
        #[clap(short='C', long, default_value = "./config", help = "A common ancestor for --infra-path, --secrets-path and --certs-path. See their descriptions for more info.")]
        config_path : PathBuf,

        /// Defines the possible nodes to generate a new node.yml file for.
        #[clap(subcommand)]
        kind : Box<GenerateNodeSubcommand>,
    },

    #[clap(name = "certs", about = "Generates root & server certificates for the given domain.")]
    Certs {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short='f', long, global=true, help = "If given, will generate any missing directories.")]
        fix_dirs : bool,
        /// The directory to write to.
        #[clap(short, long, default_value = "./", global=true, help = "The path of the directory to write the generated certificate files.")]
        path     : PathBuf,
        /// The directory to write temporary scripts to.
        #[clap(short, long, default_value = "/tmp", global=true, help = "The path of the directory to write the temporary scripts to we use for certificate generation.")]
        temp_dir : PathBuf,

        /// The type of certificate to generate.
        #[clap(subcommand)]
        kind : Box<GenerateCertsSubcommand>,
    },

    #[clap(name = "infra", about = "Generates a new 'infra.yml' file.")]
    Infra {
        /// Defines the list of domains
        #[clap(name = "LOCATIONS", help = "The list of locations (i.e., worker nodes) connected to this instance. The list is given as a list of '<ID>:<ADDR>' pairs.")]
        locations : Vec<LocationPair<':', String>>,

        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short='f', long, help = "If given, will generate any missing directories.")]
        fix_dirs : bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./infra.yml", help = "The path to write the infrastructure file to.")]
        path     : PathBuf,

        /// Determines the name of the given domain.
        #[clap(short='N', long="name", help = "Sets the name (i.e., human-friendly name, not the identifier) of the given location. Should be given as a '<LOCATION>=<NAME>` pair. If omitted, will default to the domain's identifier with some preprocessing to make it look nicer.")]
        names     : Vec<LocationPair<'=', String>>,
        /// Determines the port of the registry node on the given domain.
        #[clap(short, long="reg-port", help = "Determines the port of the delegate service on the given location. Should be given as a '<LOCATION>=<PORT>' pair. If omitted, will default to '50051' for each location.")]
        reg_ports : Vec<LocationPair<'=', u16>>,
        /// Determines the port of the delegate node on the given domain.
        #[clap(short, long="job-port", help = "Determines the port of the delegate service on the given location. Should be given as a '<LOCATION>=<PORT>' pair. If omitted, will default to '50052' for each location.")]
        job_ports : Vec<LocationPair<'=', u16>>,
    },

    #[clap(name = "backend", about = "Generates a new `backend.yml` file.")]
    Backend {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short='f', long, help = "If given, will generate any missing directories.")]
        fix_dirs : bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./backend.yml", help = "The path to write the credentials file to.")]
        path     : PathBuf,

        /// The list of capabilities to advertise for this domain.
        #[clap(short, long, help = "The list of capabilities to advertise for this domain. Use '--list-capabilities' to see them.")]
        capabilities    : Vec<Capability>,
        /// Whether to hash containers or not (but inverted).
        #[clap(short, long, help = "If given, disables the container security hash, forgoing the need for hashing (saves time on the first execution of a container on a domain)")]
        disable_hashing : bool,

        /// Defines the possible backends to generate a new backend.yml file for.
        #[clap(subcommand)]
        kind : Box<GenerateBackendSubcommand>,
    },

    #[clap(name = "policy", about = "Generates a new `policies.yml` file.")]
    Policy {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short='f', long, help = "If given, will generate any missing directories.")]
        fix_dirs : bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./policies.yml", help = "The path to write the policy file to.")]
        path     : PathBuf,

        /// Sets the default file to allow everything instead of nothing.
        #[clap(short, long, help = "Generates the file with AllowAll-rules instead of DenyAll-rules. Don't forget to edit the file if you do!")]
        allow_all : bool,
    },
}

/// Defines package-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "packages", about = "Groups commands about package management.")]
enum PackageSubcommand {
    /// Generates the hash for the given package container.
    #[clap(name = "hash", about = "Hashes the given `image.tar` file for use in policies.")]
    Hash {
        /// The path to the image file.
        #[clap(name = "IMAGE", help = "The image to compute the hash of. If it's a path that exists, will attempt to hash that file; otherwise, will hash based on an image in the local node's `packages` directory. You can use `name[:version]` syntax to specify the version.")]
        image : String,
    },
}

/// Defines data- and intermediate results-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "data", about = "Groups commands about data and intermediate result management.")]
enum DataSubcommand {

}





/***** ENTYRPOINT *****/
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Load the .env file
    dotenv().ok();

    // Parse the arguments
    let args: Arguments = Arguments::parse();

    // // Initialize the logger
    // let mut logger = env_logger::builder();
    // logger.format_module_path(false);
    // if args.debug {
    //     logger.filter_module("brane", LevelFilter::Debug).init();
    // } else {
    //     logger.filter_module("brane", LevelFilter::Warn).init();

    //     human_panic::setup_panic!(Metadata {
    //         name: "Brane CTL".into(),
    //         version: env!("CARGO_PKG_VERSION").into(),
    //         authors: env!("CARGO_PKG_AUTHORS").replace(":", ", ").into(),
    //         homepage: env!("CARGO_PKG_HOMEPAGE").into(),
    //     });
    // }

    // Initialize the logger
    if let Err(err) = HumanLogger::terminal(if args.trace { DebugMode::Full } else if args.debug { DebugMode::Debug } else { DebugMode::Friendly }).init() {
        eprintln!("WARNING: Failed to setup logger: {} (no logging for this session)", err);
    }

    // Setup the friendlier version of panic
    if !args.trace && !args.debug {
        human_panic::setup_panic!(Metadata {
            name: "Brane CTL".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            authors: env!("CARGO_PKG_AUTHORS").replace(":", ", ").into(),
            homepage: env!("CARGO_PKG_HOMEPAGE").into(),
        });
    }

    // Now match on the command
    match args.subcommand {
        CtlSubcommand::Download(subcommand) => match *subcommand {
            DownloadSubcommand::Services { fix_dirs, path, arch, version, force, kind } => {
                // Run the subcommand
                if let Err(err) = download::services(fix_dirs, path, arch, version, force, kind).await { error!("{}", err); std::process::exit(1); }
            },
        },
        CtlSubcommand::Generate(subcommand) => match *subcommand {
            GenerateSubcommand::Node{ hosts, proxy, proxy_protocol, fix_dirs, config_path, kind } => {
                // Call the thing
                if let Err(err) = generate::node(args.node_config, hosts, proxy, proxy_protocol, fix_dirs, config_path, *kind) { error!("{}", err); std::process::exit(1); }
            },

            GenerateSubcommand::Certs { fix_dirs, path, temp_dir, kind } => {
                // Call the thing
                if let Err(err) = generate::certs(fix_dirs, path, temp_dir, *kind).await { error!("{}", err); std::process::exit(1); }
            },

            GenerateSubcommand::Infra{ locations, fix_dirs, path, names, reg_ports, job_ports } => {
                // Call the thing
                if let Err(err) = generate::infra(locations, fix_dirs, path, names, reg_ports, job_ports) { error!("{}", err); std::process::exit(1); }
            },

            GenerateSubcommand::Backend{ fix_dirs, path, capabilities, disable_hashing, kind } => {
                // Call the thing
                if let Err(err) = generate::backend(fix_dirs, path, capabilities, !disable_hashing, *kind) { error!("{}", err); std::process::exit(1); }
            },
            GenerateSubcommand::Policy{ fix_dirs, path, allow_all } => {
                // Call the thing
                if let Err(err) = generate::policy(fix_dirs, path, allow_all) { error!("{}", err); std::process::exit(1); }
            },
        },

        CtlSubcommand::Packages(subcommand) => match *subcommand {
            PackageSubcommand::Hash{ image } => {
                // Call the thing
                if let Err(err) = packages::hash(args.node_config, image).await { error!("{}", err); std::process::exit(1); }
            }
        },
        CtlSubcommand::Data(subcommand) => match *subcommand {
            
        },

        CtlSubcommand::Start{ exe, file, docker_socket, docker_version, version, mode, skip_import, profile_dir, kind, } => {
            if let Err(err) = lifetime::start(exe, file, args.node_config, StartDockerOpts{ socket: docker_socket, version: docker_version }, StartOpts{ version, mode, skip_import, profile_dir }, *kind).await { error!("{}", err); std::process::exit(1); }
        },
        CtlSubcommand::Stop{ exe, file } => {
            if let Err(err) = lifetime::stop(exe, file, args.node_config) { error!("{}", err); std::process::exit(1); }
        },

        CtlSubcommand::Version { arch: _, kind: _, ctl: _, node: _ } => {
            
        },
    }
}
