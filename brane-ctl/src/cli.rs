use std::net::IpAddr;
use std::path::PathBuf;

use brane_cfg::proxy::ProxyProtocol;
use brane_ctl::spec::{
    API_DEFAULT_VERSION, DownloadServicesSubcommand, GenerateBackendSubcommand, GenerateCertsSubcommand, GenerateNodeSubcommand, InclusiveRange,
    Pair, PolicyInputLanguage, ResolvableNodeKind, StartSubcommand, VersionFix,
};
use brane_tsk::docker::ClientVersion;
use clap::{Parser, Subcommand};
use humantime::Duration as HumanDuration;
use jsonwebtoken::jwk::KeyAlgorithm;
use specifications::address::{Address, AddressOpt};
use specifications::arch::Arch;
use specifications::package::Capability;
use specifications::version::Version;

/***** ARGUMENTS *****/
/// The server-side Brane command-line interface.
#[derive(Debug, Parser)]
#[clap(name = "branectl", version, author)]
pub(crate) struct Cli {
    /// If given, prints `info` and `debug` prints.
    #[clap(long, global = true, help = "If given, prints additional information during execution.")]
    pub(crate) debug: bool,
    /// If given, prints `info`, `debug` and `trace` prints.
    #[clap(long, global = true, conflicts_with = "debug", help = "If given, prints the largest amount of debug information as possible.")]
    pub(crate) trace: bool,
    /// The path to the node config file to use.
    #[clap(
        short,
        long,
        global = true,
        default_value = "./node.yml",
        help = "The 'node.yml' file that describes properties about the node itself (i.e., the location identifier, where to find directories, \
                which ports to use, ...)"
    )]
    pub(crate) node_config: PathBuf,

    /// The subcommand that can be run.
    #[clap(subcommand)]
    pub(crate) subcommand: CtlSubcommand,
}

/// Defines subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
pub(crate) enum CtlSubcommand {
    #[clap(subcommand)]
    Download(Box<DownloadSubcommand>),
    #[clap(subcommand)]
    Generate(Box<GenerateSubcommand>),
    #[clap(subcommand)]
    Unpack(Box<UnpackSubcommand>),
    #[clap(subcommand)]
    Upgrade(Box<UpgradeSubcommand>),
    #[clap(subcommand)]
    Wizard(Box<WizardSubcommand>),

    #[clap(subcommand)]
    Packages(Box<PackageSubcommand>),
    #[clap(subcommand)]
    Data(Box<DataSubcommand>),
    #[clap(subcommand)]
    Policies(Box<PolicySubcommand>),

    #[clap(name = "start", about = "Starts the local node by loading and then launching (already compiled) image files.")]
    Start {
        #[clap(short = 'S', long, default_value = "/var/run/docker.sock", help = "The path of the Docker socket to connect to.")]
        docker_socket: PathBuf,
        #[clap(short = 'V', long, default_value = API_DEFAULT_VERSION.as_str(), help = "The version of the Docker client API that we use to connect to the engine.")]
        docker_version: ClientVersion,
        /// The docker-compose command we run.
        #[clap(short, global = true, long, default_value = "docker compose", help = "The command to use to run Docker Compose.")]
        exe: String,
        /// The docker-compose file that we start.
        #[clap(short, global=true, long, help = concat!("The docker-compose.yml file that defines the services to start. You can use '$NODE' to match either 'central' or 'worker', depending how we started. If omitted, will use the baked-in counterpart (although that only works for the default version, v", env!("CARGO_PKG_VERSION") , ")."))]
        file: Option<PathBuf>,

        /// The specific Brane version to start.
        #[clap(short, long, default_value = env!("CARGO_PKG_VERSION"), help = "The Brane version to import.")]
        version: Version,

        /// Sets the '$IMG_DIR' variable, which can easily switch the location of compiled binaries.
        #[clap(
            long,
            global = true,
            default_value = "./target/release",
            conflicts_with = "skip_import",
            help = "Sets the image directory ($IMG_DIR) to use in the image flags of the `start` command."
        )]
        image_dir:   PathBuf,
        /// If given, will use locally downloaded versions of the auxillary images.
        #[clap(
            long,
            global = true,
            help = "If given, will use downloaded .tar files of the auxillary images instead of pulling them from DockerHub. Essentially, this will \
                    change the default value of all auxillary image paths to 'Path<$IMG_DIR/aux-SVC.tar>', where 'SVC' is the specific service \
                    (e.g., 'scylla'). For more information, see the '--aux-scylla' flag."
        )]
        local_aux:   bool,
        /// Whether to skip importing images or not.
        #[clap(
            long,
            global = true,
            help = "If given, skips the import of the images. This is useful if you have already loaded the images in your Docker daemon manually."
        )]
        skip_import: bool,
        /// The profile directory to mount, if any.
        #[clap(
            short,
            long,
            help = "If given, mounts the '/logs/profile' directories in the instance container(s) to the same (given) directory on the host. Use \
                    this to effectively reach the profile files."
        )]
        profile_dir: Option<PathBuf>,

        /// Defines the possible nodes and associated flags to start.
        #[clap(subcommand)]
        kind: Box<StartSubcommand>,
    },
    #[clap(name = "stop", about = "Stops the local node if it is running.")]
    Stop {
        /// The docker-compose command we run.
        #[clap(short, long, default_value = "docker compose", help = "The command to use to run Docker Compose.")]
        exe:  String,
        /// The docker-compose file that we start.
        #[clap(short, long, help = concat!("The docker-compose.yml file that defines the services to stop. You can use '$NODE' to match either 'central' or 'worker', depending how we started. If omitted, will use the baked-in counterpart (although that only works for the default version, v", env!("CARGO_PKG_VERSION"), ")."))]
        file: Option<PathBuf>,
    },
    #[clap(name = "logs", about = "Show the logs for the specficied node")]
    Logs {
        /// The docker-compose command we run.
        #[clap(short, long, default_value = "docker compose", help = "The command to use to run Docker Compose.")]
        exe:  String,
        /// The docker-compose file that we start.
        #[clap(short, long, help = concat!("The docker-compose.yml file that defines the services to log. You can use '$NODE' to match either 'central' or 'worker', depending how we started. If omitted, will use the baked-in counterpart (although that only works for the default version, v", env!("CARGO_PKG_VERSION"), ")."))]
        file: Option<PathBuf>,
    },

    #[clap(name = "version", about = "Returns the version of this CTL tool and/or the local node.")]
    Version {
        #[clap(short, long, help = "If given, shows the architecture instead of the version when using '--ctl' or '--node'.")]
        arch: bool,
        #[clap(
            short,
            long,
            help = "Shows the kind of node (i.e., 'central' or 'worker') instead of the version. Only relevant when using '--node'."
        )]
        kind: bool,
        #[clap(
            long,
            help = "If given, shows the version of the CTL tool in an easy-to-be-parsed format. Note that, if given in combination with '--node', \
                    this one is always reported first."
        )]
        ctl:  bool,
        #[clap(
            long,
            help = "If given, shows the local node version in an easy-to-be-parsed format. Note that, if given in combination with '--ctl', this \
                    one is always reported second."
        )]
        node: bool,
    },
}

/// Defines download-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "download", about = "Download pre-compiled images or binaries from the project's repository.")]
pub(crate) enum DownloadSubcommand {
    #[clap(name = "services", about = "Downloads all of the Brane service images from the GitHub repository to the local machine.")]
    Services {
        /// Whether to create any missing directories or not.
        #[clap(short, long, global = true, help = "If given, will automatically create missing directories.")]
        fix_dirs: bool,
        /// The directory to download them to.
        #[clap(
            short,
            long,
            default_value = "./target/release",
            global = true,
            help = "The directory to download the images to. Note: if you leave it at the default, then you won't have to manually specify anything \
                    when running 'branectl start'."
        )]
        path:     PathBuf,

        /// The architecture for which to download the services.
        #[clap(
            short,
            long,
            default_value = "$LOCAL",
            global = true,
            help = "The processor architecture for which to download the images. Specify '$LOCAL' to use the architecture of the current machine."
        )]
        arch:    Arch,
        /// The version of the services to download.
        #[clap(short, long, default_value=env!("CARGO_PKG_VERSION"), global=true, help="The version of the images to download from GitHub. You can specify 'latest' to download the latest version (but that might be incompatible with this CTL version)")]
        version: Version,
        /// Whether to overwrite existing images or not.
        #[clap(
            short = 'F',
            long,
            global = true,
            help = "If given, will overwrite services that are already there. Otherwise, these are not overwritten. Note that regardless, a \
                    download will still be performed."
        )]
        force:   bool,

        /// Whether to download the central or the worker VMs.
        #[clap(subcommand)]
        kind: DownloadServicesSubcommand,
    },
}

// /// Defines arguments to the `branectl generate ...` subcommand.
// #[derive(Debug, Parser)]
// struct GenerateArguments {
//     /// The common ancestor to all `config`-files.
// }

/// Defines generate-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "generate", about = "Generate configuration files for setting up a new node.")]
pub(crate) enum GenerateSubcommand {
    #[clap(name = "node", about = "Generates a new 'node.yml' file at the location indicated by --node-config.")]
    Node {
        /// Defines one or more additional hostnames to define in the nested Docker container.
        #[clap(
            short = 'H',
            long,
            help = "One or more additional hostnames to set in the spawned Docker containers. Should be given as '<hostname>:<ip>' pairs."
        )]
        hosts: Vec<Pair<String, ':', IpAddr>>,

        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short = 'f', long, help = "If given, will generate any missing directories.")]
        fix_dirs:    bool,
        /// Custom config path.
        #[clap(
            short = 'C',
            long,
            default_value = "./config",
            help = "A common ancestor for --infra-path, --secrets-path and --certs-path. See their descriptions for more info."
        )]
        config_path: PathBuf,

        /// Defines the possible nodes to generate a new node.yml file for.
        #[clap(subcommand)]
        kind: Box<GenerateNodeSubcommand>,
    },

    #[clap(name = "certs", about = "Generates root & server certificates for the given domain.")]
    Certs {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short = 'f', long, global = true, help = "If given, will generate any missing directories.")]
        fix_dirs: bool,
        /// The directory to write to.
        #[clap(short, long, default_value = "./", global = true, help = "The path of the directory to write the generated certificate files.")]
        path:     PathBuf,
        /// The directory to write temporary scripts to.
        #[clap(
            short,
            long,
            default_value = "/tmp",
            global = true,
            help = "The path of the directory to write the temporary scripts to we use for certificate generation."
        )]
        temp_dir: PathBuf,

        /// The type of certificate to generate.
        #[clap(subcommand)]
        kind: Box<GenerateCertsSubcommand>,
    },

    #[clap(name = "infra", about = "Generates a new 'infra.yml' file.")]
    Infra {
        /// Defines the list of domains
        #[clap(
            name = "LOCATIONS",
            help = "The list of locations (i.e., worker nodes) connected to this instance. The list is given as a list of '<ID>:<ADDR>' pairs."
        )]
        locations: Vec<Pair<String, ':', String>>,

        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short = 'f', long, help = "If given, will generate any missing directories.")]
        fix_dirs: bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./infra.yml", help = "The path to write the infrastructure file to.")]
        path:     PathBuf,

        /// Determines the name of the given domain.
        #[clap(
            short = 'N',
            long = "name",
            help = "Sets the name (i.e., human-friendly name, not the identifier) of the given location. Should be given as a '<LOCATION>=<NAME>` \
                    pair. If omitted, will default to the domain's identifier with some preprocessing to make it look nicer."
        )]
        names:     Vec<Pair<String, '=', String>>,
        /// Determines the port of the registry node on the given domain.
        #[clap(
            short,
            long = "reg-port",
            help = "Determines the port of the delegate service on the given location. Should be given as a '<LOCATION>=<PORT>' pair. If omitted, \
                    will default to '50051' for each location."
        )]
        reg_ports: Vec<Pair<String, '=', u16>>,
        /// Determines the port of the delegate node on the given domain.
        #[clap(
            short,
            long = "job-port",
            help = "Determines the port of the delegate service on the given location. Should be given as a '<LOCATION>=<PORT>' pair. If omitted, \
                    will default to '50052' for each location."
        )]
        job_ports: Vec<Pair<String, '=', u16>>,
    },

    #[clap(name = "backend", about = "Generates a new `backend.yml` file.")]
    Backend {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short = 'f', long, help = "If given, will generate any missing directories.")]
        fix_dirs: bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./backend.yml", help = "The path to write the credentials file to.")]
        path:     PathBuf,

        /// The list of capabilities to advertise for this domain.
        #[clap(short, long, help = "The list of capabilities to advertise for this domain. Use '--list-capabilities' to see them.")]
        capabilities:    Vec<Capability>,
        /// Whether to hash containers or not (but inverted).
        #[clap(
            short,
            long,
            help = "If given, disables the container security hash, forgoing the need for hashing (saves time on the first execution of a container \
                    on a domain)"
        )]
        disable_hashing: bool,

        /// Defines the possible backends to generate a new backend.yml file for.
        #[clap(subcommand)]
        kind: Box<GenerateBackendSubcommand>,
    },

    #[clap(name = "policy_database", alias = "policy_db", about = "Generates a new `policies.db` database.")]
    PolicyDatabase {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short = 'f', long, help = "If given, will generate any missing directories.")]
        fix_dirs: bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./policies.db", help = "The path to write the policy database file to.")]
        path:     PathBuf,
        /// The branch to pull the migrations from.
        #[clap(
            short,
            long,
            default_value = "main",
            help = "The branch of the `https://github.com/braneframework/policy-reasoner` repository from which to pull the Diesel migrations."
        )]
        branch:   String,
    },

    #[clap(name = "policy_secret", about = "Generates a new JWT key for use in the `brane-chk` service.")]
    PolicySecret {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short = 'f', long, help = "If given, will generate any missing directories.")]
        fix_dirs: bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./policy_secret.json", help = "The path to write the policy secret to.")]
        path:     PathBuf,

        /// The identifier for this key.
        #[clap(short = 'i', long = "id", default_value = "A", help = "Some identifier to distinguish the key.")]
        key_id:  String,
        /// The algorithm used to sign JWTs.
        #[clap(short = 'a', long = "alg", default_value = "HS256", help = "The algorithm with which to sign JWTs using the generated key.")]
        jwt_alg: KeyAlgorithm,
    },

    #[clap(name = "policy_token", about = "Generates a new JWT for use to access the `brane-chk` service.")]
    PolicyToken {
        /// The name of the user using this token.
        #[clap(name = "INITIATOR", help = "The name of the user that uses this token.")]
        initiator: String,
        /// The name of the system through which the access is performed.
        #[clap(name = "SYSTEM", help = "The name of the system through which the access is performed.")]
        system: String,
        /// The expiry time.
        #[clap(
            name = "DURATION",
            help = "The duration for which this token is valid. You can use freeform syntax like '5min', '1y' or even '1h 30min'"
        )]
        exp: HumanDuration,

        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short = 'f', long, help = "If given, will generate any missing directories.")]
        fix_dirs: bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./policy_token.json", help = "The path to write the policy token to.")]
        path: PathBuf,
        /// The path of the secret file containing the key.
        #[clap(short, long, default_value = "./policy_secret.json", help = "The path that contains the policy secret with which to sign the token.")]
        secret_path: PathBuf,
    },

    #[clap(name = "proxy", about = "Generates a new `proxy.yml` file.")]
    Proxy {
        /// If given, will generate missing directories instead of throwing errors.
        #[clap(short, long, help = "If given, will generate any missing directories.")]
        fix_dirs: bool,
        /// The path to write to.
        #[clap(short, long, default_value = "./proxy.yml", help = "The path to write the proxy file to.")]
        path:     PathBuf,

        /// Defines the range of ports that we can allocate for outgoing connections.
        #[clap(
            short,
            long,
            default_value = "4200-4299",
            help = "Defines the range of ports that we may allocate when one of the Brane services wants to make an outgoing connection. Given as \
                    '<START>-<END>', where '<START>' and '<END>' are port numbers, '<START>' >= '<END>'. Both are inclusive."
        )]
        outgoing_range: InclusiveRange<u16>,
        /// Defines the map of incoming ports.
        #[clap(
            short,
            long,
            help = "Defines any incoming port mappings. Given as '<PORT>:<ADDRESS>', where the '<PORT>' is the port to open for incoming \
                    connections, and '<ADDRESS>' is the address to forward the traffic to."
        )]
        incoming: Vec<Pair<u16, ':', Address>>,
        /// Defines if the proxy should be forwarded.
        #[clap(
            short = 'F',
            long,
            help = "If given, will forward any traffic to the given destination. The specific protocol use is given in '--forward-protocol'"
        )]
        forward: Option<Address>,
        /// Defines which protocol to use if forwarding.
        #[clap(
            short = 'P',
            long,
            default_value = "socks6",
            help = "Defines how to forward the traffic to a proxy. Ignored if '--forward' is not given."
        )]
        forward_protocol: ProxyProtocol,
    },
}

/// Defines subcommands that allow us to unpack baked-in files.
#[derive(Debug, Subcommand)]
#[clap(name = "unpack", alias = "extract", about = "Unpack a certain file that is baked-in the CTL executable.")]
pub(crate) enum UnpackSubcommand {
    #[clap(
        name = "compose",
        about = "Unpacks the Docker Compose file that we use to setup the services for an node. Note, however, that this Docker Compose file is \
                 templated with a lot of environment variables, so it's only really useful if you want to change some Compose settings. Check \
                 'branectl start -f'."
    )]
    Compose {
        /// The location to which to extract the file.
        #[clap(
            name = "PATH",
            default_value = "./docker-compose-$NODE.yml",
            help = "Defines the path to which we unpack the file. You can use '$NODE' to refer to the node kind as specified by 'NODE_KIND'"
        )]
        path: PathBuf,

        /// The type of node for which to extract.
        #[clap(
            short,
            long,
            default_value = "$NODECFG",
            help = "Defines the kind of node for which to unpack the Docker Compose file. You can use '$NODECFG' to refer to the node kind defined \
                    in the `node.yml` file (see 'branectl -n')."
        )]
        kind:     ResolvableNodeKind,
        /// Whether to fix missing directories (true) or throw errors (false).
        #[clap(short, long, help = "If given, will create missing directories instead of throwing an error.")]
        fix_dirs: bool,
    },
}

/// Defines the subcommands for the upgrade subcommand
#[derive(Debug, Subcommand)]
#[clap(name = "upgrade", about = "Updates configuration files from an older BRANE version to this one.")]
pub(crate) enum UpgradeSubcommand {
    #[clap(name = "node", about = "Upgrade node.yml files to be compatible with this BRANE version.")]
    Node {
        /// The file or folder to upgrade.
        #[clap(
            name = "PATH",
            default_value = "./",
            help = "The path to the file or folder (recursively traversed) of files to upgrade to this version. If a directory, will consider any \
                    YAML files (*.yml or *.yaml) that are successfully parsed with an old node.yml parser."
        )]
        path: PathBuf,

        /// Whether to run dryly or not
        #[clap(short, long, help = "If given, does not do anything but instead just reports which files would be updated.")]
        dry_run:   bool,
        /// Whether to keep old versions
        #[clap(
            short = 'O',
            long,
            help = "If given, will not keep the old versions alongside the new ones but instead overwrite them. Use them only if you are certain no \
                    unrelated files are converted or converted incorrectly! (see '--dry-run')"
        )]
        overwrite: bool,
        /// Fixes the version from which we are converting.
        #[clap(
            short,
            long,
            default_value = "all",
            help = "Whether to consider only one version when examining a file. Can be any valid BRANE version or 'auto' to use all supported \
                    versions."
        )]
        version:   VersionFix,
    },
}

/// Defines subcommands relating to the wizard
#[derive(Debug, Subcommand)]
#[clap(name = "wizard", about = "A suite of interactive wizards to ease particular processes.")]
pub(crate) enum WizardSubcommand {
    #[clap(name = "setup", alias = "node", about = "Starts a wizard that sets up a new node.")]
    Setup {},
}

/// Defines package-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "packages", about = "Manage packages that are stored on this node.")]
pub(crate) enum PackageSubcommand {
    /// Generates the hash for the given package container.
    #[clap(name = "hash", about = "Hashes the given `image.tar` file for use in policies.")]
    Hash {
        /// The path to the image file.
        #[clap(
            name = "IMAGE",
            help = "The image to compute the hash of. If it's a path that exists, will attempt to hash that file; otherwise, will hash based on an \
                    image in the local node's `packages` directory. You can use `name[:version]` syntax to specify the version."
        )]
        image: String,
    },
}

/// Defines data- and intermediate results-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "data", about = "Manage data and intermediate results stored on this node.")]
pub(crate) enum DataSubcommand {}

/// Defines policy-related subcommands for the `branectl` tool.
#[derive(Debug, Subcommand)]
#[clap(name = "policies", alias = "policy", about = "Manage the checker's policies by adding them or setting different active versions.")]
pub(crate) enum PolicySubcommand {
    /// Activates a policy in the remote checker.
    #[clap(name = "activate", about = "Activates an already added policy in the remote checker.")]
    Activate {
        /// The policy to activate. If omitted, the CTL should request the list and present them to the user.
        #[clap(
            name = "VERSION",
            help = "The version of the policy to activate. Omit to have branectl download the version metadata from the checker and let you choose \
                    interactively."
        )]
        version: Option<i64>,

        /// Address on which to find the checker.
        #[clap(
            short,
            long,
            default_value = "localhost",
            help = "The address on which to reach the checker service, given as '<HOSTNAME>[:<PORT>]'. If you omit the port, the one from the \
                    `node.yml` file is read."
        )]
        address: AddressOpt,
        /// The JWT to use to authenticate with the remote checker.
        #[clap(
            short,
            long,
            env,
            help = "A JSON Web Token (JWT) to use to authenticate to the checker. If omitted, will use the one from the `policy_expert_secret` file \
                    in the given `node.yml` when found. Note that you can also just set an environment variable named 'TOKEN' with the value if you \
                    don't want to give it everytime."
        )]
        token:   Option<String>,
    },

    /// Adds a given policy file to the remote checker.
    #[clap(name = "add", about = "Adds a new policy to the checker, but does not yet set it as active.")]
    Add {
        /// The path to the policy file to add, but with stdout capabilities.
        #[clap(
            name = "INPUT",
            help = "The input policy to send to the remote checker. Given as a path to a file, or '-' to read from stdin (end you policy with \
                    Ctrl+D)."
        )]
        input:    String,
        /// The language of the input.
        #[clap(
            short,
            long,
            help = "The language of the input policy. Options are 'eflint' and 'eflint-json', where the former will be compiled to the latter \
                    before sending. If omitted, will attempt to deduce it based on the 'INPUT'."
        )]
        language: Option<PolicyInputLanguage>,

        /// Address on which to find the checker.
        #[clap(
            short,
            long,
            default_value = "localhost",
            help = "The address on which to reach the checker service, given as '<HOSTNAME>[:<PORT>]'. If you omit the port, the one from the \
                    `node.yml` file is read."
        )]
        address: AddressOpt,
        /// The JWT to use to authenticate with the remote checker.
        #[clap(
            short,
            long,
            env,
            help = "A JSON Web Token (JWT) to use to authenticate to the checker. If omitted, will use the one from the `policy_expert_secret` file \
                    in the given `node.yml` when found. Note that you can also just set an environment variable named 'TOKEN' with the value if you \
                    don't want to give it everytime."
        )]
        token:   Option<String>,
    },

    #[clap(name = "list", about = "Lists (and allows the inspection of) the policies on the node's checker.")]
    List {
        /// Address on which to find the checker.
        #[clap(
            short,
            long,
            default_value = "localhost",
            help = "The address on which to reach the checker service, given as '<HOSTNAME>[:<PORT>]'. If you omit the port, the one from the \
                    `node.yml` file is read."
        )]
        address: AddressOpt,
        /// The JWT to use to authenticate with the remote checker.
        #[clap(
            short,
            long,
            env,
            help = "A JSON Web Token (JWT) to use to authenticate to the checker. If omitted, will use the one from the `policy_expert_secret` file \
                    in the given `node.yml` when found. Note that you can also just set an environment variable named 'TOKEN' with the value if you \
                    don't want to give it everytime."
        )]
        token:   Option<String>,
    },
}
