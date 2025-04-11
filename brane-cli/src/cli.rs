use std::path::PathBuf;

use brane_cli::spec::{API_DEFAULT_VERSION, Hostname, VersionFix};
use brane_tsk::docker::ClientVersion;
use brane_tsk::spec::AppId;
use clap::Parser;
use specifications::arch::Arch;
use specifications::version::Version as SemVersion;

/***** ARGUMENTS *****/
/// The Brane command-line interface.
#[derive(Parser)]
#[clap(name = "brane", version, about)]
pub(crate) struct Cli {
    #[clap(long, global = true, action, help = "Enable debug mode")]
    pub(crate) debug: bool,
    #[clap(long, action, help = "Skip dependencies check")]
    pub(crate) skip_check: bool,
    #[clap(subcommand)]
    pub(crate) sub_command: SubCommand,
}

#[derive(Parser)]
pub(crate) enum SubCommand {
    #[clap(name = "certs", about = "Manage certificates for connecting to remote instances.")]
    Certs {
        // We subcommand further
        #[clap(subcommand)]
        subcommand: CertsSubcommand,
    },

    #[clap(name = "data", about = "Data-related commands.")]
    Data {
        // We subcommand further
        #[clap(subcommand)]
        subcommand: DataSubcommand,
    },

    #[clap(name = "instance", about = "Commands that relate to connecting to remote instances.")]
    Instance {
        /// Subcommand further
        #[clap(subcommand)]
        subcommand: InstanceSubcommand,
    },

    #[clap(name = "package", about = "Commands that relate to packages")]
    Package {
        /// Subcommand further
        #[clap(subcommand)]
        subcommand: PackageSubcommand,
    },

    #[clap(name = "upgrade", about = "Upgrades outdated configuration files to this Brane version")]
    Upgrade {
        // We subcommand further
        #[clap(subcommand)]
        subcommand: UpgradeSubcommand,
    },

    #[clap(name = "verify", about = "Verifies parts of Brane's configuration (useful mostly if you are in charge of an instance.")]
    Verify {
        // We subcommand further
        #[clap(subcommand)]
        subcommand: VerifySubcommand,
    },

    #[clap(name = "version", about = "Shows the version number for this Brane CLI tool and (if logged in) the remote Driver.")]
    Version {
        #[clap(short, long, action, help = "If given, shows the architecture instead of the version when using '--local' or '--remote'.")]
        arch:   bool,
        #[clap(
            short,
            long,
            action,
            help = "If given, shows the local version in an easy-to-be-parsed format. Note that, if given in combination with '--remote', this one \
                    is always reported first."
        )]
        local:  bool,
        #[clap(
            short,
            long,
            action,
            help = "If given, shows the remote Driver version in an easy-to-be-parsed format. Note that, if given in combination with '--local', \
                    this one is always reported second."
        )]
        remote: bool,
    },

    #[clap(name = "workflow", about = "Commands that relate to workflows")]
    Workflow {
        /// Subcommand further
        #[clap(subcommand)]
        subcommand: WorkflowSubcommand,
    },
}

/// Defines the subcommands for the `instance certs` subommand
#[derive(Parser)]
pub(crate) enum CertsSubcommand {
    #[clap(
        name = "add",
        about = "Adds a new CA/client certificate pair to this instance. If there are already certificates defined for this domain, will override \
                 them."
    )]
    Add {
        /// The path(s) to the certificate(s) to load.
        #[clap(
            name = "PATHS",
            help = "The path(s) to the certificate(s) to load. This should include at least the CA certificate for this domain, as well as a signed \
                    client certificate. Since a single certificate file may contain multiple certificates, however, specify how many you need."
        )]
        paths: Vec<PathBuf>,

        /// The instance for which to add it.
        #[clap(
            short,
            long,
            help = "The name of the instance to add the certificate to. If omitted, will add to the active instance instead (i.e., the one set with \
                    `brane instance select`). Use 'brane instance list' for an overview."
        )]
        instance: Option<String>,
        /// Any custom domain name.
        #[clap(
            short,
            long,
            help = "If given, overrides the location name found in the certificates. Note, however, that this name is used when we need to download \
                    from the domain, so should match the name of the location for which the certificates are valid."
        )]
        domain:   Option<String>,

        /// Whether to ask for permission before overwriting old certificates (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before overwriting old certificates. Use at your own risk.")]
        force: bool,
    },
    #[clap(name = "remove", about = "Removes the certificates for a certain domain within this instance.")]
    Remove {
        /// The name(s) of the certificate(s) to remove.
        #[clap(
            name = "DOMAINS",
            help = "The name(s) of the domain(s) for which to remove the certificates. If in doubt, consult `brane certs list`."
        )]
        domains: Vec<String>,

        /// The instance from which to remove them.
        #[clap(
            short,
            long,
            help = "The name of the instance to remove the certificates from. If omitted, will be removed from the active instance instead (i.e., \
                    the one set with `brane instance select`). Use 'brane instance list' for an overview."
        )]
        instance: Option<String>,

        /// Whether to query for permission or not (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before removing the certificates. Use at your own risk.")]
        force: bool,
    },

    #[clap(name = "list", about = "Lists the domains for which certificates are given.")]
    List {
        /// The instance from which to show the certificates
        #[clap(
            short,
            long,
            conflicts_with = "all",
            help = "The name of the instance to show the registered certificates in. If omitted, will list in the active instance instead (i.e., \
                    the one set with `brane instance select`). Use 'brane instance list' for an overview."
        )]
        instance: Option<String>,
        /// Whether to show all instances or only the given/active one.
        #[clap(short, long, conflicts_with = "instance", help = "If given, shows all certificates across all instances.")]
        all:      bool,
    },
}

/// Defines the subsubcommands for the data subcommand.
#[derive(Parser)]
pub(crate) enum DataSubcommand {
    #[clap(name = "build", about = "Builds a locally available dataset from the given data.yml file and associated files (if any).")]
    Build {
        #[clap(name = "FILE", help = "Path to the file to build.")]
        file: PathBuf,
        #[clap(short, long, help = "Path to the directory to use as the 'working directory' (defaults to the folder of the package file itself)")]
        workdir: Option<PathBuf>,
        #[clap(long, action, help = "if given, doesn't delete intermediate build files when done.")]
        keep_files: bool,
        #[clap(
            long,
            action,
            help = "If given, copies the dataset to the Brane data folder. Otherwise, merely soft links it (until the dataset is pushed to a remote \
                    repository). This is much more space efficient, but requires you to leave the original dataset in place."
        )]
        no_links: bool,
    },

    #[clap(name = "download", about = "Attempts to download one (or more) dataset(s) from the remote instance.")]
    Download {
        /// A use-case registry to use for downloading the data.
        #[clap(help = "A use-case registry to use for downloading the data.")]
        use_case: String,

        /// The name of the datasets to download.
        #[clap(name = "DATASETS", help = "The datasets to attempt to download.")]
        names: Vec<String>,

        /// The user that is performing the download
        #[clap(short, long, help = "The user that is performing the download")]
        user: Option<String>,

        /// The locations where to download each dataset. The user should make this list as long as the names, if any.
        #[clap(short, long, help = "The location identifiers from which we download each dataset, as `name=location` pairs.")]
        locs: Vec<String>,

        /// The address to proxy the transfer through.
        #[clap(short, long, help = "If given, proxies the transfer through the given proxy.")]
        proxy_addr: Option<String>,
        /// If given, forces the data transfer even if it's locally available.
        #[clap(short, long, action, help = "If given, will always attempt to transfer data remotely, even if it's already available locally.")]
        force:      bool,
    },

    #[clap(name = "list", about = "Shows the locally known datasets.")]
    List {},

    #[clap(name = "search", about = "Shows the datasets known in the remote instance.")]
    Search {},

    #[clap(
        name = "path",
        about = "Returns the path to the dataset of the given datasets (one returned per line), if it has a path. Returns '<none>' in that latter \
                 case."
    )]
    Path {
        #[clap(name = "DATASETS", help = "The name(s) of the dataset(s) to list the paths of.")]
        names: Vec<String>,
    },

    #[clap(name = "remove", about = "Removes a locally known dataset.")]
    Remove {
        #[clap(name = "DATASETS", help = "The name(s) of the dataset(s) to remove.")]
        names: Vec<String>,
        #[clap(short, long, action, help = "If given, does not ask the user for confirmation but just removes the dataset (use at your own risk!)")]
        force: bool,
    },
}

/// Defines the subcommands for the instance subommand
#[derive(Parser)]
pub(crate) enum InstanceSubcommand {
    #[clap(name = "add", about = "Defines a new instance to connect to.")]
    Add {
        /// The instance's hostname.
        #[clap(
            name = "HOSTNAME",
            help = "The hostname of the instance to connect to. Should not contain any ports or paths, and any scheme (e.g., 'http://') is ignored."
        )]
        hostname: Hostname,
        /// The port of the API service.
        #[clap(
            short,
            long,
            default_value = "50051",
            help = "The port of the API service on the remote instance. You should probably only specify this if the system administrator told you \
                    to change it."
        )]
        api_port: u16,
        /// The port of the driver service.
        #[clap(
            short,
            long,
            default_value = "50053",
            help = "The port of the driver service on the remote instance. You should probably only specify this if the system administrator told \
                    you to change it."
        )]
        drv_port: u16,
        /// The name of the user as which we login.
        #[clap(
            short = 'U',
            long,
            help = "The name as which to login to the instance. This is used to tell checkers who will download the result, but only tentatively; a \
                    final check happens using domain-specific credentials. Will default to a random name when omitted."
        )]
        user:     Option<String>,

        /// Any custom name for this instance.
        #[clap(short, long, help = "Some name to set for this instance. If omitted, will set the hostname instead.")]
        name: Option<String>,
        /// Whether to use this instance immediately or not.
        #[clap(
            short,
            long = "use",
            help = "If given, immediately uses this instance (i.e., acts as if `brane instance switch <name>` is called for this instance)"
        )]
        use_immediately: bool,
        /// Whether to skip checking if the instance is alive or not.
        #[clap(long, help = "If given, skips checking if the instance is reachable.")]
        unchecked: bool,
        /// Whether to ask for permission before overwriting old certificates (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before overwriting old certificates. Use at your own risk.")]
        force: bool,
    },
    #[clap(name = "remove", about = "Deletes a registered instance.")]
    Remove {
        /// The name(s) of the instance(s) to remove.
        #[clap(name = "NAMES", help = "The name(s) of the instance(s) to remove. If in doubt, consult `brane instance list`.")]
        names: Vec<String>,

        /// Whether to query for permission or not (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before removing the instances. Use at your own risk.")]
        force: bool,
    },

    #[clap(name = "list", about = "Lists the registered instances.")]
    List {
        /// If given, shows an additional column in the table that shows whether this instance is online or not.
        #[clap(short, long, help = "If given, shows an additional column in the table that shows whether this instance is online or not.")]
        show_status: bool,
    },
    #[clap(name = "select", about = "Switches to the registered instance with the given name.")]
    Select {
        /// The instnace's name to switch to.
        #[clap(name = "NAME", help = "The name of the instance to switch to. If in doubt, consult `brane instance list`.")]
        name: String,
    },

    #[clap(name = "edit", about = "Changes some properties of an instance.")]
    Edit {
        /// The instance's name to edit.
        #[clap(
            name = "NAME",
            help = "The name of the instance to edit if you don't want to edit the active instance. f in doubt, consult `brane instance list`."
        )]
        name: Option<String>,

        /// Change the hostname to this.
        #[clap(short = 'H', long, help = "If given, changes the hostname of this instance to the given one.")]
        hostname: Option<Hostname>,
        /// Change the API port to this.
        #[clap(short, long, help = "If given, changes the port of the API service for this instance to this.")]
        api_port: Option<u16>,
        /// Change the driver port to this.
        #[clap(short, long, help = "If given, changes the port of the driver service for this instance to this.")]
        drv_port: Option<u16>,
        /// The name of the user as which we login.
        #[clap(
            short,
            long,
            help = "If given, changes the name as which to login to the instance. This is used to tell checkers who will download the result, but \
                    only tentatively; a final check happens using domain-specific credentials."
        )]
        user:     Option<String>,
    },
}

#[derive(Parser)]
pub(crate) enum PackageSubcommand {
    #[clap(name = "build", about = "Build a package")]
    Build {
        #[clap(short, long, help = "The architecture for which to compile the image.")]
        arch: Option<Arch>,
        #[clap(
            short,
            long,
            help = "Path to the directory to use as container working directory (defaults to the folder of the package file itself)"
        )]
        workdir: Option<PathBuf>,
        #[clap(name = "FILE", help = "Path to the file to build")]
        file: PathBuf,
        #[clap(short, long, help = "Kind of package: cwl, dsl, ecu or oas")]
        kind: Option<String>,
        #[clap(short, long, help = "Path to the init binary to use (override Brane's binary)")]
        init: Option<PathBuf>,
        #[clap(long, action, help = "Don't delete build files")]
        keep_files: bool,
        #[clap(
            short,
            long,
            help = "If given, does not ask permission to convert CRLF (Windows-style line endings) to LF (Unix-style line endings), but just does \
                    it."
        )]
        crlf_ok: bool,
    },

    #[clap(name = "import", about = "Import a package")]
    Import {
        #[clap(short, long, help = "The architecture for which to compile the image.")]
        arch:    Option<Arch>,
        #[clap(name = "REPO", help = "Name of the GitHub repository containing the package")]
        repo:    String,
        #[clap(short, long, default_value = "main", help = "Name of the GitHub branch containing the package")]
        branch:  String,
        #[clap(
            short,
            long,
            help = "Path to the directory to use as container working directory, relative to the repository (defaults to the folder of the package \
                    file itself)"
        )]
        workdir: Option<PathBuf>,
        #[clap(name = "FILE", help = "Path to the file to build, relative to the repository")]
        file:    Option<PathBuf>,
        #[clap(short, long, help = "Kind of package: cwl, dsl, ecu or oas")]
        kind:    Option<String>,
        #[clap(short, long, help = "Path to the init binary to use (override Brane's binary)")]
        init:    Option<PathBuf>,

        #[clap(
            short,
            long,
            help = "If given, does not ask permission to convert CRLF (Windows-style line endings) to LF (Unix-style line endings), but just does \
                    it."
        )]
        crlf_ok: bool,
    },

    #[clap(name = "inspect", about = "Inspect a package")]
    Inspect {
        #[clap(name = "NAME", help = "Name of the package")]
        name:    String,
        #[clap(name = "VERSION", default_value = "latest", help = "Version of the package")]
        version: SemVersion,

        // Alternative syntax to use.
        #[clap(
            short,
            long,
            default_value = "custom",
            help = "Any alternative syntax to use for printed classes and functions. Can be 'bscript', 'bakery' or 'custom'."
        )]
        syntax: String,
    },

    #[clap(name = "list", about = "List packages")]
    List {
        #[clap(short, long, action, help = "If given, only print the latest version of each package instead of all versions")]
        latest: bool,
    },

    #[clap(name = "load", about = "Load a package locally")]
    Load {
        #[clap(name = "NAME", help = "Name of the package")]
        name:    String,
        #[clap(short, long, default_value = "latest", help = "Version of the package")]
        version: SemVersion,
    },

    // #[clap(name = "logout", about = "Log out from a registry")]
    // Logout {},
    #[clap(name = "pull", about = "Pull a package from a registry")]
    Pull {
        #[clap(
            name = "PACKAGES",
            help = "Specify one or more packages to pull from a remote. You can either give a package as 'NAME' or 'NAME:VERSION', where VERSION is \
                    assumed to be 'latest' if omitted."
        )]
        packages: Vec<String>,
    },

    #[clap(name = "push", about = "Push a package to a registry")]
    Push {
        #[clap(
            name = "PACKAGES",
            help = "Specify one or more packages to push to a remote. You can either give a package as 'NAME' or 'NAME:VERSION', where VERSION is \
                    assumed to be 'latest' if omitted."
        )]
        packages: Vec<String>,
    },

    #[clap(name = "remove", about = "Remove a local package.")]
    Remove {
        #[clap(short, long, help = "Don't ask for confirmation before removal.")]
        force:    bool,
        #[clap(
            name = "PACKAGES",
            help = "Specify one or more packages to remove to a remote. You can either give a package as 'NAME' or 'NAME:VERSION', where ALL \
                    versions of the packages will be removed if VERSION is omitted.."
        )]
        packages: Vec<String>,

        /// The Docker socket location.
        #[cfg(unix)]
        #[clap(
            short = 's',
            long,
            default_value = "/var/run/docker.sock",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:  PathBuf,
        /// The Docker socket location.
        #[cfg(windows)]
        #[clap(
            short = 's',
            long,
            default_value = "//./pipe/docker_engine",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:  PathBuf,
        /// The Docker socket location.
        #[cfg(not(any(unix, windows)))]
        #[clap(short = 's', long, help = "The path to the Docker socket with which we communicate with the dameon.")]
        docker_socket:  PathBuf,
        /// The Docker client version.
        #[clap(short='v', long, default_value = API_DEFAULT_VERSION.as_str(), help = "The API version with which we connect.")]
        client_version: ClientVersion,
    },

    #[clap(name = "test", about = "Test a package locally")]
    Test {
        #[clap(name = "NAME", help = "Name of the package")]
        name: String,
        #[clap(name = "VERSION", default_value = "latest", help = "Version of the package")]
        version: SemVersion,
        #[clap(
            short = 'r',
            long,
            help = "If given, prints the intermediate result returned by the tested function (if any). The given path should be relative to the \
                    'result' folder."
        )]
        show_result: Option<PathBuf>,

        /// The Docker socket location.
        #[cfg(unix)]
        #[clap(
            short = 's',
            long,
            default_value = "/var/run/docker.sock",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:   PathBuf,
        /// The Docker socket location.
        #[cfg(windows)]
        #[clap(
            short = 's',
            long,
            default_value = "//./pipe/docker_engine",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:   PathBuf,
        /// The Docker socket location.
        #[cfg(not(any(unix, windows)))]
        #[clap(short = 's', long, help = "The path to the Docker socket with which we communicate with the dameon.")]
        docker_socket:   PathBuf,
        /// The Docker client version.
        #[clap(short='v', long, default_value = API_DEFAULT_VERSION.as_str(), help = "The API version with which we connect.")]
        client_version:  ClientVersion,
        /// Whether to keep container after running or not.
        #[clap(short = 'k', long, help = "If given, does not remove containers after execution. This is useful for debugging them.")]
        keep_containers: bool,
    },

    #[clap(name = "search", about = "Search a registry for packages")]
    Search {
        #[clap(name = "TERM", help = "Term to use as search criteria")]
        term: Option<String>,
    },

    #[clap(name = "unpublish", about = "Remove a package from a registry")]
    Unpublish {
        #[clap(name = "NAME", help = "Name of the package")]
        name:    String,
        #[clap(name = "VERSION", help = "Version of the package")]
        version: SemVersion,
        #[clap(short, long, action, help = "Don't ask for confirmation")]
        force:   bool,
    },
}

#[derive(Parser)]
pub(crate) enum WorkflowSubcommand {
    #[clap(
        name = "check",
        about = "Checks a workflow against the policy in the current remote instance. You can think of this as using `brane run --remote`, except \
                 that the Workflow won't be executed - only policy is checked."
    )]
    Check {
        #[clap(name = "FILE", help = "Path to the file to run. Use '-' to run from stdin instead.")]
        file:   String,
        #[clap(short, long, action, help = "Use Bakery instead of BraneScript")]
        bakery: bool,

        #[clap(short, long, help = "If given, uses the given user as end user of a workflow instead of the one in the instance file.")]
        user: Option<String>,

        #[clap(long, help = "If given, shows profile times if they are available.")]
        profile: bool,
    },

    #[clap(name = "repl", about = "Start an interactive DSL session")]
    Repl {
        #[clap(short, long, value_names = &["address[:port]"], help = "If given, proxies any data transfers to this machine through the proxy at the given address. Irrelevant if not running remotely.")]
        proxy_addr: Option<String>,

        #[clap(name = "use case")]
        use_case: String,

        #[clap(short, long, help = "Create a remote REPL session to the instance you are currently logged-in to (see `brane login`)")]
        remote: bool,
        #[clap(short, long, value_names = &["uid"], help = "Attach to an existing remote session")]
        attach: Option<AppId>,

        #[clap(short, long, action, help = "Use Bakery instead of BraneScript")]
        bakery: bool,
        #[clap(short, long, action, help = "Clear history before session")]
        clear:  bool,

        #[clap(long, help = "If given, shows profile times if they are available.")]
        profile: bool,

        /// The Docker socket location.
        #[cfg(unix)]
        #[clap(
            short = 's',
            long,
            default_value = "/var/run/docker.sock",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:   PathBuf,
        /// The Docker socket location.
        #[cfg(windows)]
        #[clap(
            short = 's',
            long,
            default_value = "//./pipe/docker_engine",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:   PathBuf,
        /// The Docker socket location.
        #[cfg(not(any(unix, windows)))]
        #[clap(short = 's', long, help = "The path to the Docker socket with which we communicate with the dameon.")]
        docker_socket:   PathBuf,
        /// The Docker client version.
        #[clap(short='v', long, default_value = API_DEFAULT_VERSION.as_str(), help = "The API version with which we connect.")]
        client_version:  ClientVersion,
        /// Whether to keep container after running or not.
        #[clap(short = 'k', long, help = "If given, does not remove containers after execution. This is useful for debugging them.")]
        keep_containers: bool,
    },

    #[clap(name = "run", about = "Run a DSL script locally")]
    Run {
        #[clap(short, long, value_names = &["address[:port]"], help = "If given, proxies any data transfers to this machine through the proxy at the given address. Irrelevant if not running remotely.")]
        proxy_addr: Option<String>,

        #[clap(name = "use case", help = "A use-case registry to use for downloading the data.")]
        use_case: String,

        #[clap(short, long, action, help = "Use Bakery instead of BraneScript")]
        bakery: bool,

        #[clap(name = "FILE", help = "Path to the file to run. Use '-' to run from stdin instead.")]
        file:    PathBuf,
        #[clap(
            long,
            conflicts_with = "remote",
            help = "If given, uses a dummy VM in the background which never actually runs any jobs. It only returns some default value for the \
                    task's return type. Use this to run only the BraneScript part of your workflow."
        )]
        dry_run: bool,
        #[clap(
            short,
            long,
            conflicts_with = "dry_run",
            help = "Create a remote session to the instance you are currently logged-in to (see `brane login`)"
        )]
        remote:  bool,

        #[clap(long, help = "If given, shows profile times if they are available.")]
        profile: bool,

        /// The Docker socket location.
        #[cfg(unix)]
        #[clap(
            short = 's',
            long,
            default_value = "/var/run/docker.sock",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:   PathBuf,
        /// The Docker socket location.
        #[cfg(windows)]
        #[clap(
            short = 's',
            long,
            default_value = "//./pipe/docker_engine",
            help = "The path to the Docker socket with which we communicate with the dameon."
        )]
        docker_socket:   PathBuf,
        /// The Docker socket location.
        #[cfg(not(any(unix, windows)))]
        #[clap(short = 's', long, help = "The path to the Docker socket with which we communicate with the dameon.")]
        docker_socket:   PathBuf,
        /// The Docker client version.
        #[clap(short='v', long, default_value = API_DEFAULT_VERSION.as_str(), help = "The API version with which we connect.")]
        client_version:  ClientVersion,
        /// Whether to keep container after running or not.
        #[clap(short = 'k', long, help = "If given, does not remove containers after execution. This is useful for debugging them.")]
        keep_containers: bool,
    },
}

/// Defines the subcommands for the upgrade subcommand.
#[derive(Parser)]
pub(crate) enum UpgradeSubcommand {
    #[clap(name = "data", about = "Upgrades old data.yml files to this Brane version.")]
    Data {
        /// The file or folder to upgrade.
        #[clap(
            name = "PATH",
            default_value = "./",
            help = "The path to the file or folder (recursively traversed) of files to upgrade to this version. If a directory, will consider any \
                    YAML files (*.yml or *.yaml) that are successfully parsed with an old data.yml parser."
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

/// Defines the subcommands for the verify subcommand.
#[derive(Parser)]
pub(crate) enum VerifySubcommand {
    #[clap(name = "config", about = "Verifies the configuration, e.g., an `infra.yml` files")]
    Config {
        #[clap(short, long, default_value = "./config/infra.yml", help = "The location of the infra.yml file to validate")]
        infra: PathBuf,
    },
}
