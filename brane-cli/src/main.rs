//  MAIN.rs
//    by Lut99
// 
//  Created:
//    21 Sep 2022, 14:34:28
//  Last edited:
//    12 Apr 2023, 10:15:45
//  Auto updated?
//    Yes
// 
//  Description:
//!   Entrypoint to the CLI binary.
// 

#[macro_use]
extern crate human_panic;

use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use anyhow::Result;
use clap::Parser;
use console::style;
use dotenvy::dotenv;
use git2::Repository;
use log::LevelFilter;
use tempfile::tempdir;

use brane_dsl::Language;
use brane_tsk::spec::AppId;
use specifications::arch::Arch;
use specifications::package::PackageKind;
use specifications::version::Version as SemVersion;

use brane_cli::{build_ecu, build_oas, certs, data, instance, packages, registry, repl, run, test, verify, version};
use brane_cli::errors::{CliError, ImportError};
use brane_cli::spec::Hostname;


/***** ARGUMENTS *****/
#[derive(Parser)]
#[clap(name = "brane", about = "The Brane command-line interface.")]
struct Cli {
    #[clap(long, global = true, action, help = "Enable debug mode")]
    debug: bool,
    #[clap(long, action, help = "Skip dependencies check")]
    skip_check: bool,
    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    #[clap(name = "build", about = "Build a package")]
    Build {
        #[clap(short, long, help = "The architecture for which to compile the image.")]
        arch: Option<Arch>,
        #[clap(short, long, help = "Path to the directory to use as container working directory (defaults to the folder of the package file itself)")]
        workdir: Option<PathBuf>,
        #[clap(name = "FILE", help = "Path to the file to build")]
        file: PathBuf,
        #[clap(short, long, help = "Kind of package: cwl, dsl, ecu or oas")]
        kind: Option<String>,
        #[clap(short, long, help = "Path to the init binary to use (override Brane's binary)")]
        init: Option<PathBuf>,
        #[clap(long, action, help = "Don't delete build files")]
        keep_files: bool,
    },

    #[clap(name = "certs", about = "Manage certificates for connecting to remote instances.")]
    Certs {
        // We subcommand further
        #[clap(subcommand)]
        subcommand : CertsSubcommand,
    },

    #[clap(name = "data", about = "Data-related commands.")]
    Data {
        // We subcommand further
        #[clap(subcommand)]
        subcommand : DataSubcommand,
    },

    #[clap(name = "import", about = "Import a package")]
    Import {
        #[clap(short, long, help = "The architecture for which to compile the image.")]
        arch: Option<Arch>,
        #[clap(name = "REPO", help = "Name of the GitHub repository containing the package")]
        repo: String,
        #[clap(short, long, help = "Path to the directory to use as container working directory, relative to the repository (defaults to the folder of the package file itself)")]
        workdir: Option<PathBuf>,
        #[clap(name = "FILE", help = "Path to the file to build, relative to the repository")]
        file: Option<PathBuf>,
        #[clap(short, long, help = "Kind of package: cwl, dsl, ecu or oas")]
        kind: Option<String>,
        #[clap(short, long, help = "Path to the init binary to use (override Brane's binary)")]
        init: Option<PathBuf>,
    },

    #[clap(name = "inspect", about = "Inspect a package")]
    Inspect {
        #[clap(name = "NAME", help = "Name of the package")]
        name    : String,
        #[clap(name = "VERSION", default_value = "latest", help = "Version of the package")]
        version : SemVersion,

        // Alternative syntax to use.
        #[clap(short, long, default_value = "custom", help = "Any alternative syntax to use for printed classes and functions. Can be 'bscript', 'bakery' or 'custom'.")]
        syntax : String,
    },

    #[clap(name = "instance", about = "Commands that relate to connecting to remote instances.")]
    Instance {
        /// Subcommand further
        #[clap(subcommand)]
        subcommand : InstanceSubcommand,
    },

    #[clap(name = "list", about = "List packages")]
    List {
        #[clap(short, long, action, help = "If given, only print the latest version of each package instead of all versions")]
        latest: bool,
    },

    #[clap(name = "load", about = "Load a package locally")]
    Load {
        #[clap(name = "NAME", help = "Name of the package")]
        name: String,
        #[clap(short, long, default_value = "latest", help = "Version of the package")]
        version: SemVersion,
    },

    // #[clap(name = "login", about = "Log in to a registry")]
    // Login {
    //     #[clap(name = "HOST", help = "Hostname of the registry. May include a prefix URL.")]
    //     host : Hostname,

    //     #[clap(short, long, group = "identity", help = "Username of the account. Specify this if the remote instance does require secure authentication using certificates (see '--identity' in that case).")]
    //     username    : Option<String>,
    //     #[clap(short, long, group = "identity", help = "Path to the SSL certificate file to use to authenticate yourself in the remote instance. If the remote instance does not require secure authentication, consider using '--username' instead.")]
    //     certificate : Option<PathBuf>,

    //     #[clap(short, long, default_value = "50051", help = "The remote API port to connect to. You don't have to specify this if your system administrator didn't say so.")]
    //     api_port : u16,
    //     #[clap(short, long, default_value = "50053", help = "The remote driver port to connect to. You don't have to specify this if your system administrator didn't say so.")]
    //     drv_port : u16,

    //     #[clap(long, help = "If given, does not check with the remote host if the credentials are correct, but just caches them for further subcommands.")]
    //     unchecked : bool,
    // },

    // #[clap(name = "logout", about = "Log out from a registry")]
    // Logout {},

    #[clap(name = "pull", about = "Pull a package from a registry")]
    Pull {
        #[clap(name = "PACKAGES", help = "Specify one or more packages to pull from a remote. You can either give a package as 'NAME' or 'NAME:VERSION', where VERSION is assumed to be 'latest' if omitted.")]
        packages: Vec<String>,
    },

    #[clap(name = "push", about = "Push a package to a registry")]
    Push {
        #[clap(name = "PACKAGES", help = "Specify one or more packages to push to a remote. You can either give a package as 'NAME' or 'NAME:VERSION', where VERSION is assumed to be 'latest' if omitted.")]
        packages: Vec<String>,
    },

    #[clap(name = "remove", about = "Remove a local package.")]
    Remove {
        #[clap(short, long, help = "Don't ask for confirmation before removal.")]
        force: bool,
        #[clap(name = "PACKAGES", help = "Specify one or more packages to remove to a remote. You can either give a package as 'NAME' or 'NAME:VERSION', where ALL versions of the packages will be removed if VERSION is omitted..")]
        packages: Vec<String>,
    },

    #[clap(name = "repl", about = "Start an interactive DSL session")]
    Repl {
        #[clap(short, long, value_names = &["address[:port]"], help = "If given, proxies any data transfers to this machine through the proxy at the given address. Irrelevant if not running remotely.")]
        proxy_addr : Option<String>,

        #[clap(short, long, help = "Create a remote REPL session to the instance you are currently logged-in to (see `brane login`)")]
        remote : bool,
        #[clap(short, long, value_names = &["uid"], help = "Attach to an existing remote session")]
        attach : Option<AppId>,

        #[clap(short, long, action, help = "Use Bakery instead of BraneScript")]
        bakery: bool,
        #[clap(short, long, action, help = "Clear history before session")]
        clear: bool,

        #[clap(long, help = "If given, shows profile times if they are available.")]
        profile : bool,
    },

    #[clap(name = "run", about = "Run a DSL script locally")]
    Run {
        #[clap(short, long, value_names = &["address[:port]"], help = "If given, proxies any data transfers to this machine through the proxy at the given address. Irrelevant if not running remotely.")]
        proxy_addr : Option<String>,

        #[clap(short, long, action, help = "Use Bakery instead of BraneScript")]
        bakery: bool,

        #[clap(name = "FILE", help = "Path to the file to run. Use '-' to run from stdin instead.")]
        file    : PathBuf,
        #[clap(long, conflicts_with = "remote", help = "If given, uses a dummy VM in the background which never actually runs any jobs. It only returns some default value for the task's return type. Use this to run only the BraneScript part of your workflow.")]
        dry_run : bool,
        #[clap(short, long, conflicts_with = "dry_run", help = "Create a remote session to the instance you are currently logged-in to (see `brane login`)")]
        remote  : bool,

        #[clap(long, help = "If given, shows profile times if they are available.")]
        profile : bool,
    },

    #[clap(name = "test", about = "Test a package locally")]
    Test {
        #[clap(name = "NAME", help = "Name of the package")]
        name        : String,
        #[clap(short, long, default_value = "latest", help = "Version of the package")]
        version     : SemVersion,
        #[clap(short, long, help = "If given, prints the intermediate result returned by the tested function (if any). The given path should be relative to the 'result' folder.")]
        show_result : Option<PathBuf>,
    },

    #[clap(name = "search", about = "Search a registry for packages")]
    Search {
        #[clap(name = "TERM", help = "Term to use as search criteria")]
        term: Option<String>,
    },

    #[clap(name = "unpublish", about = "Remove a package from a registry")]
    Unpublish {
        #[clap(name = "NAME", help = "Name of the package")]
        name: String,
        #[clap(name = "VERSION", help = "Version of the package")]
        version: SemVersion,
        #[clap(short, long, action, help = "Don't ask for confirmation")]
        force: bool,
    },

    #[clap(name = "verify", about = "Verifies parts of Brane's configuration (useful mostly if you are in charge of an instance.")]
    Verify {
        // We subcommand further
        #[clap(subcommand)]
        subcommand : VerifySubcommand,
    },

    #[clap(name = "version", about = "Shows the version number for this Brane CLI tool and (if logged in) the remote Driver.")]
    Version {
        #[clap(short, long, action, help = "If given, shows the architecture instead of the version when using '--local' or '--remote'.")]
        arch: bool,
        #[clap(short, long, action, help = "If given, shows the local version in an easy-to-be-parsed format. Note that, if given in combination with '--remote', this one is always reported first.")]
        local: bool,
        #[clap(short, long, action, help = "If given, shows the remote Driver version in an easy-to-be-parsed format. Note that, if given in combination with '--local', this one is always reported second.")]
        remote: bool,
    },
}

/// Defines the subcommands for the `instance certs` subommand
#[derive(Parser)]
enum CertsSubcommand {
    #[clap(name = "add", about = "Adds a new CA/client certificate pair to this instance. If there are already certificates defined for this domain, will override them.")]
    Add {
        /// The path(s) to the certificate(s) to load.
        #[clap(name = "PATHS", help = "The path(s) to the certificate(s) to load. This should include at least the CA certificate for this domain, as well as a signed client certificate. Since a single certificate file may contain multiple certificates, however, specify how many you need.")]
        paths : Vec<PathBuf>,

        /// The instance for which to add it.
        #[clap(short, long, help = "The name of the instance to add the certificate to. If omitted, will add to the active instance instead (i.e., the one set with `brane instance select`). Use 'brane instance list' for an overview.")]
        instance : Option<String>,
        /// Any custom domain name.
        #[clap(short, long, help = "If given, overrides the location name found in the certificates. Note, however, that this name is used when we need to download from the domain, so should match the name of the location for which the certificates are valid.")]
        domain   : Option<String>,

        /// Whether to ask for permission before overwriting old certificates (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before overwriting old certificates. Use at your own risk.")]
        force : bool,
    },
    #[clap(name = "remove", about = "Removes the certificates for a certain domain within this instance.")]
    Remove {
        /// The name(s) of the certificate(s) to remove.
        #[clap(name = "DOMAINS", help = "The name(s) of the domain(s) for which to remove the certificates. If in doubt, consult `brane certs list`.")]
        domains : Vec<String>,

        /// The instance from which to remove them.
        #[clap(short, long, help = "The name of the instance to remove the certificates from. If omitted, will be removed from the active instance instead (i.e., the one set with `brane instance select`). Use 'brane instance list' for an overview.")]
        instance : Option<String>,

        /// Whether to query for permission or not (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before removing the certificates. Use at your own risk.")]
        force : bool,
    },

    #[clap(name = "list", about = "Lists the domains for which certificates are given.")]
    List {
        /// The instance from which to show the certificates
        #[clap(short, long, conflicts_with = "all", help = "The name of the instance to show the registered certificates in. If omitted, will list in the active instance instead (i.e., the one set with `brane instance select`). Use 'brane instance list' for an overview.")]
        instance : Option<String>,
        /// Whether to show all instances or only the given/active one.
        #[clap(short, long, conflicts_with = "instance", help = "If given, shows all certificates across all instances.")]
        all      : bool,
    },
}

/// Defines the subsubcommands for the data subcommand.
#[derive(Parser)]
enum DataSubcommand {
    #[clap(name = "build", about = "Builds a locally available dataset from the given data.yml file and associated files (if any).")]
    Build {
        #[clap(name = "FILE", help = "Path to the file to build.")]
        file       : PathBuf,
        #[clap(short, long, help = "Path to the directory to use as the 'working directory' (defaults to the folder of the package file itself)")]
        workdir    : Option<PathBuf>,
        #[clap(long, action, help = "if given, doesn't delete intermediate build files when done.")]
        keep_files : bool,
        #[clap(long, action, help = "If given, copies the dataset to the Brane data folder. Otherwise, merely soft links it (until the dataset is pushed to a remote repository). This is much more space efficient, but requires you to leave the original dataset in place.")]
        no_links   : bool,
    },

    #[clap(name = "download", about = "Attempts to download one (or more) dataset(s) from the remote instance.")]
    Download {
        /// The name of the datasets to download.
        #[clap(name = "DATASETS", help = "The datasets to attempt to download.")]
        names : Vec<String>,
        /// The locations where to download each dataset. The user should make this list as long as the names, if any.
        #[clap(short, long, help = "The location identifiers from which we download each dataset, as `name=location` pairs.")]
        locs  : Vec<String>,

        /// The address to proxy the transfer through.
        #[clap(short, long, help = "If given, proxies the transfer through the given proxy.")]
        proxy_addr : Option<String>,
        /// If given, forces the data transfer even if it's locally available.
        #[clap(short, long, action, help = "If given, will always attempt to transfer data remotely, even if it's already available locally.")]
        force      : bool,
    },

    #[clap(name = "list", about = "Shows the locally known datasets.")]
    List {},

    #[clap(name = "search", about = "Shows the datasets known in the remote instance.")]
    Search {},

    #[clap(name = "path", about = "Returns the path to the dataset of the given datasets (one returned per line), if it has a path. Returns '<none>' in that latter case.")]
    Path {
        #[clap(name = "DATASETS", help = "The name(s) of the dataset(s) to list the paths of.")]
        names : Vec<String>,
    },

    #[clap(name = "remove", about = "Removes a locally known dataset.")]
    Remove {
        #[clap(name = "DATASETS", help = "The name(s) of the dataset(s) to remove.")]
        names : Vec<String>,
        #[clap(short, long, action, help = "If given, does not ask the user for confirmation but just removes the dataset (use at your own risk!)")]
        force : bool,
    },
}

/// Defines the subcommands for the instance subommand
#[derive(Parser)]
enum InstanceSubcommand {
    #[clap(name = "add", about = "Defines a new instance to connect to.")]
    Add {
        /// The instance's hostname.
        #[clap(name = "HOSTNAME", help = "The hostname of the instance to connect to. Should not contain any ports or paths, and any scheme (e.g., 'http://') is ignored.")]
        hostname : Hostname,
        /// The port of the API service.
        #[clap(short, long, default_value = "50051", help = "The port of the API service on the remote instance. You should probably only specify this if the system administrator told you to change it.")]
        api_port : u16,
        /// The port of the driver service.
        #[clap(short, long, default_value = "50053", help = "The port of the driver service on the remote instance. You should probably only specify this if the system administrator told you to change it.")]
        drv_port : u16,

        /// Any custom name for this instance.
        #[clap(short, long, help = "Some name to set for this instance. If omitted, will set the hostname instead.")]
        name            : Option<String>,
        /// Whether to use this instance immediately or not.
        #[clap(short, long = "use", help = "If given, immediately uses this instance (i.e., acts as if `brane instance switch <name>` is called for this instance)")]
        use_immediately : bool,
        /// Whether to skip checking if the instance is alive or not.
        #[clap(long, help = "If given, skips checking if the instance is reachable.")]
        unchecked       : bool,
        /// Whether to ask for permission before overwriting old certificates (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before overwriting old certificates. Use at your own risk.")]
        force           : bool,
    },
    #[clap(name = "remove", about = "Deletes a registered instance.")]
    Remove {
        /// The name(s) of the instance(s) to remove.
        #[clap(name = "NAMES", help = "The name(s) of the instance(s) to remove. If in doubt, consult `brane instance list`.")]
        names : Vec<String>,

        /// Whether to query for permission or not (but negated).
        #[clap(short, long, help = "If given, does not ask for permission before removing the instances. Use at your own risk.")]
        force          : bool,
        /// The Docker socket location.
        #[clap(short='s', long, default_value = "/var/run/docker.sock", help = "The path to the Docker socket with which we communicate with the dameon.")]
        docker_socket  : PathBuf,
        /// The Docker client version.
        #[clap(short='v', long, default_value = "", help = "The API version with which we connect.")]
        client_version : ClientVersion,
    },

    #[clap(name = "list", about = "Lists the registered instances.")]
    List {
        /// If given, shows an additional column in the table that shows whether this instance is online or not.
        #[clap(short, long, help = "If given, shows an additional column in the table that shows whether this instance is online or not.")]
        show_status : bool,
    },
    #[clap(name = "select", about = "Switches to the registered instance with the given name.")]
    Select {
        /// The instnace's name to switch to.
        #[clap(name = "NAME", help = "The name of the instance to switch to. If in doubt, consult `brane instance list`.")]
        name : String,
    },

    #[clap(name = "edit", about = "Changes some properties of an instance.")]
    Edit {
        /// The instance's name to edit.
        #[clap(name = "NAME", help = "The name of the instance to edit if you don't want to edit the active instance. f in doubt, consult `brane instance list`.")]
        name : Option<String>,

        /// Change the hostname to this.
        #[clap(short='H', long, help = "If given, changes the hostname of this instance to the given one.")]
        hostname : Option<Hostname>,
        /// Change the API port to this.
        #[clap(short, long, help = "If given, changes the port of the API service for this instance to this.")]
        api_port : Option<u16>,
        /// Change the driver port to this.
        #[clap(short, long, help = "If given, changes the port of the driver service for this instance to this.")]
        drv_port : Option<u16>,
    },
}

/// Defines the subcommands for the verify subcommand.
#[derive(Parser)]
enum VerifySubcommand {
    #[clap(name = "config", about = "Verifies the configuration, e.g., an `infra.yml` files")]
    Config {
        #[clap(short, long, default_value = "./config/infra.yml", help = "The location of the infra.yml file to validate")]
        infra   : PathBuf,      
    },
}





/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() -> Result<()> {
    // Parse the CLI arguments
    dotenv().ok();
    let options = Cli::parse();

    // Prepare the logger
    let mut logger = env_logger::builder();
    logger.format_module_path(false);

    if options.debug {
        logger.filter_module("brane", LevelFilter::Debug).init();
    } else {
        logger.filter_module("brane", LevelFilter::Warn).init();

        setup_panic!(Metadata {
            name: "Brane CLI".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            authors: env!("CARGO_PKG_AUTHORS").replace(":", ", ").into(),
            homepage: env!("CARGO_PKG_HOMEPAGE").into(),
        });
    }

    // Check dependencies if not withheld from doing so
    if !options.skip_check {
        match brane_cli::utils::check_dependencies().await {
            Ok(Ok(()))   => {},
            Ok(Err(err)) => { eprintln!("Dependencies not met: {err}"); process::exit(1); }
            Err(err)     => { eprintln!("Could not check for dependencies: {err}"); process::exit(1); }
        }
    }

    // Create the directory structure if it does not yet exist
    if let Err(err) = generate_structure() {  }

    // Run the subcommand given
    match run(options).await {
        Ok(_) => process::exit(0),
        Err(err) => {
            eprintln!("{}: {}", style("error").bold().red(), err);
            process::exit(1);
        }
    }
}

/// **Edited: now returning CliErrors.**
/// 
/// Runs one of the subcommand as given on the Cli.
/// 
/// **Arguments**
///  * `options`: The struct with (parsed) Cli-options and subcommands.
/// 
/// **Returns**  
/// Nothing if the subcommand executed successfully (they are self-contained), or a CliError otherwise.
async fn run(options: Cli) -> Result<(), CliError> {
    use SubCommand::*;
    match options.sub_command {
        Build { arch, workdir, file, kind, init, keep_files } => {
            // Resolve the working directory
            let workdir = match workdir {
                Some(workdir) => workdir,
                None          => match std::fs::canonicalize(&file) {
                    Ok(file) => file.parent().unwrap().to_path_buf(),
                    Err(err) => { return Err(CliError::PackageFileCanonicalizeError{ path: file, err }); }
                },
            };
            let workdir = match std::fs::canonicalize(workdir) {
                Ok(workdir) => workdir,
                Err(err)    => { return Err(CliError::WorkdirCanonicalizeError{ path: file, err }); }
            };

            // Resolve the kind of the file
            let kind = if let Some(kind) = kind {
                match PackageKind::from_str(&kind) {
                    Ok(kind) => kind,
                    Err(err) => { return Err(CliError::IllegalPackageKind{ kind, err }); }
                }
            } else {
                match brane_cli::utils::determine_kind(&file) {
                    Ok(kind) => kind,
                    Err(err) => { return Err(CliError::UtilError{ err }); }
                }
            };

            // Build a new package with it
            match kind {
                PackageKind::Ecu => build_ecu::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, keep_files).await.map_err(|err| CliError::BuildError{ err })?,
                PackageKind::Oas => build_oas::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, keep_files).await.map_err(|err| CliError::BuildError{ err })?,
                _                => eprintln!("Unsupported package kind: {kind}"),
            }
        }
        Certs { subcommand } => {
            use CertsSubcommand::*;
            match subcommand {
                Add{ paths, domain, instance, force } => {
                    if let Err(err) = certs::add(instance, paths, domain, force) { return Err(CliError::CertsError{ err }); }
                }
                Remove{ domains, instance, force } => {
                    if let Err(err) = certs::remove(domains, instance, force) { return Err(CliError::CertsError{ err }); }
                }

                List{ instance, all } => {
                    if let Err(err) = certs::list(instance, all) { return Err(CliError::CertsError{ err }); }
                }
            }
        }
        Data { subcommand } => {
            // Match again
            use DataSubcommand::*;
            match subcommand {
                Build { file, workdir, keep_files, no_links } => {
                    if let Err(err) = data::build(&file, workdir.unwrap_or_else(|| file.parent().map(|p| p.into()).unwrap_or_else(|| PathBuf::from("./"))), keep_files, no_links).await { return Err(CliError::DataError { err }); }
                },
                Download{ names, locs, proxy_addr, force } => {
                    if let Err(err) = data::download(names, locs, &proxy_addr, force).await { return Err(CliError::DataError { err }); }
                },

                List {} => {
                    if let Err(err) = data::list() { return Err(CliError::DataError { err }); }
                },
                Search{} => {
                    eprintln!("search is not yet implemented.");
                    std::process::exit(1);
                },
                Path{ names } => {
                    if let Err(err) = data::path(names) { return Err(CliError::DataError { err }); }
                },

                Remove { names, force } => {
                    if let Err(err) = data::remove(names, force) { return Err(CliError::DataError{ err }); }
                },
            }
        }
        Import { arch, repo, workdir, file, kind, init } => {
            // Prepare the input URL and output directory
            let url = format!("https://github.com/{repo}");
            let dir = match tempdir() {
                Ok(dir)  => dir,
                Err(err) => { return Err(CliError::ImportError{ err: ImportError::TempDirError{ err } }); }
            };
            let dir_path = match std::fs::canonicalize(dir.path()) {
                Ok(dir_path) => dir_path,
                Err(err)     => { return Err(CliError::ImportError{ err: ImportError::TempDirCanonicalizeError{ path: dir.path().to_path_buf(), err } }); }
            };

            // Pull the repository
            if let Err(err) = Repository::clone(&url, &dir_path) {
                return Err(CliError::ImportError{ err: ImportError::RepoCloneError{ repo: url, target: dir_path, err } });
            };

            // Try to get which file we need to use as package file
            let file = match file {
                Some(file) => dir_path.join(file),
                None       => dir_path.join(brane_cli::utils::determine_file(&dir_path).map_err(|err| CliError::UtilError{ err })?),
            };
            let file = match std::fs::canonicalize(&file) {
                Ok(file) => file,
                Err(err) => { return Err(CliError::PackageFileCanonicalizeError{ path: file, err }); }
            };
            if !file.starts_with(&dir_path) { return Err(CliError::ImportError{ err: ImportError::RepoEscapeError{ path: file } }); }

            // Try to resolve the working directory relative to the repository
            let workdir = match workdir {
                Some(workdir) => dir.path().join(workdir),
                None          => file.parent().unwrap().to_path_buf(),
            };
            let workdir = match std::fs::canonicalize(workdir) {
                Ok(workdir) => workdir,
                Err(err)    => { return Err(CliError::WorkdirCanonicalizeError{ path: file, err }); }
            };
            if !workdir.starts_with(&dir_path) { return Err(CliError::ImportError{ err: ImportError::RepoEscapeError{ path: file } }); }

            // Resolve the kind of the file
            let kind = if let Some(kind) = kind {
                match PackageKind::from_str(&kind) {
                    Ok(kind) => kind,
                    Err(err) => { return Err(CliError::IllegalPackageKind{ kind, err }); }
                }
            } else {
                match brane_cli::utils::determine_kind(&file) {
                    Ok(kind) => kind,
                    Err(err) => { return Err(CliError::UtilError{ err }); }
                }
            };

            // Build a new package with it
            match kind {
                PackageKind::Ecu => build_ecu::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, false).await.map_err(|err| CliError::BuildError{ err })?,
                PackageKind::Oas => build_oas::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, false).await.map_err(|err| CliError::BuildError{ err })?,
                _                => eprintln!("Unsupported package kind: {kind}"),
            }
        }
        Inspect { name, version, syntax } => {
            if let Err(err) = packages::inspect(name, version, syntax) { return Err(CliError::OtherError{ err }); };
        }
        Instance { subcommand } => {
            // Switch on the subcommand
            use InstanceSubcommand::*;
            match subcommand {
                Add{ hostname, api_port, drv_port, name, use_immediately, unchecked, force } => {
                    if let Err(err) = instance::add(name.unwrap_or_else(|| hostname.hostname.clone()), hostname, api_port, drv_port, use_immediately, unchecked, force).await { return Err(CliError::InstanceError{ err }); }
                }
                Remove{ names, force } => {
                    if let Err(err) = instance::remove(names, force) { return Err(CliError::InstanceError{ err }); }
                }

                List{ show_status } => {
                    if let Err(err) = instance::list(show_status).await { return Err(CliError::InstanceError { err }); }
                }
                Select{ name } => {
                    if let Err(err) = instance::select(name) { return Err(CliError::InstanceError{ err }); }
                }

                Edit{ name, hostname, api_port, drv_port } => {
                    if let Err(err) = instance::edit(name, hostname, api_port, drv_port) { return Err(CliError::InstanceError{ err }); }
                }
            }
        }
        List { latest } => {
            if let Err(err) = packages::list(latest) { return Err(CliError::OtherError{ err: anyhow::anyhow!(err) }); };
        }
        Load { name, version } => {
            if let Err(err) = packages::load(name, version).await { return Err(CliError::OtherError{ err }); };
        }
        Pull { packages } => {
            // Parse the NAME:VERSION pairs into a name and a version
            if packages.is_empty() { println!("Nothing to do."); return Ok(()); }
            let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
            for package in &packages {
                parsed.push(match SemVersion::from_package_pair(package) {
                    Ok(pair) => pair,
                    Err(err) => { return Err(CliError::PackagePairParseError{ raw: package.into(), err }); }
                })
            }

            // Now delegate the parsed pairs to the actual pull() function
            if let Err(err) = registry::pull(parsed).await { return Err(CliError::RegistryError{ err }); };
        }
        Push { packages } => {
            // Parse the NAME:VERSION pairs into a name and a version
            if packages.is_empty() { println!("Nothing to do."); return Ok(()); }
            let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
            for package in packages {
                parsed.push(match SemVersion::from_package_pair(&package) {
                    Ok(pair) => pair,
                    Err(err) => { return Err(CliError::PackagePairParseError{ raw: package, err }); }
                })
            }

            // Now delegate the parsed pairs to the actual push() function
            if let Err(err) = registry::push(parsed).await { return Err(CliError::RegistryError{ err }); };
        }
        Remove { force, packages } => {
            // Parse the NAME:VERSION pairs into a name and a version
            if packages.is_empty() { println!("Nothing to do."); return Ok(()); }
            let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
            for package in packages {
                parsed.push(match SemVersion::from_package_pair(&package) {
                    Ok(pair) => pair,
                    Err(err) => { return Err(CliError::PackagePairParseError{ raw: package, err }); }
                })
            }

            // Now delegate the parsed pairs to the actual remove() function
            if let Err(err) = packages::remove(force, parsed).await { return Err(CliError::PackageError{ err }); };
        }
        Repl { proxy_addr, bakery, clear, remote, attach, profile } => {
            if let Err(err) = repl::start(proxy_addr, remote, attach, if bakery { Language::Bakery } else { Language::BraneScript }, clear, profile).await { return Err(CliError::ReplError{ err }); };
        }
        Run { proxy_addr, bakery, file, dry_run, remote, profile } => {
            if let Err(err) = run::handle(proxy_addr, if bakery { Language::Bakery } else { Language::BraneScript }, file, dry_run, remote, profile).await { return Err(CliError::RunError{ err }); };
        }
        Test { name, version, show_result } => {
            if let Err(err) = test::handle(name, version, show_result).await { return Err(CliError::TestError{ err }); };
        }
        Search { term } => {
            if let Err(err) = registry::search(term).await { return Err(CliError::OtherError{ err }); };
        }
        Unpublish { name, version, force } => {
            if let Err(err) = registry::unpublish(name, version, force).await { return Err(CliError::OtherError{ err }); };
        }
        Verify { subcommand } => {
            // Match the subcommand in question
            use VerifySubcommand::*;
            match subcommand {
                Config { infra } => {
                    // Verify the configuration
                    if let Err(err) = verify::config(infra) { return Err(CliError::VerifyError{ err }); }
                    println!("OK");
                },
            }
        }
        Version { arch, local, remote } => {
            if local || remote {
                // If any of local or remote is given, do those
                if arch {
                    if local  { if let Err(err) = version::handle_local_arch()        { return Err(CliError::VersionError{ err }); } }
                    if remote { if let Err(err) = version::handle_remote_arch().await { return Err(CliError::VersionError{ err }); } }
                } else {
                    if local  { if let Err(err) = version::handle_local_version()        { return Err(CliError::VersionError{ err }); } }
                    if remote { if let Err(err) = version::handle_remote_version().await { return Err(CliError::VersionError{ err }); } }
                }

            } else {
                // Print neatly
                if let Err(err) = version::handle().await { return Err(CliError::VersionError{ err }); }
            }
        }
    }

    Ok(())
}
