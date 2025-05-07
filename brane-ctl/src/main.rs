//  MAIN.rs
//    by Lut99
//
//  Created:
//    15 Nov 2022, 09:18:40
//  Last edited:
//    19 Nov 2024, 14:46:33
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `branectl` executable.
//

pub mod cli;

use brane_cfg::proxy::ForwardConfig;
use brane_ctl::spec::{LogsOpts, StartOpts};
use brane_ctl::{download, generate, lifetime, packages, policies, unpack, upgrade, wizard};
use brane_tsk::docker::DockerOptions;
use clap::Parser;
use cli::*;
use dotenvy::dotenv;
use error_trace::ErrorTrace as _;
use humanlog::{DebugMode, HumanLogger};
use log::error;



/***** ENTYRPOINT *****/
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Load the .env file
    dotenv().ok();

    // Parse the arguments
    let args = cli::Cli::parse();

    // Initialize the logger
    if let Err(err) = HumanLogger::terminal(if args.trace {
        DebugMode::Full
    } else if args.debug {
        DebugMode::Debug
    } else {
        DebugMode::HumanFriendly
    })
    .init()
    {
        eprintln!("WARNING: Failed to setup logger: {err} (no logging for this session)");
    }

    // Setup the friendlier version of panic
    if !args.trace && !args.debug {
        human_panic::setup_panic!();
    }

    // Now match on the command
    match args.subcommand {
        CtlSubcommand::Download(subcommand) => match *subcommand {
            DownloadSubcommand::Services { fix_dirs, path, arch, version, force, kind } => {
                // Run the subcommand
                if let Err(err) = download::services(fix_dirs, path, arch, version, force, kind).await {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },
        CtlSubcommand::Generate(subcommand) => match *subcommand {
            GenerateSubcommand::Node { hosts, fix_dirs, config_path, kind } => {
                // Call the thing
                if let Err(err) = generate::node(args.node_config, hosts, fix_dirs, config_path, *kind) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },

            GenerateSubcommand::Certs { fix_dirs, path, temp_dir, kind } => {
                // Call the thing
                if let Err(err) = generate::certs(fix_dirs, path, temp_dir, *kind).await {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },

            GenerateSubcommand::Infra { locations, fix_dirs, path, names, reg_ports, job_ports } => {
                // Call the thing
                if let Err(err) = generate::infra(locations, fix_dirs, path, names, reg_ports, job_ports) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },

            GenerateSubcommand::Backend { fix_dirs, path, capabilities, disable_hashing, kind } => {
                // Call the thing
                if let Err(err) = generate::backend(fix_dirs, path, capabilities, !disable_hashing, *kind) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },

            GenerateSubcommand::PolicyDatabase { fix_dirs, path } => {
                // Call the thing
                if let Err(err) = generate::policy_database(fix_dirs, path).await {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
            GenerateSubcommand::PolicySecret { fix_dirs, path, key_id, jwt_alg } => {
                // Call the thing
                if let Err(err) = generate::policy_secret(fix_dirs, path, key_id, jwt_alg) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
            GenerateSubcommand::PolicyToken { initiator, system, exp, fix_dirs, path, secret_path } => {
                // Call the thing
                if let Err(err) = generate::policy_token(fix_dirs, path, secret_path, initiator, system, *exp) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },

            GenerateSubcommand::Proxy { fix_dirs, path, outgoing_range, incoming, forward, forward_protocol } => {
                // Call the thing
                if let Err(err) = generate::proxy(
                    fix_dirs,
                    path,
                    outgoing_range.0,
                    incoming.into_iter().map(|p| (p.0, p.1)).collect(),
                    forward.map(|a| ForwardConfig { address: a, protocol: forward_protocol }),
                ) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },
        CtlSubcommand::Upgrade(subcommand) => match *subcommand {
            UpgradeSubcommand::Node { path, dry_run, overwrite, version } => {
                if let Err(err) = upgrade::node(path, dry_run, overwrite, version) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },
        CtlSubcommand::Unpack(subcommand) => match *subcommand {
            UnpackSubcommand::Compose { kind, path, fix_dirs } => {
                if let Err(err) = unpack::compose(kind, fix_dirs, path, args.node_config) {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },
        CtlSubcommand::Wizard(subcommand) => match *subcommand {
            WizardSubcommand::Setup {} => {
                if let Err(err) = wizard::setup() {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },

        CtlSubcommand::Packages(subcommand) => match *subcommand {
            PackageSubcommand::Hash { image } => {
                // Call the thing
                if let Err(err) = packages::hash(args.node_config, image).await {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },
        CtlSubcommand::Data(subcommand) => match *subcommand {},
        CtlSubcommand::Policies(subcommand) => match *subcommand {
            PolicySubcommand::Activate { version, address, token } => {
                // Call the thing
                if let Err(err) = policies::activate(args.node_config, version, address, token).await {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },

            PolicySubcommand::Add { input, language, address, token } => {
                // Call the thing
                if let Err(err) = policies::add(args.node_config, input, language, address, token).await {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },

            PolicySubcommand::List { address, token } => {
                // Call the thing
                if let Err(err) = policies::list(args.node_config, address, token).await {
                    error!("{}", err.trace());
                    std::process::exit(1);
                }
            },
        },

        CtlSubcommand::Start { exe, file, docker_socket, docker_version, version, image_dir, local_aux, skip_import, profile_dir, kind } => {
            if let Err(err) = lifetime::start(
                exe,
                file,
                args.node_config,
                DockerOptions { socket: docker_socket, version: docker_version },
                StartOpts { compose_verbose: args.debug || args.trace, version, image_dir, local_aux, skip_import, profile_dir },
                *kind,
            )
            .await
            {
                error!("{}", err.trace());
                std::process::exit(1);
            }
        },
        CtlSubcommand::Stop { exe, file } => {
            if let Err(err) = lifetime::stop(args.debug || args.trace, exe, file, args.node_config) {
                error!("{}", err.trace());
                std::process::exit(1);
            }
        },
        CtlSubcommand::Logs { exe, file } => {
            if let Err(err) = lifetime::logs(exe, file, args.node_config, LogsOpts { compose_verbose: args.debug || args.trace }).await {
                error!("{}", err.trace());
                std::process::exit(1);
            }
        },

        CtlSubcommand::Version { arch: _, kind: _, ctl: _, node: _ } => {},
    }
}
