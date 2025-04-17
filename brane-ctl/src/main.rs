//  MAIN.rs
//    by Lut99
//
//  Created:
//    15 Nov 2022, 09:18:40
//  Last edited:
//    01 May 2024, 15:20:07
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `branectl` executable.
//

pub mod cli;
use std::fmt::Display;

use brane_cfg::proxy::ForwardConfig;
use brane_ctl::spec::{LogsOpts, StartOpts};
use brane_ctl::{download, generate, lifetime, packages, policies, unpack, upgrade, wizard};
use brane_tsk::docker::DockerOptions;
use clap::Parser;
use cli::*;
use dotenvy::dotenv;
use error_trace::ErrorTrace as _;
use tracing::error;
use tracing::level_filters::LevelFilter;


/***** CONSTANTS *****/
/// The default log level for tracing_subscriber. Levels higher than this will be discarded.
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::WARN;
/// The environment variable used by env-filter in tracing subscriber
const LOG_LEVEL_ENV_VAR: &str = "BRANE_CTL_LOG";

#[derive(Debug)]
struct CtlError {
    inner: Box<dyn std::error::Error>,
}

// impl std::error::Error for CtlError {}
impl<T: std::error::Error + 'static> From<T> for CtlError {
    fn from(value: T) -> Self { Self { inner: Box::new(value) } }
}

impl Display for CtlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        tracing::error!("{}", self.inner.trace());
        write!(f, "Houston, we have a problem")?;
        write!(f, "{}", self.inner.trace())
    }
}

/***** ENTYRPOINT *****/
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), CtlError> {
    // Load the .env file
    dotenv().ok();

    // Parse the arguments
    let args = cli::Cli::parse();

    // Note that this can still be overriden by an environment variable
    let cli_log_level = args.logging.log_level(DEFAULT_LOG_LEVEL);
    let _otel_guard = specifications::tracing::setup_subscriber_with_otel(LOG_LEVEL_ENV_VAR, cli_log_level);

    let span = tracing::span!(tracing::Level::ERROR, "Testing");
    let _guard = span.enter();

    // Setup the friendlier version of panic
    if !args.logging.trace && !args.logging.debug {
        human_panic::setup_panic!();
    }

    if let Err(e) = run(args).await {
        tracing::error!("{}", e.inner.trace());
    }

    Ok(())
}

async fn run(args: cli::Cli) -> Result<(), CtlError> {
    // Now match on the command
    match args.subcommand {
        CtlSubcommand::Download(subcommand) => match *subcommand {
            DownloadSubcommand::Services { fix_dirs, path, arch, version, force, kind } => {
                download::services(fix_dirs, path, arch, version, force, kind).await?
            },
        },
        CtlSubcommand::Generate(subcommand) => match *subcommand {
            GenerateSubcommand::Node { hosts, fix_dirs, config_path, kind } => generate::node(args.node_config, hosts, fix_dirs, config_path, *kind)?,

            GenerateSubcommand::Certs { fix_dirs, path, temp_dir, kind } => generate::certs(fix_dirs, path, temp_dir, *kind).await?,

            GenerateSubcommand::Infra { locations, fix_dirs, path, names, reg_ports, job_ports } => {
                generate::infra(locations, fix_dirs, path, names, reg_ports, job_ports)?
            },

            GenerateSubcommand::Backend { fix_dirs, path, capabilities, disable_hashing, kind } => {
                generate::backend(fix_dirs, path, capabilities, !disable_hashing, *kind)?
            },

            GenerateSubcommand::PolicyDatabase { fix_dirs, path, branch } => generate::policy_database(fix_dirs, path, branch).await?,
            GenerateSubcommand::PolicySecret { fix_dirs, path, key_id, jwt_alg } => generate::policy_secret(fix_dirs, path, key_id, jwt_alg)?,
            GenerateSubcommand::PolicyToken { initiator, system, exp, fix_dirs, path, secret_path } => {
                generate::policy_token(fix_dirs, path, secret_path, initiator, system, *exp)?
            },

            GenerateSubcommand::Proxy { fix_dirs, path, outgoing_range, incoming, forward, forward_protocol } => generate::proxy(
                fix_dirs,
                path,
                outgoing_range.0,
                incoming.into_iter().map(|p| (p.0, p.1)).collect(),
                forward.map(|a| ForwardConfig { address: a, protocol: forward_protocol }),
            )?,
        },
        CtlSubcommand::Upgrade(subcommand) => match *subcommand {
            UpgradeSubcommand::Node { path, dry_run, overwrite, version } => upgrade::node(path, dry_run, overwrite, version)?,
        },
        CtlSubcommand::Unpack(subcommand) => match *subcommand {
            UnpackSubcommand::Compose { kind, path, fix_dirs } => unpack::compose(kind, fix_dirs, path, args.node_config)?,
        },
        CtlSubcommand::Wizard(subcommand) => match *subcommand {
            WizardSubcommand::Setup {} => wizard::setup()?,
        },

        CtlSubcommand::Packages(subcommand) => match *subcommand {
            PackageSubcommand::Hash { image } => packages::hash(args.node_config, image).await?,
        },
        CtlSubcommand::Data(subcommand) => match *subcommand {},
        CtlSubcommand::Policies(subcommand) => match *subcommand {
            PolicySubcommand::Activate { version, address, token } => policies::activate(args.node_config, version, address, token).await?,

            PolicySubcommand::Add { input, language, address, token } => {
                // Call the thing
                policies::add(args.node_config, input, language, address, token).await?
            },

            PolicySubcommand::List { address, token } => {
                // Call the thing
                policies::list(args.node_config, address, token).await?
            },
        },

        CtlSubcommand::Start { exe, file, docker_socket, docker_version, version, image_dir, local_aux, skip_import, profile_dir, kind } => {
            lifetime::start(
                exe,
                file,
                args.node_config,
                DockerOptions { socket: docker_socket, version: docker_version },
                // FIXME: Drop compose verbose?
                StartOpts { compose_verbose: args.logging.debug || args.logging.trace, version, image_dir, local_aux, skip_import, profile_dir },
                *kind,
            )
            .await?
        },
        CtlSubcommand::Stop { exe, file } => {
            // FIXME: Drop compose verbose?
            lifetime::stop(args.logging.debug || args.logging.trace, exe, file, args.node_config)?
        },
        CtlSubcommand::Logs { exe, file } => {
            // FIXME: Drop compose verbose?
            lifetime::logs(exe, file, args.node_config, LogsOpts { compose_verbose: args.logging.debug || args.logging.trace }).await?
        },

        CtlSubcommand::Version { arch: _, kind: _, ctl: _, node: _ } => (),
    };

    Ok(())
}
