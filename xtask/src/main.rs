//! xtask is the main build tool for Brane. If there is something you have to repeatedly or
//! something you have to do in CI, this is probably the place to add it.

mod build;
mod cli;
mod external_cli;
mod package;
mod registry;
mod utilities;

#[cfg(feature = "cli")]
mod completions;
#[cfg(feature = "cli")]
mod install;
#[cfg(feature = "cli")]
mod man;

#[cfg(feature = "ci")]
mod set_version;

use anyhow::Context as _;
use clap::Parser;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
#[cfg(feature = "cli")]
use {std::path::PathBuf, utilities::ensure_dir_with_cachetag};

const LOG_LEVEL_ENV_VAR: &str = "BRANE_LOG";
const DEFAULT_LOG_LEVEL: tracing::Level = tracing::Level::INFO;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = cli::xtask::Cli::parse();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().without_time().with_target(false))
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var(LOG_LEVEL_ENV_VAR)
                .with_default_directive(DEFAULT_LOG_LEVEL.into())
                .from_env_lossy(),
        )
        .init();

    use cli::xtask::XTaskSubcommand;
    match opts.subcommand {
        #[cfg(feature = "cli")]
        XTaskSubcommand::Completions { target, shell } => {
            let destination = PathBuf::from("./target/completions");
            ensure_dir_with_cachetag(&destination).context("Could not create directory with CACHEDIR.TAG")?;
            completions::generate_by_target(target.map(|x| x.0), shell, destination)?;
        },
        #[cfg(feature = "cli")]
        XTaskSubcommand::Man { target, compressed } => {
            let destination = PathBuf::from("./target/man");
            ensure_dir_with_cachetag(&destination).context("Could not create directory with CACHEDIR.TAG")?;
            man::generate_by_target(target.map(|x| x.0), destination, compressed, true)?
        },
        #[cfg(feature = "cli")]
        XTaskSubcommand::Install { parents, force } => {
            install::completions(parents, force)?;
            install::binaries(parents, force)?;
            install::manpages(parents, force)?;
        },
        #[cfg(feature = "cli")]
        XTaskSubcommand::Uninstall {} => {
            install::uninstall()?;
        },
        XTaskSubcommand::Package { platform } => match platform {
            cli::xtask::PackagePlatform::GitHub => {
                package::create_github_package().await.context("Could not create package for GitHub")?;
            },
        },
        XTaskSubcommand::Build { targets } => {
            build::build(&targets).context("Could not build all targets")?;
        },
        #[cfg(feature = "ci")]
        XTaskSubcommand::SetVersion { semver, prerelease, metadata } => {
            set_version::set_version(semver, prerelease, metadata).context("Could not rewrite version")?;
        },
    }

    Ok(())
}
