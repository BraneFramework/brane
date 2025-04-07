#![allow(dead_code)]

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
use clap_complete::shells::Shell;

const SHELLS: [Shell; 3] = [Shell::Bash, Shell::Fish, Shell::Zsh];

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = cli::xtask::Cli::parse();
    use cli::xtask::XTaskSubcommand;
    match opts.subcommand {
        #[cfg(feature = "cli")]
        XTaskSubcommand::Completions { target, shell } => {
            completions::generate(target.map(|x| x.0), shell)?;
        },
        #[cfg(feature = "cli")]
        XTaskSubcommand::Man { target, compressed } => man::create(target.map(|x| x.0), compressed)?,
        #[cfg(feature = "cli")]
        XTaskSubcommand::Install { force } => {
            install::completions(force)?;
            install::binaries(force)?;
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
