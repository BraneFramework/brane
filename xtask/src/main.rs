#![allow(dead_code)]

mod build;
mod cli;
mod package;
mod registry;
mod utilities;

#[cfg(feature = "cli")]
mod completions;
#[cfg(feature = "cli")]
mod external_cli;
#[cfg(feature = "cli")]
mod install;
#[cfg(feature = "cli")]
mod man;

use anyhow::Context as _;
use clap::Parser;
use clap_complete::shells::Shell;
#[cfg(feature = "cli")]
use {
    clap::builder::PossibleValue,
    clap::{CommandFactory, ValueEnum},
    std::sync::OnceLock,
    strum::{EnumIter, IntoEnumIterator},
};

const SHELLS: [Shell; 3] = [Shell::Bash, Shell::Fish, Shell::Zsh];

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = cli::xtask::Cli::parse();
    use cli::xtask::XTaskSubcommand;
    match opts.subcommand {
        #[cfg(feature = "cli")]
        XTaskSubcommand::Completions { binary, shell } => {
            completions::generate(binary, shell);
        },
        #[cfg(feature = "cli")]
        XTaskSubcommand::Man { target } => {
            let targets = match target {
                Some(target) => &[target][..],
                None => Target::value_variants(),
            };
            for target in targets {
                man::create_recursive(target.to_command(), "", true)?;
            }
        },
        #[cfg(feature = "cli")]
        XTaskSubcommand::Install { force } => {
            install::completions(force)?;
            install::binaries(force)?;
        },
        XTaskSubcommand::Package { kind } => match kind {
            cli::xtask::PackageKind::GitHub => {
                package::create_github_package().await.context("Could not create package for GitHub")?;
            },
        },
        XTaskSubcommand::Build { targets } => {
            build::build(&targets).context("Could not build all targets")?;
        },
    }

    Ok(())
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Target {
    Binary(Binary),
    ContainerBinary(ContainerBinary),
    Image(Image),
}

#[cfg(feature = "cli")]
impl ValueEnum for Target {
    fn value_variants<'a>() -> &'a [Self] {
        static INSTANCE: OnceLock<Box<[Target]>> = OnceLock::new();

        INSTANCE.get_or_init(|| {
            std::iter::empty()
                .chain(Binary::iter().map(Self::Binary))
                .chain(ContainerBinary::iter().map(Self::ContainerBinary))
                .chain(Image::iter().map(Self::Image))
                .collect::<Box<[_]>>()
        })
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self {
            Target::Binary(b) => b.to_possible_value(),
            Target::ContainerBinary(c) => c.to_possible_value(),
            Target::Image(i) => i.to_possible_value(),
        }
    }
}

#[cfg(feature = "cli")]
impl Target {
    pub(crate) fn to_command(self) -> clap::Command {
        match self {
            Target::Binary(x) => x.to_command(),
            Target::ContainerBinary(x) => x.to_command(),
            Target::Image(x) => x.to_command(),
        }
    }
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, Copy, ValueEnum, EnumIter)]
pub(crate) enum Binary {
    // Binaries
    #[clap(name = "branectl")]
    BraneCtl,
    #[clap(name = "brane")]
    Brane,
    #[clap(name = "branec")]
    BraneC,

    #[clap(name = "xtask")]
    XTask,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, Copy, ValueEnum, EnumIter)]
pub(crate) enum ContainerBinary {
    // Images
    #[clap(name = "branelet")]
    BraneLet,
}

#[cfg(feature = "cli")]
#[derive(Debug, Clone, Copy, ValueEnum, EnumIter)]
pub(crate) enum Image {
    #[clap(name = "brane-api")]
    BraneAPI,
    #[clap(name = "brane-drv")]
    BraneDrv,
    #[clap(name = "brane-job")]
    BraneJob,
    #[clap(name = "brane-plr")]
    BranePlr,
    #[clap(name = "brane-prx")]
    BranePrx,
    #[clap(name = "brane-reg")]
    BraneReg,
}

#[cfg(feature = "cli")]
impl Binary {
    // pub(crate) fn to_binary_name(self) -> &'static str {
    //     use Binary::*;
    //     match self {
    //         Branectl => "branectl",
    //         Brane => "brane",
    //         BraneC => "branec",
    //
    //         XTask => "xtask",
    //     }
    // }

    pub(crate) fn to_command(self) -> clap::Command {
        use Binary::*;
        match self {
            BraneCtl => crate::external_cli::ctl::Cli::command(),
            Brane => crate::external_cli::cli::Cli::command(),
            BraneC => crate::external_cli::cc::Cli::command(),

            XTask => crate::cli::xtask::Cli::command(),
        }
    }
}

#[cfg(feature = "cli")]
impl ContainerBinary {
    pub(crate) fn to_command(self) -> clap::Command {
        match self {
            ContainerBinary::BraneLet => crate::external_cli::blet::Cli::command(),
        }
    }
}

#[cfg(feature = "cli")]
impl Image {
    pub(crate) fn to_command(self) -> clap::Command {
        match self {
            Image::BraneAPI => crate::external_cli::api::Cli::command(),
            Image::BraneDrv => crate::external_cli::drv::Cli::command(),
            Image::BraneJob => crate::external_cli::job::Cli::command(),
            Image::BranePlr => crate::external_cli::plr::Cli::command(),
            Image::BranePrx => crate::external_cli::prx::Cli::command(),
            Image::BraneReg => crate::external_cli::reg::Cli::command(),
        }
    }
}
