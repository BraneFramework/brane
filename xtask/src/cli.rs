#[cfg(feature = "cli")]
use {
    crate::registry::{REGISTRY, Target, build_registry},
    clap::{ValueEnum, builder::PossibleValue},
    std::{
        env::consts::{ARCH, OS},
        sync::OnceLock,
    },
};

pub(crate) mod xtask {
    use clap::{Parser, Subcommand, ValueEnum};
    #[cfg(feature = "cli")]
    use clap_complete::Shell;

    #[cfg(feature = "cli")]
    use super::ClapTarget;

    #[derive(Debug, Parser)]
    #[clap(name = "xtask")]
    pub(crate) struct Cli {
        #[clap(subcommand)]
        pub(crate) subcommand: XTaskSubcommand,
    }

    #[derive(Debug, Subcommand)]
    pub(crate) enum XTaskSubcommand {
        #[cfg(feature = "cli")]
        /// Builds completion files for shells for either specified or all binaries
        Completions {
            #[clap(short, long)]
            /// The shell for which to build the completion
            shell:  Option<Shell>,
            #[clap(short, long)]
            /// The binary for which to build the completion
            target: Option<ClapTarget>,
        },
        #[cfg(feature = "cli")]
        /// Builds man pages for all Brane binaries
        Man {
            /// What target to create a manpage for
            #[clap(short, long)]
            target:     Option<ClapTarget>,
            /// Whether or not to compress the generated manpages
            #[clap(short, long)]
            compressed: bool,
        },
        #[cfg(feature = "cli")]
        /// Installs Brane in the relevant user directories
        Install {
            /// Whether or not to create all necessary directories if they don't exist
            #[clap(short, long)]
            force: bool,
        },
        /// Packages brane for the specified platform
        Package {
            /// The platform the package is built for
            platform: PackagePlatform,
        },
        /// Builds a set of predefined targets for Brane
        Build {
            /// The targets to build
            targets: Vec<String>,
        },
        #[cfg(feature = "ci")]
        /// Sets updates the verion of the package.
        /// Warning: This command was made for CI, and will restructure your Cargo.toml, this is
        /// fine in ephemeral environments like CI, but is probably a dealbreaking in user
        /// environments
        SetVersion {
            #[clap(short, long)]
            semver:     Option<String>,
            #[clap(short, long)]
            prerelease: Option<String>,
            #[clap(short, long)]
            metadata:   Option<String>,
        },
    }

    #[derive(ValueEnum, Debug, Clone)]
    pub(crate) enum PackagePlatform {
        #[clap(name = "github")]
        GitHub,
    }
}

#[cfg(feature = "cli")]
/// Wrapper for [`Target`]s that contain a [`clap::Command`]. This implements [`ValueEnum`], so we can
/// use clap to filter which targets have a clap CLI that we can parse, e.g. for creating manpages.
#[derive(Debug, Clone)]
pub(crate) struct ClapTarget(pub Target);

#[cfg(feature = "cli")]
impl ValueEnum for ClapTarget {
    fn value_variants<'a>() -> &'a [Self] {
        static INSTANCE: OnceLock<Box<[ClapTarget]>> = OnceLock::new();

        let targets = INSTANCE.get_or_init(|| {
            let reg = REGISTRY.get_or_init(build_registry);
            reg.list_targets(OS, ARCH).filter(|target| target.command.is_some()).cloned().map(Self).collect()
        });

        targets
    }

    fn to_possible_value(&self) -> Option<PossibleValue> { Some(self.0.package_name.clone().into()) }
}
