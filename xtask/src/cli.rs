//! Module with the command line interface for xtask. Note that this is different from the external
//! CLIs from other packages, which are defined in module [`crate::external_cli`].
#[cfg(feature = "cli")]
use {
    crate::registry::{self, Target},
    clap::{ValueEnum, builder::PossibleValue},
    std::{
        env::consts::{ARCH, OS},
        sync::OnceLock,
    },
};

/// Module containing the command line interface of xtask.
pub(crate) mod xtask {
    use clap::{Parser, Subcommand, ValueEnum};
    #[cfg(feature = "cli")]
    use clap_complete::Shell;

    #[cfg(feature = "cli")]
    use super::ClapTarget;

    // xtask is the main build tool for Brane. If there is something you have to repeatedly or
    // something you have to do in CI, this is probably the place to do so.
    #[derive(Debug, Parser)]
    #[clap(name = "xtask", version, author)]
    pub(crate) struct Cli {
        /// The various actions xtask can perform for you.
        #[clap(subcommand)]
        pub(crate) subcommand: XTaskSubcommand,
    }

    /// The various actions xtask can perform.
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
        /// Uninstall Brane from all the relevant user directories
        /// Note that this does not care what is placed there, if Brane would install there, its
        /// now gone
        Uninstall {},
        #[cfg(feature = "cli")]
        /// Installs Brane in the relevant user directories
        Install {
            /// Create all necessary directories if they don't exist
            #[clap(short, long)]
            parents: bool,
            /// Overwrite files if they already exist
            #[clap(short, long)]
            force:   bool,
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
            /// The semantic version to use.
            #[clap(short, long)]
            semver:     Option<String>,
            /// The prerelease to use, added after the semantic version with a '-' delimiter.
            #[clap(short, long)]
            // FIXME: Restrict allowed characters
            prerelease: Option<String>,
            /// The metadata to use, added after the prerelease with a '+' delimiter.
            // FIXME: Restrict allowed characters
            #[clap(short, long)]
            metadata:   Option<String>,
        },
    }

    #[derive(ValueEnum, Debug, Clone)]
    pub(crate) enum PackagePlatform {
        /// For GitHub releases.
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
            let reg = registry::registry();
            reg.list_targets(OS, ARCH).filter(|target| target.command.is_some()).cloned().map(Self).collect()
        });

        targets
    }

    fn to_possible_value(&self) -> Option<PossibleValue> { Some(self.0.package_name.clone().into()) }
}
