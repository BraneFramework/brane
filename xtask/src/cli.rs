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
        Completions {
            #[clap(short, long)]
            shell:  Option<Shell>,
            #[clap(short, long)]
            target: Option<ClapTarget>,
        },
        #[cfg(feature = "cli")]
        Man {
            #[clap(short, long)]
            target:     Option<ClapTarget>,
            #[clap(short, long)]
            compressed: bool,
        },
        #[cfg(feature = "cli")]
        Install {
            #[clap(short, long, help = "Create all necessary directories")]
            force: bool,
        },
        Package {
            /// The platform the package is built for
            platform: PackagePlatform,
        },
        Build {
            targets: Vec<String>,
        },
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
