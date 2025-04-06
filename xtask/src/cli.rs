pub(crate) mod xtask {
    use clap::{Parser, Subcommand, ValueEnum};
    #[cfg(feature = "cli")]
    use clap_complete::Shell;

    #[cfg(feature = "cli")]
    use crate::{Binary, Target};

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
            binary: Option<Binary>,
        },
        #[cfg(feature = "cli")]
        Man {
            #[clap(short, long)]
            target: Option<Target>,
        },
        #[cfg(feature = "cli")]
        Install {
            #[clap(short, long, help = "Create all necessary directories")]
            force: bool,
        },
        Package {
            kind: PackageKind,
        },
        Build {
            targets: Vec<String>,
        },
    }

    #[derive(ValueEnum, Debug, Clone)]
    pub(crate) enum PackageKind {
        #[clap(name = "github")]
        GitHub,
    }
}
