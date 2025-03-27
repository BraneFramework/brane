#![allow(dead_code)]
use std::fs::File;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::generate;
use clap_complete::shells::Shell;

const SHELLS: [(&str, Shell); 3] = [("bash", Shell::Bash), ("fish", Shell::Fish), ("zsh", Shell::Zsh)];

mod completions {
    pub(crate) mod ctl {
        include!("../../brane-ctl/src/cli.rs");
    }
    pub(crate) mod cli {
        include!("../../brane-cli/src/cli.rs");
    }
}

#[derive(Debug, Parser)]
#[clap(name = "xtask")]
struct Arguments {
    #[clap(subcommand)]
    pub(crate) subcommand: XTaskSubcommand,
}

#[derive(Debug, Subcommand)]
enum XTaskSubcommand {
    #[clap(name = "completions")]
    Completions {
        #[clap(long)]
        shell:  Option<String>,
        #[clap(name = "binary")]
        binary: Binary,
    },
    #[clap(name = "manpage")]
    ManPage { binary: Binary },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Binary {
    #[clap(name = "branectl")]
    Branectl,
    #[clap(name = "brane")]
    Brane,
    #[clap(name = "xtask")]
    XTask,
}

impl Binary {
    fn to_binary_name(self) -> &'static str {
        use Binary::*;
        match self {
            Branectl => "branectl",
            Brane => "brane",
            XTask => "xtask",
        }
    }

    fn to_command(self) -> clap::Command {
        use Binary::*;
        match self {
            Branectl => completions::ctl::Cli::command(),
            Brane => completions::cli::Cli::command(),
            XTask => Arguments::command(),
        }
    }
}

fn main() {
    let opts = Arguments::parse();
    match opts.subcommand {
        XTaskSubcommand::Completions { binary, shell } => {
            let bin_name = binary.to_binary_name();
            let mut command = binary.to_command();

            if let Some(shell) = shell {
                if let Some((extension, sh)) = SHELLS.iter().find(|(name, _)| *name == shell) {
                    let mut file = File::create(format!("{bin_name}.{extension}")).expect("Could not open/create completions file");
                    generate(*sh, &mut command, bin_name, &mut file);
                }
            } else {
                for (extension, shell) in SHELLS {
                    let mut file = File::create(format!("{bin_name}.{extension}")).expect("Could not open/create completions file");
                    generate(shell, &mut command, bin_name, &mut file);
                }
            }
        },
        XTaskSubcommand::ManPage { binary } => {
            let out_dir = PathBuf::from("./");

            let name = binary.to_binary_name();
            let command = binary.to_command();

            let man = clap_mangen::Man::new(command);

            let mut buffer: Vec<u8> = Default::default();
            man.render(&mut buffer).unwrap();

            std::fs::write(out_dir.join(format!("{name}.1")), buffer).unwrap();
        },
    }
}
