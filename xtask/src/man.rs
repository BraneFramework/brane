use std::env::consts::{ARCH, OS};
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::Context;
use clap::Command;

use crate::registry::{REGISTRY, Target, build_registry};
use crate::utilities::ensure_dir_with_cachetag;

pub(crate) fn create(target: Option<Target>, compressed: bool) -> anyhow::Result<()> {
    let targets = match target {
        Some(target) => &[target][..],
        None => &REGISTRY.get_or_init(build_registry).list_targets(OS, ARCH).cloned().collect::<Vec<_>>(),
    };

    for target in targets {
        // clap will ensure the target contains a command if a target is specified
        let Some(command) = target.clone().command else {
            continue;
        };
        create_recursive(command, "", compressed)?;
    }

    Ok(())
}

pub(crate) fn create_recursive(command: Command, prefix: &str, compressed: bool) -> anyhow::Result<()> {
    let out_dir = PathBuf::from("./target/man");

    ensure_dir_with_cachetag(&out_dir).context("Creating output directory failed")?;

    let subcommand_name = command.get_name();
    let total_command_name = if prefix.is_empty() { String::from(subcommand_name) } else { format!("{prefix}-{subcommand_name}") };
    let command = command.name(&total_command_name);

    let man = clap_mangen::Man::new(command.clone());

    let filename = out_dir.join(man.get_filename());

    if compressed {
        let filename = format!("{filename}.gz", filename = filename.display());
        let output = BufWriter::new(std::fs::File::create(filename)?);
        let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
        man.render(&mut encoder).context("Could not render man page")?;
    } else {
        let output = std::fs::File::create(filename)?;
        let mut buffer = BufWriter::new(output);
        man.render(&mut buffer).context("Could not render man page")?;
    }

    for subcommand in command.get_subcommands() {
        create_recursive(subcommand.clone(), &total_command_name, compressed)?
    }

    Ok(())
}
