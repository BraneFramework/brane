use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::Context;
use clap::Command;

pub(crate) fn create_recursive(command: Command, prefix: &str, compressed: bool) -> anyhow::Result<()> {
    let out_dir = PathBuf::from("./manpages");

    if !out_dir.exists() {
        std::fs::create_dir(&out_dir).context("Creating output directory failed")?;
    }

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
