use std::fs::File;

use clap_complete::{Generator, Shell};
use strum::IntoEnumIterator;

use crate::{Binary, SHELLS};

pub(crate) fn generate(binary: Option<Binary>, shell: Option<Shell>) {
    let shells_to_do = match shell {
        Some(shell) => &[shell][..],
        None => &SHELLS[..],
    };

    let binaries_to_do = match binary {
        Some(binary) => &[binary][..],
        None => &Binary::iter().collect::<Vec<_>>()[..],
    };

    for shell in shells_to_do {
        for binary in binaries_to_do {
            let mut command = binary.to_command();
            let bin_name = command.get_name().to_owned();
            let mut file = File::create(shell.file_name(&bin_name)).expect("Could not open/create completions file");
            clap_complete::generate(*shell, &mut command, &bin_name, &mut file);
        }
    }
}
