//  REPL.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 16:42:47
//  Last edited:
//    08 Jan 2024, 10:23:14
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the interactive Read-Eval-Print Loop.
//

use std::borrow::Cow::{self, Borrowed, Owned};
use std::fs;
use std::io::{Stderr, Stdout};

use brane_ast::ParserOptions;
use brane_dsl::Language;
use brane_exe::FullValue;
use brane_tsk::docker::DockerOptions;
use brane_tsk::spec::AppId;
use log::warn;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter, MatchingBracketHighlighter};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::history::DefaultHistory;
use rustyline::validate::{self, MatchingBracketValidator, Validator};
use rustyline::{CompletionType, Config, Context, EditMode, Editor};
use rustyline_derive::Helper;

pub use crate::errors::ReplError as Error;
use crate::instance::InstanceInfo;
use crate::run::{
    InstanceVmState, OfflineVmState, initialize_instance_vm, initialize_offline_vm, process_instance_result, process_offline_result, run_instance_vm,
    run_offline_vm,
};
use crate::utils::{ensure_config_dir, get_history_file};


/***** HELPER FUNCTIONS *****/
/// Handles magicks in the REPL.
///
/// # Arguments
/// - `line`: The line given by the user.
///
/// # Returns
/// If a magics was triggered, returns if that trigger should break the REPL (i.e., returns `Some(true)` if so or `Some(false)` if the REPL can continue but not with this line). If the line was not a REPL magick, then `None` is returned.
fn repl_magicks(line: impl AsRef<str>) -> Option<bool> {
    let line: &str = line.as_ref();

    // Switch on the command given
    if line == "exit" || line == "quit" || line == "q" {
        Some(true)
    } else if line == "help" {
        println!("You found the secret REPL-commands!");
        println!(
            "These commands are not part of BraneScript (or whatever language you're using this REPL with), but instead provide convienience \
             functions for the REPL itself."
        );
        println!();
        println!("Supported commands:");
        println!("  `exit`, `quit` or `q`   Exits the REPL. The same can be achieved by hitting `Ctrl+C` or `Ctrl+D`.");
        println!("  `help`                  Prints this overview.");
        println!();
        println!("Any other statement that is not one of the commands above is interpreted as the language you're REPLing.");
        println!();
        Some(false)
    } else {
        None
    }
}





/***** REPL HELPER *****/
/// Implements the helper for the Repl (auto-completion and syntax highlighting and such)
#[derive(Helper)]
struct ReplHelper {
    /// The completer: we auto-complete filenames, like the standard terminal
    completer: FilenameCompleter,
    /// Highlighter: we highlight matching brackets
    highlighter: MatchingBracketHighlighter,
    /// We even validate for matching brackets
    validator: MatchingBracketValidator,
    /// We hint based on the user's history
    hinter: HistoryHinter,
    /// Does something with being a coloured prompt(?)
    colored_prompt: String,
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Result<(usize, Vec<Pair>), ReadlineError> {
        self.completer.complete(line, pos, ctx)
    }
}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx).and_then(|h| h.lines().next().map(|l| l.to_string()))
    }
}

impl Highlighter for ReplHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(&'s self, prompt: &'p str, default: bool) -> Cow<'b, str> {
        if default { Borrowed(&self.colored_prompt) } else { Borrowed(prompt) }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> { Owned("\x1b[1m".to_owned() + hint + "\x1b[m") }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> { self.highlighter.highlight(line, pos) }

    fn highlight_char(&self, line: &str, pos: usize, cmd_kind: CmdKind) -> bool { self.highlighter.highlight_char(line, pos, cmd_kind) }
}

impl Validator for ReplHelper {
    fn validate(&self, ctx: &mut validate::ValidationContext) -> rustyline::Result<validate::ValidationResult> { self.validator.validate(ctx) }

    fn validate_while_typing(&self) -> bool { self.validator.validate_while_typing() }
}





/***** SUBCOMMANDS *****/
/// Entrypoint to the REPL, which performs the required initialization.
///
/// # Arguments
/// - `proxy_addr`: The address to proxy any data transfers through if they occur.
/// - `remote`: Whether to use the remote Brane instance in the login file to run the on instead.
/// - `attach`: If not None, defines the session ID of an existing session to connect to.
/// - `language`: The language with which to compile the file.
/// - `clear`: Whether or not to clear the history of the REPL before beginning.
/// - `profile`: If given, prints the profile timings to stdout if available.
/// - `docker_opts`: The DockerOpts that determines how we connect to the local Docker dameon.
/// - `keep_containers`: Whether to keep containers after execution or not.
///
/// # Errors
/// This function errors if we could not properly read from/write to the terminal. Additionally, it may error if any of the given statements fails for whatever reason.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    proxy_addr: Option<String>,
    remote: bool,
    attach: Option<AppId>,
    language: Language,
    clear: bool,
    profile: bool,
    docker_opts: DockerOptions,
    keep_containers: bool,
) -> Result<(), Error> {
    // Build the config for the rustyline REPL.
    let config = Config::builder().history_ignore_space(true).completion_type(CompletionType::Circular).edit_mode(EditMode::Emacs).build();

    // Build the helper for the REPL
    let repl_helper = ReplHelper {
        completer: FilenameCompleter::new(),
        highlighter: MatchingBracketHighlighter::new(),
        hinter: HistoryHinter {},
        colored_prompt: "".to_owned(),
        validator: MatchingBracketValidator::new(),
    };

    // Get the history file, clearing it if necessary
    if let Err(err) = ensure_config_dir(true) {
        return Err(Error::ConfigDirCreateError { err });
    };
    let history_file = match get_history_file() {
        Ok(file) => file,
        Err(err) => {
            return Err(Error::HistoryFileError { err });
        },
    };
    if clear && history_file.exists() {
        if let Err(err) = fs::remove_file(&history_file) {
            warn!("Could not clear REPL history: {}", err);
        };
    }

    // Create the REPL
    let mut rl = match Editor::with_config(config) {
        Ok(rl) => rl,
        Err(err) => {
            return Err(Error::EditorCreateError { err });
        },
    };
    rl.set_helper(Some(repl_helper));
    if let Err(err) = rl.load_history(&history_file) {
        warn!("Could not load REPL history from '{}': {}", history_file.display(), err);
    }

    // Prepare the parser options
    let options: ParserOptions = ParserOptions::new(language);

    // Initialization done; run the REPL
    println!("Welcome to the Brane REPL, press Ctrl+D to exit.\n");
    if remote {
        // Open the login file to find the remote location
        let info: InstanceInfo = match InstanceInfo::from_active_path() {
            Ok(info) => info,
            Err(err) => {
                return Err(Error::InstanceInfoError { err });
            },
        };

        // Run the thing
        remote_repl(&mut rl, info, proxy_addr, attach, options, profile).await?;
    } else {
        local_repl(&mut rl, options, docker_opts, keep_containers).await?;
    }

    // Try to save the history if we exited cleanly
    if let Err(reason) = rl.save_history(&history_file) {
        warn!("Could not save session history to '{}': {}", history_file.display(), reason);
    }

    // Done!
    Ok(())
}



/// Runs the given file on the remote instance.
///
/// # Arguments
/// - `rl`: The REPL interface we use to do the R-part of a REPL.
/// - `info`: An [`InstanceInfo`] that describes how to connect to the backend.
/// - `proxy_addr`: The address to proxy any data transfers through if they occur.
/// - `attach`: If given, uses the given ID to attach to an existing session instead of creating a new one.
/// - `options`: The ParseOptions that specify how to parse the incoming source.
/// - `profile`: If given, prints the profile timings to stdout if reported by the remote.
///
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
async fn remote_repl(
    rl: &mut Editor<ReplHelper, DefaultHistory>,
    info: InstanceInfo,
    proxy_addr: Option<String>,
    attach: Option<AppId>,
    options: ParserOptions,
    profile: bool,
) -> Result<(), Error> {
    let api_address: String = info.api.to_string();
    let drv_address: String = info.drv.to_string();

    // First we initialize the remote thing
    let mut state: InstanceVmState<Stdout, Stderr> =
        match initialize_instance_vm(&api_address, &drv_address, Some(info.user.clone()), attach, options).await {
            Ok(state) => state,
            Err(err) => {
                return Err(Error::InitializeError { what: "remote instance client", err });
            },
        };

    // Next, enter the L in REPL
    let mut count: u32 = 1;
    loop {
        // Prepare the prompt with the current iteration number
        let p = format!("{count}> ");

        // Write the prompt in a coloured way
        rl.helper_mut().expect("No helper").colored_prompt = format!("\x1b[1;32m{p}\x1b[0m");

        // Find a line to read
        match rl.readline(&p) {
            Ok(line) => {
                // The command checked out, so add it to the history
                if let Err(err) = rl.add_history_entry(line.replace('\n', " ")) {
                    warn!("Failed to update REPL history: {err}");
                }

                // Fetch REPL magicks
                if let Some(quit) = repl_magicks(&line) {
                    if quit {
                        break;
                    } else {
                        continue;
                    }
                }

                // Next, we run the VM (one snippet only ayway)
                let res: FullValue = match run_instance_vm(&drv_address, &mut state, "<stdin>", &line, profile).await {
                    Ok(res) => res,
                    Err(_) => {
                        continue;
                    },
                };

                // Then, we collect and process the result
                if let Err(err) = process_instance_result(&api_address, &proxy_addr, res).await {
                    error!("{}", Error::ProcessError { what: "remote instance VM", err });
                    continue;
                }

                // Go to the next iteration
                count += 1;
                state.state.offset += 1 + line.chars().filter(|c| *c == '\n').count();
            },
            Err(ReadlineError::Interrupted) => {
                println!("Keyboard interrupt received, exiting...");
                break;
            },
            Err(ReadlineError::Eof) => {
                break;
            },
            Err(err) => {
                error!("Failed to get new line: {}", err);
                break;
            },
        }
    }

    // Done
    Ok(())
}



/// Runs the given file on the local machine.
///
/// # Arguments
/// - `rl`: The REPL interface we use to do the R-part of a REPL.
/// - `parse_opts`: The ParseOptions that specify how to parse the incoming source.
/// - `docker_opts`: The DockerOpts that determines how we connect to the local Docker dameon.
/// - `keep_containers`: Whether to keep containers after execution or not.
///
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
async fn local_repl(
    rl: &mut Editor<ReplHelper, DefaultHistory>,
    parse_opts: ParserOptions,
    docker_opts: DockerOptions,
    keep_containers: bool,
) -> Result<(), Error> {
    // First we initialize the remote thing
    let mut state: OfflineVmState = match initialize_offline_vm(parse_opts, docker_opts, keep_containers) {
        Ok(state) => state,
        Err(err) => {
            return Err(Error::InitializeError { what: "offline VM", err });
        },
    };

    // With the VM setup, enter the L in the REPL
    let mut count: u32 = 1;
    loop {
        // Prepare the prompt with the current iteration number
        let p = format!("{count}> ");

        // Write the prompt in a coloured way
        rl.helper_mut().expect("No helper").colored_prompt = format!("\x1b[1;32m{p}\x1b[0m");

        // Find a line to read
        match rl.readline(&p) {
            Ok(line) => {
                // The command checked out, so add it to the history
                if let Err(err) = rl.add_history_entry(line.replace('\n', " ")) {
                    warn!("Failed to update REPL history: {err}");
                }

                // Fetch REPL magicks
                if let Some(quit) = repl_magicks(&line) {
                    if quit {
                        break;
                    } else {
                        continue;
                    }
                }

                // Next, we run the VM (one snippet only ayway)
                let res: FullValue = match run_offline_vm(&mut state, "<stdin>", &line).await {
                    Ok(res) => res,
                    Err(err) => {
                        return Err(Error::RunError { what: "offline VM", err });
                    },
                };

                // Then, we collect and process the result
                if let Err(err) = process_offline_result(res) {
                    error!("{}", Error::ProcessError { what: "offline VM", err });
                    continue;
                }

                // Go to the next iteration
                count += 1;
                state.state.offset += 1 + line.chars().filter(|c| *c == '\n').count();
            },
            Err(ReadlineError::Interrupted) => {
                println!("Keyboard interrupt received, exiting...");
                break;
            },
            Err(ReadlineError::Eof) => {
                break;
            },
            Err(err) => {
                error!("Failed to get new line: {}", err);
                break;
            },
        }
    }

    // Done
    Ok(())
}
