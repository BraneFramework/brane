//  REPL.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 16:42:47
//  Last edited:
//    02 May 2025, 14:38:28
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the interactive Read-Eval-Print Loop.
//

use std::borrow::Cow::{self, Borrowed, Owned};
use std::fs;
use std::io::{Stderr, Stdout};
use std::sync::Arc;

use brane_ast::errors::CompileError;
use brane_ast::state::CompileState;
use brane_ast::{CompileResult, ParserOptions};
use brane_dsl::Language;
use brane_exe::FullValue;
use brane_tsk::docker::DockerOptions;
use brane_tsk::spec::AppId;
use error_trace::ErrorTrace as _;
use log::warn;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter, MatchingBracketHighlighter};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::history::DefaultHistory;
use rustyline::validate::{self, MatchingBracketValidator, Validator};
use rustyline::{CompletionType, Config, Context, EditMode, Editor};
use rustyline_derive::Helper;
use serde::{Deserialize, Serialize};
use specifications::data::DataIndex;
use specifications::package::PackageIndex;
use specifications::wir::Workflow;

pub use crate::errors::ReplError as Error;
use crate::instance::InstanceInfo;
use crate::run::{
    self, InstanceVmState, OfflineVmState, initialize_instance_vm, initialize_offline_vm, process_instance_result, process_offline_result,
    run_instance_vm, run_offline_vm,
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

/// Compiles the given worfklow string to a Workflow.
///
/// # Arguments
/// - `state`: The CompileState to compile with (and to update).
/// - `source`: The collected source string for now. This will be updated with the new snippet.
/// - `pindex`: The PackageIndex to resolve package imports with.
/// - `dindex`: The DataIndex to resolve data instantiations with.
/// - `user`: If given, then this is some tentative identifier of the user receiving the final workflow result.
/// - `options`: The ParseOptions to use.
/// - `what`: A string describing what we're parsing (e.g., a filename, stdin, ...).
/// - `snippet`: The actual snippet to parse.
///
/// # Returns
/// A new Workflow that is the compiled and executable version of the given snippet.
///
/// # Errors
/// This function errors if the given string was not a valid workflow. If that's the case, it's also pretty-printed to stdout with source context.
#[allow(clippy::too_many_arguments)]
pub fn from_source(
    state: &mut CompileState,
    source: &mut String,
    pindex: &PackageIndex,
    dindex: &DataIndex,
    user: Option<&str>,
    options: &ParserOptions,
    what: impl AsRef<str>,
    snippet: impl AsRef<str>,
) -> Result<Workflow, CompileError> {
    let what: &str = what.as_ref();
    let snippet: &str = snippet.as_ref();

    // Append the source with the snippet
    source.push_str(snippet);
    source.push('\n');

    // Compile the snippet, possibly fetching new ones while at it
    let workflow: Workflow = match brane_ast::compile_snippet(state, snippet.as_bytes(), pindex, dindex, options) {
        CompileResult::Workflow(mut wf, warns) => {
            // Print any warnings to stdout
            for w in warns {
                w.prettyprint(what, &source);
            }

            // Then, inject the username if any
            if let Some(user) = user {
                debug!("Setting user '{user}' as receiver of final result");
                wf.user = Arc::new(Some(user.into()));
            }

            // Done
            wf
        },

        CompileResult::Eof(err) => {
            // Prettyprint it
            err.prettyprint(what, &source);
            state.offset += 1 + snippet.chars().filter(|c| *c == '\n').count();
            return Err(CompileError::AstError { what: what.into(), errs: vec![err] });
        },
        CompileResult::Err(errs) => {
            // Prettyprint them
            for e in &errs {
                e.prettyprint(what, &source);
            }
            state.offset += 1 + snippet.chars().filter(|c| *c == '\n').count();
            return Err(CompileError::AstError { what: what.into(), errs });
        },

        // Any others should not occur
        _ => {
            unreachable!();
        },
    };
    debug!("Compiled to workflow:\n\n");
    if log::max_level() == log::LevelFilter::Debug {
        brane_ast::traversals::print::ast::do_traversal(&workflow, std::io::stdout()).unwrap();
    }

    // Return
    Ok(workflow)
}





/***** SNIPPET *****/
/// Snippets are parsed sections of workflow that keeps track of the parsed lines
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snippet {
    pub lines:    usize,
    pub workflow: Workflow,
}

impl Snippet {
    /// Compiles the given worfklow string to a Snippet.
    ///
    /// # Arguments
    /// - `state`: The CompileState to compile with (and to update).
    /// - `source`: The collected source string for now. This will be updated with the new snippet.
    /// - `pindex`: The PackageIndex to resolve package imports with.
    /// - `dindex`: The DataIndex to resolve data instantiations with.
    /// - `user`: If given, then this is some tentative identifier of the user receiving the final workflow result.
    /// - `options`: The ParseOptions to use.
    /// - `what`: A string describing what we're parsing (e.g., a filename, stdin, ...).
    /// - `snippet`: The actual snippet to parse.
    ///
    /// # Returns
    /// A new Workflow that is the compiled and executable version of the given snippet.
    ///
    /// # Errors
    /// This function errors if the given string was not a valid workflow. If that's the case, it's also pretty-printed to stdout with source context.
    #[allow(clippy::too_many_arguments)]
    pub fn from_source(
        state: &mut CompileState,
        source: &mut String,
        pindex: &PackageIndex,
        dindex: &DataIndex,
        user: Option<&str>,
        options: &ParserOptions,
        what: impl AsRef<str>,
        snippet: impl AsRef<str>,
    ) -> Result<Self, CompileError> {
        let snippet = snippet.as_ref();

        Ok(Self {
            lines:    1 + snippet.chars().filter(|c| *c == '\n').count(),
            workflow: from_source(state, source, pindex, dindex, user, options, what, snippet)?,
        })
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
    use_case: String,
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
    ensure_config_dir(true).map_err(|source| Error::ConfigDirCreateError { source })?;
    let history_file = get_history_file().map_err(|source| Error::HistoryFileError { source })?;

    if clear && history_file.exists() {
        if let Err(err) = fs::remove_file(&history_file) {
            warn!("Could not clear REPL history: {}", err);
        };
    }

    // Create the REPL
    let mut rl = Editor::with_config(config).map_err(|source| Error::EditorCreateError { source })?;
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
        let info: InstanceInfo = InstanceInfo::from_active_path().map_err(|source| Error::InstanceInfoError { source })?;

        // Run the thing
        remote_repl(&mut rl, info, use_case, proxy_addr, attach, options, profile).await?;
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
    use_case: String,
    proxy_addr: Option<String>,
    attach: Option<AppId>,
    options: ParserOptions,
    profile: bool,
) -> Result<(), Error> {
    let api_address: String = info.api.to_string();
    let drv_address: String = info.drv.to_string();

    // First we initialize the remote thing
    let mut state: InstanceVmState<Stdout, Stderr> = initialize_instance_vm(&api_address, &drv_address, Some(info.user.clone()), attach, options)
        .await
        .map_err(|source| Error::InitializeError { what: "remote instance client", source })?;

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

                let line_count = 1 + line.chars().filter(|c| *c == '\n').count();

                let workflow = {
                    let pindex = state.pindex.lock();
                    let dindex = state.dindex.lock();
                    from_source(&mut state.state, &mut state.source, &pindex, &dindex, state.user.as_deref(), &state.options, "<test task>", line)
                        .map_err(|source| Error::RunError { what: "repl", source: run::Error::CompileError(source) })?
                };

                let snippet = Snippet { lines: line_count, workflow };

                // Next, we run the VM (one snippet only ayway)
                let Ok(res) = run_instance_vm(&drv_address, &mut state, &snippet.workflow, profile).await else {
                    continue;
                };

                // Then, we collect and process the result
                if let Err(source) = process_instance_result(&api_address, &proxy_addr, use_case.clone(), snippet.workflow, res).await {
                    error!("{}", Error::ProcessError { what: "remote instance VM", source }.trace());
                    continue;
                }

                // Go to the next iteration
                count += 1;
                state.state.offset += line_count;
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
    let mut state: OfflineVmState =
        initialize_offline_vm(parse_opts, docker_opts, keep_containers).map_err(|source| Error::InitializeError { what: "offline VM", source })?;

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

                // Compile the workflow
                let line_count = line.chars().filter(|&c| c == '\n').count();

                let workflow =
                    from_source(&mut state.state, &mut state.source, &state.pindex, &state.dindex, None, &state.options, "<test task>", line.clone())
                        .map_err(|source| Error::RunError { what: "local repl", source: run::Error::CompileError(source) })?;

                let snippet = Snippet { lines: line_count, workflow };

                // Next, we run the VM (one snippet only ayway)
                let res: FullValue = run_offline_vm(&mut state, snippet).await.map_err(|source| Error::RunError { what: "offline VM", source })?;

                // Then, we collect and process the result
                if let Err(source) = process_offline_result(res) {
                    error!("{}", Error::ProcessError { what: "offline VM", source }.trace());
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
            Err(source) => {
                error!("Failed to get new line: {source}");
                break;
            },
        }
    }

    // Done
    Ok(())
}
