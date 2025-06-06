//  COMPILER.rs
//    by Lut99
//
//  Created:
//    21 Oct 2024, 10:47:42
//  Last edited:
//    02 May 2025, 11:50:06
//  Auto updated?
//    Yes
//
//  Description:
//!   Bonus binary that implements a `WIR` to eFLINT JSON through
//!   `Workflow` compiler.
//

use std::fmt::{Display, Formatter, Result as FResult};
use std::fs;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::str::FromStr;

use brane_chk::workflow::{WorkflowToEflint, compile};
use clap::Parser;
use miette::{Context as _, IntoDiagnostic as _};
use policy_reasoner::workflow::Workflow;
use specifications::wir::Workflow as Wir;
use thiserror::Error;
use tracing::{Level, debug, error, info};


/***** ERRORS *****/
/// Defines errors that fail when parsing input languages.
#[derive(Debug, Error)]
#[error("Unknown input language '{0}'")]
struct UnknownInputLanguageError(String);

/// Defines errors that fail when parsing output languages.
#[derive(Debug, Error)]
#[error("Unknown output language '{0}'")]
struct UnknownOutputLanguageError(String);

/***** CONSTANTS *****/
const BLOCK_SEPARATOR: &str = "--------------------------------------------------------------------------------";




/***** ARGUMENTS *****/
/// Defines the possible input languages (and how to parse them).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum InputLanguage {
    /// It's Brane WIR.
    Wir,
    /// It's policy reasoner Workflow.
    Workflow,
}
impl Display for InputLanguage {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::Wir => write!(f, "Brane WIR"),
            Self::Workflow => write!(f, "Workflow"),
        }
    }
}
impl FromStr for InputLanguage {
    type Err = UnknownInputLanguageError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "wir" => Ok(Self::Wir),
            "wf" | "workflow" => Ok(Self::Workflow),
            raw => Err(UnknownInputLanguageError(raw.into())),
        }
    }
}

/// Defines the possible output languages (and how to parse them).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum OutputLanguage {
    /// It's policy reasoner Workflow.
    Workflow,
    /// It's eFLINT Itself.
    EFlint,
}
impl Display for OutputLanguage {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::Workflow => write!(f, "Workflow"),
            Self::EFlint => write!(f, "eFLINT"),
        }
    }
}
impl FromStr for OutputLanguage {
    type Err = UnknownOutputLanguageError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "wf" | "workflow" => Ok(Self::Workflow),
            "eflint" | "eflint-dsl" => Ok(Self::EFlint),
            raw => Err(UnknownOutputLanguageError(raw.into())),
        }
    }
}



/// Defines the arguments of the binary.
#[derive(Debug, Parser)]
struct Arguments {
    /// Whether to enable debug statements
    #[clap(long, help = "If given, enables INFO- and DEBUG-level log statements.")]
    debug: bool,
    /// Whether to enable trace statements.
    #[clap(long, help = "If given, enables TRACE-level log statements.")]
    trace: bool,

    /// The input file to compile.
    #[clap(name = "INPUT", default_value = "-", help = "The input file to compile. You can use '-' to compile from stdin.")]
    input:  String,
    /// The output file to write to.
    #[clap(short, long, default_value = "-", help = "The output file to compile to. You can use '-' to write to stdout.")]
    output: String,

    /// The input language to compile from.
    #[clap(
        short = '1',
        default_value = "wir",
        help = "The input language to compile from. Options are 'wir' for Brane's WIR, or 'wf'/'workflow' for the policy reasoner's workflow \
                representation."
    )]
    input_lang:  InputLanguage,
    /// The output language to compile to.
    #[clap(
        short = '2',
        long,
        default_value = "eflint",
        help = "The output language to compile to. Options are 'wf'/'workflow' for the policy reasoner's workflow representation, or \
                'eflint'/'eflint-dsl' for the eFLINT DSL."
    )]
    output_lang: OutputLanguage,
}





/***** FUNCTIONS *****/
/// Reads the input, then compiles it to a [`Workflow`].
///
/// # Arguments
/// - `path`: The path (or '-' for stdin) where the input may be found.
/// - `lang`: The [`InputLanguage`] determining how to get to a workflow.
///
/// # Returns
/// A [`Workflow`] that we parsed from the input.
///
/// # Errors
/// This function fails if we failed to read the input (file or stdin), or if the input couldn't
/// be compiled (it was invalid somehow).
#[inline]
fn input_to_workflow(path: &str, lang: InputLanguage) -> miette::Result<Workflow> {
    // Read the input file
    let input: String = if path == "-" {
        debug!("Reading input from stdin...");
        let mut input: String = String::new();
        std::io::stdin().read_to_string(&mut input).into_diagnostic().context("Failed to read from stdin")?;
        input
    } else {
        debug!("Reading input '{path}' from file...");
        fs::read_to_string(path).into_diagnostic().with_context(|| format!("Failed to read input file '{path}'"))?
    };

    // See if we need to parse it as a Workflow or as a WIR
    match lang {
        InputLanguage::Wir => {
            // Parse it as WIR, first
            debug!("Parsing input as Brane WIR...");
            let wir: Wir = serde_json::from_str(&input).into_diagnostic().with_context(|| {
                format!("Failed to parse {} as Brane WIR", if path == "-" { "stdin".into() } else { format!("input file '{path}'") })
            })?;

            // Then compile it to a Workflow
            let wir_id: String = wir.id.clone();
            debug!("Compiling Brane WIR '{wir_id}' to a workflow...");
            compile(wir).into_diagnostic().with_context(|| format!("Failed to compile input Brane WIR '{wir_id}' to a workflow"))
        },

        InputLanguage::Workflow => {
            // It sufficies to parse as Workflow directly
            debug!("Parsing input as a workflow...");
            serde_json::from_str(&input).into_diagnostic().with_context(|| {
                format!("Failed to parse {} as a workflow", if path == "-" { "stdin".into() } else { format!("input file '{path}'") })
            })
        },
    }
}

/// Takes a [`Workflow`] and writes it to the given output, potentially after compilation.
///
/// # Arguments
/// - `path`: The path (or '-' for stdin) where the output should be written to.
/// - `lang`: The [`OutputLanguage`] determining what to write.
/// - `workflow`: The [`Workflow`] to output.
///
/// # Errors
/// This function fails if we failed to translate the workflow to the appropriate output language,
/// or if we failed to write to the output (either stdout or file).
#[inline]
fn workflow_to_output(path: &str, lang: OutputLanguage, workflow: Workflow) -> miette::Result<()> {
    // See if we need to serialize the Workflow or compile it first
    let output: String = match lang {
        OutputLanguage::Workflow => {
            // It sufficies to serialize the Workflow directly
            debug!("Serializing workflow '{}' to JSON...", workflow.id);
            serde_json::to_string_pretty(&workflow)
                .into_diagnostic()
                .with_context(|| format!("Failed to serialize given workflow '{}'", workflow.id))?
        },

        OutputLanguage::EFlint => {
            // Compile it to eFLINT, first
            debug!("Compiling workflow '{}' to eFLINT JSON...", workflow.id);
            WorkflowToEflint(&workflow).to_string()
        },
    };

    // OK, now write to out or stdout
    if path == "-" {
        debug!("Writing result to stdout...");
        std::io::stdout().write_all(output.as_bytes()).into_diagnostic().context("Failed to write to stdout")?;
    } else {
        debug!("Writing result to output file '{path}'...");
        fs::write(path, output).into_diagnostic().with_context(|| format!("Failed to write to output file '{path}'"))?;
    }

    Ok(())
}





/***** ENTRYPOINT *****/
fn main() -> ExitCode {
    // Parse the arguments
    let args = Arguments::parse();

    // Setup the logger
    tracing_subscriber::fmt()
        .with_max_level(if args.trace {
            Level::TRACE
        } else if args.debug {
            Level::DEBUG
        } else {
            Level::WARN
        })
        .init();
    info!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:?}");
            ExitCode::FAILURE
        },
    }
}

fn run(args: Arguments) -> miette::Result<()> {
    // Get the input workflow
    let workflow: Workflow = input_to_workflow(&args.input, args.input_lang).context("Could not convert input to workflow")?;

    if tracing::enabled!(Level::DEBUG) {
        debug!("Parsed workflow form input:\n{BLOCK_SEPARATOR}\n{}\n{BLOCK_SEPARATOR}", workflow.visualize());
    }

    // Then write to the output workflow
    workflow_to_output(&args.output, args.output_lang, workflow).context("Could not convert workflow to output")?;

    // Done!
    println!(
        "Successfully compiled {} ({}) to {} ({})",
        if args.input == "-" { "stdin".into() } else { format!("input file '{}'", args.input) },
        args.input_lang,
        if args.output == "-" { "stdout".into() } else { format!("output file '{}'", args.output) },
        args.output_lang,
    );

    Ok(())
}
