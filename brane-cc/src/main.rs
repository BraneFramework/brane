//  MAIN.rs
//    by Lut99
//
//  Created:
//    18 Nov 2022, 14:36:55
//  Last edited:
//    13 Jun 2024, 16:21:19
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the `branec` binary.
//

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Stdin, Write};
use std::path::PathBuf;

use brane_ast::state::CompileState;
use brane_ast::traversals::print::ast;
use brane_ast::{CompileResult, ParserOptions, Workflow, compile_snippet};
use brane_cc::errors::CompileError;
use brane_cc::spec::IndexLocation;
use brane_dsl::Language;
use clap::Parser;
use dotenvy::dotenv;
#[cfg(unix)]
use expanduser::expanduser;
use human_panic::setup_panic;
use humanlog::{DebugMode, HumanLogger};
use log::{debug, error, info, warn};
use specifications::data::DataIndex;
use specifications::package::PackageIndex;


/***** ARGUMENTS *****/
/// The arguments for the `branec` binary.
#[derive(Parser)]
#[clap(name = "branec", author, about = "An offline compiler for BraneScript/Bakery to Workflows.")]
struct Arguments {
    /// If given, shows debug prints.
    #[clap(long, help = "If given, shows INFO- and DEBUG-level prints in the log.", env = "DEBUG")]
    debug: bool,
    /// If given, shows additional trace prints.
    #[clap(long, help = "If given, shows TRACE-level prints in the log. Implies '--debug'", env = "TRACE")]
    trace: bool,

    /// The file(s) to compile. May be '-' to compile from stdin.
    #[clap(name = "FILES", help = "The input files to compile. Use '-' to read from stdin.")]
    files:    Vec<String>,
    /// The output file to write to.
    #[clap(short, long, default_value = "-", help = "The output file to compile to. Use '-' to write to stdout.")]
    output:   String,
    /// The path / address of the packages index.
    #[clap(
        short,
        long,
        default_value = "~/.local/share/brane/packages",
        help = "The location to read the package index from. If it's a path, reads it from the local machine; if it's an address, attempts to read \
                it from the Brane instance instead. You can wrap your input in 'Local<...>' or 'Remote<...>' to disambiguate between the two."
    )]
    packages: IndexLocation,
    /// The path / address of the data index.
    #[clap(
        short,
        long,
        default_value = "~/.local/share/brane/data",
        help = "The location to read the data index from. If it's a path, reads it from the local machine; if it's an address, attempts to read it \
                from the Brane instance instead. You can wrap your input in 'Local<...>' or 'Remote<...>' to disambiguate between the two."
    )]
    data:     IndexLocation,
    /// If given, reads the packages and data in test mode, which simplifies how to interpret them since we won't be executing them.
    #[clap(
        short,
        long,
        help = "If given, reads packages and data simplified as found in the `tests` folder in the Brane repository. This can be done because the \
                packages won't be executed."
    )]
    raw:      bool,

    /// If given, does the stream thing
    #[clap(
        short,
        long,
        help = "If given, enters so-called _streaming mode_. This effectively emulates a REPL, where files may be given on stdin indefinitely \
                (separated by EOF, Ctrl+D). Each file is compiled as soon as it is completely received, and the workflow for that file is written \
                to the output file. Workflows can use definitions made in pervious workflows, just like a REPL."
    )]
    stream:   bool,
    /// Determines the input language of the source.
    #[clap(short, long, default_value = "bscript", help = "Determines the language of the input files.")]
    language: Language,
    /// If given, writes the output JSON to use as little whitespace as possible.
    #[clap(
        short,
        long,
        help = "If given, writes the output JSON in minimized format (i.e., with as little whitespace as possible). Not really readable, but \
                perfect for transmitting it to some other program."
    )]
    compact:  bool,
    /// If given, does not output JSON but instead outputs an assembly-like variant of a workflow.
    #[clap(
        short = 'P',
        long,
        help = "If given, does not output JSON but instead outputs an assembly-like variant of a workflow. Not really readable by machines, but \
                easier to understand by a human (giving this ignores --compact)."
    )]
    pretty:   bool,
}





/***** HELPER FUNCTIONS *****/
/// Reads a "file" from the input.
///
/// This is either an entire file, or everything up to a '<-- FILE -->` line.
///
/// # Arguments
/// - `name`: The name of the gived reader. Used for debugging only.
/// - `handle`: The handle to read.
///
/// # Returns
/// The string that we've read.
///
/// # Errors
/// This function errors if we failed to read the given input.
fn read_input(name: impl Into<String>, input: &mut impl BufRead) -> Result<String, CompileError> {
    // Read line-by-line
    let mut raw: String = String::new();
    let name = name.into();
    for line in input.lines() {
        // Unwrap the line
        let line: String = line.map_err(|source| CompileError::InputReadError { name: name.clone(), source })?;

        // Check if the line is our defined separator
        if line == "<-- FILE -->" {
            return Ok(raw);
        }

        // Otherwise, append
        if !line.is_empty() {
            raw.push('\n');
        }
        raw.push_str(&line);
    }

    // Done
    Ok(raw)
}



/// Compiles a snippet of BraneScript statefully.
///
/// # Arguments
/// - `state`: The CompileState that allows us to make repeated calls that are sensible.
/// - `lang`: The language to compile.
/// - `iname`: Some name useful for the reader to identify where is being read from.
/// - `input`: The reader to read the snippet from.
/// - `source`: The (automatically updated) total source, used for debugging.
/// - `oname`: Some name useful for the user to identify where is being written to.
/// - `output`: The Writer to write the output to.
/// - `pretty`: If given, does not serialize to JSON but with `brane_ast::traversals::print::ast`.
/// - `compact`: If given, serializes with as little whitespace as possible. Decreases the resulting size greatly, but also readability.
/// - `packages_loc`: Where to get the package index from. Implemented as an IndexLocation so it may be both local or remote.
/// - `data_loc`: Where to get the data index from. Implemented as an IndexLocation so it may be both local or remote.
/// - `raw_assets`: If true, don't read the package and data "canonically" but instead read them for testing purposes.
///
/// # Returns
/// Nothing directly, but does write the result to `output` and appends the input snippet to `source`.
///
/// # Errors
/// This function errors if the input is not valid BraneScript or an IO error occurred trying to read from / write to the input / output.
#[allow(clippy::too_many_arguments)]
pub async fn compile_iter(
    state: &mut CompileState,
    source: &mut String,
    lang: Language,
    iname: impl AsRef<str>,
    input: &mut impl BufRead,
    oname: impl AsRef<str>,
    output: &mut impl Write,
    pretty: bool,
    compact: bool,
    packages_loc: &IndexLocation,
    data_loc: &IndexLocation,
    raw_assets: bool,
) -> Result<(), CompileError> {
    let iname: &str = iname.as_ref();
    let oname: &str = oname.as_ref();

    // Read it
    debug!("Reading from '{}'...", iname);
    let raw: String = read_input(iname, input)?;

    // Fetch the indices
    let pindex: PackageIndex = match packages_loc {
        IndexLocation::Remote(remote) => {
            debug!("Fetching remote package index from '{}'...", remote);
            if raw_assets {
                warn!("Giving `--raw` has no effect when loading packages remotely");
            }
            brane_tsk::api::get_package_index(remote)
                .await
                .map_err(|source| CompileError::RemotePackageIndexError { endpoint: remote.clone(), source })?
        },

        IndexLocation::Local(local) => {
            // Resolve the tildes first, but only on UNIX platforms that do this
            #[cfg(unix)]
            let local: PathBuf = match expanduser(local.to_string_lossy()) {
                Ok(local) => local,
                Err(_) => local.clone(),
            };
            #[cfg(not(unix))]
            let local: PathBuf = local.clone();

            debug!("Fetching local package index from '{}'...", local.display());
            if !raw_assets {
                brane_tsk::local::get_package_index(local).map_err(|source| CompileError::LocalPackageIndexError { source })?
            } else {
                brane_shr::utilities::create_package_index_from(local)
            }
        },
    };
    let dindex: DataIndex = match data_loc {
        IndexLocation::Remote(remote) => {
            debug!("Fetching remote data index from '{}'...", remote);
            if raw_assets {
                warn!("Giving `--raw` has no effect when loading datasets remotely");
            }
            brane_tsk::api::get_data_index(remote).await.map_err(|source| CompileError::RemoteDataIndexError { endpoint: remote.clone(), source })?
        },

        IndexLocation::Local(local) => {
            // Resolve the tildes first, but only on UNIX platforms that do this
            #[cfg(unix)]
            let local: PathBuf = match expanduser(local.to_string_lossy()) {
                Ok(local) => local,
                Err(_) => local.clone(),
            };
            #[cfg(not(unix))]
            let local: PathBuf = local.clone();

            debug!("Fetching local data index from '{}'...", local.display());
            if !raw_assets {
                brane_tsk::local::get_data_index(local).map_err(|source| CompileError::LocalDataIndexError { source })?
            } else {
                brane_shr::utilities::create_data_index_from(local)
            }
        },
    };

    // Compile it
    debug!("Compiling workflow...");
    source.push_str(&raw);
    let workflow: Workflow = match compile_snippet(state, raw.as_bytes(), &pindex, &dindex, &ParserOptions::new(lang)) {
        CompileResult::Workflow(workflow, warns) => {
            // Print any warnings (on stderr)
            for warn in warns {
                warn.prettyprint(iname, &mut *source);
            }

            // Return the workflow
            workflow
        },
        CompileResult::Unresolved(_, _) => unreachable!(),
        CompileResult::Program(_, _) => unreachable!(),
        CompileResult::Eof(err) => {
            err.prettyprint(iname, source);
            writeln!(output, "---ERROR---").map_err(|source| CompileError::OutputWriteError { name: oname.into(), source })?;
            state.offset += raw.chars().filter(|c| *c == '\n').count();
            return Ok(());
        },
        CompileResult::Err(errs) => {
            for err in &errs {
                err.prettyprint(iname, &mut *source);
            }
            writeln!(output, "---ERROR---").map_err(|source| CompileError::OutputWriteError { name: oname.into(), source })?;
            state.offset += raw.chars().filter(|c| *c == '\n').count();
            return Ok(());
        },
    };
    state.offset += raw.chars().filter(|c| *c == '\n').count();

    // Serialize the output
    let sworkflow: String = if pretty {
        let mut res: Vec<u8> = vec![];
        ast::do_traversal(&workflow, &mut res).unwrap();
        String::from_utf8_lossy(&res).to_string()
    } else if !compact {
        serde_json::to_string_pretty(&workflow).map_err(|source| CompileError::WorkflowSerializeError { source })?
    } else {
        serde_json::to_string(&workflow).map_err(|source| CompileError::WorkflowSerializeError { source })?
    };

    // Write it and update the source
    debug!("Writing to '{}'...", oname);
    writeln!(output, "{sworkflow}").map_err(|source| CompileError::OutputWriteError { name: oname.into(), source })?;
    writeln!(output, "---END---").map_err(|source| CompileError::OutputWriteError { name: oname.into(), source })?;

    // Done
    Ok(())
}





/***** ENTRYPOINT *****/
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Parse any environment file
    dotenv().ok();

    // Parse the arguments
    let mut args: Arguments = Arguments::parse();

    // Setup the logger
    if let Err(err) = HumanLogger::terminal(DebugMode::from_flags(args.trace, args.debug)).init() {
        eprintln!("WARNING: Failed to setup logger: {err} (logging disabled for this session)");
    }
    info!("Initializing branec v{}", env!("CARGO_PKG_VERSION"));

    // Setup the panic mode
    if !args.trace && !args.debug {
        setup_panic!();
    }

    // Ensure there is always at least one file
    if args.files.is_empty() {
        args.files = vec!["-".into()];
    }



    // Match on whether we're streaming or not
    if !args.stream {
        // Parse all the input as one, big workflow file
        let mut source: String = String::new();
        for f in &args.files {
            debug!("Reading from '{}'...", f);

            // Attempt to open the file as a reader
            let (iname, mut ihandle): (Cow<str>, Box<dyn BufRead>) = if f != "-" {
                match File::open(f) {
                    Ok(handle) => (f.into(), Box::new(BufReader::new(handle))),
                    Err(err) => {
                        error!("Failed to open file '{}': {}", f, err);
                        std::process::exit(1);
                    },
                }
            } else {
                ("<stdin>".into(), Box::new(BufReader::new(std::io::stdin())))
            };

            // Simply append the contents to the source file
            if let Err(err) = ihandle.read_to_string(&mut source) {
                error!("Failed to read input '{}': {}", iname, err);
            }
            source.push('\n');
        }

        // Open the output already
        debug!("Opening output file '{}'...", args.output);
        let (oname, mut ohandle): (Cow<str>, Box<dyn Write>) = if args.output != "-" {
            match File::create(&args.output) {
                Ok(handle) => (args.output.into(), Box::new(handle)),
                Err(err) => {
                    error!("Failed to create output file '{}': {}", args.output, err);
                    std::process::exit(1);
                },
            }
        } else {
            ("<stdout>".into(), Box::new(std::io::stdout()))
        };

        // Compile the entire source now
        debug!("Compiling...");
        if let Err(err) = compile_iter(
            &mut CompileState::new(),
            &mut String::new(),
            args.language,
            if args.files.len() == 1 { &args.files[0] } else { "<sources>" },
            &mut Cursor::new(source),
            &oname,
            &mut ohandle,
            args.pretty,
            args.compact,
            &args.packages,
            &args.data,
            args.raw,
        )
        .await
        {
            error!("{}", err);
            std::process::exit(1);
        }
    } else {
        // Open the input
        let mut ihandle: BufReader<Stdin> = BufReader::new(std::io::stdin());

        // Open the output
        debug!("Opening output file '{}'...", args.output);
        let (oname, mut ohandle): (Cow<str>, Box<dyn Write>) = if args.output != "-" {
            match File::create(&args.output) {
                Ok(handle) => (args.output.into(), Box::new(handle)),
                Err(err) => {
                    error!("Failed to create output file '{}': {}", args.output, err);
                    std::process::exit(1);
                },
            }
        } else {
            ("<stdout>".into(), Box::new(std::io::stdout()))
        };

        // Iterate indefinitely
        let mut state: CompileState = CompileState::new();
        let mut source: String = String::new();
        loop {
            // Compile that immediately
            if let Err(err) = compile_iter(
                &mut state,
                &mut source,
                args.language,
                "<stdin>",
                &mut ihandle,
                &oname,
                &mut ohandle,
                args.pretty,
                args.compact,
                &args.packages,
                &args.data,
                args.raw,
            )
            .await
            {
                error!("{}", err);
                std::process::exit(1);
            }

            // Be sure stdout & stderr are flushed after each iter
            if let Err(err) = std::io::stdout().flush() {
                error!("Failed to flush stdout: {}", err);
            }
            if let Err(err) = std::io::stderr().flush() {
                error!("Failed to flush stderr: {}", err);
            }
        }
    }
}
