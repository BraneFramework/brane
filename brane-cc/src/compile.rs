//  COMPILE.rs
//    by Lut99
// 
//  Created:
//    16 Nov 2022, 14:36:38
//  Last edited:
//    18 Nov 2022, 15:47:38
//  Auto updated?
//    Yes
// 
//  Description:
//!   Handles things related to offline compiling.
// 

use std::borrow::Cow;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tracing::debug;

use brane_dsl::Language;
use brane_ast::{compile_snippet, CompileResult, ParserOptions, Workflow};
use brane_ast::state::CompileState;
use specifications::data::DataIndex;
use specifications::package::PackageIndex;

pub use crate::errors::CompileError as Error;
use crate::spec::IndexLocation;


/***** LIBRARY *****/
/// Compiles the given BraneScript file to a full Workflow.
/// 
/// # Arguments
/// - `language`: The language to compile.
/// - `input`: The file that is the input. Can also be '-' to read from stdin instead.
/// - `output`: The file to output to. Can also be '-' to write to stdout.
/// - `compact`: If given, serializes with as little whitespace as possible. Decreases the resulting size greatly, but also readability.
/// - `packages_loc`: Where to get the package index from. Implemented as an IndexLocation so it may be both local or remote.
/// - `data_loc`: Where to get the data index from. Implemented as an IndexLocation so it may be both local or remote.
/// 
/// # Returns
/// Nothing, but does write the compiled workflow to the given output file.
/// 
/// # Errors
/// This function errors if the input is not valid BraneScript or we failed to read the in/output.
pub async fn compile(language: Language, input: impl AsRef<Path>, output: impl AsRef<Path>, compact: bool, packages_loc: IndexLocation, data_loc: IndexLocation) -> Result<(), Error> {
    let input  : &Path = input.as_ref();
    let output : &Path = output.as_ref();

    // Open the given input
    let (iname, mut ihandle): (Cow<str>, Box<dyn Read>) = if input != PathBuf::from("-") {
        debug!("Opening input file '{}'...", input.display());
        match File::open(&input) {
            Ok(handle) => (Cow::from(input.display().to_string()), Box::new(handle)),
            Err(err)   => { return Err(Error::InputOpenError{ path: input.into(), err }); },
        }
    } else {
        ("<stdin>".into(), Box::new(std::io::stdin()))
    };

    // Open the given output
    let (oname, mut ohandle): (Cow<str>, Box<dyn Write>) = if output != PathBuf::from("-") {
        debug!("Creating output file '{}'...", output.display());
        match File::create(&output) {
            Ok(handle) => (output.display().to_string().into(), Box::new(handle)),
            Err(err)   => { return Err(Error::OutputCreateError{ path: output.into(), err }); },
        }
    } else {
        ("<stdout>".into(), Box::new(std::io::stdout()))
    };

    // Do the hard part
    compile_iter(&mut CompileState::new(), &mut String::new(), language, iname, &mut ihandle, oname, &mut ohandle, compact, &packages_loc, &data_loc).await?;

    // Done
    Ok(())
}



/// Compiles the given BraneScript files to a workflow, as if they're all part of the same one.
/// 
/// Effectively reads stdin repeatedly in a stateful compilation session.
/// 
/// # Arguments
/// - `language`: The language to compile.
/// - `output`: The file to output to. Can also be '-' to write to stdout.
/// - `compact`: If given, serializes with as little whitespace as possible. Decreases the resulting size greatly, but also readability.
/// - `packages_loc`: Where to get the package index from. Implemented as an IndexLocation so it may be both local or remote.
/// - `data_loc`: Where to get the data index from. Implemented as an IndexLocation so it may be both local or remote.
/// 
/// # Returns
/// Nothing, but does write the compiled workflow to the given output file after each input step.
/// 
/// # Errors
/// This function erros if the input is not valid BraneScript or we failed to read the in/output.
pub async fn compile_snippets(language: Language, output: impl AsRef<Path>, compact: bool, packages_loc: IndexLocation, data_loc: IndexLocation) -> Result<(), Error> {
    let output : &Path = output.as_ref();

    // Open the given input
    let (iname, mut ihandle): (&str, Box<dyn Read>) = ("<stdin>", Box::new(std::io::stdin()));

    // Open the given output
    let (oname, mut ohandle): (Cow<str>, Box<dyn Write>) = if output != PathBuf::from("-") {
        debug!("Creating output file '{}'...", output.display());
        match File::create(&output) {
            Ok(handle) => (output.display().to_string().into(), Box::new(handle)),
            Err(err)   => { return Err(Error::OutputCreateError{ path: output.into(), err }); },
        }
    } else {
        ("<stdout>".into(), Box::new(std::io::stdout()))
    };

    // Do the hard part, but repeatedly
    let mut state  : CompileState = CompileState::new();
    let mut source : String       = String::new();
    loop {
        compile_iter(&mut state, &mut source, language, iname, &mut ihandle, &oname, &mut ohandle, compact, &packages_loc, &data_loc).await?;
    }
}
