//  TESTS.rs
//    by Lut99
//
//  Created:
//    18 Oct 2024, 11:08:50
//  Last edited:
//    29 Apr 2025, 13:40:32
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements tests for the [`Workflow`](super::spec::Workflow) (or
//!   rather, its compiler(s)).
//

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

use brane_ast::{CompileResult, ParserOptions, compile_program};
use brane_shr::utilities::{create_data_index_from, create_package_index_from, test_on_dsl_files_in};
use policy_reasoner::workflow::Workflow;
use specifications::data::DataIndex;
use specifications::package::PackageIndex;
use specifications::wir as ast;
use tracing::{Level, debug};

use crate::workflow::compile::compile;


/***** CONSTANTS *****/
/// Defines the location of the tests
pub(crate) const TESTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests");
const BLOCK_SEPARATOR: &str = "--------------------------------------------------------------------------------";





/***** HELPER FUNCTIONS *****/
/// Injects some (random) data in a workflow to simulate required information from the Brane runtime.
///
/// Specifically, injects:
/// - The end user of the workflow.
///
/// # Arguments
/// - `wir`: A (mutable reference to a) BraneScript [`Workflow`](ast::Workflow).
fn prepare_workflow(wir: &mut ast::Workflow) {
    // Inject the user with a random name
    wir.user = Arc::new(Some(names::three::rand().into()));
}





/***** LIBRARY *****/
/// Run all the BraneScript tests
#[test]
fn test_checker_workflow_unoptimized() {
    let tests_path: PathBuf = PathBuf::from(TESTS_DIR);

    // Run the compiler for every applicable DSL file
    test_on_dsl_files_in("BraneScript", &tests_path, |path: PathBuf, code: String| {
        // Start by the name to always know which file this is
        println!("{BLOCK_SEPARATOR}");
        println!("File '{}' gave us:", path.display());

        // Skip some files, sadly
        if let Some(name) = path.file_name() {
            if name == OsStr::new("class.bs") {
                println!("Skipping test, since instance calling is not supported in checker workflows...");
                println!("{BLOCK_SEPARATOR}\n\n");
                return;
            }
            if name == OsStr::new("recursion.bs") {
                println!("Skipping test, since recursion is not supported in checker workflows...");
                println!("{BLOCK_SEPARATOR}\n\n");
                return;
            }
        }

        // Load the package index
        let pindex: PackageIndex = create_package_index_from(tests_path.join("packages"));
        let dindex: DataIndex = create_data_index_from(tests_path.join("data"));

        // Compile the raw source to WIR
        let mut wir: ast::Workflow = match compile_program(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript()) {
            CompileResult::Workflow(wir, warns) => {
                // Print warnings if any
                for w in warns {
                    w.prettyprint(path.to_string_lossy(), &code);
                }
                wir
            },
            CompileResult::Eof(err) => {
                // Print the error
                err.prettyprint(path.to_string_lossy(), &code);
                panic!("Failed to compile to WIR (see output above)");
            },
            CompileResult::Err(errs) => {
                // Print the errors
                for e in errs {
                    e.prettyprint(path.to_string_lossy(), &code);
                }
                panic!("Failed to compile to WIR (see output above)");
            },

            _ => {
                unreachable!();
            },
        };

        // Insert some additional content
        prepare_workflow(&mut wir);

        // Print the WIR in debug mode
        if tracing::enabled!(Level::DEBUG) {
            // Write the processed graph
            let mut buf: Vec<u8> = vec![];
            brane_ast::traversals::print::ast::do_traversal(&wir, &mut buf).unwrap();
            debug!("Compiled workflow:\n\n{}\n", String::from_utf8_lossy(&buf));
        }

        // Next, compile to the checker's workflow
        let wf: Workflow = match compile(wir) {
            Ok(wf) => wf,
            Err(err) => {
                panic!("Failed to compile WIR to CheckerWorkflow: {err}");
            },
        };

        // Now print the file for prettyness
        println!("{}", wf.visualize());
        println!("{BLOCK_SEPARATOR}\n\n");
    });
}

/// Run all the BraneScript tests _with_ optimization
#[test]
fn test_checker_workflow_optimized() {
    let tests_path: PathBuf = PathBuf::from(TESTS_DIR);

    // Run the compiler for every applicable DSL file
    test_on_dsl_files_in("BraneScript", &tests_path, |path: PathBuf, code: String| {
        // Start by the name to always know which file this is
        println!("{BLOCK_SEPARATOR}");
        println!("(Optimized) File '{}' gave us:", path.display());

        // Skip some files, sadly
        if let Some(name) = path.file_name() {
            if name == OsStr::new("class.bs") {
                println!("Skipping test, since instance calling is not supported in checker workflows...");
                println!("{BLOCK_SEPARATOR}\n\n");
                return;
            }
            if name == OsStr::new("recursion.bs") {
                println!("Skipping test, since recursion is not supported in checker workflows...");
                println!("{BLOCK_SEPARATOR}\n\n");
                return;
            }
        }

        // Load the package index
        let pindex: PackageIndex = create_package_index_from(tests_path.join("packages"));
        let dindex: DataIndex = create_data_index_from(tests_path.join("data"));

        // Compile the raw source to WIR
        let mut wir: ast::Workflow = match compile_program(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript()) {
            CompileResult::Workflow(wir, warns) => {
                // Print warnings if any
                for w in warns {
                    w.prettyprint(path.to_string_lossy(), &code);
                }
                wir
            },
            CompileResult::Eof(err) => {
                // Print the error
                err.prettyprint(path.to_string_lossy(), &code);
                panic!("Failed to compile to WIR (see output above)");
            },
            CompileResult::Err(errs) => {
                // Print the errors
                for e in errs {
                    e.prettyprint(path.to_string_lossy(), &code);
                }
                panic!("Failed to compile to WIR (see output above)");
            },

            _ => {
                unreachable!();
            },
        };

        // Insert some additional content
        prepare_workflow(&mut wir);

        // Print the WIR in debug mode
        if tracing::enabled!(Level::DEBUG) {
            // Write the processed graph
            let mut buf: Vec<u8> = vec![];
            brane_ast::traversals::print::ast::do_traversal(&wir, &mut buf).unwrap();
            debug!("Compiled workflow:\n\n{}\n", String::from_utf8_lossy(&buf));
        }

        // Next, compile to the checker's workflow
        let mut wf: Workflow = match compile(wir) {
            Ok(wf) => wf,
            Err(err) => {
                panic!("Failed to compile WIR to CheckerWorkflow: {err}");
            },
        };

        // Slide in that optimization
        wf.optimize();

        // Now print the file for prettyness
        println!("{}", wf.visualize());
        println!("{BLOCK_SEPARATOR}\n\n");
    });
}
