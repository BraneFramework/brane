//  WORKFLOW OPTIMIZE.rs
//    by Lut99
//
//  Created:
//    19 Oct 2022, 11:19:39
//  Last edited:
//    23 Dec 2022, 16:36:20
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a traversal that optimizes a workflow by combining as
//!   much edges into one as possible.
//

use crate::ast_unresolved::UnresolvedWorkflow;
use crate::errors::AstError;


/***** ARGUMENTS *****/
/// Optimizes the given UnresolvedWorkflow by collapsing successive linear edges into one edge.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same UnresolvedWorkflow but now (hopefully) with less edges.
///
/// # Errors
/// This pass doesn't error, but might return one for convention purposes.
///
/// # Panics
/// This function may panic if any of the previous passes did not do its job, and the given UnresolvedWorkflow is ill-formed.
pub fn do_traversal(root: UnresolvedWorkflow) -> Result<UnresolvedWorkflow, Vec<AstError>> {
    let mut root: UnresolvedWorkflow = root;

    // Pass over each of the buffers
    root.main_edges.merge_linear();
    for edges in root.f_edges.values_mut() {
        edges.merge_linear();
    }

    // Done
    Ok(root)
}


/***** TESTS *****/
#[cfg(test)]
mod tests {
    use brane_dsl::ParserOptions;
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::super::print::ast_unresolved;
    use super::*;
    use crate::state::CompileState;
    use crate::{CompileResult, CompileStage, compile_snippet_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_workflow_optimize() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // First, compile but not resolve
            let mut state: CompileState = CompileState::new();
            let workflow: UnresolvedWorkflow =
                match compile_snippet_to(&mut state, code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Compile) {
                    CompileResult::Unresolved(wf, warns) => {
                        // Print warnings if any
                        for w in warns {
                            w.prettyprint(path.to_string_lossy(), &code);
                        }
                        wf
                    },
                    CompileResult::Eof(err) => {
                        // Print the error
                        err.prettyprint(path.to_string_lossy(), &code);
                        panic!("Failed to optimize workflow (see output above)");
                    },
                    CompileResult::Err(errs) => {
                        // Print the errors
                        for e in errs {
                            e.prettyprint(path.to_string_lossy(), &code);
                        }
                        panic!("Failed to optimize workflow (see output above)");
                    },

                    _ => {
                        unreachable!();
                    },
                };

            // Now print the file for prettyness
            ast_unresolved::do_traversal(&state, workflow, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..40).map(|_| "- ").collect::<String>());

            // Run up to this traversal
            let mut state: CompileState = CompileState::new();
            let workflow: UnresolvedWorkflow = match compile_snippet_to(
                &mut state,
                code.as_bytes(),
                &pindex,
                &dindex,
                &ParserOptions::bscript(),
                CompileStage::WorkflowOptimization,
            ) {
                CompileResult::Unresolved(wf, warns) => {
                    // Print warnings if any
                    for w in warns {
                        w.prettyprint(path.to_string_lossy(), &code);
                    }
                    wf
                },
                CompileResult::Eof(err) => {
                    // Print the error
                    err.prettyprint(path.to_string_lossy(), &code);
                    panic!("Failed to optimize workflow (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to optimize workflow (see output above)");
                },

                _ => {
                    unreachable!();
                },
            };

            // Now print the file for prettyness
            ast_unresolved::do_traversal(&state, workflow, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
