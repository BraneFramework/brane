//  COMPILE.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 18:12:44
//  Last edited:
//    29 Apr 2025, 13:39:18
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines some toplevel functions that run all traversals as desired.
//

use std::fmt::{Display, Formatter, Result as FResult};

use brane_dsl::ast::Program;
use brane_dsl::{Error as ParseError, ParserOptions};
use log::trace;
use specifications::data::DataIndex;
use specifications::package::PackageIndex;
use specifications::wir::Workflow;

use crate::ast_unresolved::UnresolvedWorkflow;
pub use crate::errors::AstError as Error;
use crate::state::CompileState;
use crate::traversals;
pub use crate::warnings::AstWarning as Warning;


/***** AUXILLARY *****/
/// Helper enum that defines the compiler stages.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompileStage {
    // Meta stages
    /// References nb compile stage.
    None  = 0,
    /// References the last compile stage, i.e., all stages.
    All   = 15,

    // Individual stages
    /// The initial stage where we update AST TextRanges.
    Offset = 1,
    /// The second stage where we process attribute statements.
    Attributes = 2,
    /// The third stage where we resolve the symbol tables.
    Resolve = 3,
    /// The fourth stage where we resolve types (as much as possible).
    Typing = 4,
    /// The fifth stage where we null-types.
    Null  = 5,
    /// The sixth stage where we analyse data dependencies.
    Data  = 6,
    /// The seventh stage where we resolve on-structs.
    Location = 7,
    /// The eighth stage where we add user-supplied metadata to a workflow.
    Metadata = 8,
    /// The ninth stage where we apply various optimizations, e.g., constant unfolding, constant casting, function inlining, etc.
    Optimization = 9,
    /// The tenth stage where we prune the resulting tree to make compilation easier (without affecting functionality).
    Prune = 10,
    /// The eleventh stage is the really final pre-compile stage, where we already collect definitions into a flattened symbol table tree structure.
    Flatten = 11,
    /// The twelth stage where we compile the Program to a Workflow.
    Compile = 12,
    /// The thirtheenth stage where we optimize the resulting workflow some more.
    WorkflowOptimization = 13,
    /// The fourteenth and final stage where we resolve the 'next' fields in the UnresolvedWorkflow so it becomes a Workflow.
    WorkflowResolve = 14,
}



/// Defines the possible results returned by the `compile_program` function.
#[derive(Debug)]
pub enum CompileResult {
    /// It's a fully processed workflow, and a list of any warnings that occured during compilation.
    Workflow(Workflow, Vec<Warning>),
    /// It's a workflow but not yet resolved to an executable one, and a list of any warnings that occured during compilation.
    Unresolved(UnresolvedWorkflow, Vec<Warning>),
    /// It's a (possibly preprocessed) program still a,nd a list of any warnings that occured during compilation.
    Program(Program, Vec<Warning>),

    /// A very specific error has occurred that says that the parser (not the scanner) got an EOF before it was expecting it (i.e., it wants more input).
    Eof(Error),
    /// An (or rather, multiple) error(s) ha(s/ve) occurred.
    Err(Vec<Error>),
}

impl CompileResult {
    /// Force-unwraps the CompileResult as a fully compiled workflow (and any warnings that occurred), or else panics.
    ///
    /// # Returns
    /// The carried Workflow and list of warnings as a tuple.
    ///
    /// # Panics
    /// This function panics if it was not actually a workflow.
    #[inline]
    pub fn workflow(self) -> (Workflow, Vec<Warning>) {
        if let Self::Workflow(w, warns) = self {
            (w, warns)
        } else {
            panic!("Cannot unwrap CompileResult::{self} as a Workflow");
        }
    }

    /// Force-unwraps the CompileResult as a compiled but unresolved workflow (and any warnings that occurred), or else panics.
    ///
    /// # Returns
    /// The carried UnresolvedWorkflow and list of warnings as a tuple.
    ///
    /// # Panics
    /// This function panics if it was not actually an unresolved workflow.
    #[inline]
    pub fn unresolved(self) -> (UnresolvedWorkflow, Vec<Warning>) {
        if let Self::Unresolved(u, warns) = self {
            (u, warns)
        } else {
            panic!("Cannot unwrap CompileResult::{self} as an UnresolvedWorkflow");
        }
    }

    /// Force-unwraps the CompileResult as a (possibly preprocessed) Program (and any warnings that occurred), or else panics.
    ///
    /// # Returns
    /// The carried Program and list of warnings as a tuple.
    ///
    /// # Panics
    /// This function panics if it was not actually a program.
    #[inline]
    pub fn program(self) -> (Program, Vec<Warning>) {
        if let Self::Program(p, warns) = self {
            (p, warns)
        } else {
            panic!("Cannot unwrap CompileResult::{self} as a Program");
        }
    }

    /// Force-unwraps the CompileResult as 'not enough input' (a special case of Error).
    ///
    /// In whole-workflow files, this should be treated as a full error. However, in snippet cases, detecting this separately may allow them to query for more input instead.
    ///
    /// # Returns
    /// The carried Error.
    ///
    /// # Panics
    /// This function panics if it was not actually an end-of-file error.
    #[inline]
    pub fn eof(self) -> Error {
        if let Self::Eof(e) = self {
            e
        } else {
            panic!("Cannot unwrap CompileResult::{self} as an Eof");
        }
    }

    /// Force-unwraps the CompileResult as an error.
    ///
    /// # Returns
    /// The carried Error.
    ///
    /// # Panics
    /// This function panics if it was not actually an error.
    #[inline]
    pub fn err(self) -> Vec<Error> {
        if let Self::Err(e) = self {
            e
        } else {
            panic!("Cannot unwrap CompileResult::{self} as an Error");
        }
    }
}

impl Display for CompileResult {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CompileResult::*;
        match self {
            Workflow(_, _) => write!(f, "Workflow"),
            Unresolved(_, _) => write!(f, "Unresolved"),
            Program(_, _) => write!(f, "Program"),

            Eof(_) => write!(f, "Eof"),
            Err(_) => write!(f, "Err"),
        }
    }
}





/***** LIBRARY *****/
/// Runs the compiler passes in-order, all of them.
///
/// # Generic arguments
/// - `R`: The Read-implementing type of the `source` text.
///
/// # Arguments
/// - `reader`: The reader that provides access to the source code to compile.
/// - `package_index`: The PackageIndex that is used to resolve imports.
/// - `data_index`: The DataIndex that is used to resolve `Data`-structs.
/// - `options`: The ParserOptions with which we parse the given file.
///
/// # Returns
/// The compiled Workflow if it got that far, or else the compiled UnresolvedWorkflow or Program. Will also output a list of any warnings that may have occurred (empty list is good).
///
/// # Errors
/// This function may error if the program was ill-formed. Multiple errors are returned simultaneously per-stage.
#[inline]
pub fn compile_program<R: std::io::Read>(reader: R, package_index: &PackageIndex, data_index: &DataIndex, options: &ParserOptions) -> CompileResult {
    compile_program_to(reader, package_index, data_index, options, CompileStage::All)
}

/// Runs the compiler passes in-order, up to the specified pass.
///
/// # Generic arguments
/// - `R`: The Read-implementing type of the `source` text.
///
/// # Arguments
/// - `reader`: The reader that provides access to the source code to compile.
/// - `package_index`: The PackageIndex that is used to resolve imports.
/// - `data_index`: The DataIndex that is used to resolve `Data`-structs.
/// - `options`: The ParserOptions with which we parse the given file.
/// - `stage`: The CompileStage up to which to run the pipeline. Use `CompileStage::All` to do the entire thing.
///
/// # Returns
/// The compiled Workflow if it got that far, or else the compiled UnresolvedWorkflow or Program. Will also output a list of any warnings that may have occurred (empty list is good).
///
/// # Errors
/// This function may error if the program was ill-formed. Multiple errors are returned simultaneously per-stage.
#[inline]
pub fn compile_program_to<R: std::io::Read>(
    reader: R,
    package_index: &PackageIndex,
    data_index: &DataIndex,
    options: &ParserOptions,
    stage: CompileStage,
) -> CompileResult {
    compile_snippet_to(&mut CompileState::new(), reader, package_index, data_index, options, stage)
}



/// Runs the compiler in a stateful manner so that it may compile multiple snippets of the given workflow in succession.
///
/// # Generic arguments
/// - `R`: The Read-implementing type of the `source` text.
///
/// # Arguments
/// - `state`: The CompileState of any previous runs (use `CompileState::new()` if there have not been any).
/// - `reader`: The reader that provides access to the source code to compile.
/// - `package_index`: The PackageIndex that is used to resolve imports.
/// - `data_index`: The DataIndex that is used to resolve `Data`-structs.
/// - `options`: The ParserOptions with which we parse the given file.
///
/// # Returns
/// A compiled Workflow and its associated warning as a CompileResult (i.e., is guaranteed to be either `CompileResult::Workflow` or any of the error states).
///
/// # Errors
/// This function may error if the program was ill-formed. Multiple errors are returned simultaneously per-stage.
#[inline]
pub fn compile_snippet<R: std::io::Read>(
    state: &mut CompileState,
    reader: R,
    package_index: &PackageIndex,
    data_index: &DataIndex,
    options: &ParserOptions,
) -> CompileResult {
    compile_snippet_to(state, reader, package_index, data_index, options, CompileStage::All)
}

/// Runs the compiler in a stateful manner so that it may compile multiple snippets of the given workflow in succession.
///
/// # Generic arguments
/// - `R`: The Read-implementing type of the `source` text.
///
/// # Arguments
/// - `state`: The CompileState of any previous runs (use `CompileState::new()` if there have not been any).
/// - `reader`: The reader that provides access to the source code to compile.
/// - `package_index`: The PackageIndex that is used to resolve imports.
/// - `data_index`: The DataIndex that is used to resolve `Data`-structs.
/// - `options`: The ParserOptions with which we parse the given file.
/// - `stage`: The CompileStage up to which to run the pipeline. Use `CompileStage::All` to do the entire thing.
///
/// # Returns
/// The compiled Workflow if it got that far, or else the compiled UnresolvedWorkflow or Program. Will also output a list of any warnings that may have occurred (empty list is good).
///
/// # Errors
/// This function may error if the program was ill-formed. Multiple errors are returned simultaneously per-stage.
pub fn compile_snippet_to<R: std::io::Read>(
    state: &mut CompileState,
    reader: R,
    package_index: &PackageIndex,
    data_index: &DataIndex,
    options: &ParserOptions,
    stage: CompileStage,
) -> CompileResult {
    let mut warnings: Vec<Warning> = vec![];

    // Something that always has to be done; parse the source from the given text...
    trace!("Reading input");
    let mut reader: R = reader;
    let mut source: String = String::new();
    if let Err(source) = reader.read_to_string(&mut source) {
        return CompileResult::Err(vec![Error::ReaderReadError { source }]);
    }
    // ...and compile it to a program
    trace!("Parsing as {}", options.lang);
    let mut program: Program = match brane_dsl::parse(source, package_index, options) {
        Ok(program) => program,
        Err(ParseError::Eof { lang, err }) => {
            return CompileResult::Eof(Error::ParseError { source: ParseError::Eof { lang, err } });
        },
        Err(source) => {
            return CompileResult::Err(vec![Error::ParseError { source }]);
        },
    };

    // Run the various traversals
    // First up: preprocessing (offset updating)
    if stage >= CompileStage::Offset {
        trace!("Running traversal: offset");
        program = match traversals::offset::do_traversal(program, state) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }

    // Program analysis (attribute processing, resolving symbol tables, type analysis, location analysis)
    if stage >= CompileStage::Attributes {
        trace!("Running traversal: attributes");
        program = match traversals::attributes::do_traversal(program, &mut warnings) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Resolve {
        trace!("Running traversal: resolve");
        program = match traversals::resolve::do_traversal(state, package_index, data_index, program) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Typing {
        trace!("Running traversal: typing");
        program = match traversals::typing::do_traversal(program, &mut warnings) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Null {
        trace!("Running traversal: null");
        program = match traversals::null::do_traversal(program) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Data {
        trace!("Running traversal: data");
        program = match traversals::data::do_traversal(state, program) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Location {
        trace!("Running traversal: location");
        program = match traversals::location::do_traversal(program) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Metadata {
        trace!("Running traversal: metadata");
        program = match traversals::metadata::do_traversal(program, &mut warnings) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }

    // Then, the optional optimization stage of the Program (constant unfolding, dead code removal, ...)
    if stage >= CompileStage::Optimization {
        trace!("Running traversal: optimization");
        /* Not implemented yet */
    }

    // Finally, prepare for compilation (prune & flatten) and compile to an unresolved workflow.
    if stage >= CompileStage::Prune {
        trace!("Running traversal: prune");
        program = match traversals::prune::do_traversal(program) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Flatten {
        trace!("Running traversal: flatten");
        program = match traversals::flatten::do_traversal(state, program) {
            Ok(program) => program,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };
    }
    if stage >= CompileStage::Compile {
        // Perform the compilation itself
        trace!("Running traversal: compile");
        let mut uworkflow = match traversals::compile::do_traversal(state, program, &mut warnings) {
            Ok(uworkflow) => uworkflow,
            Err(errs) => {
                return CompileResult::Err(errs);
            },
        };

        // Optimize the resulting workflow (basically binary code optimization)
        if stage >= CompileStage::WorkflowOptimization {
            trace!("Running traversal: workflow_optimize");
            uworkflow = match traversals::workflow_optimize::do_traversal(uworkflow) {
                Ok(uworkflow) => uworkflow,
                Err(errs) => {
                    return CompileResult::Err(errs);
                },
            };
        }

        // Finally, resolve the workflow
        if stage >= CompileStage::WorkflowResolve {
            // Yup resolving happening here
            trace!("Running traversal: workflow_resolve");
            let workflow = match traversals::workflow_resolve::do_traversal(state, uworkflow) {
                Ok(workflow) => workflow,
                Err(errs) => {
                    return CompileResult::Err(errs);
                },
            };

            // We can return as a workflow
            trace!("Compilation done (result: Workflow)");
            return CompileResult::Workflow(workflow, warnings);
        }

        // Otherwise, we never got past an unresolved workflow
        trace!("Compilation done (result: Unresolved)");
        return CompileResult::Unresolved(uworkflow, warnings);
    }

    // If we're still here, we never compiled to an unresolved workflow
    trace!("Compilation done (result: Program)");
    CompileResult::Program(program, warnings)
}
