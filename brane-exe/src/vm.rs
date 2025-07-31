//  VM.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 17:41:33
//  Last edited:
//    02 May 2025, 15:10:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the VM trait, which is a simple trait for defining VMs
//!   that use threads.
//

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use specifications::profiling::ProfileScopeHandle;
use specifications::wir::{SymTable, Workflow};

use crate::errors::VmError;
use crate::spec::{CustomGlobalState, CustomLocalState, RunState, VmPlugin};
use crate::thread::Thread;
use crate::value::FullValue;





/***** LIBRARY *****/
/// Defines a common interface (and some code) for virtual machines.
#[async_trait]
pub trait Vm {
    /// The type of the thread-global extension to the runtime state.
    type GlobalState: CustomGlobalState;
    /// The type of the thread-local extension to the runtime state.
    type LocalState: CustomLocalState;



    // Child-specific
    /// A function that stores the given runtime state information in the parent struct.
    ///
    /// This is important and will be used later.
    ///
    /// # Arguments
    /// - `state`: The current state of the workflow we have executed.
    ///
    /// # Returns
    /// Nothing, but should change the internals to return this state later upon request.
    ///
    /// # Errors
    /// This function may error for its own reasons.
    fn store_state(this: &Arc<RwLock<Self>>, state: RunState<Self::GlobalState>) -> Result<(), VmError>;

    /// A function that returns the VM's runtime state in the parent struct.
    ///
    /// This is important and will be used later.
    ///
    /// # Returns
    /// The RunState of this application if it exists, or else None.
    ///
    /// # Errors
    /// This function may error for its own reasons.
    fn load_state(this: &Arc<RwLock<Self>>) -> Result<RunState<Self::GlobalState>, VmError>;



    // Global
    /// Initializes a new global state based on the given custom part.
    ///
    /// # Arguments
    /// - `pindex`: The package index which we can use for resolving packages.
    /// - `dindex`: The data index which we can use for resolving datasets.
    /// - `custom`: The custom part of the global state with which we will initialize it.
    ///
    /// # Returns
    /// A new RunState instance.
    #[inline]
    fn new_state(custom: Self::GlobalState) -> RunState<Self::GlobalState> { RunState::new(Arc::new(SymTable::new()), Arc::new(RwLock::new(custom))) }

    /// Runs the given workflow, possibly asynchronously (if a parallel is encountered / there are external functions calls and the given closure runs this asynchronously.)
    ///
    /// # Generic arguments
    /// - `P`: The "VM plugin" that will fill in the blanks with respect to interacting with the outside world.
    ///
    /// # Arguments
    /// - `snippet`: The snippet to compile. This is either the entire workflow, or a snippet of it. In the case of the latter, the internal state will be used (and updated).
    /// - `prof`: The ProfileScope that can be used to provide additional information about the timings of the VM (framework-wise, not user-wise).
    ///
    /// # Returns
    /// The result if the Workflow returned any, together with the edge that produced it. Only if the workflow is empty will this be [`None`].
    async fn run<P: VmPlugin<GlobalState = Self::GlobalState, LocalState = Self::LocalState>>(
        this: Arc<RwLock<Self>>,
        snippet: Workflow,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<FullValue, VmError>
    where
        Self: Sync,
    {
        // Fetch the previous state (if any)
        let mut state: RunState<Self::GlobalState> = Self::load_state(&this)?;
        state.fstack.update_table(snippet.table.clone());

        // Create a new thread with (a copy of) the internal state, if any.
        let main: Thread<Self::GlobalState, Self::LocalState> = Thread::from_state(&snippet, state);

        // Run the workflow
        match main.run_snippet::<P>(prof.into()).await {
            Ok((res, state)) => {
                // Convert the value into a full value (if any)
                let res: FullValue = res.into_full(state.fstack.table());

                // Store the state
                Self::store_state(&this, state)?;

                // Done, return
                Ok(res)
            },
            Err(err) => Err(err),
        }
    }
}


/***** TESTS *****/
#[cfg(test)]
pub mod tests {
    use brane_ast::fetcher::SnippetFetcher;
    use brane_ast::state::CompileState;
    use brane_ast::traversals::print::ast;
    use brane_ast::{CompileResult, ParserOptions, compile_snippet};
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files_async};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::*;
    use crate::dummy::DummyVm;


    /// Tests the traversal by generating symbol tables for every file.
    #[tokio::test]
    async fn test_snippets() {
        // Run the tests on all the files
        test_on_dsl_files_async("BraneScript", |path, code| {
            async move {
                // Start by the name to always know which file this is
                println!("{}", (0..80).map(|_| '-').collect::<String>());
                println!("File '{}' gave us:", path.display());

                // Load the package index
                let pindex: PackageIndex = create_package_index();
                let dindex: DataIndex = create_data_index();

                // Run the program but now line-by-line (to test the snippet function)
                let mut source: String = String::new();
                let mut state: CompileState = CompileState::new();
                let mut vm: DummyVm = DummyVm::new();
                let mut iter = code.split('\n');
                for (offset, l) in SnippetFetcher::new(|| Ok(iter.next().map(|l| l.into()))) {
                    // Append the source (for errors only)
                    source.push_str(&l);

                    // Compile the workflow
                    let workflow: Workflow = match compile_snippet(&mut state, l.as_bytes(), &pindex, &dindex, &ParserOptions::bscript()) {
                        CompileResult::Workflow(wf, warns) => {
                            // Print warnings if any
                            for w in warns {
                                w.prettyprint(path.to_string_lossy(), &source);
                            }
                            wf
                        },
                        CompileResult::Eof(err) => {
                            // Fetch more data instead
                            err.prettyprint(path.to_string_lossy(), &source);
                            panic!("Failed to compile to workflow (see output above)");
                        },
                        CompileResult::Err(errs) => {
                            // Print the errors
                            for e in errs {
                                e.prettyprint(path.to_string_lossy(), &source);
                            }
                            panic!("Failed to compile to workflow (see output above)");
                        },

                        _ => {
                            unreachable!();
                        },
                    };

                    // Print the file itself
                    ast::do_traversal(&workflow, std::io::stdout()).unwrap();
                    println!("{}", (0..40).map(|_| "- ").collect::<String>());

                    // Run the VM on this snippet
                    vm = match vm.exec(workflow).await {
                        (vm, Ok(value)) => {
                            println!("Workflow stdout:");
                            vm.flush_stdout();
                            println!();
                            println!("Workflow returned: {value:?}");
                            vm
                        },
                        (_, Err(err)) => {
                            eprintln!("{err}");
                            panic!("Failed to execute workflow (snippet) (see output above)");
                        },
                    };

                    // Increment the state offset
                    state.offset += offset.line;
                }
                println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
            }
        })
        .await;
    }
}
