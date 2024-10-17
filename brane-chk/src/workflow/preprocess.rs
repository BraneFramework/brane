//  PREPROCESS.rs
//    by Lut99
//
//  Created:
//    02 Nov 2023, 14:52:26
//  Last edited:
//    12 Jun 2024, 17:41:53
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines a preprocessing step on a [WIR](Workflow) that simplifies it
//!   to increase the support of the simpler checker workflow.
//

use std::collections::{HashMap, HashSet};
use std::error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::panic::catch_unwind;
use std::sync::Arc;

use brane_ast::MergeStrategy;
use brane_ast::ast::{Edge, EdgeInstr, FunctionDef, SymTable, TaskDef, Workflow};
use brane_ast::func_id::FunctionId;
use brane_ast::spec::BuiltinFunctions;
use brane_exe::pc::{ProgramCounter, ResolvedProgramCounter};
use enum_debug::EnumDebug as _;
use log::{debug, trace};

use super::utils;

/***** TESTS *****/
#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use brane_ast::traversals::print::ast;
    use brane_ast::{CompileResult, ParserOptions, compile_program};
    use brane_shr::utilities::{create_data_index_from, create_package_index_from, test_on_dsl_files_in};
    use humanlog::{DebugMode, HumanLogger};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::*;

    /// Runs checks to verify the workflow inlining analysis
    #[test]
    fn test_checker_workflow_inline_analysis() {
        // Setup logger if told
        if std::env::var("TEST_LOGGER").map(|value| value == "1" || value == "true").unwrap_or(false) {
            if let Err(err) = HumanLogger::terminal(DebugMode::Full).init() {
                eprintln!("WARNING: Failed to setup test logger: {err} (no logging for this session)");
            }
        }

        // Defines a few test files with expected inlinable functions
        let tests: [(&str, &str, HashMap<usize, Option<HashSet<usize>>>); 5] = [
            ("case1", r#"println("Hello, world!");"#, HashMap::from([(1, None)])),
            (
                "case2",
                r#"func hello_world() { return "Hello, world!"; } println(hello_world());"#,
                HashMap::from([(1, None), (4, Some(HashSet::new()))]),
            ),
            (
                "case3",
                r#"func foo() { return "Foo"; } func foobar() { return foo() + "Bar"; } println(foobar());"#,
                HashMap::from([(1, None), (4, Some(HashSet::new())), (5, Some(HashSet::from([4])))]),
            ),
            ("case4", r#"import hello_world; println(hello_world());"#, HashMap::from([(1, None)])),
            (
                "case5",
                r#"func hello_world(n) { if (n <= 0) { return "Hello, world!"; } else { return "Hello, " + hello_world(n - 1) + "\n"; } } println(hello_world(3));"#,
                HashMap::from([(1, None), (4, None)]),
            ),
        ];

        // Load example package- and data indices
        let tests_path: PathBuf = PathBuf::from(super::super::tests::TESTS_DIR);
        let pindex: PackageIndex = create_package_index_from(tests_path.join("packages"));
        let dindex: DataIndex = create_data_index_from(tests_path.join("data"));

        // Test them each
        for (id, test, gold) in tests.into_iter() {
            // Compile to BraneScript (we'll assume this works)
            let wir: Workflow = match compile_program(test.as_bytes(), &pindex, &dindex, &ParserOptions::bscript()) {
                CompileResult::Workflow(wir, _) => wir,
                CompileResult::Err(errs) => {
                    for err in errs {
                        err.prettyprint(format!("<{id}>"), test);
                    }
                    panic!("Failed to compile BraneScript (see error above)");
                },
                CompileResult::Eof(err) => {
                    err.prettyprint(format!("<{id}>"), test);
                    panic!("Failed to compile BraneScript (see error above)");
                },

                _ => {
                    unreachable!();
                },
            };
            // Emit the compiled workflow
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("Test '{id}'");
            println!();
            ast::do_traversal(&wir, std::io::stdout()).unwrap();
            println!();

            // Analyse function calls (we'll assume this works too)
            let calls: HashMap<ProgramCounter, usize> = resolve_calls(&wir, &wir.table, &mut vec![], ProgramCounter::start(), None, None).unwrap().0;
            println!(
                "Resolved functions calls: {:?}",
                calls.iter().map(|(pc, func_id)| (format!("{}", pc.resolved(&wir.table)), *func_id)).collect::<HashMap<String, usize>>()
            );

            // Analyse the inlinable funcs
            let mut pred: HashMap<usize, Option<HashSet<usize>>> = HashMap::with_capacity(calls.len());
            find_inlinable_funcs(&wir, &calls, &mut vec![], ProgramCounter::start(), None, &mut pred);
            println!("Inlinable functions: {pred:?}");
            println!();

            // Neat, done, assert it was right
            assert_eq!(pred, gold);
        }
    }

    /// Runs the workflow inlining on the test files only
    #[test]
    fn test_checker_workflow_simplify() {
        let tests_path: PathBuf = PathBuf::from(super::super::tests::TESTS_DIR);

        // Setup logger if told
        if std::env::var("TEST_LOGGER").map(|value| value == "1" || value == "true").unwrap_or(false) {
            if let Err(err) = HumanLogger::terminal(DebugMode::Full).init() {
                eprintln!("WARNING: Failed to setup test logger: {err} (no logging for this session)");
            }
        }
        // Scope the function
        let test_file: Option<String> = std::env::var("TEST_FILE").ok();

        // Run the compiler for every applicable DSL file
        test_on_dsl_files_in("BraneScript", &tests_path, |path: PathBuf, code: String| {
            // Skip if not the file we're looking for
            if let Some(test_file) = &test_file {
                if path.file_name().is_none() || path.file_name().unwrap().to_string_lossy() != test_file.as_str() {
                    return;
                }
            }

            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Skip some files, sadly
            if let Some(name) = path.file_name() {
                if name == OsStr::new("class.bs") {
                    println!("Skipping test, since instance calling is not supported in checker workflows...");
                    println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
                    return;
                }
            }

            // Load the package index
            let pindex: PackageIndex = create_package_index_from(tests_path.join("packages"));
            let dindex: DataIndex = create_data_index_from(tests_path.join("data"));

            // Compile the raw source to WIR
            let wir: Workflow = match compile_program(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript()) {
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

            // Alright preprocess it
            let wir: Workflow = match simplify(wir) {
                Ok((wir, _)) => wir,
                Err(err) => {
                    panic!("Failed to preprocess WIR: {err}");
                },
            };

            // Now print the file for prettyness
            ast::do_traversal(&wir, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}

/***** ERRORS *****/
/// Defines errors that may occur when preprocessing a [`Workflow`].
#[derive(Debug)]
pub enum Error {
    /// Unknown task given.
    UnknownTask { id: usize },
    /// Unknown function given.
    UnknownFunc { id: FunctionId },
    /// A [`Call`](ast::Edge::Call)-edge was encountered while we didn't know of a function ID on the stack.
    CallingWithoutId { pc: ResolvedProgramCounter },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            UnknownTask { id } => write!(f, "Encountered unknown task ID {id} in Node"),
            UnknownFunc { id } => write!(f, "Encountered unknown function ID {id} in Call"),
            CallingWithoutId { pc } => write!(f, "Attempted to call function at {pc} without statically known task ID on the stack"),
        }
    }
}
impl error::Error for Error {}

/***** ANALYSIS FUNCTIONS *****/
/// Checks whether the given stream of instructions would end with a function ID on top of the stack.
///
/// # Arguments
/// - `instrs`: The list of instructions to analyse.
/// - `idx`: The index of the particular instruction (i.e., the previous one) to examine. When calling this functio non-recursively, use the **last** instruction.
///
/// # Returns
/// A double [`Option`] detailling what's possible:
/// - [`Some(Some(...))`] means that there was a function ID on top.
/// - [`Some(None)`] means that we _know_ there is _no_ function ID on top.
/// - [`None`] means that nothing was pushed, i.e., whatever was on top is still on top.
fn pushes_func_id(instrs: &[EdgeInstr], idx: usize) -> Option<Option<usize>> {
    // Pop the next instruction
    let instr: &EdgeInstr = if idx < instrs.len() {
        &instrs[idx]
    } else {
        // If we reached the last instruction, then we know no value was pushed :celebrate:
        return None;
    };

    // Examine what it does
    // NOTE: The BraneScript compiler only supports function calls over identifiers and projections. So we can ignore gnarly array stuff etc!
    // NOTE: Actually... we know violently little statically of class calls in general, because they are fully pushed to dynamic land. We _could_ learn it by tracking
    //       a variable's contents over multiple edges, but that fucks; let's give up and only support direct calls for now.
    match instr {
        // What we're looking for!
        EdgeInstr::Function { def } => Some(Some(*def)),

        // Things instructions only pop, potentially (accidentally) removing our function
        // Jep just tell the thign we don't know, we don't need it for direct function calls
        EdgeInstr::Pop {} | EdgeInstr::PopMarker {} | EdgeInstr::DynamicPop {} | EdgeInstr::VarSet { .. } => Some(None),

        // Alright some weird local branching; fuck it, also give up because we don't know which of the branches will do it
        EdgeInstr::Branch { .. } | EdgeInstr::BranchNot { .. } => Some(None),

        // These instructions never pop- or push anything
        EdgeInstr::VarDec { .. } | EdgeInstr::VarUndec { .. } => Some(None),

        // These instructions push invalid things _for sure_
        EdgeInstr::Cast { .. }
        | EdgeInstr::Not {}
        | EdgeInstr::Neg {}
        | EdgeInstr::And {}
        | EdgeInstr::Or {}
        | EdgeInstr::Add {}
        | EdgeInstr::Sub {}
        | EdgeInstr::Mul {}
        | EdgeInstr::Div {}
        | EdgeInstr::Mod {}
        | EdgeInstr::Eq {}
        | EdgeInstr::Ne {}
        | EdgeInstr::Lt {}
        | EdgeInstr::Le {}
        | EdgeInstr::Gt {}
        | EdgeInstr::Ge {}
        | EdgeInstr::Array { .. }
        | EdgeInstr::ArrayIndex { .. }
        | EdgeInstr::Instance { .. }
        | EdgeInstr::Proj { .. }
        | EdgeInstr::VarGet { .. }
        | EdgeInstr::Boolean { .. }
        | EdgeInstr::Integer { .. }
        | EdgeInstr::Real { .. }
        | EdgeInstr::String { .. } => Some(None),
    }
}

/// Analyses the edges in an [`Workflow`] to resolve function calls to the ID of the functions they call.
///
/// # Arguments
/// - `wir`: The [`Workflow`] to analyse.
/// - `table`: A running [`VirtualSymTable`] that determines the current types in scope.
/// - `trace`: A stack of call pointers that keeps track of the trace of function calls. Allows us to avoid recursion.
/// - `stack_id`: The function ID currently known to be on the stack. Is [`None`] if we don't know this.
/// - `pc`: The program-counter-index of the edge to analyse. These are pairs of `(function, edge_idx)`, where main is referred to by [`usize::MAX`](usize).
/// - `breakpoint`: An optional program-counter-index that, if given, will not analyse that edge onwards (excluding it too).
///
/// # Returns
/// A tuple with a [`HashMap`] that maps call indices (as program-counter-indices) to function IDs and an optional top call ID currently on the stack.
///
/// Note that, if a call ID occurs in the map but has [`None`] as function ID, it means it does not map to a body (e.g., a builtin).
///
/// # Errors
/// This function may error if we failed to statically discover the function IDs.
fn resolve_calls(
    wir: &Workflow,
    table: &SymTable,
    trace: &mut Vec<ProgramCounter>,
    pc: ProgramCounter,
    stack_id: Option<usize>,
    breakpoint: Option<ProgramCounter>,
) -> Result<(HashMap<ProgramCounter, usize>, Option<usize>), Error> {
    // Quit if we're at the breakpoint
    if let Some(breakpoint) = breakpoint {
        if pc == breakpoint {
            return Ok((HashMap::new(), None));
        }
    }

    // Get the edge in the workflow
    let edge: &Edge = match utils::get_edge(wir, pc) {
        Some(edge) => edge,
        None => return Ok((HashMap::new(), None)),
    };

    // Match to recursively process it
    trace!("Attempting to resolve calls in {} ({:?})", pc.resolved(table), edge.variant());
    match edge {
        Edge::Node { task, next, .. } => {
            // Attempt to discover the return type of the Node.
            let def: &TaskDef = match table.tasks.get(*task) {
                Some(def) => def,
                None => return Err(Error::UnknownTask { id: *task }),
            };

            // Alright, recurse with the next instruction
            resolve_calls(wir, table, trace, pc.jump(*next), if def.func().ret.is_void() { stack_id } else { None }, breakpoint)
        },

        Edge::Linear { instrs, next } => {
            // Analyse the instructions to find out if we can deduce a new `stack_id`
            let stack_id: Option<usize> = if !instrs.is_empty() { pushes_func_id(instrs, instrs.len() - 1).unwrap_or(stack_id) } else { stack_id };

            // Analyse the next one
            resolve_calls(wir, table, trace, pc.jump(*next), stack_id, breakpoint)
        },

        Edge::Stop {} => Ok((HashMap::new(), None)),

        Edge::Branch { true_next, false_next, merge } => {
            // First, analyse the branches
            let (mut calls, mut stack_id): (HashMap<_, _>, Option<usize>) =
                resolve_calls(wir, table, trace, pc.jump(*true_next), stack_id, merge.map(|merge| pc.jump(merge)))?;
            if let Some(false_next) = false_next {
                let (false_calls, false_stack) = resolve_calls(wir, table, trace, pc.jump(*false_next), stack_id, merge.map(|merge| pc.jump(merge)))?;
                calls.extend(false_calls);
                if stack_id != false_stack {
                    stack_id = None;
                }
            }

            // Analyse the remaining part next
            if let Some(merge) = merge {
                let (merge_calls, merge_stack) = resolve_calls(wir, table, trace, pc.jump(*merge), stack_id, breakpoint)?;
                calls.extend(merge_calls);
                stack_id = merge_stack;
            }

            // Alright, return the found results
            Ok((calls, stack_id))
        },

        Edge::Parallel { branches, merge } => {
            // Simply analyse all branches first. No need to worry about their return values and such, since that's not until the `Join`.
            let mut calls: HashMap<_, _> = HashMap::new();
            for branch in branches {
                calls.extend(resolve_calls(wir, table, trace, pc.jump(*branch), stack_id, breakpoint)?.0);
            }

            // OK, then analyse the rest assuming the stack is unchanged (we can do that because the parallel's branches get clones)
            let (new_calls, stack_id): (HashMap<_, _>, Option<usize>) = resolve_calls(wir, table, trace, pc.jump(*merge), stack_id, breakpoint)?;
            calls.extend(new_calls);
            Ok((calls, stack_id))
        },

        Edge::Join { merge, next } => {
            // Simply do the next, only _not_ resetting the stack ID if no value is returned.
            resolve_calls(wir, table, trace, pc.jump(*next), if *merge == MergeStrategy::None { stack_id } else { None }, breakpoint)
        },

        Edge::Loop { cond, body, next } => {
            // Traverse the three individually, using the stack ID of the codebody that precedes it
            let (mut calls, mut cond_id): (HashMap<_, _>, Option<usize>) =
                resolve_calls(wir, table, trace, pc.jump(*cond), stack_id, Some(pc.jump(*body - 1)))?;
            let (body_calls, _): (HashMap<_, _>, Option<usize>) = resolve_calls(wir, table, trace, pc.jump(*body), cond_id, Some(pc.jump(*cond)))?;
            calls.extend(body_calls);
            if let Some(next) = next {
                let (next_calls, next_id): (HashMap<_, _>, Option<usize>) = resolve_calls(wir, table, trace, pc.jump(*next), cond_id, breakpoint)?;
                calls.extend(next_calls);
                cond_id = next_id;
            }

            // Done!
            Ok((calls, cond_id))
        },

        Edge::Call { input: _, result: _, next } => {
            // Alright time to jump functions based on the current top-of-the-stack
            let stack_id: usize = match stack_id {
                Some(id) => id,
                None => {
                    return Err(Error::CallingWithoutId { pc: pc.resolved(table) });
                },
            };

            // We can early quit upon recursion
            if trace.contains(&pc) {
                let mut calls: HashMap<ProgramCounter, usize> = HashMap::from([(pc, stack_id)]);
                let (next_calls, next_id): (HashMap<_, _>, Option<usize>) = resolve_calls(wir, table, trace, pc.jump(*next), None, breakpoint)?;
                calls.extend(next_calls);
                return Ok((calls, next_id));
            }

            // Add the mapping to the table
            let mut calls: HashMap<ProgramCounter, usize> = HashMap::from([(pc, stack_id)]);

            // Resolve the call of the function (builtins simply return nothing, so are implicitly handled)
            trace.push(pc);
            let (call_calls, call_id): (HashMap<_, _>, Option<usize>) = resolve_calls(wir, table, trace, ProgramCounter::call(stack_id), None, None)?;
            trace.pop();
            calls.extend(call_calls);

            // Then continue with the next one
            let (next_calls, next_id): (HashMap<_, _>, Option<usize>) = resolve_calls(wir, table, trace, pc.jump(*next), call_id, breakpoint)?;
            calls.extend(next_calls);
            Ok((calls, next_id))
        },

        Edge::Return { result: _ } => {
            // If we're in the main function, this acts as an [`Elem::Stop`] with value
            if pc.is_main() {
                return Ok((HashMap::new(), None));
            }

            // To see whether we pass a function ID, consult the function definition
            let def: &FunctionDef = match catch_unwind(|| table.func(pc.func_id)) {
                Ok(def) => def,
                Err(_) => return Err(Error::UnknownFunc { id: pc.func_id }),
            };

            // Only return the current one if the function returns void
            if def.ret.is_void() { Ok((HashMap::new(), stack_id)) } else { Ok((HashMap::new(), None)) }
        },
    }
}

/// Attempts to find all non-recursive functions in the given WIR.
///
/// The only moment when we don't consider a function inlinable is if the function call is:
/// - Recursive
/// - A builtin
/// - Undecidable
///
/// # Arguments
/// - `wir`: The input [WIR](Workflow) to analyse.
/// - `calls`: The map of call indices to which function is actually called.
/// - `trace`: A trace of function IDs that we've "called".
/// - `pc`: Points to the current [`Edge`] to analyse.
/// - `breakpoint`: If given, then analysis should stop when this PC is hit.
/// - `inlinable`: The result we're recursively building. This set simply collects all function IDs and maps them to inlinable or not. If they are, then their ID is mapped to a list of functions on which the call depends (or else [`None`]).
///
/// # Returns
/// A list of all function calls found (that are inlinable). This builds a dependency tree of which calls the given depends on.
fn find_inlinable_funcs(
    wir: &Workflow,
    calls: &HashMap<ProgramCounter, usize>,
    trace: &mut Vec<usize>,
    pc: ProgramCounter,
    breakpoint: Option<ProgramCounter>,
    inlinable: &mut HashMap<usize, Option<HashSet<usize>>>,
) -> HashSet<usize> {
    // Stop on the breakpoint
    if let Some(breakpoint) = breakpoint {
        if pc == breakpoint {
            return HashSet::new();
        }
    }
    // Attempt to get the edge
    let edge: &Edge = match utils::get_edge(wir, pc) {
        Some(edge) => edge,
        None => return HashSet::new(),
    };

    // Match on its kind
    trace!("Finding inlinable functions in {} ({:?})", pc.resolved(&wir.table), edge.variant());
    match edge {
        Edge::Node { next, .. } | Edge::Linear { next, .. } => {
            // Doesn't call any functions, so just proceed with the next one
            find_inlinable_funcs(wir, calls, trace, pc.jump(*next), breakpoint, inlinable)
        },

        Edge::Stop {} => HashSet::new(),

        Edge::Branch { true_next, false_next, merge } => {
            // Analyse the left branch...
            let mut dependencies: HashSet<usize> =
                find_inlinable_funcs(wir, calls, trace, pc.jump(*true_next), merge.map(|merge| pc.jump(merge)), inlinable);
            // ...the right branch...
            if let Some(false_next) = false_next {
                dependencies.extend(find_inlinable_funcs(wir, calls, trace, pc.jump(*false_next), merge.map(|merge| pc.jump(merge)), inlinable));
            }
            // ...and the merge!
            if let Some(merge) = merge {
                dependencies.extend(find_inlinable_funcs(wir, calls, trace, pc.jump(*merge), breakpoint, inlinable));
            }
            dependencies
        },

        Edge::Parallel { branches, merge } => {
            // Collect all the branches
            let mut dependencies: HashSet<usize> = HashSet::new();
            for branch in branches {
                dependencies.extend(find_inlinable_funcs(wir, calls, trace, pc.jump(*branch), Some(pc.jump(*merge)), inlinable));
            }

            // Run merge and done is Cees
            dependencies.extend(find_inlinable_funcs(wir, calls, trace, pc.jump(*merge), breakpoint, inlinable));
            dependencies
        },

        Edge::Join { next, .. } => find_inlinable_funcs(wir, calls, trace, pc.jump(*next), breakpoint, inlinable),

        Edge::Loop { cond, body, next } => {
            // Traverse the condition...
            let mut dependencies: HashSet<usize> = find_inlinable_funcs(wir, calls, trace, pc.jump(*cond), Some(pc.jump(*body - 1)), inlinable);
            // ...the body...
            dependencies.extend(find_inlinable_funcs(wir, calls, trace, pc.jump(*body), Some(pc.jump(*cond)), inlinable));
            // ...and finally, the next step, if any
            if let Some(next) = next {
                dependencies.extend(find_inlinable_funcs(wir, calls, trace, pc.jump(*next), breakpoint, inlinable));
            }
            dependencies
        },

        Edge::Call { next, .. } => {
            // OK, the exciting point!

            // Resolve the function ID we're calling
            let func_id: usize = match calls.get(&pc) {
                Some(id) => *id,
                None => {
                    panic!("Encountered unresolved call after running call analysis");
                },
            };
            let def: &FunctionDef = match wir.table.funcs.get(func_id) {
                Some(def) => def,
                None => panic!("Failed to get definition of function {func_id} after call analysis"),
            };

            // Analyse next, since all codepaths do this always
            let mut dependencies: HashSet<usize> = find_inlinable_funcs(wir, calls, trace, pc.jump(*next), None, inlinable);
            dependencies.insert(func_id);

            // Functions are not inlinable if builtins; if so, return
            if BuiltinFunctions::is_builtin(&def.name) {
                trace!("Function {} ('{}') is not inlinable because it is a builtin", func_id, def.name);
                inlinable.insert(func_id, None);
                return dependencies;
            }

            // Examine if this call would introduce a recursive problem
            if trace.contains(&func_id) {
                // It's been in our callstack before - that means recursion!
                // Change our minds about its inlinability
                trace!("Function {} ('{}') is not inlinable because it is recursive", func_id, def.name);
                inlinable.insert(func_id, None);
                return dependencies;
            }
            if inlinable.contains_key(&func_id) {
                // We've already seen this one! However, _don't_ change our mind about its inlinability because it means a repeated function call
                // NOTE: No need to go into the call body, as we've done this the first time we saw it
                trace!("Function {} ('{}') is skipped because we have seen it before", func_id, def.name);
                return dependencies;
            }
            trace!("Function {} ('{}') is assumed as inlinable until we see it recursive", func_id, def.name);

            // For now assume that the function exist with no deps; we inject these later
            inlinable.insert(func_id, Some(HashSet::new()));

            // If we get this far, recurse into the body
            trace.push(func_id);
            let func_deps: HashSet<usize> = find_inlinable_funcs(wir, calls, trace, ProgramCounter::call(func_id), None, inlinable);
            trace.pop();

            // Now we can inject the entries
            if let Some(deps) = inlinable.get_mut(&func_id).unwrap() {
                deps.extend(func_deps);
            }

            // Return the dependencies in _this_ body.
            dependencies
        },

        Edge::Return { result: _ } => HashSet::new(),
    }
}

/// Orders a given map of inlinable functions such that, when ordered inline, every function will have its calls inlined if possible.
///
/// More specifically, the order makes sure that functions on which other functions depend (i.e., they make calls to it) are inlined first so that they can be inlined properly in the functions calling them.
///
/// # Arguments
/// - `ordered`: The vector of ordered function IDs that is being populated. The inline order is left-to-right (i.e., the leftmost function should never have a dependency, the second-to-left can only depend on the leftmost, etc).
/// - `inlinable`: The map of inlinable functions to their dependencies.
fn order_inlinable<'i>(ordered: &mut Vec<usize>, inlinable: &HashMap<usize, Option<HashSet<usize>>>, mut next: impl Iterator<Item = &'i usize>) {
    // Get a function to inline
    let func_id: usize = match next.next() {
        Some(id) => *id,
        None => return,
    };
    let deps: &HashSet<usize> = match inlinable.get(&func_id).unwrap() {
        Some(deps) => deps,
        None => {
            // No need to inline this one, so just continue
            trace!("order_inlinable(): Not considering function {func_id} because it is not inlinable (deps is None)");
            order_inlinable(ordered, inlinable, next);
            return;
        },
    };

    // Examine the dependencies
    if deps.is_empty() {
        // Base-case; add to the list first before any other
        trace!("order_inlinable(): Function {func_id} is inlinable but has no dependencies");
        ordered.push(func_id);
        order_inlinable(ordered, inlinable, next);
        trace!("order_inlinable(): New result: {ordered:?}");
    } else {
        // Recursive case: add all the dependencies first
        trace!("order_inlinable(): Function {func_id} is inlinable and has dependencies");
        order_inlinable(ordered, inlinable, deps.iter());
        ordered.push(func_id);
        trace!("order_inlinable(): New result: {ordered:?}");
        order_inlinable(ordered, inlinable, next);
    }
}

/// Given a vector, removes all duplicates from it.
///
/// Retains the **first** occurrences.
///
/// # Arguments
/// - `data`: The vector to deduplicate.
fn keep_unique_first(data: &mut Vec<usize>) {
    // A buffer of seen elements
    let mut seen: HashSet<usize> = HashSet::new();
    data.retain(|elem| {
        if seen.contains(elem) {
            false
        } else {
            seen.insert(*elem);
            true
        }
    });
}

/// Traverses the given function body and replaces all [`Edge::Return`] with an [`Edge::Linear`] pointing to the given edge index.
///
/// Also bumps definition pointers with the given values. This is necessary because we need to pull function scopes one layer up.
///
/// # Arguments
/// - `edges`: The edges to traverse.
/// - `calls`: The map of program counters to calls that we update with any nested call's' new position.
/// - `func_id`: The ID of this function.
/// - `start_idx`: The index to add all next indices.
/// - `ret_idx`: The index to point the returning linears to.
/// - `pc`: Points to the current [`Edge`] to replace potentially.
/// - `breakpoint`: If given, then analysis should stop when this PC is hit.
fn prep_func_body(
    edges: &mut [Edge],
    calls: &mut HashMap<ProgramCounter, usize>,
    func_id: usize,
    start_idx: usize,
    ret_idx: usize,
    pc: usize,
    breakpoint: Option<usize>,
) {
    // Stop on the breakpoint
    if let Some(breakpoint) = breakpoint {
        if pc == breakpoint {
            return;
        }
    }
    // Attempt to get the edge
    let edge: &mut Edge = match edges.get_mut(pc) {
        Some(edge) => edge,
        None => return,
    };

    // Match on its kind
    match edge {
        Edge::Node { next, .. } | Edge::Linear { next, .. } => {
            // Update the nexts
            let old_next: usize = *next;
            *next += start_idx;

            // Continue traversing
            prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_next, breakpoint);
        },

        Edge::Stop {} => (),

        Edge::Branch { true_next, false_next, merge } => {
            let (old_true_next, old_false_next, old_merge): (usize, Option<usize>, Option<usize>) = (*true_next, *false_next, *merge);

            // Update the nexts
            *true_next += start_idx;
            if let Some(false_next) = false_next {
                *false_next += start_idx;
            }
            if let Some(merge) = merge {
                *merge += start_idx;
            }

            // Analyse the left branch...
            prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_true_next, old_merge);
            // ...the right branch...
            if let Some(old_false_next) = old_false_next {
                prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_false_next, old_merge);
            }
            // ...and the merge!
            if let Some(old_merge) = old_merge {
                prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_merge, breakpoint);
            }
        },

        Edge::Parallel { branches, merge } => {
            let (old_branches, old_merge): (Vec<usize>, usize) = (branches.clone(), *merge);

            // Update the nexts
            for branch in branches {
                *branch += start_idx;
            }
            *merge += start_idx;

            // Collect all the branches
            for old_branch in old_branches {
                prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_branch, Some(old_merge));
            }

            // Run merge and done is Cees
            prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_merge, breakpoint);
        },

        Edge::Join { next, .. } => {
            let old_next: usize = *next;
            *next += start_idx;
            prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_next, breakpoint);
        },

        Edge::Loop { cond, body: lbody, next } => {
            let (old_cond, old_lbody, old_next): (usize, usize, Option<usize>) = (*cond, *lbody, *next);

            // Update the nexts
            *cond += start_idx;
            *lbody += start_idx;
            if let Some(next) = next {
                *next += start_idx;
            }

            // Traverse the condition...
            prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_cond, Some(old_lbody - 1));
            // ...the body...
            prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_lbody, Some(old_cond));
            // ...and finally, the next step, if any
            if let Some(old_next) = old_next {
                prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_next, breakpoint);
            }
        },

        Edge::Call { next, .. } => {
            let old_next: usize = *next;

            // Update the next
            *next += start_idx;

            // Update the call list with this dude's new position
            calls.insert(
                ProgramCounter::new(FunctionId::Main, start_idx + pc),
                *calls.get(&ProgramCounter::new(func_id, pc)).unwrap_or_else(|| panic!("Encountered unresolved call after call ID analysis")),
            );

            // Prepare the remainder
            prep_func_body(edges, calls, func_id, start_idx, ret_idx, old_next, breakpoint);
        },

        Edge::Return { result: _ } => {
            // Yank it
            trace!("Yanking return edge at '{pc}' with a linear edge to '{ret_idx}'");
            *edge = Edge::Linear { instrs: vec![], next: ret_idx };
        },
    }
}

/// Inlines the given set of functions in the given WIR function body.
///
/// Note that this is a rather confusing operation space-wise. To prevent program counter pointers from becoming invalid, we simply replace the call with an empty [`Edge::Linear`] that connects to the body appended at the end of the stream. Then, the body connects back to the call's old `next`.
///
/// # Arguments
/// - `body`: A [WIR](Workflow) function body to inline functions _in_.
/// - `calls`: The map of call indices to which function is actually called.
/// - `funcs`: A map of call IDs to function bodies ready to be substituted in the `body`.
/// - `inlinable`: A collection of functions that determines if functions are inlinable. If the set of `deps` is [`Some`], it's inlinable; else it's not.
/// - `func_id`: The ID of the function we're inlining.
/// - `pc`: Points to the current [`Edge`] to analyse.
/// - `breakpoint`: If given, then analysis should stop when this PC is hit.
// It's a compiler function, too many arguments are kinda its thing :P No it's not worth it to come up with structs for this.
#[allow(clippy::too_many_arguments)]
fn inline_funcs_in_body(
    body: &mut Vec<Edge>,
    calls: &mut HashMap<ProgramCounter, usize>,
    funcs: &HashMap<usize, Vec<Edge>>,
    inlinable: &HashMap<usize, Option<HashSet<usize>>>,
    func_id: FunctionId,
    pc: usize,
    breakpoint: Option<usize>,
) {
    // Stop on the breakpoint
    if let Some(breakpoint) = breakpoint {
        if pc == breakpoint {
            return;
        }
    }
    // Attempt to get the edge
    let body_len: usize = body.len();
    let edge: &mut Edge = match body.get_mut(pc) {
        Some(edge) => edge,
        None => return,
    };

    // Match on its kind
    match edge {
        Edge::Node { next, .. } | Edge::Linear { next, .. } => {
            let next: usize = *next;
            inline_funcs_in_body(body, calls, funcs, inlinable, func_id, next, breakpoint)
        },

        Edge::Stop {} => (),

        Edge::Branch { true_next, false_next, merge } => {
            let (true_next, false_next, merge): (usize, Option<usize>, Option<usize>) = (*true_next, *false_next, *merge);

            // Analyse the left branch...
            inline_funcs_in_body(body, calls, funcs, inlinable, func_id, true_next, merge);
            // ...the right branch...
            if let Some(false_next) = false_next {
                inline_funcs_in_body(body, calls, funcs, inlinable, func_id, false_next, merge)
            }
            // ...and the merge!
            if let Some(merge) = merge {
                inline_funcs_in_body(body, calls, funcs, inlinable, func_id, merge, breakpoint)
            }
        },

        Edge::Parallel { branches, merge } => {
            let (branches, merge): (Vec<usize>, usize) = (branches.clone(), *merge);

            // Collect all the branches
            for branch in branches {
                inline_funcs_in_body(body, calls, funcs, inlinable, func_id, branch, Some(merge));
            }

            // Run merge and done is Cees
            inline_funcs_in_body(body, calls, funcs, inlinable, func_id, merge, breakpoint);
        },

        Edge::Join { next, .. } => {
            let next: usize = *next;
            inline_funcs_in_body(body, calls, funcs, inlinable, func_id, next, breakpoint)
        },

        Edge::Loop { cond, body: lbody, next } => {
            let (cond, lbody, next): (usize, usize, Option<usize>) = (*cond, *lbody, *next);

            // Traverse the condition...
            inline_funcs_in_body(body, calls, funcs, inlinable, func_id, cond, Some(lbody - 1));
            // ...the body...
            inline_funcs_in_body(body, calls, funcs, inlinable, func_id, lbody, Some(cond));
            // ...and finally, the next step, if any
            if let Some(next) = next {
                inline_funcs_in_body(body, calls, funcs, inlinable, func_id, next, breakpoint);
            }
        },

        Edge::Call { next, .. } => {
            let next: usize = *next;

            // Resolve the function ID we're calling
            let call_id: usize = match calls.get(&ProgramCounter::new(func_id, pc)) {
                Some(id) => *id,
                None => {
                    panic!("Encountered unresolved call after running inline analysis");
                },
            };

            // Assert this is an inlinable function (and not external)
            if inlinable.get(&call_id).map(|deps| deps.is_none()).unwrap_or(true) {
                // Simply skip after doing the next
                trace!("Not inlining function call to function {call_id} at {pc}");
                inline_funcs_in_body(body, calls, funcs, inlinable, func_id, next, breakpoint);
                return;
            }
            trace!("Inlining function call to function {call_id} at {pc}");

            // Otherwise, yank the call with a linear that refers to the inlined body instead (we'll put it after all the other edges to avoid them moving)
            // Note: we insert a pop to consume the function reference pushed on the stack to execute the call
            *edge = Edge::Linear { instrs: vec![EdgeInstr::Pop {}], next: body_len };

            // Prepare the call body by replacing returns with normal links and by bumping all definitions
            let mut call_body: Vec<Edge> = funcs
                .get(&call_id)
                .unwrap_or_else(|| {
                    panic!("Encountered function ID '{call_id}' without function body after inline analysis (might be an uninlined dependency)")
                })
                .clone();
            prep_func_body(&mut call_body, calls, call_id, body_len, next, 0, None);

            // Append it to the main body and the inlining is complete
            body.extend(call_body);

            // End with the next edges
            inline_funcs_in_body(body, calls, funcs, inlinable, func_id, next, breakpoint);
        },

        Edge::Return { result: _ } => (),
    }
}

/***** SIMPLIFICATION FUNCTIONS *****/
/// Attempts to inline functions in the WIR as much as possible.
///
/// The only moment when we don't is if the function call is:
/// - Recursive
/// - A builtin
/// - Undecidable
///
/// # Arguments
/// - `wir`: The input [WIR](Workflow) to simply.
/// - `calls`: The map of call indices to which function is actually called.
///
/// # Returns
/// The same `wir` as given, but then optimized.
///
/// # Errors
/// This function may error if the input workflow is incoherent.
pub fn inline_functions(mut wir: Workflow, calls: &mut HashMap<ProgramCounter, usize>) -> Workflow {
    // Analyse which functions in the WIR are non-recursive
    let mut inlinable: HashMap<usize, Option<HashSet<usize>>> = HashMap::with_capacity(calls.len());
    find_inlinable_funcs(&wir, calls, &mut vec![], ProgramCounter::start(), None, &mut inlinable);
    debug!(
        "Inlinable functions: {}",
        inlinable
            .iter()
            .filter_map(|(id, deps)| if let Some(deps) = deps {
                Some(format!(
                    "'{}' (depends on {})",
                    wir.table.funcs.get(*id).map(|def| def.name.as_str()).unwrap_or("???"),
                    deps.iter()
                        .map(|id| format!("'{}'", wir.table.funcs.get(*id).map(|def| def.name.as_str()).unwrap_or("???")))
                        .collect::<Vec<String>>()
                        .join(", "),
                ))
            } else {
                None
            })
            .collect::<Vec<String>>()
            .join(", ")
    );

    // Order them so that we satisfy function dependencies
    let mut inline_order: Vec<usize> = Vec::with_capacity(inlinable.len());
    order_inlinable(&mut inline_order, &inlinable, inlinable.keys());
    keep_unique_first(&mut inline_order);
    debug!(
        "Inline order: {}",
        inline_order
            .iter()
            .map(|id| format!("'{}'", wir.table.funcs.get(*id).map(|def| def.name.as_str()).unwrap_or("???"),))
            .collect::<Vec<String>>()
            .join(", ")
    );

    {
        // Tear open the Workflow to satisfy the borrow checker
        let Workflow { id: _, graph: wir_graph, metadata: _, funcs: wir_funcs, table: wir_table, user: _ } = &mut wir;

        // Extract the graph behind the Arc
        let mut graph: Arc<Vec<Edge>> = Arc::new(vec![]);
        std::mem::swap(&mut graph, wir_graph);
        let mut graph: Vec<Edge> = Arc::into_inner(graph).unwrap();
        // Extract the functions behind the Arc
        let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(HashMap::new());
        std::mem::swap(&mut funcs, wir_funcs);
        let mut funcs: HashMap<usize, Vec<Edge>> = Arc::into_inner(funcs).unwrap();
        // Extract the WIR table
        let mut table: Arc<SymTable> = Arc::new(SymTable::new());
        std::mem::swap(&mut table, wir_table);
        let table: SymTable = Arc::into_inner(table).unwrap();

        // Inline non-main function bodies first
        let mut new_funcs: HashMap<usize, Vec<Edge>> = HashMap::new();
        for id in inline_order {
            // Acquire the body
            let mut new_body: Vec<Edge> = funcs.get(&id).unwrap().clone();

            // Inline the functions in this body
            debug!("Inlining functions in function {id}");
            inline_funcs_in_body(&mut new_body, calls, &new_funcs, &inlinable, FunctionId::Func(id), 0, None);
            new_funcs.insert(id, new_body);
        }
        funcs = new_funcs;

        // Now inline the main with all function bodies inlined correctly
        debug!("Inlining functions in main");
        inline_funcs_in_body(&mut graph, calls, &funcs, &inlinable, FunctionId::Main, 0, None);

        // Write the functions and graphs back
        let mut table: Arc<SymTable> = Arc::new(table);
        std::mem::swap(wir_table, &mut table);
        let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(funcs);
        std::mem::swap(wir_funcs, &mut funcs);
        let mut graph: Arc<Vec<Edge>> = Arc::new(graph);
        std::mem::swap(wir_graph, &mut graph);
    }

    // OK, we did all we could
    wir
}

/***** LIBRARY *****/
/// Simplifies the given WIR-workflow as much as possible to increase the compatability with checker workflows.
///
/// Most importantly, it:
/// - Attempts to inline functions as long as they're non-recursive (since functions are not supported)
///
/// # Arguments
/// - `wir`: The input [WIR](Workflow) to simply.
///
/// # Returns
/// A tuple of the same `wir` as given, but then optimized, and a mapping of (remaining) [`Edge::Call`]s to whatever function they actually map.
///
/// # Errors
/// This function may error if the input workflow is incoherent.
pub fn simplify(mut wir: Workflow) -> Result<(Workflow, HashMap<ProgramCounter, usize>), Error> {
    // Analyse call dependencies first
    let (mut calls, _): (HashMap<ProgramCounter, usize>, _) = resolve_calls(&wir, &wir.table, &mut vec![], ProgramCounter::start(), None, None)?;
    debug!("Resolved calls as: {:?}", calls.iter().map(|(pc, id)| (format!("{}", pc.resolved(&wir.table)), *id)).collect::<HashMap<String, usize>>());

    // Simplify functions as much as possible
    wir = inline_functions(wir, &mut calls);

    // Done!
    Ok((wir, calls))
}
