//  THREAD.rs
//    by Lut99
//
//  Created:
//    09 Sep 2022, 13:23:41
//  Last edited:
//    23 Jul 2024, 01:31:41
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a single Thread of a VM, which sequentially executes a
//!   given stream of Edges.
//

use std::any::type_name;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use async_recursion::async_recursion;
use brane_ast::ast::{ClassDef, ComputeTaskDef, Edge, EdgeInstr, FunctionDef, TaskDef};
use brane_ast::func_id::FunctionId;
use brane_ast::locations::Location;
use brane_ast::spec::{BuiltinClasses, BuiltinFunctions};
use brane_ast::{DataType, MergeStrategy, Workflow};
use enum_debug::EnumDebug as _;
use futures::future::{BoxFuture, FutureExt};
use log::debug;
use specifications::data::{AccessKind, AvailabilityKind, DataName};
use specifications::profiling::{ProfileScopeHandle, ProfileScopeHandleOwned};
use tokio::spawn;
use tokio::task::JoinHandle;

use crate::dbg_node;
use crate::errors::ReturnEdge;
pub use crate::errors::VmError as Error;
use crate::frame_stack::FrameStack;
use crate::pc::ProgramCounter;
use crate::spec::{CustomGlobalState, CustomLocalState, RunState, TaskInfo, VmPlugin};
use crate::stack::Stack;
use crate::value::{FullValue, Value};


/***** TESTS *****/
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use brane_ast::traversals::print::ast;
    use brane_ast::{CompileResult, ParserOptions, compile_program};
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files_async};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::*;
    use crate::dummy::{DummyPlanner, DummyPlugin, DummyState};


    /// Tests the traversal by generating symbol tables for every file.
    #[tokio::test]
    async fn test_thread() {
        // Setup the simple logger
        #[cfg(feature = "test_logging")]
        if let Err(err) = humanlog::HumanLogger::terminal(humanlog::DebugMode::Debug).init() {
            eprintln!("WARNING: Failed to setup logger: {err} (no logging for this session)");
        }

        // Run the tests on all the files
        test_on_dsl_files_async("BraneScript", |path, code| {
            async move {
                // Start by the name to always know which file this is
                println!("{}", (0..80).map(|_| '-').collect::<String>());
                println!("File '{}' gave us:", path.display());

                // Load the package index
                let pindex: PackageIndex = create_package_index();
                let dindex: DataIndex = create_data_index();

                // Compile it to a workflow
                let workflow: Workflow = match compile_program(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript()) {
                    CompileResult::Workflow(wf, warns) => {
                        // Print warnings if any
                        for w in warns {
                            w.prettyprint(path.to_string_lossy(), &code);
                        }
                        wf
                    },
                    CompileResult::Eof(err) => {
                        // Print the error
                        err.prettyprint(path.to_string_lossy(), &code);
                        panic!("Failed to compile to workflow (see output above)");
                    },
                    CompileResult::Err(errs) => {
                        // Print the errors
                        for e in errs {
                            e.prettyprint(path.to_string_lossy(), &code);
                        }
                        panic!("Failed to compile to workflow (see output above)");
                    },

                    _ => {
                        unreachable!();
                    },
                };

                // Run the dummy planner on the workflow
                let workflow: Arc<Workflow> = Arc::new(DummyPlanner::plan(&mut HashMap::new(), workflow));

                // Now print the file for prettyness
                ast::do_traversal(&workflow, std::io::stdout()).unwrap();
                println!("{}", (0..40).map(|_| "- ").collect::<String>());

                // Run the program
                let text: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
                let main: Thread<DummyState, ()> = Thread::new(&workflow, DummyState {
                    workflow: Some(workflow.clone()),
                    results:  Arc::new(Mutex::new(HashMap::new())),
                    text:     text.clone(),
                });
                match main.run::<DummyPlugin>(ProfileScopeHandleOwned::dummy()).await {
                    Ok(value) => {
                        println!("Workflow stdout:");
                        print!("{}", text.lock().unwrap());
                        println!();
                        println!("Workflow returned: {value:?}");
                    },
                    Err(err) => {
                        err.prettyprint();
                        panic!("Failed to execute workflow (see output above)");
                    },
                }
                println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
            }
        })
        .await;
    }
}





/***** HELPER ENUMS *****/
/// Defines the result of an Edge execution.
#[derive(Debug)]
enum EdgeResult {
    /// The Edge completed the thread, returning a value. It also contains the timings it took to do the last instruction.
    Ok(Value),
    /// The Edge execution was a success but the workflow continues (to the given body and the given edge in that body, in fact). It also contains the timings it took to do the last instruction.
    Pending(ProgramCounter),
    /// The Edge execution was a disaster and something went wrong.
    Err(Error),
}





/***** HELPER FUNCTIONS *****/
/// Preprocesses any datasets / intermediate results in the given value.
///
/// # Arguments
/// - `global`: The global VM plugin state to use when actually preprocessing a dataset.
/// - `local`: The local VM plugin state to use when actually preprocessing a dataset.
/// - `pc`: The current program counter index.
/// - `task`: The Task definition for which we are preprocessing.
/// - `at`: The location where we are preprocessing.
/// - `value`: The FullValue that might contain a to-be-processed dataset or intermediate result (or recurse into a value that does).
/// - `input`: The input map for the upcoming task so that we know where the value is planned to be.
/// - `data`: The map that we will populate with the access methods once available.
/// - `prof`: A ProfileScopeHandleOwned that is used to provide more details about the time it takes to preprocess a local argument. Note that this is _not_ user-relevant, only debug/framework-relevant.
///
/// # Returns
/// Adds any preprocessed datasets to `data`, then returns the ValuePreprocessProfile to discover how long it took us to do so.
///
/// # Errors
/// This function may error if the given `input` does not contain any of the data in the value _or_ if the referenced input is not yet planned.
#[async_recursion]
#[allow(clippy::too_many_arguments, clippy::multiple_bound_locations)]
async fn preprocess_value<'p: 'async_recursion, P: VmPlugin>(
    global: &Arc<RwLock<P::GlobalState>>,
    local: &P::LocalState,
    pc: ProgramCounter,
    task: &TaskDef,
    at: &Location,
    value: &FullValue,
    input: &HashMap<DataName, Option<AvailabilityKind>>,
    data: &mut HashMap<DataName, JoinHandle<Result<AccessKind, P::PreprocessError>>>,
    prof: ProfileScopeHandle<'p>,
) -> Result<(), Error> {
    // If it's a data or intermediate result, get it; skip it otherwise
    let name: DataName = match value {
        // The data and intermediate result, of course
        FullValue::Data(name) => DataName::Data(name.into()),
        FullValue::IntermediateResult(name) => DataName::IntermediateResult(name.into()),

        // Also handle any nested stuff
        FullValue::Array(values) => {
            for (i, v) in values.iter().enumerate() {
                prof.nest_fut(format!("[{i}]"), |scope| preprocess_value::<P>(global, local, pc, task, at, v, input, data, scope)).await?;
            }
            return Ok(());
        },
        FullValue::Instance(name, props) => {
            for (n, v) in props {
                prof.nest_fut(format!("{name}.{n}"), |scope| preprocess_value::<P>(global, local, pc, task, at, v, input, data, scope)).await?;
            }
            return Ok(());
        },

        // The rest is irrelevant
        _ => {
            return Ok(());
        },
    };

    // Fetch it from the input
    let avail: AvailabilityKind = match input.get(&name) {
        Some(avail) => match avail {
            Some(avail) => avail.clone(),
            None => {
                return Err(Error::UnplannedInput { pc, task: task.name().into(), name });
            },
        },
        None => {
            return Err(Error::UnknownInput { pc, task: task.name().into(), name });
        },
    };

    // If it is unavailable, download it and make it available
    let access: JoinHandle<Result<AccessKind, P::PreprocessError>> = match avail {
        AvailabilityKind::Available { how } => {
            debug!("{} '{}' is locally available", name.variant(), name.name());
            tokio::spawn(async move { Ok(how) })
        },
        AvailabilityKind::Unavailable { how } => {
            debug!("{} '{}' is remotely available", name.variant(), name.name());

            // Call the external transfer function
            // match P::preprocess(global, local, at, &name, how).await {
            //     Ok(access) => access,
            //     Err(err)   => { return Err(Error::Custom{ pc, err: Box::new(err) }); }
            // }
            let prof = ProfileScopeHandleOwned::from(prof);
            let global = global.clone();
            let local = local.clone();
            let at = at.clone();
            let name = name.clone();
            tokio::spawn(async move {
                prof.nest_fut(format!("{}::preprocess()", type_name::<P>()), |scope| P::preprocess(global, local, pc, at, name, how, scope)).await
            })
        },
    };

    // Insert it into the map, done
    data.insert(name, access);
    Ok(())
}

/// Runs a single instruction, modifying the given stack and variable register.
///
/// # Arguments
/// - `pc`: The location of the edge we're executing (used for debugging purposes).
/// - `idx`: The index of the instruction we're executing (used for debugging purposes).
/// - `instr`: The EdgeInstr to execute.
/// - `stack`: The Stack that represents temporary state for executing.
/// - `fstack`: The FrameStack that we read/write variable from/to.
///
/// # Returns
/// The next index to execute. Note that this is _relative_ to the given instruction (so it will typically be 1)
///
/// # Errors
/// This function may error if execution of the instruction failed. This is typically due to incorrect runtime typing.
fn exec_instr(pc: ProgramCounter, idx: usize, instr: &EdgeInstr, stack: &mut Stack, fstack: &mut FrameStack) -> Result<i64, Error> {
    use EdgeInstr::*;
    let next: i64 = match instr {
        Cast { res_type } => {
            // Get the top value off the stack
            let value: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Any }),
            };

            // Attempt to cast it based on the value it is
            let value: Value = match value.cast(res_type, fstack.table()) {
                Ok(value) => value,
                Err(err) => {
                    return Err(Error::CastError { pc, instr: idx, err });
                },
            };

            // Push the value back
            stack.push(value).to_instr(pc, idx)?;
            1
        },
        Pop {} => {
            // Get the top value off the stack and discard it
            if stack.pop().is_none() {
                return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Any });
            };
            1
        },
        PopMarker {} => {
            // Push a pop marker on top of the stack.
            stack.push_pop_marker().to_instr(pc, idx)?;
            1
        },
        DynamicPop {} => {
            // Let the stack handle this one.
            stack.dpop();
            1
        },

        Branch { next } => {
            // Examine the top value on the the stack
            let value: Value = match stack.pop() {
                Some(value) => value,
                None => {
                    return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Boolean });
                },
            };

            // Examine it as a boolean
            let value_type: DataType = value.data_type(fstack.table());
            let value: bool = match value.try_as_bool() {
                Some(value) => value,
                None => {
                    return Err(Error::StackTypeError { pc, instr: Some(idx), got: value_type, expected: DataType::Boolean });
                },
            };

            // Branch only if true
            if value { *next } else { 1 }
        },
        BranchNot { next } => {
            // Examine the top value on the the stack
            let value: Value = match stack.pop() {
                Some(value) => value,
                None => {
                    return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Boolean });
                },
            };

            // Examine it as a boolean
            let value_type: DataType = value.data_type(fstack.table());
            let value: bool = match value.try_as_bool() {
                Some(value) => value,
                None => {
                    return Err(Error::StackTypeError { pc, instr: Some(idx), got: value_type, expected: DataType::Boolean });
                },
            };

            // Branch only if **false**
            if !value { *next } else { 1 }
        },

        Not {} => {
            // Get the top value off the stack
            let value: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            // Get it as a boolean
            let value_type: DataType = value.data_type(fstack.table());
            let value: bool = match value.try_as_bool() {
                Some(value) => value,
                None => {
                    return Err(Error::StackTypeError { pc, instr: Some(idx), got: value_type, expected: DataType::Boolean });
                },
            };

            // Push the negated value back
            stack.push(Value::Boolean { value: !value }).to_instr(pc, idx)?;
            1
        },
        Neg {} => {
            // Get the top value off the stack
            let value: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get it as an integer or real value
            match value {
                Value::Integer { value } => {
                    // Put the negated value back
                    stack.push(Value::Integer { value: -value }).to_instr(pc, idx)?;
                },
                Value::Real { value } => {
                    // Put the negated value back
                    stack.push(Value::Real { value: -value }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                value => {
                    return Err(Error::StackTypeError { pc, instr: Some(idx), got: value.data_type(fstack.table()), expected: DataType::Numeric });
                },
            };
            1
        },

        And {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Boolean }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Boolean }),
            };
            // Get them both as boolean values
            let (lhs_type, rhs_type): (DataType, DataType) = (lhs.data_type(fstack.table()), rhs.data_type(fstack.table()));
            let (lhs, rhs): (bool, bool) = match (lhs.try_as_bool(), rhs.try_as_bool()) {
                (Some(lhs), Some(rhs)) => (lhs, rhs),
                (_, _) => {
                    return Err(Error::StackLhsRhsTypeError { pc, instr: idx, got: (lhs_type, rhs_type), expected: DataType::Boolean });
                },
            };

            // Push the conjunction of the two on top again
            stack.push(Value::Boolean { value: lhs && rhs }).to_instr(pc, idx)?;
            1
        },
        Or {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Boolean }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Boolean }),
            };
            // Get them both as boolean values
            let (lhs_type, rhs_type): (DataType, DataType) = (lhs.data_type(fstack.table()), rhs.data_type(fstack.table()));
            let (lhs, rhs): (bool, bool) = match (lhs.try_as_bool(), rhs.try_as_bool()) {
                (Some(lhs), Some(rhs)) => (lhs, rhs),
                (_, _) => {
                    return Err(Error::StackLhsRhsTypeError { pc, instr: idx, got: (lhs_type, rhs_type), expected: DataType::Boolean });
                },
            };

            // Push the disjunction of the two on top again
            stack.push(Value::Boolean { value: lhs || rhs }).to_instr(pc, idx)?;
            1
        },

        Add {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Addable }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Addable }),
            };

            // Get them both as either numeric _or_ string values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the added value back
                    stack.push(Value::Integer { value: lhs + rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the added value back
                    stack.push(Value::Real { value: lhs + rhs }).to_instr(pc, idx)?;
                },
                (Value::String { value: mut lhs }, Value::String { value: rhs }) => {
                    // Put the concatenated value back
                    lhs.push_str(&rhs);
                    stack.push(Value::String { value: lhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Addable,
                    });
                },
            };
            1
        },
        Sub {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get them both as either numeric _or_ string values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Integer { value: lhs - rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Real { value: lhs - rhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Numeric,
                    });
                },
            };
            1
        },
        Mul {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get them both as either numeric _or_ string values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the multiplied value back
                    stack.push(Value::Integer { value: lhs * rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the multiplied value back
                    stack.push(Value::Real { value: lhs * rhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Numeric,
                    });
                },
            };
            1
        },
        Div {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get them both as either numeric _or_ string values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the divided value back
                    stack.push(Value::Integer { value: lhs / rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the divided value back
                    stack.push(Value::Real { value: lhs / rhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Numeric,
                    });
                },
            };
            1
        },
        Mod {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Integer }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Integer }),
            };
            // Get them both as integer values
            let (lhs_type, rhs_type): (DataType, DataType) = (lhs.data_type(fstack.table()), rhs.data_type(fstack.table()));
            let (lhs, rhs): (i64, i64) = match (lhs.try_as_int(), rhs.try_as_int()) {
                (Some(lhs), Some(rhs)) => (lhs, rhs),
                (_, _) => {
                    return Err(Error::StackLhsRhsTypeError { pc, instr: idx, got: (lhs_type, rhs_type), expected: DataType::Integer });
                },
            };

            // Push the modulo of the two on top again
            stack.push(Value::Integer { value: lhs % rhs }).to_instr(pc, idx)?;
            1
        },

        Eq {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Simply push if they are the same
            stack.push(Value::Boolean { value: lhs == rhs }).to_instr(pc, idx)?;
            1
        },
        Ne {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Simply push if they are not the same
            stack.push(Value::Boolean { value: lhs != rhs }).to_instr(pc, idx)?;
            1
        },
        Lt {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get them both as numeric values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs < rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs < rhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Numeric,
                    });
                },
            };
            1
        },
        Le {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get them both as numeric values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs <= rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs <= rhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Numeric,
                    });
                },
            };
            1
        },
        Gt {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get them both as numeric values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs > rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs > rhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Numeric,
                    });
                },
            };
            1
        },
        Ge {} => {
            // Pop the lhs and rhs off the stack (reverse order)
            let rhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };
            let lhs: Value = match stack.pop() {
                Some(value) => value,
                None => return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Numeric }),
            };

            // Get them both as numeric values
            match (lhs, rhs) {
                (Value::Integer { value: lhs }, Value::Integer { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs >= rhs }).to_instr(pc, idx)?;
                },
                (Value::Real { value: lhs }, Value::Real { value: rhs }) => {
                    // Put the subtracted value back
                    stack.push(Value::Boolean { value: lhs >= rhs }).to_instr(pc, idx)?;
                },

                // Yeah no not that one
                (lhs, rhs) => {
                    return Err(Error::StackLhsRhsTypeError {
                        pc,
                        instr: idx,
                        got: (lhs.data_type(fstack.table()), rhs.data_type(fstack.table())),
                        expected: DataType::Numeric,
                    });
                },
            };
            1
        },

        Array { length, res_type } => {
            let mut res_type: DataType = res_type.clone();

            // Pop enough values off the stack
            let mut elems: Vec<Value> = Vec::with_capacity(*length);
            for _ in 0..*length {
                // Pop the value
                let value: Value = match stack.pop() {
                    Some(value) => value,
                    None => {
                        return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: res_type });
                    },
                };

                // Update the res_type if necessary; otherwise, make sure this is of the correct type
                if let DataType::Any = &res_type {
                    res_type = value.data_type(fstack.table());
                } else if res_type != value.data_type(fstack.table()) {
                    return Err(Error::ArrayTypeError { pc, instr: idx, got: value.data_type(fstack.table()), expected: res_type });
                }

                // Add the element
                elems.push(value);
            }
            // Remember, stack pushes are in reversed direction
            elems.reverse();

            // Create the array and push it back
            stack.push(Value::Array { values: elems }).to_instr(pc, idx)?;
            1
        },
        ArrayIndex { res_type } => {
            // Pop the index
            let index: Value = match stack.pop() {
                Some(index) => index,
                None => {
                    return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Integer });
                },
            };
            // as an integer
            let index_type: DataType = index.data_type(fstack.table());
            let index: i64 = match index.try_as_int() {
                Some(index) => index,
                None => {
                    return Err(Error::StackTypeError { pc, instr: Some(idx), got: index_type, expected: DataType::Integer });
                },
            };

            // Get the array itself
            let arr: Value = match stack.pop() {
                Some(arr) => arr,
                None => {
                    return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Array { elem_type: Box::new(res_type.clone()) } });
                },
            };
            // as an array of values but indexed correctly
            let arr_type: DataType = arr.data_type(fstack.table());
            let mut arr: Vec<Value> = match arr.try_as_array() {
                Some(arr) => arr,
                None => {
                    return Err(Error::StackTypeError {
                        pc,
                        instr: Some(idx),
                        got: arr_type,
                        expected: DataType::Array { elem_type: Box::new(res_type.clone()) },
                    });
                },
            };

            // Now index the array and push that element back
            if index < 0 || index as usize >= arr.len() {
                return Err(Error::ArrIdxOutOfBoundsError { pc, instr: idx, got: index, max: arr.len() });
            }

            // Finally, push that element back and return
            stack.push(arr.swap_remove(index as usize)).to_instr(pc, idx)?;
            1
        },
        Instance { def } => {
            let class: &ClassDef = fstack.table().class(*def);

            // Pop as many elements as are required (wow)
            let mut fields: Vec<Value> = Vec::with_capacity(class.props.len());
            for i in 0..class.props.len() {
                // Pop the value
                let value: Value = match stack.pop() {
                    Some(value) => value,
                    None => {
                        return Err(Error::EmptyStackError {
                            pc,
                            instr: Some(idx),
                            expected: class.props[class.props.len() - 1 - i].data_type.clone(),
                        });
                    },
                };

                // Make sure this is of the correct type
                if !value.data_type(fstack.table()).allowed_by(&class.props[class.props.len() - 1 - i].data_type) {
                    return Err(Error::InstanceTypeError {
                        pc,
                        instr: idx,
                        got: value.data_type(fstack.table()),
                        class: class.name.clone(),
                        field: class.props[class.props.len() - 1 - i].name.clone(),
                        expected: class.props[class.props.len() - 1 - i].data_type.clone(),
                    });
                }

                // Add the element
                fields.push(value);
            }
            fields.reverse();

            // Map them with the class names (alphabetically)
            let mut field_names: Vec<std::string::String> = class.props.iter().map(|v| v.name.clone()).collect();
            field_names.sort_by_key(|n| n.to_lowercase());
            let mut values: HashMap<std::string::String, Value> = field_names.into_iter().zip(fields).collect();

            // Push an instance with those values - unless it's a specific builtin
            if class.name == BuiltinClasses::Data.name() {
                stack.push(Value::Data { name: values.remove("name").unwrap().try_as_string().unwrap() }).to_instr(pc, idx)?;
            } else if class.name == BuiltinClasses::IntermediateResult.name() {
                stack.push(Value::IntermediateResult { name: values.remove("name").unwrap().try_as_string().unwrap() }).to_instr(pc, idx)?;
            } else {
                stack.push(Value::Instance { values, def: *def }).to_instr(pc, idx)?;
            }
            1
        },
        Proj { field } => {
            // Pop the instance value
            let value: Value = match stack.pop() {
                Some(value) => value,
                None => {
                    return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: DataType::Class { name: format!("withField={field}") } });
                },
            };
            // as an instance
            let value_type: DataType = value.data_type(fstack.table());
            let (mut values, def): (HashMap<std::string::String, Value>, usize) = match value.try_as_instance() {
                Some(value) => value,
                None => {
                    return Err(Error::StackTypeError {
                        pc,
                        instr: Some(idx),
                        got: value_type,
                        expected: DataType::Class { name: format!("withField={field}") },
                    });
                },
            };

            // Attempt to find the value with the correct field
            let value: Value = match values.remove(field) {
                Some(value) => value,
                None => {
                    // Try as function instead
                    let mut res: Option<Value> = None;
                    for m in &fstack.table().class(def).methods {
                        if &fstack.table().func(FunctionId::Func(*m)).name == field {
                            res = Some(Value::Method { values, cdef: def, fdef: *m });
                            break;
                        }
                    }
                    match res {
                        Some(res) => res,
                        None => {
                            return Err(Error::ProjUnknownFieldError {
                                pc,
                                instr: idx,
                                class: fstack.table().class(def).name.clone(),
                                field: field.clone(),
                            });
                        },
                    }
                },
            };

            // Push it
            stack.push(value).to_instr(pc, idx)?;
            1
        },

        VarDec { def } => {
            // Simply declare it
            if let Err(err) = fstack.declare(*def) {
                return Err(Error::VarDecError { pc, instr: idx, err });
            }
            1
        },
        VarUndec { def } => {
            // Simply undeclare it
            if let Err(err) = fstack.undeclare(*def) {
                return Err(Error::VarUndecError { pc, instr: idx, err });
            }
            1
        },
        VarGet { def } => {
            // Attempt to get the value from the variable register
            let value: Value = match fstack.get(*def) {
                Ok(value) => value.clone(),
                Err(err) => {
                    return Err(Error::VarGetError { pc, instr: idx, err });
                },
            };

            // Push it
            stack.push(value).to_instr(pc, idx)?;
            1
        },
        VarSet { def } => {
            // Pop the top value off the stack
            let value: Value = match stack.pop() {
                Some(value) => value,
                None => {
                    return Err(Error::EmptyStackError { pc, instr: Some(idx), expected: fstack.table().var(*def).data_type.clone() });
                },
            };

            // Set it in the register, done
            if let Err(err) = fstack.set(*def, value) {
                return Err(Error::VarSetError { pc, instr: idx, err });
            };
            1
        },

        Boolean { value } => {
            // Push a boolean with the given value
            stack.push(Value::Boolean { value: *value }).to_instr(pc, idx)?;
            1
        },
        Integer { value } => {
            // Push an integer with the given value
            stack.push(Value::Integer { value: *value }).to_instr(pc, idx)?;
            1
        },
        Real { value } => {
            // Push a real with the given value
            stack.push(Value::Real { value: *value }).to_instr(pc, idx)?;
            1
        },
        String { value } => {
            // Push a string with the given value
            stack.push(Value::String { value: value.clone() }).to_instr(pc, idx)?;
            1
        },
        Function { def } => {
            // Push a function with the given definition
            stack.push(Value::Function { def: *def }).to_instr(pc, idx)?;
            1
        },
    };

    // Done
    Ok(next)
}





/***** LIBRARY *****/
/// Represents a single thread that may be executed.
pub struct Thread<G: CustomGlobalState, L: CustomLocalState> {
    /// The graph containing the main edges to execute (indexed by `usize::MAX`).
    graph: Arc<Vec<Edge>>,
    /// The list of function edges to execute.
    funcs: Arc<HashMap<usize, Vec<Edge>>>,

    /// The 'program counter' of this thread. It first indexed the correct body (`usize::MAX` for main, or else the index of the function), and then the offset within that body.
    pc: ProgramCounter,

    /// The stack which we use for temporary values.
    stack:  Stack,
    /// The frame stack is used to process function calls.
    fstack: FrameStack,

    /// The threads that we're blocking on.
    threads: Vec<(usize, JoinHandle<Result<Value, Error>>)>,

    /// The thread-global custom part of the RunState.
    global: Arc<RwLock<G>>,
    /// The thread-local custom part of the RunState.
    local:  L,
}

impl<G: CustomGlobalState, L: CustomLocalState> Thread<G, L> {
    /// Spawns a new main thread from the given workflow.
    ///
    /// # Arguments
    /// - `workflow`: The Workflow that this thread will execute.
    /// - `pindex`: The PackageIndex we use to resolve packages.
    /// - `dindex`: The DataIndex we use to resolve datasets.
    /// - `global`: The app-wide custom state with which to initialize this thread.
    ///
    /// # Returns
    /// A new Thread that may be executed.
    #[inline]
    pub fn new(workflow: &Workflow, global: G) -> Self {
        let global: Arc<RwLock<G>> = Arc::new(RwLock::new(global));
        Self {
            graph: workflow.graph.clone(),
            funcs: workflow.funcs.clone(),

            pc: ProgramCounter::start(),

            stack:  Stack::new(2048),
            fstack: FrameStack::new(512, workflow.table.clone()),

            threads: vec![],

            global: global.clone(),
            local:  L::new(&global),
        }
    }

    /// Spawns a new main thread that does not start from scratch but instead the given VmState.
    ///
    /// # Arguments
    /// - `workflow`: The workflow to execute.
    /// - `state`: The runstate to "resume" this thread with.
    #[inline]
    pub fn from_state(workflow: &Workflow, state: RunState<G>) -> Self {
        Self {
            graph: workflow.graph.clone(),
            funcs: workflow.funcs.clone(),

            pc: ProgramCounter::start(),

            stack:  Stack::new(2048),
            fstack: state.fstack,

            threads: vec![],

            global: state.global.clone(),
            local:  L::new(&state.global),
        }
    }

    /// 'Forks' this thread such that it may branch in a parallel statement.
    ///
    /// # Arguments
    /// - `offset`: The offset (as a `(body, idx)` pair) where the thread will begin computation in the edges list.
    ///
    /// # Returns
    /// A new Thread that is partly cloned of this one.
    #[inline]
    pub fn fork(&self, offset: ProgramCounter) -> Self {
        Self {
            graph: self.graph.clone(),
            funcs: self.funcs.clone(),

            pc: offset,

            stack:  Stack::new(2048),
            fstack: self.fstack.fork(),

            threads: vec![],

            global: self.global.clone(),
            local:  L::new(&self.global),
        }
    }

    /// Saves the important bits of this Thread for a next execution round.
    #[inline]
    fn into_state(self) -> RunState<G> {
        RunState {
            fstack: self.fstack,

            global: self.global,
        }
    }

    /// Retrieves the current edge based on the given program counter.
    ///
    /// # Arguments
    /// - `pc`: Points to the edge to retrieve.
    ///
    /// # Returns
    /// A reference to the Edge to execute.
    ///
    /// # Errors
    /// This function may error if the program counter is out-of-bounds.
    fn get_edge(&self, pc: ProgramCounter) -> Result<&Edge, Error> {
        if pc.func_id.is_main() {
            // Assert the index is within range
            if pc.edge_idx < self.graph.len() {
                Ok(&self.graph[pc.edge_idx])
            } else {
                Err(Error::PcOutOfBounds { func: pc.func_id, edges: self.graph.len(), got: pc.edge_idx })
            }
        } else {
            // Assert the function is within range
            if let Some(edges) = self.funcs.get(&pc.func_id.id()) {
                // Assert the index is within range
                if pc.edge_idx < edges.len() {
                    Ok(&edges[pc.edge_idx])
                } else {
                    Err(Error::PcOutOfBounds { func: pc.func_id, edges: edges.len(), got: pc.edge_idx })
                }
            } else {
                Err(Error::UnknownFunction { func: pc.func_id })
            }
        }
    }

    /// Executes a single edge, modifying the given stacks and variable register.
    ///
    /// # Arguments
    /// - `pc`: Points to the current edge to execute (as a [`ProgramCounter``]).
    /// - `plugins`: An object implementing various parts of task execution that are dependent on the actual setup (i.e., offline VS instance).
    /// - `prof`: A ProfileScopeHandleOwned that is used to provide more details about the execution times of a single edge. Note that this is _not_ user-relevant, only debug/framework-relevant.
    ///
    /// # Returns
    /// The next index to execute. Note that this is an _absolute_ index (so it will typically be `idx` + 1)
    ///
    /// # Errors
    /// This function may error if execution of the edge failed. This is typically due to incorrect runtime typing or due to failure to perform an external function call.
    async fn exec_edge<P: VmPlugin<GlobalState = G, LocalState = L>>(&mut self, pc: ProgramCounter, prof: ProfileScopeHandleOwned) -> EdgeResult {
        // We can early stop if the program counter is out-of-bounds
        if pc.func_id.is_main() {
            if pc.edge_idx >= self.graph.len() {
                debug!("Nothing to do (main, PC {} >= #edges {})", pc.edge_idx, self.graph.len());
                // We didn't really execute anything, so no timing taken
                return EdgeResult::Ok(Value::Void);
            }
        } else {
            let f: &[Edge] = self.funcs.get(&pc.func_id.id()).unwrap_or_else(|| panic!("Failed to find function with index '{}'", pc.func_id.id()));
            if pc.edge_idx >= f.len() {
                debug!("Nothing to do ({}, PC {} >= #edges {})", pc.func_id.id(), pc.edge_idx, f.len());
                // We didn't really execute anything, so no timing taken
                return EdgeResult::Ok(Value::Void);
            }
        }

        // Get the edge based on the index
        let edge: &Edge = if pc.func_id.is_main() {
            &self.graph[pc.edge_idx]
        } else {
            &self.funcs.get(&pc.func_id.id()).unwrap_or_else(|| panic!("Failed to find function with index '{}'", pc.func_id.id()))[pc.edge_idx]
        };
        dbg_node!("{pc}) Executing Edge: {edge:?}");

        // Match on the specific edge
        use Edge::*;
        let next: ProgramCounter = match edge {
            Node { task: task_id, at, input, result, next, .. } => {
                // Resolve the task
                let task: &TaskDef = self.fstack.table().task(*task_id);

                // Match the thing to do
                match task {
                    TaskDef::Compute(ComputeTaskDef { package, version, function, args_names, requirements }) => {
                        debug!("Calling compute task '{}' ('{}' v{})", task.name(), package, version);

                        // Collect the arguments from the stack (remember, reverse order)
                        let retr = prof.time("Argument retrieval");
                        let mut args: HashMap<String, FullValue> = HashMap::with_capacity(function.args.len());
                        for i in 0..function.args.len() {
                            let i: usize = function.args.len() - 1 - i;

                            // Get the element
                            let value: Value = match self.stack.pop() {
                                Some(value) => value,
                                None => {
                                    return EdgeResult::Err(Error::EmptyStackError { pc, instr: None, expected: function.args[i].clone() });
                                },
                            };

                            // Check it has the correct type
                            let value_type: DataType = value.data_type(self.fstack.table());
                            if !value_type.allowed_by(&function.args[i]) {
                                return EdgeResult::Err(Error::FunctionTypeError {
                                    pc,
                                    name: task.name().into(),
                                    arg: i,
                                    got: value_type,
                                    expected: function.args[i].clone(),
                                });
                            }

                            // Add it to the list
                            args.insert(args_names[i].clone(), value.into_full(self.fstack.table()));
                        }

                        // Unwrap the location
                        let at: &Location = match at {
                            Some(at) => at,
                            None => {
                                return EdgeResult::Err(Error::UnresolvedLocation { pc, name: function.name.clone() });
                            },
                        };
                        retr.stop();

                        // Next, fetch all the datasets required by calling the external transfer function;
                        // The map created maps data names to ways of accessing them locally that may be passed to the container itself.
                        let prepr = prof.nest("argument preprocessing");
                        let total = prepr.time("Total");
                        let mut handles: HashMap<DataName, JoinHandle<Result<AccessKind, P::PreprocessError>>> = HashMap::new();
                        for (i, value) in args.values().enumerate() {
                            // Preprocess the given value
                            if let Err(err) = prepr
                                .nest_fut(format!("argument {i}"), |scope| {
                                    preprocess_value::<P>(&self.global, &self.local, pc, task, at, value, input, &mut handles, scope)
                                })
                                .await
                            {
                                return EdgeResult::Err(err);
                            }
                        }
                        // Join the handles
                        let mut data: HashMap<DataName, AccessKind> = HashMap::with_capacity(handles.len());
                        for (name, handle) in handles {
                            match handle.await {
                                Ok(res) => match res {
                                    Ok(access) => {
                                        data.insert(name, access);
                                    },
                                    Err(err) => {
                                        return EdgeResult::Err(Error::Custom { pc, err: Box::new(err) });
                                    },
                                },
                                Err(err) => {
                                    return EdgeResult::Err(Error::Custom { pc, err: Box::new(err) });
                                },
                            }
                        }
                        total.stop();
                        prepr.finish();

                        // Prepare the TaskInfo for the call
                        let info: TaskInfo = TaskInfo {
                            pc,
                            def: *task_id,

                            name: &function.name,
                            package_name: package,
                            package_version: version,
                            requirements,

                            args,
                            location: at,
                            input: data,
                            result,
                        };

                        // Call the external call function with the correct arguments
                        let mut res: Option<Value> = match prof
                            .nest_fut(format!("{}::execute()", type_name::<P>()), |scope| P::execute(&self.global, &self.local, info, scope))
                            .await
                        {
                            Ok(res) => res.map(|v| v.into_value(self.fstack.table())),
                            Err(err) => {
                                return EdgeResult::Err(Error::Custom { pc, err: Box::new(err) });
                            },
                        };

                        // If the function returns an intermediate result but returned nothing, that's fine; we inject the result here
                        if function.ret == DataType::IntermediateResult && (res.is_none() || res.as_ref().unwrap() == &Value::Void) {
                            // Make the intermediate result available for next steps by possible pushing it to the next registry
                            let name: &str = result.as_ref().unwrap();
                            let path: PathBuf = name.into();
                            if let Err(err) = prof
                                .nest_fut(format!("{}::publicize()", type_name::<P>()), |scope| {
                                    P::publicize(&self.global, &self.local, at, name, &path, scope)
                                })
                                .await
                            {
                                return EdgeResult::Err(Error::Custom { pc, err: Box::new(err) });
                            }

                            // Return the new, intermediate result
                            res = Some(Value::IntermediateResult { name: name.into() });
                        }

                        // Verify its return value
                        let _ret = prof.time("Return analysis");
                        if let Some(res) = res {
                            // Verification
                            let res_type: DataType = res.data_type(self.fstack.table());
                            if res_type != function.ret {
                                return EdgeResult::Err(Error::ReturnTypeError { pc, got: res_type, expected: function.ret.clone() });
                            }

                            // If we have it anyway, might as well push it onto the stack
                            if let Err(err) = self.stack.push(res) {
                                return EdgeResult::Err(Error::StackError { pc, instr: None, err });
                            }
                        } else if function.ret != DataType::Void {
                            return EdgeResult::Err(Error::ReturnTypeError { pc, got: DataType::Void, expected: function.ret.clone() });
                        }
                    },

                    TaskDef::Transfer => {
                        todo!();
                    },
                }

                // Move to the next edge
                pc.jump(*next)
            },
            Linear { instrs, next } => {
                // Run the instructions (as long as they don't crash)
                let mut instr_pc: usize = 0;
                while instr_pc < instrs.len() {
                    // It looks a bit funky, but we simply add the relative offset after every constrution to the edge-local program counter
                    instr_pc = (instr_pc as i64
                        + match prof.time_func(format!("instruction {instr_pc}"), || {
                            exec_instr(pc, instr_pc, &instrs[instr_pc], &mut self.stack, &mut self.fstack)
                        }) {
                            Ok(next) => next,
                            Err(err) => {
                                return EdgeResult::Err(err);
                            },
                        }) as usize;
                }

                // Move to the next edge
                pc.jump(*next)
            },
            Stop {} => {
                // Done no value
                return EdgeResult::Ok(Value::Void);
            },

            Branch { true_next, false_next, .. } => {
                // Which branch to take depends on the top value of the stack; so get it
                let value: Value = match self.stack.pop() {
                    Some(value) => value,
                    None => {
                        return EdgeResult::Err(Error::EmptyStackError { pc, instr: None, expected: DataType::Boolean });
                    },
                };
                // as boolean
                let value_type: DataType = value.data_type(self.fstack.table());
                let value: bool = match value.try_as_bool() {
                    Some(value) => value,
                    None => {
                        return EdgeResult::Err(Error::StackTypeError { pc, instr: None, got: value_type, expected: DataType::Boolean });
                    },
                };

                // Branch appropriately
                if value {
                    pc.jump(*true_next)
                } else {
                    match false_next {
                        Some(false_next) => pc.jump(*false_next),
                        None => {
                            return EdgeResult::Ok(Value::Void);
                        },
                    }
                }
            },
            Parallel { branches, merge } => {
                // Fork this thread for every branch
                self.threads.clear();
                self.threads.reserve(branches.len());
                for (i, b) in branches.iter().enumerate() {
                    // Fork the thread for that branch
                    let thread: Self = self.fork(pc.jump(*b));
                    let prof = prof.clone();

                    // Schedule its running on the runtime (`spawn`)
                    self.threads.push((i, spawn(async move { prof.nest_fut(format!("branch {i}"), |scope| thread.run::<P>(scope.into())).await })));
                }

                // Mark those threads to wait for, and then move to the join
                pc.jump(*merge)
            },
            Join { merge, next } => {
                // Await the threads first (if any)
                // No need to catch profile results, since writing is done in the `nest_fut` function that's already embedded in the future
                let mut results: Vec<(usize, Value)> = Vec::with_capacity(self.threads.len());
                for (i, t) in &mut self.threads {
                    match t.await {
                        Ok(status) => match status {
                            Ok(res) => {
                                results.push((*i, res));
                            },
                            Err(err) => {
                                return EdgeResult::Err(err);
                            },
                        },
                        Err(err) => {
                            return EdgeResult::Err(Error::SpawnError { pc, err });
                        },
                    }
                }
                self.threads.clear();

                // Join their values into one according to the merge strategy
                let _merge = prof.time("Result merging");
                let result: Option<Value> = match merge {
                    MergeStrategy::First | MergeStrategy::FirstBlocking => {
                        if results.is_empty() {
                            panic!("Joining with merge strategy '{merge:?}' after no threads have been run; this should never happen!");
                        }

                        // It's a bit hard to do this unblocking right now, but from the user the effect will be the same.
                        Some(results.swap_remove(0).1)
                    },
                    MergeStrategy::Last => {
                        if results.is_empty() {
                            panic!("Joining with merge strategy '{merge:?}' after no threads have been run; this should never happen!");
                        }

                        // It's a bit hard to do this unblocking right now, but from the user the effect will be the same.
                        Some(results.swap_remove(results.len() - 1).1)
                    },

                    MergeStrategy::Sum => {
                        if results.is_empty() {
                            panic!("Joining with merge strategy '{merge:?}' after no threads have been run; this should never happen!");
                        }

                        // Prepare the sum result
                        let result_type: DataType = results[0].1.data_type(self.fstack.table());
                        let mut result: Value = if result_type == DataType::Integer {
                            Value::Integer { value: 0 }
                        } else if result_type == DataType::Real {
                            Value::Real { value: 0.0 }
                        } else {
                            return EdgeResult::Err(Error::IllegalBranchType {
                                pc,
                                branch: 0,
                                merge: *merge,
                                got: result_type,
                                expected: DataType::Numeric,
                            });
                        };

                        // Sum the results into that
                        for (i, r) in results {
                            match result {
                                Value::Integer { ref mut value } => {
                                    if let Value::Integer { value: new_value } = r {
                                        *value += new_value;
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },
                                Value::Real { ref mut value } => {
                                    if let Value::Real { value: new_value } = r {
                                        *value += new_value;
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },

                                _ => {
                                    unreachable!();
                                },
                            }
                        }

                        // Done, result is now a combination of all values
                        Some(result)
                    },
                    MergeStrategy::Product => {
                        if results.is_empty() {
                            panic!("Joining with merge strategy '{merge:?}' after no threads have been run; this should never happen!");
                        }

                        // Prepare the sum result
                        let result_type: DataType = results[0].1.data_type(self.fstack.table());
                        let mut result: Value = if result_type == DataType::Integer {
                            Value::Integer { value: 0 }
                        } else if result_type == DataType::Real {
                            Value::Real { value: 0.0 }
                        } else {
                            return EdgeResult::Err(Error::IllegalBranchType {
                                pc,
                                branch: 0,
                                merge: *merge,
                                got: result_type,
                                expected: DataType::Numeric,
                            });
                        };

                        // Sum the results into that
                        for (i, r) in results {
                            match result {
                                Value::Integer { ref mut value } => {
                                    if let Value::Integer { value: new_value } = r {
                                        *value *= new_value;
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },
                                Value::Real { ref mut value } => {
                                    if let Value::Real { value: new_value } = r {
                                        *value *= new_value;
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },

                                _ => {
                                    unreachable!();
                                },
                            }
                        }

                        // Done, result is now a combination of all values
                        Some(result)
                    },

                    MergeStrategy::Max => {
                        if results.is_empty() {
                            panic!("Joining with merge strategy '{merge:?}' after no threads have been run; this should never happen!");
                        }

                        // Prepare the sum result
                        let result_type: DataType = results[0].1.data_type(self.fstack.table());
                        let mut result: Value = if result_type == DataType::Integer {
                            Value::Integer { value: i64::MIN }
                        } else if result_type == DataType::Real {
                            Value::Real { value: f64::NEG_INFINITY }
                        } else {
                            return EdgeResult::Err(Error::IllegalBranchType {
                                pc,
                                branch: 0,
                                merge: *merge,
                                got: result_type,
                                expected: DataType::Numeric,
                            });
                        };

                        // Sum the results into that
                        for (i, r) in results {
                            match result {
                                Value::Integer { ref mut value } => {
                                    if let Value::Integer { value: new_value } = r {
                                        if new_value > *value {
                                            *value = new_value;
                                        }
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },
                                Value::Real { ref mut value } => {
                                    if let Value::Real { value: new_value } = r {
                                        if new_value > *value {
                                            *value = new_value;
                                        }
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },

                                _ => {
                                    unreachable!();
                                },
                            }
                        }

                        // Done, result is now a combination of all values
                        Some(result)
                    },
                    MergeStrategy::Min => {
                        if results.is_empty() {
                            panic!("Joining with merge strategy '{merge:?}' after no threads have been run; this should never happen!");
                        }

                        // Prepare the sum result
                        let result_type: DataType = results[0].1.data_type(self.fstack.table());
                        let mut result: Value = if result_type == DataType::Integer {
                            Value::Integer { value: i64::MAX }
                        } else if result_type == DataType::Real {
                            Value::Real { value: f64::INFINITY }
                        } else {
                            return EdgeResult::Err(Error::IllegalBranchType {
                                pc,
                                branch: 0,
                                merge: *merge,
                                got: result_type,
                                expected: DataType::Numeric,
                            });
                        };

                        // Sum the results into that
                        for (i, r) in results {
                            match result {
                                Value::Integer { ref mut value } => {
                                    if let Value::Integer { value: new_value } = r {
                                        if new_value < *value {
                                            *value = new_value;
                                        }
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },
                                Value::Real { ref mut value } => {
                                    if let Value::Real { value: new_value } = r {
                                        if new_value < *value {
                                            *value = new_value;
                                        }
                                    } else {
                                        return EdgeResult::Err(Error::BranchTypeError {
                                            pc,
                                            branch: i,
                                            got: r.data_type(self.fstack.table()),
                                            expected: result.data_type(self.fstack.table()),
                                        });
                                    }
                                },

                                _ => {
                                    unreachable!();
                                },
                            }
                        }

                        // Done, result is now a combination of all values
                        Some(result)
                    },

                    MergeStrategy::All => {
                        if results.is_empty() {
                            panic!("Joining with merge strategy '{merge:?}' after no threads have been run; this should never happen!");
                        }

                        // Collect them all in an Array of (the same!) values
                        let mut elems: Vec<Value> = Vec::with_capacity(results.len());
                        let mut elem_type: Option<DataType> = None;
                        for (i, r) in results {
                            if let Some(elem_type) = &mut elem_type {
                                // Verify it's correctly typed
                                let r_type: DataType = r.data_type(self.fstack.table());
                                if elem_type != &r_type {
                                    return EdgeResult::Err(Error::BranchTypeError { pc, branch: i, got: r_type, expected: elem_type.clone() });
                                }

                                // Add it to the list
                                elems.push(r);
                            } else {
                                // It's the first one; make sure there is _something_ and then add it
                                let r_type: DataType = r.data_type(self.fstack.table());
                                if r_type == DataType::Void {
                                    return EdgeResult::Err(Error::IllegalBranchType {
                                        pc,
                                        branch: i,
                                        merge: *merge,
                                        got: DataType::Void,
                                        expected: DataType::NonVoid,
                                    });
                                }
                                elem_type = Some(r_type);
                                elems.push(r);
                            }
                        }

                        // Set it as an Array result
                        Some(Value::Array { values: elems })
                    },

                    MergeStrategy::None => None,
                };

                // We can now push that onto the stack, then go to next
                if let Some(result) = result {
                    if let Err(err) = self.stack.push(result) {
                        return EdgeResult::Err(Error::StackError { pc, instr: None, err });
                    }
                }
                pc.jump(*next)
            },

            Loop { cond, .. } => {
                // The thing is built in such a way we can just run the condition and be happy
                // EDIT: Yeah so this was not a good idea xZ only place in the entire codebase where this is convenient...
                pc.jump(*cond)
            },

            Call { input: _, result: _, next } => {
                // Get the top value off the stack
                let value: Value = match self.stack.pop() {
                    Some(value) => value,
                    None => return EdgeResult::Err(Error::EmptyStackError { pc, instr: None, expected: DataType::Numeric }),
                };
                // Get it as a function index
                let def: usize = match value {
                    Value::Function { def } => def,
                    Value::Method { values, cdef, fdef } => {
                        // Insert the instance as a stack value, and only then proceed to call
                        let stack_len: usize = self.stack.len();
                        if let Err(err) =
                            self.stack.insert(stack_len - (self.fstack.table().func(FunctionId::Func(fdef)).args.len() - 1), Value::Instance {
                                values,
                                def: cdef,
                            })
                        {
                            return EdgeResult::Err(Error::StackError { pc, instr: None, err });
                        };
                        fdef
                    },
                    value => {
                        return EdgeResult::Err(Error::StackTypeError {
                            pc,
                            instr: None,
                            got: value.data_type(self.fstack.table()),
                            expected: DataType::Callable,
                        });
                    },
                };
                // Resolve the function index
                let sig: &FunctionDef = self.fstack.table().func(FunctionId::Func(def));

                // Double-check the correct values are on the stack
                let stack_len: usize = self.stack.len();
                for (i, v) in self.stack[stack_len - sig.args.len()..].iter().enumerate() {
                    let v_type: DataType = v.data_type(self.fstack.table());
                    if !v_type.allowed_by(&sig.args[i]) {
                        return EdgeResult::Err(Error::FunctionTypeError {
                            pc,
                            name: sig.name.clone(),
                            arg: i,
                            got: v_type,
                            expected: sig.args[i].clone(),
                        });
                    }
                }

                // Either run as a builtin (if it is defined as one) or else run the call
                if sig.name == BuiltinFunctions::Print.name() {
                    // We have one variable that is a string; so print it
                    let text: String = self.stack.pop().unwrap().try_as_string().unwrap();
                    if let Err(err) = prof
                        .nest_fut(format!("{}::stdout(false)", type_name::<P>()), |scope| P::stdout(&self.global, &self.local, &text, false, scope))
                        .await
                    {
                        return EdgeResult::Err(Error::Custom { pc, err: Box::new(err) });
                    }

                    // Done, go to the next immediately
                    pc.jump(*next)
                } else if sig.name == BuiltinFunctions::PrintLn.name() {
                    // We have one variable that is a string; so print it
                    let text: String = self.stack.pop().unwrap().try_as_string().unwrap();
                    if let Err(err) = prof
                        .nest_fut(format!("{}::stdout(true)", type_name::<P>()), |scope| P::stdout(&self.global, &self.local, &text, true, scope))
                        .await
                    {
                        return EdgeResult::Err(Error::Custom { pc, err: Box::new(err) });
                    }

                    // Done, go to the next immediately
                    pc.jump(*next)
                } else if sig.name == BuiltinFunctions::Len.name() {
                    // Fetch the array
                    let array: Vec<Value> = self.stack.pop().unwrap().try_as_array().unwrap();

                    // Push the length back onto the stack
                    if let Err(err) = self.stack.push(Value::Integer { value: array.len() as i64 }) {
                        return EdgeResult::Err(Error::StackError { pc, instr: None, err });
                    }

                    // We can then go to the next one immediately
                    pc.jump(*next)
                } else if sig.name == BuiltinFunctions::CommitResult.name() {
                    // Fetch the arguments
                    let res_name: String = self.stack.pop().unwrap().try_as_intermediate_result().unwrap();
                    let data_name: String = self.stack.pop().unwrap().try_as_string().unwrap();

                    // Try to find out where this res lives, currently
                    let loc: &String = match self.fstack.table().results.get(&res_name) {
                        Some(loc) => loc,
                        None => {
                            return EdgeResult::Err(Error::UnknownResult { pc, name: res_name });
                        },
                    };

                    // Call the external data committer
                    let res_path: PathBuf = res_name.as_str().into();
                    if let Err(err) = prof
                        .nest_fut(format!("{}::commit()", type_name::<P>()), |scope| {
                            P::commit(&self.global, &self.local, loc, &res_name, &res_path, &data_name, scope)
                        })
                        .await
                    {
                        return EdgeResult::Err(Error::Custom { pc, err: Box::new(err) });
                    };

                    // Push the resulting data onto the stack
                    if let Err(err) = self.stack.push(Value::Data { name: data_name }) {
                        return EdgeResult::Err(Error::StackError { pc, instr: None, err });
                    }

                    // We can then go to the next one immediately
                    pc.jump(*next)
                } else {
                    // Push the return address onto the frame stack and then go to the correct function
                    if let Err(err) = self.fstack.push(def, pc.jump(*next)) {
                        return EdgeResult::Err(Error::FrameStackPushError { pc, err });
                    }
                    ProgramCounter::call(def)
                }
            },
            Return { result: _ } => {
                // Attempt to pop the top frame off the frame stack
                let (ret, ret_type): (ProgramCounter, DataType) = match self.fstack.pop() {
                    Ok(res) => res,
                    Err(err) => {
                        return EdgeResult::Err(Error::FrameStackPopError { pc, err });
                    },
                };

                // Check if the top value on the stack has this value
                if ret != ProgramCounter::new(FunctionId::Main, usize::MAX) {
                    // If there is something to return, verify it did
                    if !ret_type.is_void() {
                        // Peek the top value
                        let value: &Value = match self.stack.peek() {
                            Some(value) => value,
                            None => {
                                return EdgeResult::Err(Error::EmptyStackError { pc, instr: None, expected: ret_type });
                            },
                        };

                        // Compare its data type
                        let value_type: DataType = value.data_type(self.fstack.table());
                        if !value_type.allowed_by(&ret_type) {
                            return EdgeResult::Err(Error::ReturnTypeError { pc, got: value_type, expected: ret_type });
                        }
                    }

                    // Go to the stack'ed index
                    ret
                } else {
                    // We return the top value on the stack (if any) as a result of this thread
                    return EdgeResult::Ok(self.stack.pop().unwrap_or(Value::Void));
                }
            },
        };

        // Return it
        EdgeResult::Pending(next)
    }

    /// Runs the thread once until it is pending for something (either other threads or external function calls).
    ///
    /// # Arguments
    /// - `prof`: A ProfileScopeHandleOwned that is used to provide more details about the execution times of a workflow execution. Note that this is _not_ user-relevant, only debug/framework-relevant.
    ///   
    ///   The reason it is owned is due to the boxed return future. It's your responsibility to keep the parent into scope after the future returns; if you don't any collected profile results will likely not be printed.
    ///
    /// # Returns
    /// The value that this thread returns once it is done.
    ///
    /// # Errors
    /// This function may error if execution of an edge or instruction failed. This is typically due to incorrect runtime typing.
    pub fn run<P: VmPlugin<GlobalState = G, LocalState = L>>(mut self, prof: ProfileScopeHandleOwned) -> BoxFuture<'static, Result<Value, Error>> {
        async move {
            // Start executing edges from where we left off
            let prof: ProfileScopeHandleOwned = prof;
            loop {
                // Run the edge
                self.pc = match prof
                    .nest_fut(format!("{:?} ({})", self.get_edge(self.pc)?.variant(), self.pc), |scope| self.exec_edge::<P>(self.pc, scope.into()))
                    .await
                {
                    // Either quit or continue, noting down the time taken
                    EdgeResult::Ok(value) => {
                        return Ok(value);
                    },
                    EdgeResult::Pending(next) => next,

                    // We failed
                    EdgeResult::Err(err) => {
                        return Err(err);
                    },
                };
            }
        }
        .boxed()
    }

    /// Runs the thread once until it is pending for something (either other threads or external function calls).
    ///
    /// This overload supports snippet execution, returning the state that is necessary for the next repl-loop together with the result.
    ///
    /// # Arguments
    /// - `prof`: A ProfileScopeHandleOwned that is used to provide more details about the execution times of a workflow execution. Note that this is _not_ user-relevant, only debug/framework-relevant.
    ///   
    ///   The reason it is owned is due to the boxed return future. It's your responsibility to keep the parent into scope after the future returns; if you don't any collected profile results will likely not be printed.
    ///
    /// # Returns
    /// A tuple of the value that is returned by this thread and the running state used to refer to variables produced in this run, respectively.
    ///
    /// # Errors
    /// This function may error if execution of an edge or instruction failed. This is typically due to incorrect runtime typing.
    pub fn run_snippet<P: VmPlugin<GlobalState = G, LocalState = L>>(
        mut self,
        prof: ProfileScopeHandleOwned,
    ) -> BoxFuture<'static, Result<(Value, RunState<G>), Error>> {
        async move {
            // Start executing edges from where we left off
            let prof: ProfileScopeHandleOwned = prof;
            loop {
                // Run the edge
                self.pc = match prof
                    .nest_fut(format!("{:?} ({})", self.get_edge(self.pc)?.variant(), self.pc), |scope| self.exec_edge::<P>(self.pc, scope.into()))
                    .await
                {
                    // Either quit or continue, noting down the time taken
                    // Return not just the value, but also the VmState part of this thread to keep.
                    EdgeResult::Ok(value) => {
                        return Ok((value, self.into_state()));
                    },
                    EdgeResult::Pending(next) => next,

                    // We failed
                    EdgeResult::Err(err) => {
                        return Err(err);
                    },
                };
            }
        }
        .boxed()
    }
}
