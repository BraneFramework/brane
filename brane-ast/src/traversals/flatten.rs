//  FLATTEN.rs
//    by Lut99
//
//  Created:
//    15 Sep 2022, 08:26:20
//  Last edited:
//    12 Dec 2023, 15:57:21
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a traversal that flattens the scopes (i.e., symbol
//!   tables) of the given program. This effectively brings all nested
//!   scopes back to the toplevel.
//

use std::cell::{Ref, RefCell, RefMut};
use std::rc::Rc;

use brane_dsl::SymbolTable;
use brane_dsl::ast::{Block, Expr, Program, Stmt};
use brane_dsl::symbol_table::{ClassEntry, FunctionEntry, VarEntry};
use enum_debug::EnumDebug as _;

use crate::errors::AstError;
pub use crate::errors::FlattenError as Error;
use crate::state::{ClassState, CompileState, FunctionState, TableState, TaskState, VarState};


/***** MACROS ******/
/// Generates the correct number of spaces for an indent.
macro_rules! indent {
    ($n_spaces:expr) => {
        ((0..$n_spaces).map(|_| ' ').collect::<String>())
    };
}


/***** CONSTANTS *****/
/// Determines the increase in indentation for every nested level.
const INDENT_SIZE: usize = 4;


/***** HELPER FUNCTIONS *****/
/// Recursive print function that makes it just that easier to inspect the TableState.
///
/// # Arguments
/// - `state`: The TableState to print.
/// - `indent`: The current indent to print with.
///
/// # Returns
/// Nothing, but does print to stdout.
#[allow(dead_code)]
fn print_state(state: &TableState, indent: usize) {
    // Print all items but in not in the conventional order
    println!("{}Tasks:", indent!(indent));
    for t in &state.tasks {
        println!(
            "{}{}[{}]::{}({}) -> {}",
            indent!(INDENT_SIZE + indent),
            t.package_name,
            t.package_version,
            t.name,
            (0..t.signature.args.len()).map(|i| format!("{}: {}", t.arg_names[i], t.signature.args[i])).collect::<Vec<String>>().join(", "),
            t.signature.ret,
        );
    }

    println!("{}Classes:", indent!(indent));
    for c in &state.classes {
        println!("{}class {} {{", indent!(INDENT_SIZE + indent), c.name);
        for p in &c.props {
            println!("{}{}: {},", indent!(2 * INDENT_SIZE + indent), p.name, p.data_type);
        }
        for m in &c.methods {
            let f: &FunctionState = &state.funcs[*m];
            println!(
                "{}&{}::{}({}) -> {},",
                indent!(INDENT_SIZE + indent),
                f.class_name.as_ref().unwrap(),
                f.name,
                (0..f.signature.args.len()).map(|i| format!("{}", f.signature.args[i])).collect::<Vec<String>>().join(", "),
                f.signature.ret,
            );
        }
    }

    println!("{}Variables:", indent!(indent));
    for v in &state.vars {
        println!("{}{}: {}", indent!(INDENT_SIZE + indent), v.name, v.data_type);
    }

    // Finally, these recurse
    println!("{}Functions:", indent!(indent));
    for f in &state.funcs {
        println!(
            "{}{}{}({}) -> {}",
            indent!(INDENT_SIZE + indent),
            if let Some(class_name) = &f.class_name { format!("{class_name}::") } else { String::new() },
            f.name,
            (0..f.signature.args.len()).map(|i| format!("{}", f.signature.args[i])).collect::<Vec<String>>().join(", "),
            f.signature.ret,
        );
    }
}



/// Doesn't just move the given (function) entry to the given CompileState, it also resolves the entry's index.
///
/// # Arguments
/// - `func`: The FunctionEntry to move.
/// - `table`: The TableState to add the entry to.
///
/// # Returns
/// Nothing, but does change both the given table and the given entry.
fn move_func(func: &Rc<RefCell<FunctionEntry>>, table: &mut TableState) -> Result<(), Error> {
    // // Step zero: copy over any nested results
    // for (name, avail) in &ftable.results {
    //     if table.results.insert(name.clone(), avail.clone()).is_some() {
    //         return Err(Error::IntermediateResultConflict { name: name.clone() });
    //     }
    // }

    // Step one: create the new FunctionState
    let state: FunctionState = {
        let entry: Ref<FunctionEntry> = func.borrow();
        FunctionState {
            name:      entry.name.clone(),
            signature: entry.signature.clone(),

            class_name: entry.class_name.clone(),

            range: entry.range.clone(),
        }
    };

    // Step two: add the entry (and get the new index)
    let index: usize = table.funcs.len();
    table.funcs.push(state);

    // Step three: resolve the index of the function
    {
        let mut entry: RefMut<FunctionEntry> = func.borrow_mut();
        entry.index = index;
    }

    // Done
    Ok(())
}

/// Doesn't just move the given (task) entry to the given CompileState, it also resolves the entry's index.
///
/// # Arguments
/// - `task`: The FunctionEntry (as a task) to move.
/// - `table`: The TableState to add the entry to.
///
/// # Returns
/// Nothing, but does change both the given table and the given entry.
fn move_task(task: &Rc<RefCell<FunctionEntry>>, table: &mut TableState) {
    // Step one: create the new TaskState
    let state: TaskState = {
        let entry: Ref<FunctionEntry> = task.borrow();
        TaskState {
            name: entry.name.clone(),
            signature: entry.signature.clone(),
            arg_names: entry.arg_names.clone(),
            requirements: entry.requirements.clone().unwrap(),

            package_name:    entry.package_name.clone().unwrap(),
            package_version: entry.package_version.unwrap(),

            range: entry.range.clone(),
        }
    };

    // Step two: add the entry (and get the new index)
    let index: usize = table.tasks.len();
    table.tasks.push(state);

    // Step three: resolve the index of the task
    {
        let mut entry: RefMut<FunctionEntry> = task.borrow_mut();
        entry.index = index;
    }
}

/// Doesn't just move the given (class) entry to the given CompileState, it also resolves the entry's index.
///
/// # Arguments
/// - `class`: The ClassEntry to move.
/// - `mtables`: A list of TableStates for every method in this table. They are mapped by method name.
/// - `table`: The TableState to add the entry to.
///
/// # Returns
/// Nothing, but does change both the given table and the given entry.
// fn move_class(class: &Rc<RefCell<ClassEntry>>, mtables: HashMap<String, TableState>, table: &mut TableState) {
fn move_class(class: &Rc<RefCell<ClassEntry>>, table: &mut TableState) -> Result<(), Error> {
    // Step one: create the new ClassState
    let state: ClassState = {
        let entry: Ref<ClassEntry> = class.borrow();

        // Collect the properties
        let mut props: Vec<Rc<RefCell<VarEntry>>> = entry.symbol_table.borrow().variables().map(|(_, p)| p.clone()).collect();
        props.sort_by(|a, b| a.borrow().name.to_lowercase().cmp(&b.borrow().name.to_lowercase()));
        let props: Vec<VarState> = props
            .into_iter()
            .map(|v| {
                let entry: Ref<VarEntry> = v.borrow();
                VarState {
                    name:      entry.name.clone(),
                    data_type: entry.data_type.clone(),

                    function_name: entry.function_name.clone(),
                    class_name:    entry.class_name.clone(),

                    range: entry.range.clone(),
                }
            })
            .collect();

        // Collect the methods, by reference
        let methods: Vec<usize> = {
            let est: Ref<SymbolTable> = entry.symbol_table.borrow();
            let mut methods: Vec<usize> = Vec::with_capacity(est.n_functions());
            for (_, m) in est.functions() {
                // Move the thing
                move_func(m, table)?;

                // Get the index to return
                methods.push(m.borrow().index)
            }
            methods
        };

        // Use those to create the ClassState
        ClassState {
            name: entry.signature.name.clone(),
            props,
            methods,

            package_name: entry.package_name.clone(),
            package_version: entry.package_version,

            range: entry.range.clone(),
        }
    };

    // Step two: add the entry (and get the new index)
    let index: usize = table.classes.len();
    table.classes.push(state);

    // Step three: resolve the index of the class
    {
        let mut entry: RefMut<ClassEntry> = class.borrow_mut();
        entry.index = index;
    }

    // Done
    Ok(())
}

/// Doesn't just move the given (variable) entry to the given CompileState, it also resolves the entry's index.
///
/// # Arguments
/// - `var`: The VarEntry to move.
/// - `table`: The TableState to add the entry to.
///
/// # Returns
/// Nothing, but does change both the given table and the given entry.
fn move_var(var: &Rc<RefCell<VarEntry>>, table: &mut TableState) {
    // Step one: create the new VarState
    let state: VarState = {
        let entry: Ref<VarEntry> = var.borrow();
        VarState {
            name:      entry.name.clone(),
            data_type: entry.data_type.clone(),

            function_name: entry.function_name.clone(),
            class_name:    entry.class_name.clone(),

            range: entry.range.clone(),
        }
    };

    // Step two: add the entry (and get the new index)
    let index: usize = table.vars.len();
    table.vars.push(state);

    // Step three: resolve the index of the variable
    {
        let mut entry: RefMut<VarEntry> = var.borrow_mut();
        entry.index = index;
    }
}





/***** TRAVERSAL FUNCTIONS *****/
/// Passes a block, collecting all of its definitions (i.e., symbol table entries) into the given CompileState.
///
/// # Arguments
/// - `block`: The Block to traverse.
/// - `table`: The TableState to define everything in.
/// - `errors`: A list of errors that may be collected during traversal.
///
/// # Returns
/// Nothing, but does change contents of symbol tables.
///
/// # Errors
/// This function may error in the (statistically improbable) event that two intermediate result identifiers collide.
pub fn pass_block(block: &mut Block, table: &mut TableState, errors: &mut Vec<Error>) {
    // We recurse to find any other blocks / functions. Only at definitions themselves do we inject them.
    for s in &mut block.stmts {
        pass_stmt(s, table, errors);
    }
}

/// Passes a Stmt, collecting any definitions it makes into the given CompileState, effectively flattening its own symbol tables.
///
/// # Arguments
/// - `stmt`: The Stmt to traverse.
/// - `table`: The TableState to define everything in.
/// - `errors`: A list of errors that may be collected during traversal.
///
/// # Returns
/// Nothing, but does change contents of symbol tables.
///
/// # Errors
/// This function may error in the (statistically improbable) event that two intermediate result identifiers collide.
pub fn pass_stmt(stmt: &mut Stmt, table: &mut TableState, errors: &mut Vec<Error>) {
    // Match the stmt
    use Stmt::*;
    #[allow(clippy::collapsible_match)]
    match stmt {
        Block { block } => {
            pass_block(block, table, errors);
        },

        Import { st_funcs, st_classes, .. } => {
            // Define all functions into the state (no need to do fancy nesting here, since it's externally defined -> nothing we (can) worry about)
            for f in st_funcs.as_ref().unwrap() {
                move_task(f, table);
            }
            // Then do all classes
            for c in st_classes.as_ref().unwrap() {
                if let Err(err) = move_class(c, table) {
                    errors.push(err);
                }
            }
        },
        FuncDef { code, st_entry, .. } => {
            // Add the function with an empty table first, just so that it exists
            let entry: &Rc<RefCell<FunctionEntry>> = st_entry.as_ref().unwrap();
            if let Err(err) = move_func(entry, table) {
                errors.push(err);
            }

            // Now build the correct table by defining the function's arguments
            for a in &entry.borrow().params {
                move_var(a, table);
            }

            // Then add any other body statements.
            pass_block(code, table, errors);
        },
        ClassDef { methods, st_entry, .. } => {
            // Define the class first with dummy tables to have it exist in the nested ones
            if let Err(err) = move_class(st_entry.as_ref().unwrap(), table) {
                errors.push(err);
            }

            // We can then construct the proper tables
            for m in methods {
                // Match on a function explicitly due to us needing to know its name
                if let Stmt::FuncDef { code, st_entry, .. } = &mut **m {
                    // Define the function's arguments first
                    {
                        let entry: Ref<FunctionEntry> = st_entry.as_ref().unwrap().borrow();
                        for a in &entry.params {
                            move_var(a, table);
                        }
                    }

                    // Then add any other body statements.
                    pass_block(code, table, errors);
                } else {
                    panic!("Method in ClassDef is not a FunctionDef");
                };
            }
        },
        Return { expr, .. } => {
            if let Some(expr) = expr {
                pass_expr(expr, table);
            }
        },

        If { cond, consequent, alternative, .. } => {
            pass_expr(cond, table);
            pass_block(consequent, table, errors);
            if let Some(alternative) = alternative {
                pass_block(alternative, table, errors);
            }
        },
        For { initializer, condition, consequent, .. } => {
            pass_stmt(initializer, table, errors);
            pass_expr(condition, table);
            pass_block(consequent, table, errors);
        },
        While { condition, consequent, .. } => {
            pass_expr(condition, table);
            pass_block(consequent, table, errors);
        },
        Parallel { blocks, st_entry, .. } => {
            // Continue traversal first (the entry is not in scope for that bit)
            for b in blocks {
                pass_block(b, table, errors);
            }

            // Define the variable if it exists
            if let Some(st_entry) = st_entry {
                move_var(st_entry, table);
            }
        },

        LetAssign { value, st_entry, .. } => {
            // Recurse
            pass_expr(value, table);

            // Define the variable
            move_var(st_entry.as_ref().unwrap(), table);
        },
        Assign { value, .. } => {
            pass_expr(value, table);
        },

        Expr { expr, .. } => {
            pass_expr(expr, table);
        },

        // The rest neither recurses nor defines
        Empty {} => {},
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in flatten traversal", stmt.variant()),
    }
}

/// Passes an expression to look for intermediate results to put in the global table, as well as any data definitions.
///
/// # Arguments
/// - `expr`: The expression to traverse.
/// - `table`: The TableState to define the intermediate results in.
/// - `errors`: A list of errors that may be collected during traversal.
///
/// # Returns
/// Nothing, but does change contents of symbol tables.
///
/// # Errors
/// This function may error in the (statistically improbable) event that two intermediate result identifiers collide.
fn pass_expr(expr: &mut Expr, _table: &mut TableState) {
    use Expr::*;
    match expr {
        Cast { expr, .. } => {
            pass_expr(expr, _table);
        },

        Call { expr, args, .. } => {
            // Recurse into the rest
            pass_expr(expr, _table);
            for a in args {
                pass_expr(a, _table);
            }
        },
        Array { values, .. } => {
            for v in values {
                pass_expr(v, _table);
            }
        },
        ArrayIndex { array, index, .. } => {
            pass_expr(array, _table);
            pass_expr(index, _table);
        },

        UnaOp { expr, .. } => {
            pass_expr(expr, _table);
        },
        BinOp { lhs, rhs, .. } => {
            pass_expr(lhs, _table);
            pass_expr(rhs, _table);
        },
        Proj { lhs, rhs, .. } => {
            pass_expr(lhs, _table);
            pass_expr(rhs, _table);
        },

        Instance { properties, .. } => {
            // NOTE: Adding datasets to the workflow is left for a runtime set, since we do not know yet how to access it.
            // Recurse the properties
            for p in properties {
                pass_expr(&mut p.value, _table);
            }
        },

        // The rest either is not relevant, does not recurse or will never occur here
        _ => {},
    }
}





/***** LIBRARY *****/
/// Flattens the symbol tables in the given AST to only have a global and function-wide scope.
///
/// Note that this cannot lead to conflicts, since variable names (should) have already been resolved.
///
/// # Arguments
/// - `state`: The CompileState that we use to pre-define and flatten scopes in.
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same nodes as went in, but now with a flattened symbol table structure (i.e., nested blocks will have empty tables).
///
/// # Errors
/// This pass doesn't really error, but the option is here for convention purposes.
pub fn do_traversal(state: &mut CompileState, root: Program) -> Result<Program, Vec<AstError>> {
    let mut root = root;

    // Iterate over all statements to prune the tree
    let mut errors: Vec<Error> = vec![];
    pass_block(&mut root.block, &mut state.table, &mut errors);

    // Done
    if errors.is_empty() { Ok(root) } else { Err(errors.into_iter().map(|e| e.into()).collect()) }
}

/***** TESTS *****/
#[cfg(test)]
mod tests {
    use brane_dsl::ParserOptions;
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::super::print::symbol_tables;
    use super::*;
    use crate::state::CompileState;
    use crate::{CompileResult, CompileStage, compile_snippet_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_flatten() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // Run up to this traversal
            let mut state: CompileState = CompileState::new();
            let program: Program =
                match compile_snippet_to(&mut state, code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Flatten) {
                    CompileResult::Program(p, warns) => {
                        // Print warnings if any
                        for w in warns {
                            w.prettyprint(path.to_string_lossy(), &code);
                        }
                        p
                    },
                    CompileResult::Eof(err) => {
                        // Print the error
                        err.prettyprint(path.to_string_lossy(), &code);
                        panic!("Failed to flatten symbol tables (see output above)");
                    },
                    CompileResult::Err(errs) => {
                        // Print the errors
                        for e in errs {
                            e.prettyprint(path.to_string_lossy(), &code);
                        }
                        panic!("Failed to flatten symbol tables (see output above)");
                    },

                    _ => {
                        unreachable!();
                    },
                };

            // Now print the file for prettyness
            symbol_tables::do_traversal(program, std::io::stdout()).unwrap();
            println!("{}\n", (0..40).map(|_| "- ").collect::<String>());
            print_state(&state.table, 0);
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
