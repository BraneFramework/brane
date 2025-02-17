//  DATA.rs
//    by Lut99
//
//  Created:
//    25 Oct 2022, 13:34:31
//  Last edited:
//    08 Dec 2023, 10:41:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a traversal that analyses data dependencies for external
//!   calls.
//

use std::cell::{Ref, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

use brane_dsl::ast::{Block, Data, Expr, Program, Stmt};
use brane_dsl::symbol_table::{ClassEntry, FunctionEntry, SymbolTableEntry, VarEntry};
use brane_dsl::{DataType, SymbolTable};
use enum_debug::EnumDebug as _;
use log::debug;
use uuid::Uuid;

use crate::errors::AstError;
use crate::spec::{BuiltinClasses, BuiltinFunctions};
use crate::state::{CompileState, DataState};


/***** TRAVERSAL FUNCTIONS *****/
/// Attempts to analyse the data dependencies for this block.
///
/// # Arguments
/// - `block`: The Block to traverse.
/// - `table`: The DataTable we use to keep track of which variable has what value.
/// - `is_branch`: Indicates whether the current block is a branching block (true) or not (false). By "branching block", we mean a block that _might_ be taken, but not sure (or that is taken _for sure_ but with different inputs, as in the case of a loop).
///
/// # Returns
/// This functions returns the possible datasets that are _returned_ in this block. This is thus different from `pass_expr()`.
fn pass_block(block: &mut Block, table: &mut DataState, is_branch: bool) -> HashSet<Data> {
    // Iterate over all the statements
    let mut ids: HashSet<Data> = HashSet::new();
    for s in &mut block.stmts {
        let sids: HashSet<Data> = pass_stmt(s, table, is_branch, &block.table);
        ids.extend(sids);
    }

    // Done
    ids
}

/// Attempts to analyse the data dependencies for this statement.
///
/// # Arguments
/// - `stmt`: The Stmt to traverse.
/// - `table`: The DataTable we use to keep track of which variable has what value.
/// - `is_branch`: Indicates whether the current block is a branching block (true) or not (false). By "branching block", we mean a block that _might_ be taken, but not sure (or that is taken _for sure_ but with different inputs, as in the case of a loop).
/// - `scope`: The symbol table of the current block we are in, i.e., the current scope.
///
/// # Returns
/// This functions returns the possible datasets that are _returned_ in this statement. This is thus different from `pass_expr()`.
fn pass_stmt(stmt: &mut Stmt, table: &mut DataState, is_branch: bool, scope: &Rc<RefCell<SymbolTable>>) -> HashSet<Data> {
    // Match on the exact statement
    use Stmt::*;
    match stmt {
        Block { block, .. } => pass_block(block, table, is_branch),

        FuncDef { code, st_entry, .. } => {
            // Function bodies never branch themselves (once called, they are always executed non-branching)
            let ids: HashSet<Data> = pass_block(code, table, false);

            // Push the results to the data table
            table.set_funcs(&st_entry.as_ref().unwrap().borrow().name, ids);

            // The definition itself doesn't return, so it doesn't introduce new identifiers
            HashSet::new()
        },
        ClassDef { methods, .. } => {
            // Simply recurse, that'll do it (we are not interested in the results, since this function never returns anyway)
            for m in methods {
                // Function bodies never branch themselves (once called, they are always executed non-branching)
                pass_stmt(m, table, false, scope);
            }

            // The definition itself doesn't return, so it doesn't introduce new identifiers
            HashSet::new()
        },
        Return { expr, output, .. } => {
            if let Some(expr) = expr {
                // Return whether the expression returns any datasets
                let res: HashSet<Data> = pass_expr(expr, table);
                output.clone_from(&res);
                res
            } else {
                // Otherwise, it doesn't return any new identifiers
                HashSet::new()
            }
        },

        If { cond, consequent, alternative, .. } => {
            // We don't care about the condition, but recurse it for any inter-expression dependencies
            pass_expr(cond, table);

            // Do the consequent, in a branching manner
            let mut ids: HashSet<Data> = pass_block(consequent, table, true);
            // Do the alternative too if there is one
            if let Some(alternative) = alternative {
                ids.extend(pass_block(alternative, table, true));
            }
            // Return the found ids
            ids

            // // Next, we do different things depending on whether there is an alternative
            // if let Some(alternative) = alternative {
            //     // If it's both, we first split the table in two halves, since any values added in the true block are not possible to obtain in the false block
            //     let mut false_table = table.clone();

            //     // Next, run the blocks with their own tables
            //     let mut ids: HashSet<Data> = pass_block(consequent, table);
            //     ids.extend(pass_block(alternative, &mut false_table));

            //     // Merge the table together again to get the post-if possibilities
            //     table.extend(false_table);

            //     // Now return the list of possible returns
            //     ids
            // } else {
            //     // If it's only the consequent, we just do that block
            //     pass_block(consequent, table)
            // }
        },
        For { initializer, condition, increment, consequent, .. } => {
            // Do the initializer, condition and increment for traversal purposes (the order makes sense, I think - if we ever get weird behaviour, check here)
            pass_stmt(initializer, table, is_branch, scope);
            pass_expr(condition, table);
            pass_stmt(increment, table, is_branch, scope);

            // We consider the body to be branching, since the assignment values of variables may change depending on the first or later iterations (as far as data/result input is concerned)
            pass_block(consequent, table, true);
            // Don't forget to run again to update the loop itself
            pass_block(consequent, table, true)
        },
        While { condition, consequent, .. } => {
            // The condition is recursed only to resolve in-condition dependencies
            pass_expr(condition, table);

            // We consider the body to be branching, since the assignment values of variables may change depending on the first or later iterations (as far as data/result input is concerned)
            pass_block(consequent, table, true);
            // Don't forget to run again to update the loop itself
            pass_block(consequent, table, true)
        },
        Parallel { blocks, st_entry, .. } => {
            // The parallel _does_ return, Tim - or at least, we have to put it in the variable if there is one
            let mut ids: HashSet<Data> = HashSet::new();
            for b in blocks {
                ids.extend(pass_block(b, table, is_branch));
            }

            // Put it in the variable if this Parallel is returning
            if let Some(st_entry) = st_entry {
                table.set_vars(&st_entry.borrow().name, ids);
            }

            // It never returns (since any returns it has are parallel-local)
            HashSet::new()
        },

        LetAssign { value, st_entry, .. } | Assign { value, st_entry, .. } => {
            // Traverse the value
            let ids: HashSet<Data> = pass_expr(value, table);

            // Now we do the trick; if this variable originates in this scope, _or_ we are guaranteed to be executing as only branch, we override whatever input is set for the variable; otherwise, we simply extend since whatever it has, it may still have it later
            let entry: &Rc<RefCell<VarEntry>> = st_entry.as_ref().unwrap();
            if !is_branch || scope.borrow().variables().any(|v| Rc::ptr_eq(v.1, entry)) {
                let entry: Ref<VarEntry> = entry.borrow();
                debug!("Overwriting data assignment for '{}' (is not branch? {}, is this scope? {})", entry.name, !is_branch, is_branch);
                table.set_vars(&entry.name, ids);
            } else {
                let entry: Ref<VarEntry> = entry.borrow();
                debug!("Extending data assignment for '{}'", entry.name);
                let mut new_ids: HashSet<Data> = table.get_var(&entry.name).clone();
                new_ids.extend(ids);
                table.set_vars(&entry.name, new_ids);
            }

            // The statement itself never returns, though
            HashSet::new()
        },
        Expr { expr, .. } => {
            // Recurse but never return
            pass_expr(expr, table);
            HashSet::new()
        },

        // The rest no matter
        Import { .. } | Empty { .. } => HashSet::new(),
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in data traversal", stmt.variant()),
    }
}

/// Attempts to analyse the data dependencies for this expression.
///
/// # Arguments
/// - `expr`: The Expr to traverse.
/// - `table`: The DataTable we use to keep track of which variable has what value.
///
/// # Returns
/// This function returns the possible identifiers that the evaluation of this expression can be if it concerns a Data or IntermediateResult. Note that this differs from `pass_block()` and `pass_stmt()`.
fn pass_expr(expr: &mut Expr, table: &DataState) -> HashSet<Data> {
    use Expr::*;
    match expr {
        Cast { expr, .. } => {
            // Only dataset casts are allowed if it is a dataset itself; so we can simply recurse it
            pass_expr(expr, table)
        },

        Call { args, input, result, st_entry, .. } => {
            // Populating calls is what this traversal is all about, so let's dive into the interesting stuff

            // // Find out if this call is external
            // let is_external: bool = if let Some(st_entry) = st_entry {
            //     let entry: Ref<FunctionEntry> = st_entry.borrow();
            //     entry.package_name.is_some()
            // } else {
            //     false
            // };

            // // Only do interesting stuff if this function _is_ external, though
            // if is_external {
            // Traverse into the arguments to find the input identifiers
            let mut ids: HashSet<Data> = HashSet::new();
            for a in args.iter_mut() {
                ids.extend(pass_expr(a, table));
            }
            *input = ids.into_iter().collect();

            // What type of data this function returns depends on whether the function is external or not
            if let Some(st_entry) = st_entry.as_ref() {
                let entry: Ref<FunctionEntry> = st_entry.borrow();
                if entry.package_name.is_some() {
                    // It's external; as such, if it returns a result, either return an already generated result ID or generate a new one. Otherwise, this function doesn't return shit.
                    if !result.is_empty() {
                        result.clone()
                    } else if entry.signature.ret == DataType::Class(BuiltinClasses::IntermediateResult.name().into()) {
                        // If this call is an external one _and_ it returns a result, we want to note it as such.

                        // Generate the identifier for this result
                        let uuid: String = Uuid::new_v4().to_string()[..6].into();
                        let id: String = format!("result_{}_{}", entry.name, uuid);
                        let res: HashSet<Data> = HashSet::from([Data::IntermediateResult(id)]);

                        // Note it in the function
                        result.clone_from(&res);

                        // Return the identifier to return from this call
                        res
                    } else {
                        // Nothing to return
                        HashSet::new()
                    }
                } else {
                    // It's an internal call. As such, propagate what we know of the symbol table declaration (or rather, compile state).
                    if entry.name == BuiltinFunctions::CommitResult.name() {
                        // Attempt to find out the name of the dataset
                        let arg: &Expr = args.first().unwrap();
                        if let Expr::Literal { literal: brane_dsl::ast::Literal::String { value, .. } } = arg {
                            // OK return that as a data
                            let res: HashSet<Data> = HashSet::from([Data::Data(value.clone())]);
                            result.clone_from(&res);
                            res
                        } else {
                            panic!("Got non-string-literal name argument for builtin `commit_result()`");
                        }
                    } else if entry.name == BuiltinFunctions::Print.name()
                        || entry.name == BuiltinFunctions::PrintLn.name()
                        || entry.name == BuiltinFunctions::Len.name()
                    {
                        // Simply return NOTHING :P
                        HashSet::new()
                    } else {
                        // It's not a builtin but a custom one; refer to the compile state
                        // NOTE: Tough luck if the function was never defined before (why does it just return nothing when it's not found instead of error?). But I _guess_ that would indeed be unlikely, this far in the compilation process.
                        table.get_func(&entry.name).clone()
                    }
                }
            } else {
                // Not much we can say if the entry is not resolved :/
                HashSet::new()
            }

            // // If this function returns an IntermediateResult, generate the ID while at it (and it wasn't done so already)
            // if result.is_none() {
            //     let entry: Ref<FunctionEntry> = st_entry.as_ref().unwrap().borrow();
            //     if entry.signature.ret == DataType::Class(BuiltinClasses::Data.name().into())
            //         || entry.signature.ret == DataType::Class(BuiltinClasses::IntermediateResult.name().into())
            //     {
            //         // If this call is an external one _and_ it returns a result, we want to note it as such.

            //         // Generate the identifier for this result
            //         let uuid: String = Uuid::new_v4().to_string()[..6].into();
            //         let id: String = format!("result_{}_{}", entry.name, uuid);

            //         // Note it in the function
            //         *result = Some(if entry.signature.ret == DataType::Class(BuiltinClasses::Data.name().into()) {
            //             Data::Data(())
            //         });

            //         // Return the identifier to return from this call
            //         HashSet::from([Data::IntermediateResult(id)])
            //     } else {
            //         HashSet::new()
            //     }
            // } else if let Some(result) = result {
            //     // Otherwise, we don't generate a new one but return the value of result
            //     HashSet::from([Data::IntermediateResult(result.clone())])
            // } else {
            // }

            // } else {
            //     // Still recurse into the arguments to catch any nested calls
            //     for a in args {
            //         pass_expr(a, table);
            //     }

            //     // The returned identifier is quite simply that of the function itself
            //     if let Some(st_entry) = st_entry {
            //         table.get_func(&st_entry.borrow().name).clone()
            //     } else {
            //         HashSet::new()
            //     }

            // }
        },
        Array { values, .. } => {
            // We are lazy, and accept state space explosion in case someone is so nuts to have an array of Data
            let mut ids: HashSet<Data> = HashSet::new();
            for v in values {
                ids.extend(pass_expr(v, table));
            }
            ids
        },
        ArrayIndex { array, index, .. } => {
            // Do the array first, and remember that to return
            let ids: HashSet<Data> = pass_expr(array, table);
            // We do the other side for fun as well
            pass_expr(index, table);

            // But return the ids of the array expression, that's importat
            ids
        },

        UnaOp { expr, .. } => {
            // Simply recurse, since there aren't really any expressions possible on datasets and such
            pass_expr(expr, table)
        },
        BinOp { lhs, rhs, .. } => {
            // There's not really a data-changing operation, so just join and we assume it won't really matter
            let mut ids: HashSet<Data> = pass_expr(lhs, table);
            ids.extend(pass_expr(rhs, table));
            ids
        },
        Proj { st_entry, .. } => {
            // The projection is a stand-in for a variable, so we'd like the current value of that one
            if let Some(st_entry) = st_entry {
                match st_entry {
                    SymbolTableEntry::FunctionEntry(_) | SymbolTableEntry::ClassEntry(_) => {
                        // Although the entries are interesting, the projection itself doesn't return a value, so no data chances
                        HashSet::new()
                    },

                    SymbolTableEntry::VarEntry(st_entry) => {
                        // Return the matching value for the referenced variable here
                        table.get_var(&st_entry.borrow().name).clone()
                    },
                }
            } else {
                HashSet::new()
            }
        },

        Instance { properties, st_entry, .. } => {
            // Note down whether this happens to be a Data or an IntermediateResult
            let is_data: bool = {
                let entry: Ref<ClassEntry> = st_entry.as_ref().unwrap().borrow();
                if entry.signature.name == BuiltinClasses::IntermediateResult.name() {
                    panic!("Didn't expect an explicit IntermediateResult instantiation");
                }
                entry.signature.name == BuiltinClasses::Data.name()
            };

            // Recurse into the properties to traverse the expressions there
            let mut name: Option<String> = None;
            for p in properties {
                pass_expr(&mut p.value, table);

                // While at it, note if we find 'name' - and if we do, its value
                if is_data && &p.name.value == "name" {
                    name = Some(if let Expr::Literal { literal: brane_dsl::ast::Literal::String { value, .. } } = &*p.value {
                        value.clone()
                    } else {
                        panic!("Expected a String literal as Data/IntermediateResult `name` property, got {:?}", &*p.value);
                    })
                }
            }

            // If we are a data, then return the name as an identifier
            if is_data {
                if let Some(id) = name {
                    HashSet::from([Data::Data(id)])
                } else {
                    panic!("Got a Data/IntermediateResult without a `name`; this should never happen");
                }
            } else {
                HashSet::new()
            }
        },
        VarRef { st_entry, .. } => {
            // In this case, simply return the value in the table
            table.get_var(&st_entry.as_ref().unwrap().borrow().name).clone()
        },

        // Any others are never returning anything of interest
        _ => HashSet::new(),
    }
}





/***** LIBRARY *****/
/// Analyses data dependencies in the given `brane-dsl` AST.
///
/// Note that type analysis must already have been performed.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same nodes as went in, but now with added in `input` and `result` annotations to each external call.
///
/// # Errors
/// This pass typically does not error, but the option is here for convention purposes.
pub fn do_traversal(state: &mut CompileState, root: Program) -> Result<Program, Vec<AstError>> {
    let mut root = root;

    // Iterate over all statements to analyse dependencies
    // (The main block is obviously never branching either)
    pass_block(&mut root.block, &mut state.data, false);

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

    use super::super::print::symbol_tables;
    use super::*;
    use crate::state::CompileState;
    use crate::{CompileResult, CompileStage, compile_snippet_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_data() {
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
                match compile_snippet_to(&mut state, code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Data) {
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
            // println!("{}\n", (0..40).map(|_| "- ").collect::<String>());
            // print_state(&state.table, 0);
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
