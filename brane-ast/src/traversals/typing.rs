//  TYPING.rs
//    by Lut99
//
//  Created:
//    19 Aug 2022, 16:34:16
//  Last edited:
//    08 Dec 2023, 11:09:07
//  Auto updated?
//    Yes
//
//  Description:
//!   Performs type analysis on the AST, i.e., resolving the types that
//!   haven't been already and verifying the required ones are there.
//

use std::cell::{Ref, RefCell, RefMut};
use std::rc::Rc;

use brane_dsl::ast::{Block, Expr, Node, Program, Stmt};
use brane_dsl::spec::MergeStrategy;
use brane_dsl::symbol_table::{ClassEntry, FunctionEntry, SymbolTableEntry, VarEntry};
use brane_dsl::{DataType, SymbolTable, TextPos, TextRange};
use enum_debug::EnumDebug as _;

use crate::errors::AstError;
pub use crate::errors::TypeError as Error;
use crate::spec::BuiltinClasses;
use crate::warnings::AstWarning;
pub use crate::warnings::TypeWarning as Warning;


/***** HELPER FUNCTIONS *****/
/// Inserts a 'forced cast', i.e., makes sure the source type is casteable and then insret a new Cast expresion to make it so (if necessary).
///
/// Note that, for convenience, this function also evaluates the type of the given expression first.
///
/// # Arguments
/// - `expr`: The expression to cast. Note that we take ownership since we might want to wrap it in a Cast expression.
/// - `target`: The DataType to force a cast to.
/// - `symbol_table`: The SymbolTable that represents the current scope.
/// - `errors`: A list we use to accumulate errors as they occur.
///
/// # Returns
/// Returns either `expr` again, or an `Expr::Call` wrapping `expr`.
///
/// # Errors
/// This function errors if the source type is not casteable to the target type.
///
/// If errors occur, they are appended to the `errors` list. The same expression as given is returned in that case.
fn force_cast(expr: Expr, target: DataType, symbol_table: &Rc<RefCell<SymbolTable>>, errors: &mut Vec<Error>) -> Expr {
    let mut expr: Expr = expr;

    // Resolve the expression which we check first
    let source: DataType = pass_expr(&mut expr, symbol_table, errors);
    // If it's the same type, then we can early stop and simply return it (no casting needed)
    if source == target {
        return expr;
    }

    // Otherwise, fail it it cannot be casted
    let range: TextRange = expr.range().clone();
    if !source.coercible_to(&target) {
        errors.push(Error::IncorrectType { got: source, expected: target, range });
        return expr;
    }

    // Otherwise otherwise, insert the cast for when we will evaluate the expression's value.
    Expr::new_cast(Box::new(expr), target, range)
}

/// Helper function that inserts casts in the given block around return statements appropriately.
///
/// Note that it assumes that the target type is compatible with the given block's type.
///
/// # Arguments
/// - `block`: The block who's return statements to cast.
/// - `data_type`: The DataType to cast to.
///
/// # Returns
/// Nothing, but does wrap the expressions of nested return statements in casts.
fn insert_casts_at_returns(s: &mut Stmt, target: &DataType) {
    // Match the statement
    use Stmt::*;
    #[allow(clippy::collapsible_match)]
    match s {
        // Most blocks are just recursion
        Block { block } => {
            for s in block.stmts.iter_mut() {
                insert_casts_at_returns(s, target);
            }
        },
        If { consequent, alternative, .. } => {
            for s in consequent.stmts.iter_mut() {
                insert_casts_at_returns(s, target);
            }
            if let Some(alternative) = alternative {
                for s in alternative.stmts.iter_mut() {
                    insert_casts_at_returns(s, target);
                }
            }
        },
        For { consequent, .. } => {
            for s in consequent.stmts.iter_mut() {
                insert_casts_at_returns(s, target);
            }
        },
        While { consequent, .. } => {
            for s in consequent.stmts.iter_mut() {
                insert_casts_at_returns(s, target);
            }
        },
        Parallel { .. } => {
            // Any returns in parallels return the _branch_, not the current stream, so we ignore
        },

        // The return is the interesting one, obviously
        Return { expr, .. } => {
            // Wrap it in a cast to the target type if there is a return statement
            if let Some(expr) = expr {
                let range: TextRange = expr.range().clone();
                *expr = brane_dsl::ast::Expr::new_cast(Box::new(expr.clone()), target.clone(), range);
            }
        },

        // We ignore the rest
        Import { .. } | FuncDef { .. } | ClassDef { .. } | LetAssign { .. } | Assign { .. } | Expr { .. } | Empty {} => {},
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in typing traversal's 'insert_casts_at_returns()'", s.variant()),
    }
}





/***** TRAVERSAL FUNCTIONS *****/
/// Attempts to resolve the type of this block and verifies it is well-types.
///
/// # Arguments
/// - `block`: The Block to traverse.
/// - `warnings`: A list that will collect any warnings during compilation. If it's empty, then it may be assumed for warnings occurred.
/// - `errors`: A list we use to accumulate errors as they occur.
///
/// # Returns
/// The return type of all the return statements in this block with the text range of the earliest return statement, or None if there are none.
///
/// # Errors
/// This function may error if there were semantic problems while analysing the type.
///
/// If errors occur, they are appended to the `errors` list. 'None' is returned in that case.
fn pass_block(block: &mut Block, warnings: &mut Vec<Warning>, errors: &mut Vec<Error>) -> Option<(DataType, TextRange)> {
    // Simply recurse, examining if all return statements evaluate to the same value
    let mut return_type: Option<(DataType, TextRange)> = None;
    for s in block.stmts.iter_mut() {
        // Analyse the statement
        let stmt_type: Option<(DataType, TextRange)> = pass_stmt(s, &block.table, warnings, errors);

        // Overwrite the return type if not yet, or error if it does not match
        if let Some(stmt_type) = stmt_type {
            // Compare
            if let Some(return_type) = &return_type {
                if !stmt_type.0.coercible_to(&return_type.0) {
                    errors.push(Error::IncompatibleReturns {
                        got: stmt_type.0,
                        expected: return_type.0.clone(),
                        got_range: stmt_type.1,
                        expected_range: return_type.1.clone(),
                    });
                    return None;
                }
                // Insert casts at the return statements if necessary
                if stmt_type.0 != return_type.0 {
                    insert_casts_at_returns(s, &return_type.0);
                }
            } else {
                return_type = Some(stmt_type);
            }
        }
    }

    // Set the return type
    block.ret_type = return_type.as_ref().map(|(d, _)| d.clone());

    // The table should now be populated for this block
    return_type
}

/// Attempts to resolve the type of this statement and verifies it is well-types.
///
/// # Arguments
/// - `stmt`: The Stmt to traverse.
/// - `symbol_table`: The SymbolTable that represents the current scope.
/// - `warnings`: A list that will collect any warnings during compilation. If it's empty, then it may be assumed for warnings occurred.
/// - `errors`: A list we use to accumulate errors as they occur.
///
/// # Returns
/// The return type of all the return statements in this block with the text range of the earliest return statement, or None if there are none.
///
/// # Errors
/// This function may error if there were semantic problems while analysing the type.
///
/// If errors occur, they are appended to the `errors` list. 'None' is returned in that case.
fn pass_stmt(
    stmt: &mut Stmt,
    symbol_table: &Rc<RefCell<SymbolTable>>,
    warnings: &mut Vec<Warning>,
    errors: &mut Vec<Error>,
) -> Option<(DataType, TextRange)> {
    // Match on the exact statement
    use Stmt::*;
    let return_type: Option<_> = match stmt {
        Block { block, .. } => {
            // Simply recurse the inner block
            pass_block(block, warnings, errors)
        },

        Import { name, st_funcs, .. } => {
            // Check if none of the functions return a Data
            for f in st_funcs.as_ref().unwrap() {
                let fe: Ref<FunctionEntry> = f.borrow();
                if fe.signature.ret == DataType::Class(BuiltinClasses::Data.name().into()) {
                    errors.push(Error::IllegalDataReturnError { name: fe.name.clone(), range: name.range().clone() });
                }
            }

            // Nothing returns here
            None
        },
        FuncDef { params, code, st_entry, .. } => {
            // If the first parameters happens to be the class, we can know that before resolving
            if !params.is_empty() && &params[0].value == "self" {
                let entry: Ref<FunctionEntry> = st_entry.as_ref().unwrap().borrow();
                entry.params[0].borrow_mut().data_type = DataType::Class(entry.class_name.clone().unwrap());
            }

            // Recurse into the block to resolve the parameters and such
            let ret_type: DataType = pass_block(code, warnings, errors).map(|(d, _)| d).unwrap_or(DataType::Void);

            // Extract the argument types if they are resolved
            let mut entry: RefMut<FunctionEntry> = st_entry.as_ref().unwrap().borrow_mut();
            entry.signature.args = {
                let st: Ref<SymbolTable> = code.table.borrow();
                params
                    .iter()
                    .map(|p| {
                        let entry: Rc<RefCell<VarEntry>> = st.get_var(&p.value).unwrap();
                        let e: Ref<VarEntry> = entry.borrow();
                        e.data_type.clone()
                    })
                    .collect()
            };

            // Set the return type
            entry.signature.ret = ret_type;

            // Return None since a function definition itself does not return
            None
        },
        ClassDef { methods, st_entry, .. } => {
            // Go into the method bodies to resolve them. Because we use a SymbolTable to map them, this automatically updates them in all relevant ways.
            let entry: Ref<ClassEntry> = st_entry.as_ref().unwrap().borrow();
            for m in methods.iter_mut() {
                pass_stmt(m, &entry.symbol_table, warnings, errors);
            }

            // This statement itself never returns
            None
        },
        Return { expr, range, ref mut data_type, .. } => {
            // Resolve the type of the expression if any
            let expr_type: DataType = if let Some(expr) = expr { pass_expr(expr, symbol_table, errors) } else { DataType::Void };
            *data_type = expr_type.clone();

            // Always returns that type
            Some((expr_type, range.clone()))
        },

        If { ref mut cond, consequent, ref mut alternative, .. } => {
            // Force the condition type to a boolean
            *cond = force_cast(cond.clone(), DataType::Boolean, symbol_table, errors);

            // Recurse into the bodies
            let mut ret_type: Option<_> = pass_block(consequent, warnings, errors);
            if let Some(alternative) = alternative {
                let ret: Option<_> = pass_block(alternative, warnings, errors);

                // Overwrite or make sure the return statements collide
                if let Some(ret_type) = &ret_type {
                    if let Some(ret) = ret {
                        if !ret.0.coercible_to(&ret_type.0) {
                            errors.push(Error::IncompatibleReturns {
                                got: ret.0,
                                expected: ret_type.0.clone(),
                                got_range: ret.1,
                                expected_range: ret_type.1.clone(),
                            });
                            return None;
                        }
                        // Insert casts at the return statements if necessary
                        if ret.0 != ret_type.0 {
                            for s in alternative.stmts.iter_mut() {
                                insert_casts_at_returns(s, &ret_type.0);
                            }
                        }
                    }
                } else {
                    ret_type = ret;
                }
            }

            // Done
            ret_type
        },
        For { initializer, ref mut condition, increment, consequent, .. } => {
            // Resolve the initializer type
            pass_stmt(initializer, &consequent.table, warnings, errors);
            // Force the condition type to a boolean
            *condition = force_cast(condition.clone(), DataType::Boolean, symbol_table, errors);
            // Resolve the increment type
            pass_stmt(increment, &consequent.table, warnings, errors);

            // Descent into the consequent
            pass_block(consequent, warnings, errors)
        },
        While { condition, consequent, .. } => {
            // Force the condition type to a boolean
            *condition = force_cast(condition.clone(), DataType::Boolean, symbol_table, errors);

            // Descent into the consequent
            pass_block(consequent, warnings, errors)
        },
        Parallel { result, blocks, merge, st_entry, attrs: _, range } => {
            // First, examine the result types of each of the blocks and make sure they evaluate to the same
            let mut ret_type: Option<(DataType, TextRange)> = None;
            for (i, b) in blocks.iter_mut().enumerate() {
                // Get the return type of the block (if any)
                let ret: Option<(DataType, TextRange)> = pass_block(b, warnings, errors);

                // Check if there is at least something if we expect it to
                if result.is_some() && (ret.is_none() || ret.as_ref().unwrap().0 == DataType::Void) {
                    errors.push(Error::ParallelNoReturn { block: i, range: b.range().clone() });
                    return None;
                }
                #[allow(clippy::unnecessary_unwrap)]
                if result.is_none() && (ret.is_some() && ret.as_ref().unwrap().0 != DataType::Void) {
                    errors.push(Error::ParallelUnexpectedReturn { block: i, got: ret.unwrap().0, range: b.range().clone() });
                    return None;
                }

                // If that checks out, make sure it matches the return type of the previous ones
                if let Some(ret_type) = &ret_type {
                    if let Some(ret) = ret {
                        if !ret.0.coercible_to(&ret_type.0) {
                            errors.push(Error::IncompatibleReturns {
                                got: ret.0,
                                expected: ret_type.0.clone(),
                                got_range: ret.1,
                                expected_range: ret_type.1.clone(),
                            });
                            return None;
                        }
                        // Insert casts at the return statements if necessary
                        if ret.0 != ret_type.0 {
                            for s in &mut b.stmts {
                                insert_casts_at_returns(s, &ret_type.0);
                            }
                        }
                    } else {
                        errors.push(Error::ParallelIncompleteReturn { block: i, expected: ret_type.0.clone(), range: b.range().clone() });
                        return None;
                    }
                } else {
                    ret_type = ret;
                }
            }

            // With a return statement in mind, we will now resolve if the type matches the merge strategy
            let strat: (MergeStrategy, TextRange) =
                if let Some(merge) = merge { (MergeStrategy::from(&merge.value), merge.range.clone()) } else { (MergeStrategy::None, range.clone()) };
            // Match on the result type
            if let Some(ret) = &ret_type {
                // Match on the strategy to verify the types
                match strat.0 {
                    MergeStrategy::First | MergeStrategy::FirstBlocking | MergeStrategy::Last => {
                        // Any will do (except void ofcourse)
                        if let DataType::Void = &ret.0 {
                            errors.push(Error::ParallelIllegalType {
                                merge:    strat.0,
                                got:      ret.0.clone(),
                                expected: vec![DataType::Any],
                                range:    ret.1.clone(),
                                reason:   strat.1,
                            });
                            return None;
                        }
                    },

                    MergeStrategy::Sum | MergeStrategy::Product | MergeStrategy::Max | MergeStrategy::Min => {
                        // Only integers and reals
                        match &ret.0 {
                            DataType::Integer | DataType::Real => {},
                            _ => {
                                errors.push(Error::ParallelIllegalType {
                                    merge:    strat.0,
                                    got:      ret.0.clone(),
                                    expected: vec![DataType::Integer, DataType::Real],
                                    range:    ret.1.clone(),
                                    reason:   strat.1,
                                });
                                return None;
                            },
                        }
                    },

                    MergeStrategy::All => {
                        // As usual, except that we replace the return type with an array
                        ret_type = Some((DataType::Array(Box::new(ret.0.clone())), ret.1.clone()));
                    },

                    MergeStrategy::None => {
                        // Error! This should not happen!
                        errors.push(Error::ParallelNoStrategy { range: strat.1 });
                        return None;
                    },
                }
            } else if strat.0 != MergeStrategy::None {
                // Specified for nothing
                warnings.push(Warning::UnusedMergeStrategy { merge: strat.0, range: strat.1 });
            }

            // Link the found return type in our own statement, if any
            if let Some(st_entry) = st_entry.as_ref() {
                let mut entry: RefMut<VarEntry> = st_entry.borrow_mut();
                entry.data_type = ret_type.unwrap_or((DataType::Void, TextRange::none())).0;
            }

            // A parallel statement itself does not return, though
            None
        },

        LetAssign { value, st_entry, .. } => {
            // Resolve the type of the expression
            let data_type: DataType = pass_expr(value, symbol_table, errors);

            // That's our type too
            let mut entry: RefMut<VarEntry> = st_entry.as_ref().unwrap().borrow_mut();
            entry.data_type = data_type;

            // A LetAssign never returns
            None
        },
        Assign { ref mut value, st_entry, .. } => {
            // Get the current datatype (should always be resolved, since otherwise it would have been marked as undeclared)
            let data_type: DataType = {
                let entry: Ref<VarEntry> = st_entry.as_ref().unwrap().borrow();
                entry.data_type.clone()
            };

            // If the data type is Null or Any, then we might override the value instead of casting
            if data_type == DataType::Any {
                let expr_type: DataType = pass_expr(value, symbol_table, errors);
                st_entry.as_ref().unwrap().borrow_mut().data_type = expr_type;
            } else {
                // Force a cast to this variable's type on the expression
                *value = force_cast(value.clone(), data_type, symbol_table, errors);
            }

            // An Assigns never returns
            None
        },
        Expr { expr, ref mut data_type, .. } => {
            // Recurse into the expression
            *data_type = pass_expr(expr, symbol_table, errors);

            // A simple expr statement never returns
            None
        },

        // We ignore the rest
        Empty { .. } => None,
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in typing traversal", stmt.variant()),
    };

    // We're done here
    return_type
}

/// Resolves the type of the given expression, making sure everything checks out along the way.
///
/// # Arguments
/// - `expr`: The Expr to traverse.
/// - `symbol_table`: The SymbolTable that represents the current scope.
/// - `errors`: A list we use to accumulate errors as they occur.
///
/// # Returns
/// The evaluated type of the expression.
///
/// # Errors
/// This function may error if there were semantic problems while analysing the type.
///
/// If errors occur, they are appended to the `errors` list. 'Any' is returned in that case.
fn pass_expr(expr: &mut Expr, symbol_table: &Rc<RefCell<SymbolTable>>, errors: &mut Vec<Error>) -> DataType {
    // Match the expression
    use Expr::*;
    match expr {
        Cast { expr, target, .. } => {
            // Evaluate the expression
            let data_type: DataType = pass_expr(expr, symbol_table, errors);

            // Check if it's casteable to the target
            if !data_type.coercible_to(&target) {
                errors.push(Error::IncorrectType { got: data_type, expected: target.clone(), range: expr.range().clone() });
                return DataType::Any;
            }

            // Return the target as to-be-evaluated type
            target.clone()
        },

        Call { expr, args, ref mut st_entry, range, .. } => {
            // Get the referenced function entry in the identifier
            let st: Ref<SymbolTable> = symbol_table.borrow();
            let f_entry: Rc<RefCell<FunctionEntry>> = match &**expr {
                Expr::Proj { st_entry, .. } => {
                    // Attempt to cast the general entry to a function entry
                    if let Some(entry) = st_entry.as_ref() {
                        match entry {
                            SymbolTableEntry::FunctionEntry(f) => f.clone(),
                            SymbolTableEntry::VarEntry(v) => {
                                let entry: Ref<VarEntry> = v.borrow();
                                errors.push(Error::NonFunctionCall {
                                    got: entry.data_type.clone(),
                                    range: expr.range().clone(),
                                    defined_range: range.clone(),
                                });
                                return DataType::Any;
                            },
                            _ => {
                                panic!("Encountered non-Var, non-Function symbol table entry type in projection");
                            },
                        }
                    } else {
                        // The SymbolTable entry was not yet resolved; any further analysis will have to wait until runtime.
                        return DataType::Any;
                    }
                },
                Expr::Identifier { name, .. } => {
                    // Search the symbol table for this identifier
                    match st.get_func(&name.value) {
                        Some(entry) => entry,
                        None => {
                            errors.push(Error::UndefinedFunctionCall { name: name.value.clone(), range: name.range.clone() });
                            return DataType::Any;
                        },
                    }
                },

                _ => {
                    panic!("Encountered non-Proj, non-Identifier expression as identifier for a call expression");
                },
            };

            // Check if the number of arguments matches the expected amount
            let fe: Ref<FunctionEntry> = f_entry.borrow();
            // Don't forget to compensate for the implicit 'self'
            if fe.signature.args.len() - usize::from(fe.class_name.is_some()) != args.len() {
                errors.push(Error::FunctionArityError {
                    name: fe.name.clone(),
                    got: args.len(),
                    expected: fe.signature.args.len(),
                    got_range: TextRange::new(
                        args.iter().next().map(|a| a.start().clone()).unwrap_or(TextPos::none()),
                        args.iter().last().map(|a| a.end().clone()).unwrap_or(TextPos::none()),
                    ),
                    expected_range: fe.range.clone(),
                });
                return DataType::Any;
            }
            // Make sure the types match
            for (i, a) in args.iter_mut().enumerate() {
                *a = Box::new(force_cast(*a.clone(), fe.signature.args[i].clone(), symbol_table, errors));
            }

            // It does; return the return type
            *st_entry = Some(f_entry.clone());
            fe.signature.ret.clone()
        },
        Array { values, ref mut data_type, .. } => {
            // Make sure all values evaluate to the same type
            let mut elem_type: Option<(DataType, TextRange)> = None;
            for v in values.iter_mut() {
                // Evaluate the expression
                let expr_type: DataType = pass_expr(v, symbol_table, errors);

                // Make sure it is the same as used before
                if let Some((elem_type, range)) = &elem_type {
                    if !expr_type.coercible_to(elem_type) {
                        errors.push(Error::InconsistentArrayError {
                            got: expr_type,
                            expected: elem_type.clone(),
                            got_range: v.range().clone(),
                            expected_range: range.clone(),
                        });
                        return DataType::Any;
                    }
                    // Insert a cast in the value if necessary
                    if &expr_type != elem_type {
                        let range: TextRange = v.range().clone();
                        *v = Box::new(Expr::new_cast(v.clone(), elem_type.clone(), range));
                    }
                } else {
                    elem_type = Some((expr_type, v.range().clone()));
                }
            }
            let elem_type: DataType = elem_type.map(|(d, _)| d).unwrap_or(DataType::Any);

            // Set the type internally
            *data_type = elem_type.clone();

            // Return the found type (if it's an empty array, it has type any)
            DataType::Array(Box::new(elem_type))
        },
        ArrayIndex { array, ref mut index, ref mut data_type, .. } => {
            // Make sure the array evaluates to an Array type and get the inner type (no implicit casting here).
            let arr_type: DataType = pass_expr(array, symbol_table, errors);
            let elem_type: DataType = if let DataType::Array(t) = arr_type {
                *t
            } else {
                errors.push(Error::NonArrayIndexError { got: arr_type, range: array.range().clone() });
                return DataType::Any;
            };
            *data_type = elem_type.clone();

            // Make sure the index is a number
            *index = Box::new(force_cast((**index).clone(), DataType::Integer, symbol_table, errors));

            // Return the element type as evaluated type
            elem_type
        },
        Pattern { .. } => {
            // Let's for now not worry about this
            todo!();
        },

        UnaOp { op, ref mut expr, .. } => {
            // Depending on the operation, check the types
            match op {
                brane_dsl::ast::UnaOp::Not { .. } => {
                    // Expect boolean, return boolean
                    *expr = Box::new(force_cast((**expr).clone(), DataType::Boolean, symbol_table, errors));
                    DataType::Boolean
                },
                brane_dsl::ast::UnaOp::Neg { .. } => {
                    // Expect integer or real, return the same thing
                    let mut expr_type: DataType = pass_expr(expr, symbol_table, errors);
                    if expr_type != DataType::Integer && expr_type != DataType::Real {
                        *expr = Box::new(force_cast((**expr).clone(), DataType::Integer, symbol_table, errors));
                        expr_type = DataType::Integer;
                    }
                    expr_type
                },
                brane_dsl::ast::UnaOp::Prio { .. } => {
                    // Simply return the contents' type
                    pass_expr(expr, symbol_table, errors)
                },

                // The rest should never get here
                op => {
                    panic!("Got unary operator '{op}' in a UnaOp expression; this should never happen!");
                },
            }
        },
        BinOp { op, ref mut lhs, ref mut rhs, .. } => {
            // Match the operator to determine how to evaluate it
            match op {
                brane_dsl::ast::BinOp::And { .. } | brane_dsl::ast::BinOp::Or { .. } => {
                    // Expect boolean, return boolean
                    *lhs = Box::new(force_cast((**lhs).clone(), DataType::Boolean, symbol_table, errors));
                    *rhs = Box::new(force_cast((**rhs).clone(), DataType::Boolean, symbol_table, errors));
                    DataType::Boolean
                },

                brane_dsl::ast::BinOp::Add { .. } => {
                    // First evaluate the sides
                    let mut lhs_type: DataType = pass_expr(lhs, symbol_table, errors);
                    let mut rhs_type: DataType = pass_expr(rhs, symbol_table, errors);

                    // If both are Any, there is not much more to say
                    if (lhs_type == DataType::Any) && (rhs_type == DataType::Any) {
                    } else {
                        // If the types are (runtime) strings, then treat as such
                        if (lhs_type == DataType::String || lhs_type == DataType::Any) && (rhs_type == DataType::String || rhs_type == DataType::Any)
                        {
                            *lhs = Box::new(force_cast((**lhs).clone(), DataType::String, symbol_table, errors));
                            *rhs = Box::new(force_cast((**rhs).clone(), DataType::String, symbol_table, errors));
                            lhs_type = DataType::String;
                        } else {
                            // Now either has to be an integer or a real, or casteable to one
                            if lhs_type != DataType::Integer && lhs_type != DataType::Real {
                                *lhs = Box::new(force_cast((**lhs).clone(), DataType::Integer, symbol_table, errors));
                                lhs_type = DataType::Integer;
                            }
                            if rhs_type != DataType::Integer && rhs_type != DataType::Real {
                                *rhs = Box::new(force_cast((**rhs).clone(), DataType::Integer, symbol_table, errors));
                                rhs_type = DataType::Integer;
                            }

                            // Finally, if either is real and the other not, promote it
                            if lhs_type == DataType::Real && rhs_type != DataType::Real {
                                *rhs = Box::new(force_cast((**rhs).clone(), DataType::Real, symbol_table, errors));
                            }
                            if lhs_type != DataType::Real && rhs_type == DataType::Real {
                                *lhs = Box::new(force_cast((**lhs).clone(), DataType::Real, symbol_table, errors));
                            }
                        }
                    }

                    // Return the type of the lhs (which is now the same as rhs)
                    lhs_type
                },
                brane_dsl::ast::BinOp::Sub { .. } | brane_dsl::ast::BinOp::Mul { .. } | brane_dsl::ast::BinOp::Div { .. } => {
                    // First evaluate the sides
                    let mut lhs_type: DataType = pass_expr(lhs, symbol_table, errors);
                    let mut rhs_type: DataType = pass_expr(rhs, symbol_table, errors);

                    // Now either has to be an integer or a real, or casteable to one
                    if lhs_type != DataType::Integer && lhs_type != DataType::Real {
                        *lhs = Box::new(force_cast((**lhs).clone(), DataType::Integer, symbol_table, errors));
                        lhs_type = DataType::Integer;
                    }
                    if rhs_type != DataType::Integer && rhs_type != DataType::Real {
                        *rhs = Box::new(force_cast((**rhs).clone(), DataType::Integer, symbol_table, errors));
                        rhs_type = DataType::Integer;
                    }

                    // Finally, if either is real and the other not, promote it
                    if lhs_type == DataType::Real && rhs_type != DataType::Real {
                        *rhs = Box::new(force_cast((**rhs).clone(), DataType::Real, symbol_table, errors));
                    }
                    if lhs_type != DataType::Real && rhs_type == DataType::Real {
                        *lhs = Box::new(force_cast((**lhs).clone(), DataType::Real, symbol_table, errors));
                    }

                    // Return the type of the lhs (which is now the same as rhs)
                    lhs_type
                },
                brane_dsl::ast::BinOp::Mod { .. } => {
                    // Expect two integers
                    *lhs = Box::new(force_cast((**lhs).clone(), DataType::Integer, symbol_table, errors));
                    *rhs = Box::new(force_cast((**rhs).clone(), DataType::Integer, symbol_table, errors));
                    DataType::Integer
                },

                brane_dsl::ast::BinOp::Eq { .. } | brane_dsl::ast::BinOp::Ne { .. } => {
                    // Do pass them, even though we don't care about the type
                    pass_expr(lhs, symbol_table, errors);
                    pass_expr(rhs, symbol_table, errors);

                    // Both sides can be anything but just return bool
                    DataType::Boolean
                },
                brane_dsl::ast::BinOp::Lt { .. }
                | brane_dsl::ast::BinOp::Le { .. }
                | brane_dsl::ast::BinOp::Gt { .. }
                | brane_dsl::ast::BinOp::Ge { .. } => {
                    // First evaluate the sides
                    let mut lhs_type: DataType = pass_expr(lhs, symbol_table, errors);
                    let mut rhs_type: DataType = pass_expr(rhs, symbol_table, errors);

                    // Now either has to be an integer or a real, or casteable to one
                    if lhs_type != DataType::Integer && lhs_type != DataType::Real {
                        *lhs = Box::new(force_cast((**lhs).clone(), DataType::Integer, symbol_table, errors));
                        lhs_type = DataType::Integer;
                    }
                    if rhs_type != DataType::Integer && rhs_type != DataType::Real {
                        *rhs = Box::new(force_cast((**rhs).clone(), DataType::Integer, symbol_table, errors));
                        rhs_type = DataType::Integer;
                    }

                    // Finally, if either is real and the other not, promote it
                    if lhs_type == DataType::Real && rhs_type != DataType::Real {
                        *rhs = Box::new(force_cast((**rhs).clone(), DataType::Real, symbol_table, errors));
                    }
                    if lhs_type != DataType::Real && rhs_type == DataType::Real {
                        *lhs = Box::new(force_cast((**lhs).clone(), DataType::Real, symbol_table, errors));
                    }

                    // Now return a boolean
                    DataType::Boolean
                },
            }
        },
        Proj { st_entry, .. } => {
            // Match either a variable or method
            if let Some(entry) = st_entry.as_ref() {
                match entry {
                    SymbolTableEntry::FunctionEntry(f) => f.borrow().signature.ret.clone(),
                    SymbolTableEntry::VarEntry(v) => v.borrow().data_type.clone(),
                    _ => {
                        panic!("Encountered non-Var, non-Function symbol table entry type in projection");
                    },
                }
            } else {
                DataType::Any
            }
        },

        Instance { name, properties, st_entry, .. } => {
            // Get the underlying type's symbol table
            let entry: Ref<ClassEntry> = st_entry.as_ref().unwrap().borrow();
            let cst: Ref<SymbolTable> = entry.symbol_table.borrow();

            // Start by resolving the property types
            for p in properties.iter_mut() {
                // Get the type of this property (whether it is part of this type or not is checked in the previous traversal)
                let p_type: DataType = cst.get_var(&p.name.value).unwrap().borrow().data_type.clone();

                // Make sure evaluation is correct
                *p.value = force_cast((*p.value).clone(), p_type, symbol_table, errors);
            }

            // Return the class name as its type
            DataType::Class(name.value.clone())
        },
        VarRef { st_entry, .. } => {
            // Return the type of this variable reference
            st_entry.as_ref().unwrap().borrow().data_type.clone()
        },
        Literal { literal } => {
            // Simply return the type of the literal
            literal.data_type()
        },

        // The rest is ambigious
        _ => DataType::Any,
    }
}





/***** LIBRARY *****/
/// Resolves typing in the given `brane-dsl` AST.
///
/// Note that the symbol tables must already have been constructed.
///
/// This effectively resolves all unresolved types in the symbol tables and verifies everything is compatible. Additionally, it may also insert implicit type casts where able.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
/// - `warnings`: A list that will collect any warnings during compilation. If it's empty, then it may be assumed for warnings occurred.
///
/// # Returns
/// The same nodes as went in, but now with no unresolved types.
///
/// # Errors
/// This pass may throw multiple `AstError::ResolveError`s if the user made mistakes with their variable references.
pub fn do_traversal(root: Program, warnings: &mut Vec<AstWarning>) -> Result<Program, Vec<AstError>> {
    let mut root = root;
    let mut warns: Vec<Warning> = vec![];

    // Iterate over all statements to deduce type information (if relevant)
    let mut errors: Vec<Error> = vec![];
    for s in root.block.stmts.iter_mut() {
        if let Some((ret_type, ret_range)) = pass_stmt(s, &root.block.table, &mut warns, &mut errors) {
            if ret_type == DataType::Class(BuiltinClasses::IntermediateResult.name().into()) {
                warnings.push(Warning::ReturningIntermediateResult { range: ret_range }.into());
            }
        }
    }

    // Done
    warnings.append(&mut warns.into_iter().map(|w| w.into()).collect::<Vec<AstWarning>>());
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
    use crate::{CompileResult, CompileStage, compile_program_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_typing() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Typing) {
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
                    panic!("Failed to analyse locations (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to analyse locations (see output above)");
                },

                _ => {
                    unreachable!();
                },
            };

            // Now print the symbol tables for prettyness
            symbol_tables::do_traversal(program, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
