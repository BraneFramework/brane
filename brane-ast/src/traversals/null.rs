//  NULL.rs
//    by Lut99
//
//  Created:
//    19 Dec 2022, 10:04:38
//  Last edited:
//    08 Dec 2023, 11:09:15
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a traversal that resolves null-types from the tree,
//!   resolving them with more proper types.
//

use brane_dsl::ast::{Block, Expr, Literal, Program, Stmt};
use enum_debug::EnumDebug as _;

use crate::errors::AstError;
pub use crate::errors::NullError as Error;


/***** TRAVERSAL FUNCTIONS *****/
/// Traverses a Block to find any null-occurances.
///
/// # Arguments
/// - `block`: The Block to traverse.
/// - `errors`: The list that accumulates errors as we do the traversal.
///
/// # Returns
/// Nothing, but might change internal nodes to get rid of null-casts.
///
/// # Errors
/// This function may error if the user made incorrect usage of `null`. In that case, the error is appended to `errors` and the function might return early.
fn pass_block(block: &mut Block, errors: &mut Vec<Error>) {
    // Simply do all statements in this block
    for s in &mut block.stmts {
        pass_stmt(s, errors);
    }
}

/// Traverses a Stmt to find any null-occurances.
///
/// # Arguments
/// - `stmt`: The Stmt to traverse.
/// - `errors`: The list that accumulates errors as we do the traversal.
///
/// # Returns
/// Nothing, but might change internal nodes to get rid of null-casts.
///
/// # Errors
/// This function may error if the user made incorrect usage of `null`. In that case, the error is appended to `errors` and the function might return early.
fn pass_stmt(stmt: &mut Stmt, errors: &mut Vec<Error>) {
    // Match on the given statement
    use Stmt::*;
    match stmt {
        Block { block } => {
            pass_block(block, errors);
        },

        FuncDef { code, .. } => {
            pass_block(code, errors);
        },
        ClassDef { methods, .. } => {
            for m in methods {
                pass_stmt(m, errors);
            }
        },
        Return { expr, .. } => {
            if let Some(expr) = expr {
                pass_expr(expr, errors);
            }
        },

        If { cond, consequent, alternative, .. } => {
            pass_expr(cond, errors);
            pass_block(consequent, errors);
            if let Some(alternative) = alternative {
                pass_block(alternative, errors);
            }
        },
        For { initializer, condition, increment, consequent, .. } => {
            pass_stmt(initializer, errors);
            pass_expr(condition, errors);
            pass_stmt(increment, errors);
            pass_block(consequent, errors);
        },
        While { condition, consequent, .. } => {
            pass_expr(condition, errors);
            pass_block(consequent, errors);
        },
        Parallel { blocks, .. } => {
            for b in blocks {
                pass_block(b, errors);
            }
        },

        LetAssign { value, .. } => {
            // We'll allow it if this value is a null
            match value {
                // Null is allowed, and no need to traverse it
                brane_dsl::ast::Expr::Literal { literal: Literal::Null { .. } } => {},

                // Otherwise, traverse
                value => pass_expr(value, errors),
            }
        },
        Assign { value, .. } => {
            // We always crawl since null is not allowed
            pass_expr(value, errors);
        },
        Expr { expr, .. } => {
            pass_expr(expr, errors);
        },

        // The rest we don't care.
        Import { .. } | Empty {} => {},
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in resolve traversal", stmt.variant()),
    }
}

/// Traverses an Expr to get rid of null-casts.
///
/// Note that at this time, we have already treated any legal null's; so any we find here are always illegal.
///
/// # Arguments
/// - `expr`: The Expr to traverse.
/// - `errors`: The list that accumulates errors as we do the traversal.
///
/// # Returns
/// Nothing, but might change this or internal nodes to get rid of null-casts.
///
/// # Errors
/// This function may error if the user made incorrect usage of `null`. In that case, the error is appended to `errors` and the function might return early.
fn pass_expr(expr: &mut Expr, errors: &mut Vec<Error>) {
    // Match the expression given
    use Expr::*;
    match expr {
        Cast { expr, .. } => {
            pass_expr(expr, errors);
        },

        Call { expr, args, .. } => {
            // Pass 'em all
            pass_expr(expr, errors);
            for a in args {
                pass_expr(a, errors);
            }
        },
        Array { values, .. } => {
            for v in values {
                pass_expr(v, errors);
            }
        },
        ArrayIndex { array, index, .. } => {
            pass_expr(array, errors);
            pass_expr(index, errors);
        },
        Pattern { exprs, .. } => {
            for e in exprs {
                pass_expr(e, errors);
            }
        },

        UnaOp { expr, .. } => {
            pass_expr(expr, errors);
        },
        BinOp { lhs, rhs, .. } => {
            pass_expr(lhs, errors);
            pass_expr(rhs, errors);
        },
        Proj { lhs, rhs, .. } => {
            pass_expr(lhs, errors);
            pass_expr(rhs, errors);
        },

        Instance { properties, .. } => {
            for p in properties {
                pass_expr(&mut p.value, errors);
            }
        },
        Literal { literal } => {
            pass_literal(literal, errors);
        },

        // The rest we don't interact with
        Identifier { .. } | VarRef { .. } | Empty {} => {},
    }
}

/// Traverses a Literal to detect illegal usage of null.
///
/// Note that at this time, we have already treated any legal null's; so any we find here are always illegal.
///
/// # Arguments
/// - `lit`: The Literal to traverse.
/// - `errors`: The list that accumulates errors as we do the traversal.
///
/// # Errors
/// This function may error if the user made incorrect usage of `null`. In that case, the error is appended to `errors` and the function might return early.
fn pass_literal(lit: &Literal, errors: &mut Vec<Error>) {
    // We only do one thing: error if we see a `null` here
    if let Literal::Null { range } = lit {
        errors.push(Error::IllegalNull { range: range.clone() });
    }
}





/***** LIBRARY *****/
/// Resolves null-typing in the given `brane-dsl` AST.
///
/// Note that the symbol tables must already have been constructed.
///
/// The goal of this traversal is to get rid of `DataType::Null` occurrances, asserting that null is only used in let-assignments.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same nodes as went in, but now with proper null-usage.
///
/// # Errors
/// This pass may throw multiple `AstError::NullError`s if the user made mistakes with their variable references.
pub fn do_traversal(root: Program) -> Result<Program, Vec<AstError>> {
    let mut root = root;

    // Iterate over the statements to find usage of nulls.
    let mut errors: Vec<Error> = vec![];
    pass_block(&mut root.block, &mut errors);

    // Returns the errors
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
    fn test_null() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Null) {
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
                    panic!("Failed to analyse null-usage (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to analyse null-usage (see output above)");
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
