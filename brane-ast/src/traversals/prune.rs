//  RETURN.rs
//    by Lut99
//
//  Created:
//    31 Aug 2022, 18:00:09
//  Last edited:
//    13 Dec 2023, 08:21:57
//  Auto updated?
//    Yes
//
//  Description:
//!   Traversal that prunes the AST for compilation.
//!
//!   In particular, inserts return statements into functions such that there
//!   if one for every codepath and compiles for-loops to while-statements.
//

use std::cell::Ref;
use std::collections::HashSet;
use std::mem;

use brane_dsl::ast::{Attribute, Block, Node, Program, Stmt};
use brane_dsl::symbol_table::FunctionEntry;
use brane_dsl::{DataType, TextPos, TextRange};
use enum_debug::EnumDebug as _;

use crate::errors::AstError;
pub use crate::errors::PruneError as Error;


/***** TRAVERSAL FUNCTIONS *****/
/// Prunes the statements in the given block for compilation.
///
/// # Arguments
/// - `block`: The Block to prune.
/// - `attr_stack`: A mutable stack that keeps track of the attributes active by parent blocks.
/// - `errors`: The list that can keep track of multiple errors.
///
/// # Returns
/// Whether or not the block completely returns or not. Also alters, adds or removes statements to or from the block.
///
/// # Errors
/// This function may error if a given statement in the block is a function that does not correctly return on all paths.
///
/// If an error occurred, it is written to the given `errors` list. The function then still returns whether this block itself fully returns or not.
fn pass_block(block: &mut Block, attr_stack: &mut Vec<Vec<Attribute>>, errors: &mut Vec<Error>) -> bool {
    // Push the block's attributes
    attr_stack.push(block.attrs.clone());

    // Iterate over the statements in the block.
    let old_stmts: Vec<Stmt> = mem::take(&mut block.stmts);
    let mut new_stmts: Vec<Stmt> = Vec::with_capacity(old_stmts.len());
    let mut fully_returns: bool = false;
    for s in old_stmts {
        // Run 'em through the statements (to replace for's into while's and such)
        let (mut new_stmt, returns): (Vec<Stmt>, bool) = pass_stmt(s, attr_stack, errors);
        new_stmts.append(&mut new_stmt);

        // If this statement returns completely (we already know it does of the correct type), then ignore the rest of the statements
        if returns {
            fully_returns = true;
            break;
        }
    }

    // Pop the attributes again
    attr_stack.pop();

    // // Done
    // decs.append(&mut new_stmts);
    // block.stmts = decs;
    block.stmts = new_stmts;
    fully_returns
}

/// Prunes the given statement for compilation.
///
/// # Arguments
/// - `stmt`: The statement to prune.
/// - `attr_stack`: A mutable stack that keeps track of the attributes active by parent blocks.
/// - `errors`: The list that can keep track of multiple errors.
///
/// # Returns
/// A tuple of a (series of) Stmt(s) to replace the given one, and whether this statement _fully_ returns. This list will typically be the given statement only, but not necessarily so.
///
/// # Errors
/// This function may error if the given statement is a function that does not correctly return on all paths.
///
/// If an error occurred, it is written to the given `errors` list. The function then still returns whether this statement fully returns or not.
fn pass_stmt(stmt: Stmt, attr_stack: &mut Vec<Vec<Attribute>>, errors: &mut Vec<Error>) -> (Vec<Stmt>, bool) {
    let mut stmt: Stmt = stmt;

    // Match the statement
    use Stmt::*;
    match &mut stmt {
        Block { ref mut block, .. } => {
            // Simply pass into the block
            let returns: bool = pass_block(block, attr_stack, errors);

            // Return the statement as-is
            (vec![stmt], returns)
        },

        FuncDef { code, st_entry, .. } => {
            // Go into the block so see if it fully returns
            let returns: bool = pass_block(code, attr_stack, errors);

            // We know all returns are of a valid type; so if there is one and returns are missing, error
            if !returns {
                // If there is a specific type expected, error
                let ret_type: DataType = {
                    let e: Ref<FunctionEntry> = st_entry.as_ref().unwrap().borrow();
                    e.signature.ret.clone()
                };
                if ret_type != DataType::Any && ret_type != DataType::Void {
                    errors.push(Error::MissingReturn {
                        expected: ret_type,
                        range:    TextRange::new(TextPos::new(code.end().line, code.end().col - 1), code.end().clone()),
                    });
                    return (vec![stmt], false);
                }

                // Otherwise, insert a void return
                code.stmts.push(Stmt::Return {
                    expr:      None,
                    data_type: ret_type,
                    output:    HashSet::new(),
                    range:     TextRange::none(),
                    attrs:     attr_stack.iter().flatten().cloned().collect(),
                });
            }

            // Done (the function definition itself never returns)
            (vec![stmt], false)
        },
        ClassDef { methods, .. } => {
            // Recurse into all of the methods
            for m in methods {
                let old_m: Stmt = mem::take(m);
                let (mut new_m, _) = pass_stmt(old_m, attr_stack, errors);
                if new_m.len() != 1 {
                    panic!("Method statement was pruned to something else than 1 statement; this should never happen!");
                }
                *m = Box::new(new_m.pop().unwrap());
            }
            // The class definition itself never returns
            (vec![stmt], false)
        },
        Return { .. } => {
            // Clearly, a return statement always returns
            (vec![stmt], true)
        },

        If { consequent, alternative, .. } => {
            // Inspect if the consequent fully returns
            let true_returns: bool = pass_block(consequent, attr_stack, errors);
            // Inspect if the alternative returns
            let false_returns: bool = if let Some(alternative) = alternative { pass_block(alternative, attr_stack, errors) } else { false };

            // This if-statement returns if both blocks return
            (vec![stmt], true_returns && false_returns)
        },
        For { initializer, condition, increment, consequent, range, .. } => {
            let initializer: Stmt = mem::take(initializer);
            let condition: brane_dsl::ast::Expr = mem::take(condition);
            let increment: Stmt = mem::take(increment);
            let mut consequent: brane_dsl::ast::Block = mem::take(consequent);
            let range: TextRange = mem::take(range);

            // We transform this for-loop to a while-loop first

            // Step 1: Push the initializer as a previous statement (scope is already resolved, so no worries about pushing it one up).
            let mut stmts: Vec<Stmt> = Vec::with_capacity(2);
            stmts.push(initializer);

            // Step 2: Add the increment to the end of the consequent
            consequent.stmts.push(increment);

            // Step 3: Write the condition + updated consequent as a new While loop
            let while_stmt: Stmt = Stmt::While { condition, consequent: Box::new(consequent), attrs: vec![], range };

            // Step 4: Analyse as a normal while-loop (increment is not (yet) needed here)
            let (mut while_stmt, returns): (Vec<Stmt>, bool) = pass_stmt(while_stmt, attr_stack, errors);
            stmts.append(&mut while_stmt);

            // Step 5: Done
            (stmts, returns)
        },
        While { consequent, .. } => {
            // Check if the block returns
            let returns: bool = pass_block(consequent, attr_stack, errors);
            (vec![stmt], returns)
        },
        Parallel { blocks, .. } => {
            // A Parallel statement cannot return, but technically might define functions to still recurse
            for b in blocks {
                pass_block(b, attr_stack, errors);
            }

            // Done
            (vec![stmt], false)
        },

        // The rest neither recurses nor defines
        Import { .. } | LetAssign { .. } | Assign { .. } | Expr { .. } | Empty {} => (vec![stmt], false),
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in prune traversal", stmt.variant()),
    }
}





/***** LIBRARY *****/
/// Prunes the given `brane-dsl` AST for compilation.
///
/// Note that the previous traversals should all already have come to pass.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same nodes as went in, but now ready for compilation.
///
/// # Errors
/// This pass may throw multiple `AstError::PruneErrors`s if the locations could not be satisactorily deduced.
pub fn do_traversal(root: Program) -> Result<Program, Vec<AstError>> {
    let mut root = root;

    // Iterate over all statements to prune the tree
    let mut errors: Vec<Error> = vec![];
    pass_block(&mut root.block, &mut vec![], &mut errors);

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

    use super::super::print::dsl;
    use super::*;
    use crate::{CompileResult, CompileStage, compile_program_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_prune() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // Run up to this traversal
            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Prune) {
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
                    panic!("Failed to prune AST (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to prune AST (see output above)");
                },

                _ => {
                    unreachable!();
                },
            };

            // Now print the file for prettyness
            dsl::do_traversal(program, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
