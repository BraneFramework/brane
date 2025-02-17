//  ATTRIBUTES.rs
//    by Lut99
//
//  Created:
//    08 Dec 2023, 11:35:48
//  Last edited:
//    12 Dec 2023, 16:35:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a traversal that processes [`Stmt::Attribute`]s and
//!   [`Stmt::AttributeInner`]s into attribute annotations on other
//!   statement nodes.
//

use brane_dsl::ast::{Attribute, Block, Node as _, Program, Stmt};

use crate::errors::AstError;
use crate::warnings::AstWarning;
pub use crate::warnings::AttributesWarning as Warning;

/***** TRAVERSAL FUNCTIONS *****/
/// Traverses a block to process annotation statements.
///
/// # Arguments
/// - `block`: The [`Block`] to traverse.
/// - `prev_attrs`: The attributes returned by the previous statement if it was a [`Stmt::Attribute`], or else an empty vector.
/// - `warns`: A list to keep track of warnings that occur.
fn pass_block(block: &mut Block, prev_attrs: Vec<Attribute>, warns: &mut Vec<Warning>) {
    let Block { stmts, table: _, ret_type: _, attrs, range: _ } = block;

    // Set the attributes passed from the previous one
    attrs.extend(prev_attrs);

    // Simply pass its statements
    let mut next_attrs: Vec<Attribute> = vec![];
    for s in stmts.iter_mut() {
        // Pass it with this block's attribute list as parent, though
        next_attrs = pass_stmt(s, attrs, next_attrs, warns);
    }

    // Warn about final attributes not found
    for attr in next_attrs {
        warns.push(Warning::UnmatchedAttribute { range: attr.range().clone() });
    }

    // Retain only non-attribute statements
    stmts.retain(|s| !matches!(s, Stmt::Attribute(_)) && !matches!(s, Stmt::AttributeInner(_)));
}

/// Traverses a statement to process annotation statements.
///
/// # Arguments
/// - `stmt`: The [`Stmt`] to traverse.
/// - `parent_attrs`: A list of the parent attributes, updated when we find a [`Stmt::AttributeInner`].
/// - `prev_attrs`: The attributes returned by the previous statement if it was a [`Stmt::Attribute`], or else an empty vector.
/// - `warns`: A list to keep track of warnings that occur.
///
/// # Returns
/// The attributes returned by this statement if it was a [`Stmt::Attribute`], or else an empty vector.
fn pass_stmt(stmt: &mut Stmt, parent_attrs: &mut Vec<Attribute>, mut prev_attrs: Vec<Attribute>, warns: &mut Vec<Warning>) -> Vec<Attribute> {
    // Match on the statement
    use Stmt::*;
    match stmt {
        Attribute(attr) => {
            // Add the attributes as next one
            prev_attrs.push(attr.clone());
            prev_attrs
        },
        AttributeInner(attr) => {
            // Add the attributes to the parent
            parent_attrs.push(attr.clone());
            vec![]
        },

        Block { block } => {
            pass_block(block, prev_attrs, warns);
            vec![]
        },

        Import { name: _, version: _, st_funcs: _, st_classes: _, attrs, range: _ } => {
            // Set the previous attributes
            attrs.extend(prev_attrs);
            vec![]
        },
        FuncDef { ident: _, params: _, code, st_entry: _, attrs, range: _ } => {
            // Set the previous attributes
            attrs.extend(prev_attrs);

            // Traverse the body
            // Note: we pass empty because the attributes to the class have already been given
            pass_block(code, vec![], warns);
            vec![]
        },
        ClassDef { ident: _, props: _, methods, st_entry: _, symbol_table: _, attrs, range: _ } => {
            // Set the previous attributes
            attrs.extend(prev_attrs);

            // Traverse the methods
            for method in methods {
                // Note: we pass empty because the attributes to the class have already been given
                pass_stmt(method, parent_attrs, vec![], warns);
            }
            vec![]
        },
        Return { expr: _, data_type: _, output: _, attrs, range: _ } => {
            attrs.extend(prev_attrs);
            vec![]
        },

        If { cond: _, consequent, alternative, attrs, range: _ } => {
            attrs.extend(prev_attrs);

            // Pass the blocks
            pass_block(consequent, vec![], warns);
            if let Some(alternative) = alternative {
                // Note: we pass empty because the attributes to the class have already been given
                pass_block(alternative, vec![], warns);
            }
            vec![]
        },
        For { initializer: _, condition: _, increment: _, consequent, attrs, range: _ } => {
            attrs.extend(prev_attrs);
            // Note: we pass empty because the attributes to the class have already been given
            pass_block(consequent, vec![], warns);
            vec![]
        },
        While { condition: _, consequent, attrs, range: _ } => {
            attrs.extend(prev_attrs);
            // Note: we pass empty because the attributes to the class have already been given
            pass_block(consequent, vec![], warns);
            vec![]
        },
        Parallel { result: _, blocks, merge: _, st_entry: _, attrs, range: _ } => {
            attrs.extend(prev_attrs);
            for block in blocks {
                // Note: we pass empty because the attributes to the class have already been given
                pass_block(block, vec![], warns);
            }
            vec![]
        },

        LetAssign { name: _, value: _, st_entry: _, attrs, range: _ } => {
            attrs.extend(prev_attrs);
            vec![]
        },
        Assign { name: _, value: _, st_entry: _, attrs, range: _ } => {
            attrs.extend(prev_attrs);
            vec![]
        },
        Expr { expr: _, data_type: _, attrs, range: _ } => {
            attrs.extend(prev_attrs);
            vec![]
        },

        Empty {} => vec![],
    }
}





/***** LIBRARY *****/
/// Processes annotation statements into annotations on the other statements in the AST.
///
/// The goal of this traversal is to get rid of [`Stmt::Attribute`] and [`Stmt::AttributeInner`] occurrances, populating the `attrs`-field in various [`Stmt`] variants.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same nodes as went in, but now with annotation statements translated to annotations on structs.
///
/// # Errors
/// This pass may throw multiple `AstError::AttributesError`s if the user made mistakes with their variable references.
pub fn do_traversal(mut root: Program, warnings: &mut Vec<AstWarning>) -> Result<Program, Vec<AstError>> {
    // Traverse the tree, doin' all the work
    let mut warns: Vec<Warning> = vec![];
    pass_block(&mut root.block, vec![], &mut warns);

    // Process the warnings
    warnings.extend(warns.into_iter().map(AstWarning::AttributesWarning));

    // Returns the errors
    Ok(root)
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
    fn test_attributes() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Attributes) {
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
                    panic!("Failed to process attributes (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to process attributes (see output above)");
                },

                _ => {
                    unreachable!();
                },
            };

            // Now print the symbol tables for prettyness
            dsl::do_traversal(program, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
