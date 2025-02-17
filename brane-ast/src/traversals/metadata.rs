//  METADATA.rs
//    by Lut99
//
//  Created:
//    08 Dec 2023, 16:34:54
//  Last edited:
//    13 Dec 2023, 08:21:29
//  Auto updated?
//    Yes
//
//  Description:
//!   Traversal that annotates the given workflow with metadata from tags.
//

use std::collections::HashMap;

use brane_dsl::TextRange;
use brane_dsl::ast::{Attribute, Block, Expr, Literal, Metadata, Node as _, Program, Stmt};
use enum_debug::EnumDebug as _;

use crate::errors::AstError;
use crate::warnings::AstWarning;
pub use crate::warnings::MetadataWarning as Warning;


/***** HELPER FUNCTIONS *****/
/// Parses a [`Metadata`] from a given `str`.
///
/// # Arguments
/// - `raw`: The raw [`str`] to parse.
/// - `range`: A [`TextRange`] that denotes where the being-parsed string lives. This is used for debugging.
///
/// # Returns
/// A parsed [`Metadata`] struct.
///
/// # Errors
/// This function may error if we failed to parse the Metadata correctly.
fn parse_metadata(raw: &str, range: &TextRange) -> Result<Metadata, Warning> {
    // Attempt to find the separating dot
    let dot_pos: usize = match raw.find('.') {
        Some(pos) => pos,
        None => return Err(Warning::TagWithoutDot { raw: raw.into(), range: range.clone() }),
    };

    // Store it as two then
    Ok(Metadata { owner: raw[..dot_pos].into(), tag: raw[dot_pos + 1..].into() })
}

/// Searches the given attributes for `tag`/`metadata`-attributes and use that to apply metadata-tags.
///
/// # Arguments
/// - `attrs`: The list of attributes to search.
/// - `metadata`: A list of tags already in scope (and where they are defined).
/// - `is_workflow`: Whether we're collecting workflow tags or not.
/// - `warns`: A list used to keep track of occurred warns.
///
/// # Errors
/// This function may error if the current combination of attributes leads to zero possible locations.
fn process_attrs_loc_location(attrs: &[Attribute], metadata: &mut HashMap<Metadata, TextRange>, is_workflow: bool, warns: &mut Vec<Warning>) {
    for attr in attrs {
        match attr {
            Attribute::List { key, values, range } => {
                if (is_workflow
                    && (key.value == "wf_tag" || key.value == "wf_metadata" || key.value == "workflow_tag" || key.value == "workflow_metadata"))
                    || (!is_workflow && (key.value == "tag" || key.value == "metadata"))
                {
                    // Add the tag's tags to the current list
                    for value in values {
                        // Get the string value
                        let value_range: &TextRange = value.range();
                        let (value, range): (&str, TextRange) = if let Literal::String { value, range: _ } = value {
                            (value.as_str(), range.clone())
                        } else {
                            warns.push(Warning::NonStringTag { range: value.range().clone() });
                            continue;
                        };

                        // Attempt to parse into a Metadata with the dot
                        let md: Metadata = match parse_metadata(value, value_range) {
                            Ok(metadata) => metadata,
                            Err(warn) => {
                                warns.push(warn);
                                continue;
                            },
                        };

                        // Move the metadata to the thing
                        if let Some(prev) = metadata.get(&md) {
                            warns.push(Warning::DuplicateTag { prev: prev.clone(), range });
                            continue;
                        } else {
                            metadata.insert(md, range);
                        }
                    }
                }
            },

            // Ignore other attributes
            Attribute::KeyPair { .. } => {},
        }
    }
}

/// Warns users for attributes that have no effect.
///
/// # Arguments
/// - `attrs`: The list of attributes to search.
/// - `warns`: A list used to keep track of occurred warns.
fn warn_useless_attrs(attrs: &[Attribute], warns: &mut Vec<Warning>) {
    // Collect the attributes
    let mut metadata: HashMap<Metadata, TextRange> = HashMap::new();
    process_attrs_loc_location(attrs, &mut metadata, false, warns);

    // Warn
    for range in metadata.into_values() {
        warns.push(Warning::UselessTag { range });
    }
}





/***** TRAVERSAL FUNCTIONS *****/
/// Passes a [`Block`].
///
/// # Arguments
/// - `block`: The [`Block`] to traverse.
/// - `metadata`: The current metadata in scope to apply to applicable things (and where they are defined).
/// - `warns`: A list that keeps track of warnings that occurred.
fn pass_block(block: &mut Block, mut metadata: HashMap<Metadata, TextRange>, warns: &mut Vec<Warning>) {
    // Process block attributes
    process_attrs_loc_location(&block.attrs, &mut metadata, false, warns);

    // Process the statements
    for stmt in &mut block.stmts {
        pass_stmt(stmt, metadata.clone(), warns);
    }
}

/// Passes a [`Stmt`].
///
/// # Arguments
/// - `stmt`: The [`Stmt`] to traverse.
/// - `metadata`: The current metadata in scope to apply to applicable things (and where they are defined).
/// - `warns`: A list that keeps track of warnings that occurred.
fn pass_stmt(stmt: &mut Stmt, mut metadata: HashMap<Metadata, TextRange>, warns: &mut Vec<Warning>) {
    // Match on the statement
    use Stmt::*;
    match stmt {
        Block { block } => {
            pass_block(block, metadata, warns);
        },

        Import { name: _, version: _, st_classes: _, st_funcs: _, attrs, range: _ } => {
            // Remind the user metadata is useless here
            warn_useless_attrs(attrs, warns);
        },
        FuncDef { ident: _, params: _, code, st_entry: _, attrs, range: _ } => {
            // Remind the user metadata is useless here
            process_attrs_loc_location(attrs, &mut metadata, false, warns);

            // Traverse the body
            pass_block(code, metadata, warns);
        },
        ClassDef { ident: _, props: _, methods, st_entry: _, symbol_table: _, attrs, range: _ } => {
            // Remind the user metadata is useless here
            process_attrs_loc_location(attrs, &mut metadata, false, warns);
            // Traverse the methods
            for method in methods {
                pass_stmt(method, metadata.clone(), warns);
            }
        },
        Return { expr, data_type: _, output: _, attrs, range: _ } => {
            // Traverse into the expression if there is any
            if let Some(expr) = expr {
                process_attrs_loc_location(attrs, &mut metadata, false, warns);
                pass_expr(expr, &metadata, warns);
            }
        },

        If { cond, consequent, alternative, attrs, range: _ } => {
            // Process attributes for the expression
            process_attrs_loc_location(attrs, &mut metadata, false, warns);

            // Traverse into the expression, then bodies
            pass_expr(cond, &metadata, warns);
            pass_block(consequent, metadata.clone(), warns);
            if let Some(alternative) = alternative {
                pass_block(alternative, metadata, warns);
            }
        },
        For { initializer, condition, increment, consequent, attrs, range: _ } => {
            // Process attributes for the expression
            process_attrs_loc_location(attrs, &mut metadata, false, warns);

            // Traverse into the expressions, then bodies
            pass_stmt(initializer, metadata.clone(), warns);
            pass_expr(condition, &metadata, warns);
            pass_stmt(increment, metadata.clone(), warns);
            pass_block(consequent, metadata, warns);
        },
        While { condition, consequent, attrs, range: _ } => {
            // Process attributes for the expression
            process_attrs_loc_location(attrs, &mut metadata, false, warns);

            // Traverse into the expressions, then bodies
            pass_expr(condition, &metadata, warns);
            pass_block(consequent, metadata, warns);
        },
        Parallel { result: _, blocks, merge: _, st_entry: _, attrs, range: _ } => {
            // Process attributes for the expression
            process_attrs_loc_location(attrs, &mut metadata, false, warns);

            // Traverse into the bodies
            for block in blocks {
                pass_block(block, metadata.clone(), warns);
            }
        },

        LetAssign { name: _, value, st_entry: _, attrs, range: _ } => {
            // Process attributes for the expression
            process_attrs_loc_location(attrs, &mut metadata, false, warns);
            // Process the expression
            pass_expr(value, &metadata, warns);
        },
        Assign { name: _, value, st_entry: _, attrs, range: _ } => {
            // Process attributes for the expression
            process_attrs_loc_location(attrs, &mut metadata, false, warns);
            // Process the expression
            pass_expr(value, &metadata, warns);
        },
        Expr { expr, data_type: _, attrs, range: _ } => {
            // Process attributes for the expression
            process_attrs_loc_location(attrs, &mut metadata, false, warns);
            // Process the expression
            pass_expr(expr, &metadata, warns);
        },

        Empty {} => {},
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in metadata traversal", stmt.variant()),
    }
}

/// Passes an [`Expr`].
///
/// # Arguments
/// - `expr`: The [`Expr`] to traverse.
/// - `metadata`: The current metadata in scope to apply to applicable things (and where they are defined).
/// - `warns`: A list that keeps track of warnings that occurred.
fn pass_expr(expr: &mut Expr, metadata: &HashMap<Metadata, TextRange>, _warns: &mut Vec<Warning>) {
    // Match on the expression
    use Expr::*;
    match expr {
        Cast { expr, target: _, range: _ } => pass_expr(expr, metadata, _warns),

        Call { expr, args, st_entry, locations: _, input: _, result: _, metadata: call_metadata, range: _ } => {
            // Examine if it's an external call
            if st_entry.as_ref().map(|entry| entry.borrow().package_name.is_some()).unwrap_or(false) {
                call_metadata.extend(metadata.keys().cloned());
            }

            // Otherwise, recurse into the expressions
            pass_expr(expr, metadata, _warns);
            for arg in args {
                pass_expr(arg, metadata, _warns);
            }
        },
        Array { values, data_type: _, range: _ } => {
            for value in values {
                pass_expr(value, metadata, _warns);
            }
        },
        ArrayIndex { array, index, data_type: _, range: _ } => {
            pass_expr(array, metadata, _warns);
            pass_expr(index, metadata, _warns);
        },

        UnaOp { op: _, expr, range: _ } => pass_expr(expr, metadata, _warns),
        BinOp { op: _, lhs, rhs, range: _ } => {
            pass_expr(lhs, metadata, _warns);
            pass_expr(rhs, metadata, _warns);
        },
        Proj { lhs, rhs, st_entry: _, range: _ } => {
            pass_expr(lhs, metadata, _warns);
            pass_expr(rhs, metadata, _warns);
        },

        Instance { name: _, properties, st_entry: _, range: _ } => {
            for prop in properties {
                pass_expr(&mut prop.value, metadata, _warns);
            }
        },

        // The rest has no chance of hosting a call
        Pattern { .. } | VarRef { .. } | Identifier { .. } | Literal { .. } | Empty {} => {},
    }
}





/***** LIBRARY *****/
/// Processes `#[tag(...)]`/`#[metadata(...)]`-annotations into annotations on various things in the AST.
///
/// The goal of this traversal is to populate `metadata`-fields in various AST elements.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same nodes as went in, but now with annotation statements translated to annotations on structs.
///
/// # Errors
/// This pass may throw multiple `AstError::MetadataError`s if the user made mistakes with their variable references.
pub fn do_traversal(mut root: Program, warnings: &mut Vec<AstWarning>) -> Result<Program, Vec<AstError>> {
    let mut warns: Vec<Warning> = vec![];

    // Apply the program attributes to the program metadata
    let mut root_metadata: HashMap<Metadata, TextRange> = HashMap::new();
    process_attrs_loc_location(&root.block.attrs, &mut root_metadata, true, &mut warns);
    root.metadata = root_metadata.into_keys().collect();

    // Traverse the tree, doin' all the work
    pass_block(&mut root.block, HashMap::new(), &mut warns);

    // Process the warnings
    warnings.extend(warns.into_iter().map(AstWarning::MetadataWarning));

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
    fn test_metadata() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Metadata) {
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
                    panic!("Failed to process tags (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to process tags (see output above)");
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
