//  LOCATION.rs
//    by Lut99
//
//  Created:
//    05 Sep 2022, 16:27:08
//  Last edited:
//    08 Dec 2023, 17:16:27
//  Auto updated?
//    Yes
//
//  Description:
//!   Resolves the extra location restrictions that on-structures impose.
//!
//!   Note that this traversal is actually only here in a deprecated fashion.
//

use std::collections::HashSet;

use brane_dsl::TextRange;
use brane_dsl::ast::{Attribute, Block, Expr, Literal, Node, Program, Stmt};
use brane_dsl::location::{AllowedLocations, Location};
use enum_debug::EnumDebug as _;

use crate::errors::AstError;
pub use crate::errors::LocationError as Error;


/***** HELPER FUNCTIONS *****/
/// Searches the given attributes for `loc`/`location`-attributes and use that to scope the given [`AllowedLocations`].
///
/// # Arguments
/// - `attrs`: The list of attributes to search.
/// - `locations`: The [`AllowedLocations`] list to scope down.
/// - `reasons`: A trail of [`TextRange`]s that is used to point to all attributes leading to the current (faultive) scope.
/// - `errors`: A list used to keep track of occurred errors.
///
/// # Errors
/// This function may error if the current combination of attributes leads to zero possible locations.
fn process_attrs_loc_location(attrs: &[Attribute], locations: &mut AllowedLocations, reasons: &mut Vec<TextRange>, errors: &mut Vec<Error>) {
    for attr in attrs {
        match attr {
            Attribute::List { key, values, range } => {
                if key.value == "on" || key.value == "loc" || key.value == "location" {
                    // Keep track of where this lives for errors
                    reasons.push(range.clone());

                    // Assert the values a literals
                    let locs: HashSet<Location> = values
                        .iter()
                        .filter_map(|value| {
                            if let Literal::String { value, range: _ } = value {
                                Some(Location::from(value.clone()))
                            } else {
                                errors.push(Error::IllegalLocation { range: value.range().clone() });
                                None
                            }
                        })
                        .collect();

                    // Compute the intersection with the existing one
                    locations.intersection(&mut AllowedLocations::Exclusive(locs));
                    if locations.is_empty() {
                        errors.push(Error::OnNoLocation { range: range.clone(), reasons: reasons.clone() });
                        return;
                    }
                }
            },

            // Ignore other attributes
            Attribute::KeyPair { .. } => {},
        }
    }
}





/***** TRAVERSAL FUNCTIONS *****/
/// Attempts to resolve the location restrictions of all function calls in this Stmt.
///
/// # Arguments
/// - `stmt`: The Stmt to traverse.
/// - `locations`: The current restriction of locations as imposed by the on-structs.
/// - `reasons`: The ranges of the on-structs that somehow restrict the current call.
/// - `errors`: A list we use to accumulate errors as they occur.
///
/// # Errors
/// This function may error if there were semantic problems while resolving the locations.
///
/// If errors occur, they are appended to the `errors` list. The function is early-quit in that case.
fn pass_stmt(stmt: &mut Stmt, mut locations: AllowedLocations, mut reasons: Vec<TextRange>, errors: &mut Vec<Error>) {
    // Match on the exact statement
    use Stmt::*;
    #[allow(clippy::collapsible_match)]
    match stmt {
        Block { block } => {
            pass_block(block, locations, reasons, errors);
        },

        FuncDef { ident: _, params: _, code, st_entry: _, attrs, range: _ } => {
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);
            pass_block(code, locations, reasons, errors);
        },
        ClassDef { ident: _, props: _, methods, st_entry: _, symbol_table: _, attrs, range: _ } => {
            // Analyse the attributes for location scopes
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);

            // Apply to method bodies
            for m in methods {
                pass_stmt(m, locations.clone(), reasons.clone(), errors);
            }
        },
        Return { expr, data_type: _, output: _, attrs, range: _ } => {
            if let Some(expr) = expr {
                process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);
                pass_expr(expr, locations, reasons, errors);
            }
        },

        If { cond, consequent, alternative, attrs, range: _ } => {
            // Apply attributes
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);

            // Pass everything in this statement
            pass_expr(cond, locations.clone(), reasons.clone(), errors);
            pass_block(consequent, locations.clone(), reasons.clone(), errors);
            if let Some(alternative) = alternative {
                pass_block(alternative, locations, reasons, errors)
            };
        },
        For { initializer, condition, increment, consequent, attrs, range: _ } => {
            // Apply attributes
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);

            // Pass everything in this statement
            pass_stmt(initializer, locations.clone(), reasons.clone(), errors);
            pass_expr(condition, locations.clone(), reasons.clone(), errors);
            pass_stmt(increment, locations.clone(), reasons.clone(), errors);
            pass_block(consequent, locations, reasons, errors);
        },
        While { condition, consequent, attrs, range: _ } => {
            // Apply attributes
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);

            // Pass everything in this statement
            pass_expr(condition, locations.clone(), reasons.clone(), errors);
            pass_block(consequent, locations, reasons, errors);
        },
        Parallel { blocks, merge: _, result: _, st_entry: _, attrs, range: _ } => {
            // Apply attributes
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);

            // Pass everything in this statement
            for b in blocks {
                pass_block(b, locations.clone(), reasons.clone(), errors);
            }
        },

        LetAssign { value, name: _, st_entry: _, attrs, range: _ } => {
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);
            pass_expr(value, locations, reasons, errors);
        },
        Assign { name: _, value, st_entry: _, attrs, range: _ } => {
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);
            pass_expr(value, locations, reasons, errors);
        },
        Expr { expr, data_type: _, attrs, range: _ } => {
            process_attrs_loc_location(attrs, &mut locations, &mut reasons, errors);
            pass_expr(expr, locations, reasons, errors);
        },

        // The rest no matter
        Import { .. } | Empty { .. } => {},
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in location traversal", stmt.variant()),
    };
}

/// Attempts to resolve the location restrictions of all function calls in this Block.
///
/// # Arguments
/// - `block`: The Block to traverse.
/// - `locations`: The current restriction of locations as imposed by the on-structs.
/// - `reasons`: The ranges of the on-structs that somehow restrict the current call.
/// - `errors`: A list we use to accumulate errors as they occur.
///
/// # Errors
/// This function may error if there were semantic problems while resolving the locations.
///
/// If errors occur, they are appended to the `errors` list. The function is early-quit in that case.
fn pass_block(block: &mut Block, mut locations: AllowedLocations, mut reasons: Vec<TextRange>, errors: &mut Vec<Error>) {
    // Inspect if the block has annotations about the location
    process_attrs_loc_location(&block.attrs, &mut locations, &mut reasons, errors);

    // Then recurse into the statements with the location restrictions
    for s in &mut block.stmts {
        pass_stmt(s, locations.clone(), reasons.clone(), errors);
    }
}

/// Attempts to resolve the location restrictions of all function calls in this Expr.
///
/// # Arguments
/// - `expr`: The Expr to traverse.
/// - `on_locations`: The current restriction of locations as imposed by the on-structs.
/// - `on_reasons`: The ranges of the on-structs that somehow restrict the current call.
/// - `errors`: A list we use to accumulate errors as they occur.
///
/// # Returns
/// This function returns the restrictions of the expression as a whole, together with a list of sources for that restriction. This only applies to calls within it, but is necessary for parent calls to know about.
///
/// # Errors
/// This function may error if there were semantic problems while resolving the locations.
///
/// If errors occur, they are appended to the `errors` list. The function is early-quit in that case.
fn pass_expr(expr: &mut Expr, on_locations: AllowedLocations, on_reasons: Vec<TextRange>, errors: &mut Vec<Error>) {
    use Expr::*;
    match expr {
        Cast { expr, .. } => {
            pass_expr(expr, on_locations, on_reasons, errors);
        },

        Call { expr, args, ref mut locations, range, .. } => {
            // Resolve the nested stuff first
            pass_expr(expr, on_locations.clone(), on_reasons.clone(), errors);
            for a in args {
                pass_expr(a, on_locations.clone(), on_reasons.clone(), errors);
            }

            // Add the current location if it added to the restriction
            let mut on_reasons: Vec<TextRange> = on_reasons;
            if locations.is_exclusive() {
                on_reasons.push(range.clone());
            }

            // Take the union of the already imposed restrictions + those imposed by On-blocks
            let mut on_locations: AllowedLocations = on_locations;
            locations.intersection(&mut on_locations);
            if locations.is_empty() {
                errors.push(Error::NoLocation { range: range.clone(), reasons: on_reasons });
            }
        },
        Array { values, .. } => {
            for v in values {
                pass_expr(v, on_locations.clone(), on_reasons.clone(), errors);
            }
        },
        ArrayIndex { array, index, .. } => {
            pass_expr(array, on_locations.clone(), on_reasons.clone(), errors);
            pass_expr(index, on_locations, on_reasons, errors);
        },

        UnaOp { expr, .. } => {
            pass_expr(expr, on_locations, on_reasons, errors);
        },
        BinOp { lhs, rhs, .. } => {
            pass_expr(lhs, on_locations.clone(), on_reasons.clone(), errors);
            pass_expr(rhs, on_locations, on_reasons, errors);
        },
        Proj { lhs, rhs, .. } => {
            pass_expr(lhs, on_locations.clone(), on_reasons.clone(), errors);
            pass_expr(rhs, on_locations, on_reasons, errors);
        },

        Instance { properties, .. } => {
            for p in properties {
                pass_expr(&mut p.value, on_locations.clone(), on_reasons.clone(), errors);
            }
        },

        // The rest we don't care
        _ => {},
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
///
/// # Returns
/// The same nodes as went in, but now with no unresolved types.
///
/// # Errors
/// This pass may throw multiple `AstError::ResolveError`s if the user made mistakes with their variable references.
pub fn do_traversal(root: Program) -> Result<Program, Vec<AstError>> {
    let mut root = root;

    // Iterate over all statements to build their symbol tables (if relevant)
    let mut errors: Vec<Error> = vec![];
    pass_block(&mut root.block, AllowedLocations::All, vec![], &mut errors);

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
    fn test_location() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // Run up to this traversal
            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Location) {
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

            // Now print the file for prettyness
            dsl::do_traversal(program, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
