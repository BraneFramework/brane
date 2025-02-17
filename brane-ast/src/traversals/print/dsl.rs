//  DSL.rs
//    by Lut99
//
//  Created:
//    18 Aug 2022, 13:46:22
//  Last edited:
//    12 Dec 2023, 14:57:30
//  Auto updated?
//    Yes
//
//  Description:
//!   Prints the `brane-dsl` AST in BraneScript-like Syntax.
//

use std::io::Write;

use brane_dsl::ast::{self as dsl_ast, Attribute, Block, Expr, Identifier, Literal, Program, Property, PropertyExpr, Stmt};
use brane_dsl::location::AllowedLocations;

pub use crate::errors::AstError as Error;





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





/***** TRAVERSAL FUNCTIONS *****/
/// Prints a Stmt node.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `stmt`: The Stmt to traverse.
/// - `indent`: The current base indent of all new lines to write.
///
/// # Returns
/// Nothing, but does print it.
pub fn pass_stmt(writer: &mut impl Write, stmt: &Stmt, indent: usize) -> std::io::Result<()> {
    // Match on the statement itself
    use Stmt::*;
    match stmt {
        Attribute(attr) => {
            // Print the attribute
            pass_attr(writer, attr, false, indent)?;
        },
        AttributeInner(attr) => {
            // Print the attribute
            pass_attr(writer, attr, true, indent)?;
        },

        Block { block } => {
            // Pass over the block instead, but do print the indentation first.
            write!(writer, "{}", indent!(indent))?;
            pass_block(writer, block, indent)?;
            writeln!(writer)?;
        },

        Import { name, version, st_funcs: _, st_classes: _, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // Print as an import statement
            write!(writer, "{}import ", indent!(indent))?;
            // Print the identifier
            pass_identifier(writer, name)?;
            // Print the version, optionally
            if let Literal::Semver { range, .. } = &version {
                if range.is_some() {
                    write!(writer, "[")?;
                    pass_literal(writer, version)?;
                    write!(writer, "]")?;
                }
            } else {
                panic!("Got a non-Semver Literal '{version:?}' in an import statement; this should never happen!");
            }
            // Do newline
            writeln!(writer)?;
        },
        FuncDef { ident, params, code, st_entry: _, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // Print the 'func' prefix
            write!(writer, "{}func ", indent!(indent))?;
            // Print the identifier
            pass_identifier(writer, ident)?;
            // Print the parameters
            write!(writer, "(")?;
            let mut first = true;
            for p in params {
                if first {
                    first = false;
                } else {
                    write!(writer, ", ")?;
                }
                pass_identifier(writer, p)?;
            }
            // Print the block
            write!(writer, ") ")?;
            pass_block(writer, code, indent)?;
            writeln!(writer)?;
        },
        ClassDef { ident, props, methods, st_entry: _, symbol_table: _, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // Print the 'class' prefix
            write!(writer, "{}class ", indent!(indent))?;
            // Print the identifier
            pass_identifier(writer, ident)?;
            // Print the class opening
            writeln!(writer, " {{")?;
            // Print the properties
            let largest_prop: usize = props.iter().map(|p| p.name.value.len()).max().unwrap_or(0);
            for p in props {
                pass_property(writer, p, largest_prop, indent + 3)?;
            }
            // Print a newline if any properties have been written
            if !props.is_empty() {
                writeln!(writer)?;
            }
            // Print the methods
            for m in methods {
                pass_stmt(writer, m, indent + 3)?;
            }
            // Finally, print the closing bracket
            writeln!(writer, "{}}}", indent!(indent))?;
        },
        Return { expr, data_type: _, output: _, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // Print the return
            write!(writer, "{}return", indent!(indent))?;
            // If there is an expression, print it
            if let Some(expr) = expr {
                write!(writer, " ")?;
                pass_expr(writer, expr, indent)?;
            }
            // Print the semicolon
            writeln!(writer, ";")?;
        },

        If { cond, consequent, alternative, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }
            // Print the if first + its condition
            write!(writer, "{}if (", indent!(indent))?;
            pass_expr(writer, cond, indent)?;
            write!(writer, ") ")?;
            // Print the if-block
            pass_block(writer, consequent, indent)?;
            // If there is an else, do that
            if let Some(alternative) = alternative {
                write!(writer, " else ")?;
                pass_block(writer, alternative, indent)?;
            }
            writeln!(writer)?;
        },
        For { initializer, condition, increment, consequent, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }
            // Print the three for parts
            write!(writer, "{}for (", indent!(indent))?;
            pass_stmt(writer, initializer, indent)?;
            write!(writer, " ")?;
            pass_expr(writer, condition, indent)?;
            write!(writer, "; ")?;
            pass_stmt(writer, increment, indent)?;
            write!(writer, ") ")?;
            // Print the block
            pass_block(writer, consequent, indent)?;
            writeln!(writer)?;
        },
        While { condition, consequent, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }
            // Print the while + its condition
            write!(writer, "{}while (", indent!(indent))?;
            pass_expr(writer, condition, indent)?;
            write!(writer, ") ")?;
            // Print the block
            pass_block(writer, consequent, indent)?;
            writeln!(writer)?;
        },
        Parallel { result, blocks, merge: _, st_entry: _, attrs, range: _ } => {
            // Print the statement's attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // If there is a result, parse that first
            write!(writer, "{}", indent!(indent))?;
            if let Some(result) = result {
                write!(writer, "let ")?;
                pass_identifier(writer, result)?;
                write!(writer, " = ")?;
            }
            // Print the parallel thingy
            writeln!(writer, "parallel [")?;
            // Print the blocks
            for b in blocks {
                // Pass over the block instead, but do print the indentation first.
                write!(writer, "{}", indent!(indent + INDENT_SIZE))?;
                pass_block(writer, b, indent)?;
                writeln!(writer)?;
            }
            writeln!(writer, "{}]", indent!(indent))?;
        },

        LetAssign { name, value, st_entry: _, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // Print the let thingy first + the name
            write!(writer, "{}let ", indent!(indent))?;
            pass_identifier(writer, name)?;
            // Print the expression
            write!(writer, " := ")?;
            pass_expr(writer, value, indent)?;
            writeln!(writer, ";")?;
        },
        Assign { name, value, st_entry: _, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // Just print the identifier
            write!(writer, "{}", indent!(indent))?;
            pass_identifier(writer, name)?;
            // Print the expression
            write!(writer, " := ")?;
            pass_expr(writer, value, indent)?;
            writeln!(writer, ";")?;
        },
        Expr { expr, data_type: _, attrs, range: _ } => {
            // Print the attributes
            for attr in attrs {
                pass_attr(writer, attr, false, indent)?;
            }

            // Print the expression + semicolon
            write!(writer, "{}", indent!(indent))?;
            pass_expr(writer, expr, indent)?;
            writeln!(writer, ";")?;
        },

        Empty {} => {},
    }

    // Done
    Ok(())
}

/// Prints an attribute.
///
/// # Arguments
/// - `writer`: The [`Write`]r to write to.
/// - `attr`: The [`Attribute`] to traverse.
/// - `is_inner`: If true, prints as an inner attribute (i.e., `#![...]` instead of `#[...]`).
/// - `indent`: The current base indentation of all new lines to write.
///
/// # Errors
/// This function may error if we failed to write to `writer`.
pub fn pass_attr(writer: &mut impl Write, attr: &Attribute, is_inner: bool, indent: usize) -> std::io::Result<()> {
    // Print the preceding tokens
    write!(writer, "{}#{}[", indent!(indent), if is_inner { "!" } else { "" })?;
    // Print the attribute value
    match attr {
        Attribute::KeyPair { key, value, range: _ } => {
            pass_identifier(writer, key)?;
            write!(writer, " = ")?;
            pass_literal(writer, value)?;
        },
        Attribute::List { key, values, range: _ } => {
            pass_identifier(writer, key)?;
            write!(writer, "(")?;
            let mut first: bool = true;
            for value in values {
                if first {
                    first = false;
                } else {
                    write!(writer, ", ")?;
                }
                pass_literal(writer, value)?;
            }
            write!(writer, ")")?;
        },
    }
    // Print the suffixing tokens
    writeln!(writer, "]")?;

    // Done!
    Ok(())
}

/// Prints a Block node.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `block`: The Block to traverse.
/// - `indent`: The current base indent of all new lines to write.
///
/// # Returns
/// Nothing, but does print it.
pub fn pass_block(writer: &mut impl Write, block: &Block, indent: usize) -> std::io::Result<()> {
    // Print the curly bracket (no indent used, since it's expression position)
    writeln!(writer, "{{")?;

    // Write the block's attributes as inner ones
    for attr in &block.attrs {
        pass_attr(writer, attr, true, indent + INDENT_SIZE)?;
    }

    // Print all statements with extra indent
    for s in block.stmts.iter() {
        pass_stmt(writer, s, indent + INDENT_SIZE)?;
    }

    // Print the closing curly bracket
    write!(writer, "{}}}", indent!(indent))?;

    // Done
    Ok(())
}

/// Prints an Identifier node.
///
/// This will always be printed as a non-statement, so no indentation required.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `identifier`: The Identifier to traverse.
///
/// # Returns
/// Nothing, but does print it.
pub fn pass_identifier(writer: &mut impl Write, identifier: &Identifier) -> std::io::Result<()> {
    // Print the full value
    write!(writer, "{}", identifier.value)
}

/// Prints a Property node.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `prop`: The Property to traverse.
/// - `largest_prop`: The longest property name. It will auto-pad all names to this length to make a nice list.
/// - `indent`: The current base indent of all new lines to write.
///
/// # Returns
/// Nothing, but does print it.
pub fn pass_property(writer: &mut impl Write, prop: &Property, largest_prop: usize, indent: usize) -> std::io::Result<()> {
    // Print the identation, then the name identifier
    write!(writer, "{}", indent!(indent))?;
    pass_identifier(writer, &prop.name)?;
    // Print the colon, then the data type
    writeln!(writer, "{} : {};", indent!(largest_prop - prop.name.value.len()), prop.data_type)?;

    // Done
    Ok(())
}

/// Prints an Expr node.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `expr`: The Expr to traverse.
/// - `indent`: The current base indent of all new lines to write.
///
/// # Returns
/// Nothing, but does print it.
pub fn pass_expr(writer: &mut impl Write, expr: &Expr, indent: usize) -> std::io::Result<()> {
    // Match the expression
    use Expr::*;
    match expr {
        Cast { expr, target, .. } => {
            // Print the cast operator
            write!(writer, "(({target}) ")?;
            // Print the expression
            pass_expr(writer, expr, indent)?;
            // Print the closing bracket
            write!(writer, ")")?;
        },

        Call { expr, args, st_entry: _, locations, input: _, result: _, metadata, range: _ } => {
            // Print the identifying expression
            pass_expr(writer, expr, indent)?;
            // Print the arguments
            write!(writer, "(")?;
            let mut first = true;
            for a in args {
                if first {
                    first = false;
                } else {
                    write!(writer, ", ")?;
                }
                pass_expr(writer, a, indent)?;
            }
            // Print the closing bracket
            write!(writer, ")")?;

            // Print locations
            if let AllowedLocations::Exclusive(locs) = locations {
                write!(writer, " @[{}]", locs.iter().map(|l| l.into()).collect::<Vec<String>>().join(","))?;
            }
            // Print metadata
            if !metadata.is_empty() {
                write!(
                    writer,
                    " <{}>",
                    metadata
                        .iter()
                        .map(|md| format!(
                            "#{}.{}",
                            if md.owner.contains(' ') { format!("\"{}\"", md.owner) } else { md.owner.clone() },
                            if md.tag.contains(' ') { format!("\"{}\"", md.tag) } else { md.tag.clone() }
                        ))
                        .collect::<Vec<String>>()
                        .join(" ")
                )?;
            }
        },
        Array { values, .. } => {
            // Print the values wrapped in '[]'
            write!(writer, "[")?;
            let mut first = true;
            for v in values {
                if first {
                    first = false;
                } else {
                    write!(writer, ", ")?;
                }
                pass_expr(writer, v, indent)?;
            }
            write!(writer, "]")?;
        },
        ArrayIndex { array, index, .. } => {
            // Print the array first
            pass_expr(writer, array, indent)?;
            // Print the index expression wrapped in '[]'
            write!(writer, "[")?;
            pass_expr(writer, index, indent)?;
            write!(writer, "]")?;
        },
        Pattern { exprs, .. } => {
            // We use ad-hoc syntax for now
            write!(writer, "Pattern<")?;
            let mut first = true;
            for e in exprs {
                if first {
                    first = false;
                } else {
                    write!(writer, ", ")?;
                }
                pass_expr(writer, e, indent)?;
            }
            write!(writer, ">")?;
        },

        UnaOp { op, expr, .. } => {
            // How to print exact is operator-determined
            match op {
                dsl_ast::UnaOp::Idx { .. } => {
                    // Print the expr expression wrapped in '[]'
                    write!(writer, "[")?;
                    pass_expr(writer, expr, indent)?;
                    write!(writer, "]")?;
                },
                dsl_ast::UnaOp::Not { .. } => {
                    // Print the logical negation, then the expression
                    write!(writer, "(!")?;
                    pass_expr(writer, expr, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::UnaOp::Neg { .. } => {
                    // Print the mathmatical negation, then the expression
                    write!(writer, "(-")?;
                    pass_expr(writer, expr, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::UnaOp::Prio { .. } => {
                    // Print simply in between brackets
                    write!(writer, "(")?;
                    pass_expr(writer, expr, indent)?;
                    write!(writer, ")")?;
                },
            }
        },
        BinOp { op, lhs, rhs, .. } => {
            // How to print exact is operator-determined
            match op {
                dsl_ast::BinOp::And { .. } => {
                    // Print lhs && rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " && ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Or { .. } => {
                    // Print lhs || rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " || ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },

                dsl_ast::BinOp::Add { .. } => {
                    // Print lhs + rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " + ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Sub { .. } => {
                    // Print lhs - rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " - ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Mul { .. } => {
                    // Print lhs * rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " * ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Div { .. } => {
                    // Print lhs / rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " / ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Mod { .. } => {
                    // Print lhs % rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " % ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },

                dsl_ast::BinOp::Eq { .. } => {
                    // Print lhs == rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " == ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Ne { .. } => {
                    // Print lhs != rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " != ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Lt { .. } => {
                    // Print lhs < rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " < ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Le { .. } => {
                    // Print lhs <= rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " <= ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Gt { .. } => {
                    // Print lhs > rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " > ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                dsl_ast::BinOp::Ge { .. } => {
                    // Print lhs >= rhs
                    write!(writer, "(")?;
                    pass_expr(writer, lhs, indent)?;
                    write!(writer, " >= ")?;
                    pass_expr(writer, rhs, indent)?;
                    write!(writer, ")")?;
                },
                // dsl_ast::BinOp::Proj{ .. } => {
                //     // Print lhs.rhs
                //     write!(writer, "(")?;
                //     pass_expr(writer, lhs, indent)?;
                //     write!(writer, ".")?;
                //     pass_expr(writer, rhs, indent)?;
                //     write!(writer, ")")?;
                // },
            }
        },
        Proj { lhs, rhs, .. } => {
            // Print lhs.rhs
            pass_expr(writer, lhs, indent)?;
            write!(writer, ".")?;
            pass_expr(writer, rhs, indent)?;
        },

        Instance { name, properties, .. } => {
            // Print 'new Name'
            write!(writer, "new ")?;
            pass_identifier(writer, name)?;
            // Print the body
            writeln!(writer, " {{")?;
            let largest_prop: usize = properties.iter().map(|p| p.name.value.len()).max().unwrap_or(0);
            for p in properties {
                // Print the proprerty name followed by its value
                pass_property_expr(writer, p, largest_prop, indent + 3)?;
            }
            // Print the closing thingy
            write!(writer, "{}}}", indent!(indent))?;
        },
        VarRef { name, .. } => {
            // Print the identifier
            pass_identifier(writer, name)?;
        },
        Identifier { name, .. } => {
            // Print the identifier
            pass_identifier(writer, name)?;
        },
        Literal { literal } => {
            // Print the literal
            pass_literal(writer, literal)?;
        },

        Empty {} => {},
    }

    // Done
    Ok(())
}

/// Prints a PropertyExpr node.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `prop`: The PropertyExpr to traverse.
/// - `largest_prop`: The longest property name. It will auto-pad all names to this length to make a nice list.
///
/// # Returns
/// Nothing, but does print it.
pub fn pass_property_expr(writer: &mut impl Write, prop: &PropertyExpr, largest_prop: usize, indent: usize) -> std::io::Result<()> {
    // Print the identation, then the name identifier
    write!(writer, "{}", indent!(indent))?;
    pass_identifier(writer, &prop.name)?;
    // Print the colon, then the expression
    write!(writer, "{} : ", indent!(largest_prop - prop.name.value.len()))?;
    pass_expr(writer, &prop.value, indent + 3)?;
    // Finally print the comma
    writeln!(writer, ",")?;

    // Done
    Ok(())
}

/// Prints a Literal node.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `literal`: The Literal to traverse.
///
/// # Returns
/// Nothing, but does print it.
pub fn pass_literal(writer: &mut impl Write, literal: &Literal) -> std::io::Result<()> {
    // Match on the exact literal kind
    use Literal::*;
    match literal {
        Null { .. } => {
            write!(writer, "null")?;
        },
        Boolean { value, .. } => {
            write!(writer, "{}", if *value { "true" } else { "false" })?;
        },
        Integer { value, .. } => {
            write!(writer, "{}", *value)?;
        },
        Real { value, .. } => {
            write!(writer, "{}", *value)?;
        },
        String { value, .. } => {
            write!(writer, "\"{value}\"")?;
        },
        Semver { value, .. } => {
            write!(writer, "{value}")?;
        },
        Void { .. } => {
            write!(writer, "<void>")?;
        },
    }

    // Done
    Ok(())
}





/***** LIBRARY *****/
/// Starts printing the root of the AST (i.e., a series of statements).
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
/// - `writer`: The `Write`r to write to.
///
/// # Returns
/// The same root node as went in (since this compiler pass performs no transformations on the tree).
///
/// # Errors
/// This pass doesn't really error, but is here for convention purposes.
pub fn do_traversal(root: Program, mut writer: impl Write) -> Result<Program, Vec<Error>> {
    // Write the metadata
    if let Err(err) = writeln!(
        &mut writer,
        "{}\n",
        root.metadata
            .iter()
            .map(|md| format!(
                "#{}.{}",
                if md.owner.contains(' ') { format!("\"{}\"", md.owner) } else { md.owner.clone() },
                if md.tag.contains(' ') { format!("\"{}\"", md.tag) } else { md.tag.clone() }
            ))
            .collect::<Vec<String>>()
            .join(" ")
    ) {
        return Err(vec![Error::WriteError { err }]);
    }
    // Write the attributes
    for a in &root.block.attrs {
        if let Err(err) = pass_attr(&mut writer, a, true, 0) {
            return Err(vec![Error::WriteError { err }]);
        }
    }
    if let Err(err) = writeln!(&mut writer) {
        return Err(vec![Error::WriteError { err }]);
    }
    // Iterate over all statements and run the appropriate match
    for s in &root.block.stmts {
        if let Err(err) = pass_stmt(&mut writer, s, 0) {
            return Err(vec![Error::WriteError { err }]);
        }
    }

    // Done
    Ok(root)
}


/***** TESTS *****/
#[cfg(test)]
pub mod tests {
    use brane_dsl::ParserOptions;
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::*;
    use crate::{CompileResult, CompileStage, compile_program_to};


    /// 'Tests' the traversal by printing the AST for every node.
    #[test]
    fn test_print() {
        test_on_dsl_files("BraneScript", |path, code| {
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // Run up to this traversal
            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::None) {
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
                    panic!("Failed to parse file (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to parse file (see output above)");
                },

                _ => {
                    unreachable!();
                },
            };

            // Now print the tree
            do_traversal(program, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
