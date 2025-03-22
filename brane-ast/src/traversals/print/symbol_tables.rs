//  SYMBOL TABLES.rs
//    by Lut99
//
//  Created:
//    19 Aug 2022, 12:43:19
//  Last edited:
//    08 Dec 2023, 11:06:12
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a traversal that prints all symbol tables neatly for a
//!   given program.
//

use std::cell::{Ref, RefCell};
use std::io::Write;
use std::rc::Rc;

use brane_dsl::SymbolTable;
use brane_dsl::ast::{Block, Program, Stmt};
use brane_dsl::symbol_table::{ClassEntry, FunctionEntry, VarEntry};

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
fn pass_stmt(writer: &mut impl Write, stmt: &Stmt, indent: usize) -> std::io::Result<()> {
    // Match on the statement itself
    use Stmt::*;
    match stmt {
        Block { block } => {
            // Simply print this one's symbol table
            write!(writer, "{}__nested_block: ", indent!(indent))?;
            pass_block(writer, block, indent)?;
            writeln!(writer)?;
        },

        FuncDef { ident, code, .. } => {
            // Print the code block's symbol table
            write!(writer, "{}Function '{}': ", indent!(indent), ident.value)?;
            pass_block(writer, code, indent)?;
            writeln!(writer)?;
        },
        ClassDef { methods, .. } => {
            // Recurse into the methods
            for m in methods.iter() {
                pass_stmt(writer, m, indent)?;
            }
        },

        If { consequent, alternative, .. } => {
            // Print the symbol tables of the consequent and (optionally) the alternative
            write!(writer, "{}If ", indent!(indent))?;
            pass_block(writer, consequent, indent)?;
            if let Some(alternative) = alternative {
                write!(writer, " Else ")?;
                pass_block(writer, alternative, indent)?;
            }
            writeln!(writer)?;
        },
        For { consequent, .. } => {
            // Print the symbol table of the consequent
            write!(writer, "{}For ", indent!(indent))?;
            pass_block(writer, consequent, indent)?;
            writeln!(writer)?;
        },
        While { consequent, .. } => {
            // Print the block
            write!(writer, "{}While ", indent!(indent))?;
            pass_block(writer, consequent, indent)?;
            writeln!(writer)?;
        },
        Parallel { blocks, .. } => {
            // Print the blocks
            writeln!(writer, "{}Parallel [", indent!(indent))?;
            for (i, b) in blocks.iter().enumerate() {
                write!(writer, "{}__brach_{}: ", indent!(indent), i)?;
                pass_block(writer, b, indent + 3)?;
                writeln!(writer)?;
            }
            writeln!(writer, "{}]", indent!(indent))?;
        },

        // We don't care about the rest
        _ => {},
    }

    // Done
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
fn pass_block(writer: &mut impl Write, block: &Block, indent: usize) -> std::io::Result<()> {
    // Print the current symbol table
    writeln!(writer, "[")?;
    pass_symbol_table(writer, &block.table, indent + INDENT_SIZE)?;

    // Now we print the following symbol tables with additional indentation
    let st: Ref<SymbolTable> = block.table.borrow();
    if !block.stmts.is_empty() && (st.has_functions() || st.has_classes() || st.has_variables()) {
        writeln!(writer)?;
    }
    for stmt in block.stmts.iter() {
        pass_stmt(writer, stmt, indent + INDENT_SIZE)?;
    }

    // Done
    write!(writer, "{}]", indent!(indent))
}

/// Prints a SymbolTable.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `symbol_table`: The SymbolTable to traverse.
/// - `indent`: The current base indent of all new lines to write.
///
/// # Returns
/// Nothing, but does print it.
fn pass_symbol_table(writer: &mut impl Write, symbol_table: &Rc<RefCell<SymbolTable>>, indent: usize) -> std::io::Result<()> {
    // Borrow the table
    let st: Ref<SymbolTable> = symbol_table.borrow();

    // First, print all of its functions
    for (name, f) in st.functions() {
        let f: Ref<FunctionEntry> = f.borrow();
        writeln!(
            writer,
            "{}{}func {}{}{}",
            indent!(indent),
            if f.index != usize::MAX { format!("{}) ", f.index) } else { String::new() },
            if let Some(pkg) = &f.package_name { format!("{pkg}::") } else { String::new() },
            name,
            f.signature
        )?;
    }
    // Next, print all of its classes
    for (_, c) in st.classes() {
        let c: Ref<ClassEntry> = c.borrow();

        // Print the class signature header
        writeln!(
            writer,
            "{}{}class {}{} {{",
            indent!(indent),
            if c.index != usize::MAX { format!("{}) ", c.index) } else { String::new() },
            if let Some(pkg) = &c.package_name { format!("{pkg}::") } else { String::new() },
            c.signature
        )?;
        // Print the associated symbol table
        pass_symbol_table(writer, &c.symbol_table, indent + INDENT_SIZE)?;
        // Print the closing thing done
        writeln!(writer, "{}}}", indent!(indent))?;
    }
    // Finally, print the variables
    for (name, v) in st.variables() {
        let v: Ref<VarEntry> = v.borrow();
        writeln!(
            writer,
            "{}{}var {} : {},",
            indent!(indent),
            if v.index != usize::MAX { format!("{}) ", v.index) } else { String::new() },
            name,
            v.data_type
        )?;
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
/// This pass generally doesn't error, but is here for convention purposes.
pub fn do_traversal(root: Program, writer: impl Write) -> Result<Program, Vec<Error>> {
    let mut writer = writer;

    // Iterate over all statements and run the appropriate match
    write!(&mut writer, "__root ").map_err(|source| vec![Error::WriteError { source }])?;
    pass_block(&mut writer, &root.block, 0).map_err(|source| vec![Error::WriteError { source }])?;
    writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;

    // Done
    Ok(root)
}
