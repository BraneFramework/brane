//  AST UNRESOLVED.rs
//    by Lut99
//
//  Created:
//    05 Sep 2022, 11:08:57
//  Last edited:
//    12 Dec 2023, 19:03:43
//  Auto updated?
//    Yes
//
//  Description:
//!   A print traversal that may print a compiled but unresolved workflow
//!   to stdout.
//

use std::cell::Ref;
use std::collections::{HashMap, HashSet};
use std::io::Write;

use brane_dsl::DataType;

use crate::ast::{Edge, EdgeInstr};
use crate::ast_unresolved::UnresolvedWorkflow;
use crate::edgebuffer::{EdgeBuffer, EdgeBufferNode, EdgeBufferNodeLink, EdgeBufferNodePtr};
pub use crate::errors::AstError as Error;
use crate::state::{CompileState, FunctionState, TableState, TaskState};


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
/// Prints the global table of the Workflow.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `table`: The TableState that we print.
/// - `indent`: The indent with which to print the table.
///
/// # Returns
/// Nothing, but does print the table to stdout.
pub fn pass_table(writer: &mut impl Write, table: &TableState, indent: usize) -> std::io::Result<()> {
    // Simply print all fields in a less-cluttering-to-most-cluttering order

    // Variables first
    for v in &table.vars {
        writeln!(writer, "{}Var {}: {};", indent!(indent), &v.name, v.data_type)?;
    }
    if !table.vars.is_empty() {
        writeln!(writer)?;
    }

    // Then, print all normal functions...
    for f in &table.funcs {
        writeln!(
            writer,
            "{}Function {}({}){}",
            indent!(indent),
            &f.name,
            f.signature.args.iter().map(|a| format!("{a}")).collect::<Vec<String>>().join(", "),
            if f.signature.ret != DataType::Void { format!(" -> {}", f.signature.ret) } else { String::new() },
        )?;
    }
    // ...and all tasks
    for t in &table.tasks {
        writeln!(
            writer,
            "{}Task<Compute> {}{}::{}({}){};",
            indent!(indent),
            t.package_name,
            if !t.package_version.is_latest() { format!("<{}>", t.package_version) } else { String::new() },
            &t.name,
            t.signature.args.iter().enumerate().map(|(i, a)| format!("{}: {}", t.arg_names[i], a)).collect::<Vec<String>>().join(", "),
            if t.signature.ret != DataType::Void { format!(" -> {}", t.signature.ret) } else { String::new() },
        )?;
    }
    if !table.vars.is_empty() || !table.funcs.is_empty() || !table.tasks.is_empty() {
        writeln!(writer)?;
    }

    // Finally print the class definitions
    for c in &table.classes {
        writeln!(
            writer,
            "{}Class {}{} {{",
            indent!(indent),
            if let Some(package) = &c.package_name {
                format!(
                    "{}{}::",
                    package,
                    if !c.package_version.as_ref().unwrap().is_latest() {
                        format!("<{}>", c.package_version.as_ref().unwrap())
                    } else {
                        String::new()
                    }
                )
            } else {
                String::new()
            },
            &c.name
        )?;
        // Print all properties
        for p in &c.props {
            writeln!(writer, "{}property {}: {};", indent!(INDENT_SIZE + indent), &p.name, p.data_type)?;
        }
        // Print all functions
        for m in &c.methods {
            let f: &FunctionState = &table.funcs[*m];
            writeln!(
                writer,
                "{}method {}({}){};",
                indent!(INDENT_SIZE + indent),
                &f.name,
                f.signature.args.iter().map(|a| format!("{a}")).collect::<Vec<String>>().join(", "),
                if f.signature.ret != DataType::Void { format!(" -> {}", f.signature.ret) } else { String::new() },
            )?;
        }
        writeln!(writer, "{}}};", indent!(indent))?;
    }
    if !table.vars.is_empty() || !table.funcs.is_empty() || !table.tasks.is_empty() || !table.classes.is_empty() {
        writeln!(writer)?;
    }

    // _Finally_ finally, print the intermediate results
    for (name, avail) in &table.results {
        writeln!(writer, "{}IntermediateResult '{}' -> '{:?}'", indent!(INDENT_SIZE), name, avail)?;
    }

    // Done
    Ok(())
}

/// Prints the extra function bodies of the Workflow.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `workflow`: The UnresolvedWorkflow who's function buffers we print.
/// - `table`: The VirtualTableState that we use to resolve definitions.
/// - `indent`: The indent with which to print the function buffers.
///
/// # Returns
/// Nothing, but does print the function buffers to stdout.
pub fn pass_f_edges(writer: &mut impl Write, f_edges: &HashMap<usize, EdgeBuffer>, table: &TableState, indent: usize) -> std::io::Result<()> {
    for (i, edges) in f_edges {
        // Print the header, resolving it
        let f: &FunctionState = table.func(*i);
        writeln!(
            writer,
            "{}Function {}({}){} {{",
            indent!(indent),
            &f.name,
            f.signature.args.iter().map(|a| format!("{a}")).collect::<Vec<String>>().join(", "),
            if f.signature.ret != DataType::Void { format!(" -> {}", f.signature.ret) } else { String::new() },
        )?;

        // Print the edge body (use the correct table!)
        pass_edges(writer, edges, table, INDENT_SIZE + indent, HashSet::new())?;

        // Print the closing brackets
        writeln!(writer, "{}}}", indent!(indent))?;
    }

    // DOne
    Ok(())
}

/// Prints a given EdgeBuffer to stdout.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `edges`: The EdgeBuffer to print.
/// - `table`: The VirtualTableState that we use to resolve indices.
/// - `indent`: The indent with which to print the buffer.
/// - `stop`: An optional set of nodes that we need to stop iterating for (useful for printing joining branches).
///
/// # Returns
/// Nothing, but does print the buffer to stdout.
// Clippy: Hash of EdgeBufferNodePtr is not mutable
#[allow(clippy::mutable_key_type)]
pub fn pass_edges(
    writer: &mut impl Write,
    edges: &EdgeBuffer,
    table: &TableState,
    indent: usize,
    stop: HashSet<EdgeBufferNodePtr>,
) -> std::io::Result<()> {
    // We will write the edges in an instruction-like way, except that branches will be funky :#
    match edges.start() {
        Some(start) => {
            // Loop 'n' match
            let mut temp: Option<EdgeBufferNodePtr> = Some(start.clone());
            while temp.is_some() {
                // Get the next value
                let node: EdgeBufferNodePtr = temp.take().unwrap();

                // If we already had this one, stop
                if stop.contains(&node) {
                    break;
                }
                // Print it
                let n: Ref<EdgeBufferNode> = node.borrow();
                pass_edge(writer, &n.edge, table, indent)?;

                // Match on it
                match &n.next {
                    EdgeBufferNodeLink::Linear(next) => {
                        // Move to the next
                        temp = Some(next.clone());
                    },
                    EdgeBufferNodeLink::Branch(true_branch, false_branch, next) => {
                        // Add next to a copy of the hashset
                        // Clippy: Hash of EdgeBufferNodePtr is not mutable
                        #[allow(clippy::mutable_key_type)]
                        let mut nested_stop: HashSet<EdgeBufferNodePtr> = stop.clone();
                        if let Some(next) = next {
                            nested_stop.insert(next.clone());
                        }

                        // Print the header
                        write!(writer, "{}Branch {{", indent!(indent))?;
                        // Print the true branch
                        if let Some(true_branch) = true_branch {
                            writeln!(writer)?;
                            pass_edges(writer, &true_branch.into(), table, INDENT_SIZE + indent, nested_stop.clone())?;
                            write!(writer, "{}", indent!(indent))?;
                        }
                        write!(writer, "}} {{")?;
                        // Print the fales branch
                        if let Some(false_branch) = false_branch {
                            writeln!(writer)?;
                            pass_edges(writer, &false_branch.into(), table, INDENT_SIZE + indent, nested_stop.clone())?;
                            write!(writer, "{}", indent!(indent))?;
                        }
                        writeln!(writer, "}}")?;

                        // Continue with the next, if any
                        if let Some(next) = next {
                            temp = Some(next.clone());
                        }
                    },
                    EdgeBufferNodeLink::Parallel(branches, join) => {
                        // Add join to a copy of the hashset
                        // Clippy: Hash of EdgeBufferNodePtr is not mutable
                        #[allow(clippy::mutable_key_type)]
                        let mut nested_stop: HashSet<EdgeBufferNodePtr> = stop.clone();
                        nested_stop.insert(join.clone());

                        // Print the branches things
                        write!(writer, "{}Parallel", indent!(indent))?;
                        for b in branches {
                            writeln!(writer, " {{")?;
                            pass_edges(writer, &b.into(), table, INDENT_SIZE + indent, nested_stop.clone())?;
                            write!(writer, "{}}}", indent!(indent))?;
                        }
                        writeln!(writer)?;

                        // Continue with the join, if any
                        temp = Some(join.clone());
                    },
                    EdgeBufferNodeLink::Loop(cond, body, next) => {
                        // Add next to a copy of the hashset
                        // Clippy: Hash of EdgeBufferNodePtr is not mutable
                        #[allow(clippy::mutable_key_type)]
                        let mut nested_stop: HashSet<EdgeBufferNodePtr> = stop.clone();
                        if let Some(next) = next {
                            nested_stop.insert(next.clone());
                        }

                        // Print the branches things
                        writeln!(writer, "{}Loop {{", indent!(indent))?;
                        pass_edges(writer, &cond.into(), table, INDENT_SIZE + indent, nested_stop.clone())?;
                        writeln!(writer, "{}}} {{", indent!(indent))?;
                        if let Some(body) = body {
                            pass_edges(writer, &body.into(), table, INDENT_SIZE + indent, nested_stop)?;
                        }
                        writeln!(writer, "{}}}", indent!(indent))?;

                        // Continue with the next, if any
                        if let Some(next) = next {
                            temp = Some(next.clone());
                        }
                    },

                    // The rest doest not progress but print for niceness (if we feel like it)
                    EdgeBufferNodeLink::None => {
                        writeln!(writer, "{}<None>", indent!(indent))?;
                    },
                    EdgeBufferNodeLink::End => {
                        writeln!(writer, "{}<End>", indent!(indent))?;
                    },
                    _ => {},
                };
            }
        },
        None => {
            writeln!(writer, "{}<no edges>", indent!(indent))?;
        },
    }

    // Done
    Ok(())
}

/// Prints a given Edge to stdout.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `edge`: The Edge to print.
/// - `table`: The VirtualTableState that we use to resolve indices.
/// - `indent`: The indent with which to print the buffer.
///
/// # Returns
/// Nothing, but does print the edge to stdout.
pub fn pass_edge(writer: &mut impl Write, edge: &Edge, table: &TableState, indent: usize) -> std::io::Result<()> {
    // Match the Edge
    use Edge::*;
    match edge {
        Node { task, .. } => {
            // Write the task as compute or transfer
            let task: &TaskState = table.task(*task);
            let task: String = format!(
                "{}{}::{}",
                task.package_name,
                if !task.package_version.is_latest() { format!("<{}>", task.package_version) } else { String::new() },
                task.name
            );

            // Write it
            writeln!(writer, "{}Node({})", indent!(indent), task)?;
        },
        Linear { instrs, .. } => {
            // Print the instructions linearly
            write!(writer, "{}[", indent!(indent))?;
            let mut first: bool = true;
            for i in instrs {
                if first {
                    first = false;
                } else {
                    write!(writer, "\n{}", indent!(1 + indent))?;
                }
                pass_edge_instr(writer, i, table)?;
            }
            writeln!(writer, "]")?;
        },
        Stop {} => {
            writeln!(writer, "{}<Stop>", indent!(indent))?;
        },

        Call { .. } => {
            writeln!(writer, "{}Call", indent!(indent))?;
        },
        Return { .. } => {
            writeln!(writer, "{}<Return>", indent!(indent))?;
        },

        // The rest doesn't have to be printed
        _ => {},
    }

    // Done
    Ok(())
}

/// Prints a given EdgeInstr to stdout.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `instr`: The EdgeInstr to print.
/// - `table`: The VirtualTableState we use to resolve indices.
///
/// # Returns
/// Nothing, but does print the instruction to stdout.
pub fn pass_edge_instr(writer: &mut impl Write, instr: &EdgeInstr, table: &TableState) -> std::io::Result<()> {
    // Match the instruction
    use EdgeInstr::*;
    match instr {
        Cast { res_type } => {
            write!(writer, "{instr} {res_type}")?;
        },

        Branch { next } => {
            write!(writer, "{instr} {next}")?;
        },
        BranchNot { next } => {
            write!(writer, "{instr} {next}")?;
        },

        Proj { field } => {
            write!(writer, "{instr} {field}")?;
        },

        Array { length, res_type } => {
            write!(writer, "{instr} {res_type},{length}")?;
        },
        ArrayIndex { res_type } => {
            write!(writer, "{instr} {res_type}")?;
        },
        Instance { def } => {
            write!(writer, "{} {}", instr, table.class(*def).name)?;
        },

        VarDec { def } => {
            write!(writer, "{} {}", instr, table.var(*def).name)?;
        },
        VarUndec { def } => {
            write!(writer, "{} {}", instr, table.var(*def).name)?;
        },
        VarSet { def } => {
            write!(writer, "{} {}", instr, table.var(*def).name)?;
        },
        VarGet { def } => {
            write!(writer, "{} {}", instr, table.var(*def).name)?;
        },

        Boolean { value } => {
            write!(writer, "{instr} {value}")?;
        },
        Integer { value } => {
            write!(writer, "{instr} {value}")?;
        },
        Real { value } => {
            write!(writer, "{instr} {value}")?;
        },
        String { value } => {
            write!(
                writer,
                "{} \"{}\"",
                instr,
                value.replace('\n', "\\n").replace('\t', "\\t").replace('\r', "\\r").replace('\\', "\\\\").replace('\"', "\\\"")
            )?;
        },
        Function { def } => {
            write!(writer, "{} {}", instr, table.func(*def).name)?;
        },

        // Any other instruction is just printing it without any value
        instr => {
            write!(writer, "{instr}")?;
        },
    }

    // Done
    Ok(())
}





/***** LIBRARY *****/
/// Starts printing the root of the AST (i.e., an UnresolvedWorkflow).
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `state`: The TableState that we use to resolve definition references.
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same root node as went in (since this compiler pass performs no transformations on the tree).
///
/// # Errors
/// This pass doesn't really error, but is here for convention purposes.
pub fn do_traversal(state: &CompileState, root: UnresolvedWorkflow, mut writer: impl Write) -> Result<UnresolvedWorkflow, Vec<Error>> {
    let UnresolvedWorkflow { main_edges, f_edges, metadata } = &root;

    writeln!(&mut writer, "UnresolvedWorkflow {{").map_err(|source| vec![Error::WriteError { source }])?;

    // Print parsed metadata
    if !metadata.is_empty() {
        for md in metadata.iter() {
            writeln!(
                &mut writer,
                "{}#{}.{}{}",
                indent!(INDENT_SIZE),
                if md.owner.contains(' ') { format!("\"{}\"", md.owner) } else { md.owner.clone() },
                if md.tag.contains(' ') { format!("\"{}\"", md.tag) } else { md.tag.clone() },
                if let Some((assigner, signature)) = &md.signature { format!(" <{assigner}.{signature}>") } else { String::new() }
            )
            .map_err(|source| vec![Error::WriteError { source }])?;
        }
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
    }

    // First up: print the workflow's table
    pass_table(&mut writer, &state.table, INDENT_SIZE).map_err(|source| vec![Error::WriteError { source }])?;
    writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
    writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
    writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;

    // Print the main function body
    pass_edges(&mut writer, main_edges, &state.table, INDENT_SIZE, HashSet::new()).map_err(|source| vec![Error::WriteError { source }])?;

    // Print the function edges
    if !f_edges.is_empty() {
        pass_f_edges(&mut writer, f_edges, &state.table, INDENT_SIZE).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
    }

    // Done
    writeln!(&mut writer, "}}").map_err(|source| vec![Error::WriteError { source }])?;
    Ok(root)
}
