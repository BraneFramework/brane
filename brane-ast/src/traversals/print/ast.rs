//  AST.rs
//    by Lut99
//
//  Created:
//    31 Aug 2022, 09:25:11
//  Last edited:
//    06 Feb 2024, 11:38:47
//  Auto updated?
//    Yes
//
//  Description:
//!   Prints the `brane-ast` AST.
//

use std::collections::HashSet;
use std::io::Write;

use crate::ast::{Edge, EdgeInstr, FunctionDef, SymTable, TaskDef, Workflow};
use crate::data_type::DataType;
pub use crate::errors::AstError as Error;
use crate::func_id::FunctionId;


/***** MACROS ******/
/// Generates the correct number of spaces for an indent.
macro_rules! indent {
    ($n_spaces:expr) => {
        ((0..$n_spaces).map(|_| ' ').collect::<String>())
    };
}

/// Generates a properly padded line number.
macro_rules! line_number {
    ($l:expr) => {
        format!("{:>1$}", $l, LINE_SIZE)
    };
}





/***** CONSTANTS *****/
/// Determines the number of decimals the line numbers will always have
const LINE_SIZE: usize = 4;
/// Determines the increase in indentation for every nested level.
const INDENT_SIZE: usize = 4;





/***** TRAVERSAL FUNCTIONS *****/
/// Prints the global table of the Workflow.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `table`: The SymTable we print.
/// - `indent`: The indent with which to print the table.
///
/// # Returns
/// Nothing, but does print the table to stdout.
fn pass_table(writer: &mut impl Write, table: &SymTable, indent: usize) -> std::io::Result<()> {
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
            "{}Function {}({}){};",
            indent!(indent),
            &f.name,
            f.args.iter().map(|a| format!("{a}")).collect::<Vec<String>>().join(", "),
            if f.ret != DataType::Void { format!(" -> {}", f.ret) } else { String::new() },
        )?;
    }
    // ...and all tasks
    for t in &table.tasks {
        match t {
            TaskDef::Compute(def) => {
                if !def.requirements.is_empty() {
                    writeln!(writer, "{}#[requirements = {:?}]", indent!(indent), def.requirements)?;
                }
                writeln!(
                    writer,
                    "{}Task<Compute> {}{}::{}({}){};",
                    indent!(indent),
                    def.package,
                    if !def.version.is_latest() { format!("<{}>", def.version) } else { String::new() },
                    &def.function.name,
                    def.function.args.iter().enumerate().map(|(i, a)| format!("{}: {}", def.args_names[i], a)).collect::<Vec<String>>().join(", "),
                    if def.function.ret != DataType::Void { format!(" -> {}", def.function.ret) } else { String::new() },
                )?;
            },
            TaskDef::Transfer => writeln!(writer, "Task<Transfer>;")?,
        }
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
            if let Some(package) = &c.package { format!("{package}::") } else { String::new() },
            &c.name
        )?;
        // Print all properties
        for p in &c.props {
            writeln!(writer, "{}property {}: {};", indent!(INDENT_SIZE + indent), &p.name, p.data_type)?;
        }
        // Print all functions
        for m in &c.methods {
            let m: &FunctionDef = &table.funcs[*m];
            writeln!(
                writer,
                "{}method &{}({}){};",
                indent!(INDENT_SIZE + indent),
                &m.name,
                m.args.iter().map(|a| format!("{a}")).collect::<Vec<String>>().join(", "),
                if m.ret != DataType::Void { format!(" -> {}", m.ret) } else { String::new() },
            )?;
        }
        writeln!(writer, "{}}};", indent!(indent))?;
    }
    if !table.vars.is_empty() || !table.funcs.is_empty() || !table.tasks.is_empty() || !table.classes.is_empty() {
        writeln!(writer)?;
    }

    // And the results
    for (name, avail) in table.results.iter() {
        writeln!(writer, "{}IntermediateResult '{}' -> '{:?}'", indent!(INDENT_SIZE), name, avail)?;
    }

    // Done
    Ok(())
}

/// Prints a given Edge buffer to stdout.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `index`: The starting index in the edges list to follow.
/// - `edges`: The list of Edges to print.
/// - `table`: The SymTable we use to resolve indices.
/// - `indent`: The indent with which to print the buffer.
/// - `done`: A set of nodes we've already seen that we use to avoid getting stuck forever.
///
/// # Returns
/// Nothing, but does print the buffer to stdout.
fn pass_edges(
    writer: &mut impl Write,
    index: usize,
    edges: &[Edge],
    table: &SymTable,
    indent: usize,
    done: &mut HashSet<usize>,
) -> std::io::Result<()> {
    // Loop until we are out-of-bounds or encounter a stop
    let mut i: usize = index;
    while i < edges.len() {
        // If we've alread done this one, stop
        if done.contains(&i) {
            writeln!(writer, "{} {}<Link to {}>", indent!(LINE_SIZE), indent!(indent), i)?;
            break;
        }
        done.insert(i);

        // Get the node's value
        let node: &Edge = &edges[i];

        // Match on it
        use Edge::*;
        match node {
            Node { task, locs, at, input, result, metadata, next } => {
                // Write the Node as a task call
                writeln!(
                    writer,
                    "{} {}Node({}){}{}{}{}",
                    line_number!(i),
                    indent!(indent),
                    match &table.task(*task) {
                        TaskDef::Compute(def) => format!(
                            "{}{}::{}",
                            def.package,
                            if !def.version.is_latest() { format!("<{}>", def.version) } else { String::new() },
                            def.function.name
                        ),
                        TaskDef::Transfer => "__builtin::transfer".into(),
                    },
                    if locs.is_restrictive() { format!(" <limited to: {}>", locs.restricted().join(",")) } else { String::new() },
                    if let Some(at) = at { format!(" @{at}") } else { String::new() },
                    if !input.is_empty() || result.is_some() {
                        format!(
                            " [{} -> {}]",
                            if !input.is_empty() {
                                input
                                    .iter()
                                    .map(|(name, avail)| {
                                        format!("'{}'{}", name, if let Some(avail) = avail { format!(" ({avail:?})") } else { String::new() })
                                    })
                                    .collect::<Vec<String>>()
                                    .join(", ")
                                    .to_string()
                            } else {
                                "''".into()
                            },
                            if let Some(name) = result { format!("'{name}'") } else { "''".into() },
                        )
                    } else {
                        String::new()
                    },
                    if !metadata.is_empty() {
                        format!(
                            " <{}>",
                            metadata
                                .iter()
                                .map(|md| format!(
                                    "#{}.{}{}",
                                    if md.owner.contains(' ') { format!("\"{}\"", md.owner) } else { md.owner.clone() },
                                    if md.tag.contains(' ') { format!("\"{}\"", md.tag) } else { md.tag.clone() },
                                    if let Some((assigner, signature)) = &md.signature {
                                        format!(" <{assigner}.{signature}>")
                                    } else {
                                        String::new()
                                    }
                                ))
                                .collect::<Vec<String>>()
                                .join(",")
                        )
                    } else {
                        String::new()
                    },
                )?;

                // Move to the next node
                i = *next;
            },
            Linear { instrs, next } => {
                // Write the instructions within this edge
                write!(writer, "{} {}[", line_number!(i), indent!(indent))?;
                let mut first: bool = true;
                for i in instrs {
                    if first {
                        first = false;
                    } else {
                        write!(writer, "\n{} {} ", indent!(LINE_SIZE), indent!(indent))?;
                    }
                    pass_edge_instr(writer, i, table)?;
                }
                writeln!(writer, "]")?;

                // Move to the next node
                i = *next;
            },
            Stop {} => {
                // Write a simple stop
                writeln!(writer, "{} {}<Stop>", line_number!(i), indent!(indent))?;

                // Do still move to the next node, if any
                i += 1;
            },

            Branch { true_next, false_next, merge } => {
                // Add the merge point to the 'already done' map for this loop
                let rem_merge: Option<bool> = merge.as_ref().map(|m| done.insert(*m));

                // Write the two branches of the branch
                write!(writer, "{} {}Branch {{", line_number!(i), indent!(indent))?;
                if merge.is_none() || merge.as_ref().unwrap() != true_next {
                    writeln!(writer)?;
                    pass_edges(writer, *true_next, edges, table, INDENT_SIZE + indent, done)?;
                    write!(writer, "{} {}", indent!(LINE_SIZE), indent!(indent))?;
                }
                write!(writer, "}} {{")?;
                if false_next.is_some() && (merge.is_none() || merge.as_ref().unwrap() != false_next.as_ref().unwrap()) {
                    writeln!(writer)?;
                    pass_edges(writer, false_next.unwrap(), edges, table, INDENT_SIZE + indent, done)?;
                    write!(writer, "{} {}", indent!(LINE_SIZE), indent!(indent))?;
                }
                writeln!(writer, "}}")?;

                // Remove the 'already done' to make sure it is written next
                if rem_merge.is_some() && rem_merge.unwrap() {
                    done.remove(merge.as_ref().unwrap());
                }

                // Move to the next node
                match merge {
                    Some(merge) => {
                        i = *merge;
                    },
                    None => i += 1,
                }
            },
            Parallel { branches, merge } => {
                // Add the merge point to the 'already done' map for this loop
                let rem_merge: bool = done.insert(*merge);

                // Write the branches of the branch, in sequence
                write!(writer, "{} {}Parallel {{", line_number!(i), indent!(indent))?;
                let mut first: bool = true;
                for i in 0..branches.len() {
                    if *merge != branches[i] {
                        // Add the next branch
                        let rem_merge: bool = if i < branches.len() - 1 { done.insert(branches[i + 1]) } else { false };

                        // Print it
                        if first {
                            first = false;
                        } else {
                            write!(writer, "}} {{")?;
                        }
                        writeln!(writer)?;
                        pass_edges(writer, branches[i], edges, table, INDENT_SIZE + indent, done)?;
                        write!(writer, "{} {}", indent!(LINE_SIZE), indent!(indent))?;

                        // Remove the next one again
                        if rem_merge {
                            done.remove(&branches[i + 1]);
                        }
                    }
                }
                writeln!(writer, "}}")?;

                // Remove the 'already done' to make sure it is written next
                if rem_merge {
                    done.remove(merge);
                }

                // Move to the next node
                i = *merge;
            },
            Join { merge, next } => {
                // Write the join itself
                writeln!(writer, "{} {}Join({:?})", line_number!(i), indent!(indent), *merge)?;

                // Move to the next node
                i = *next;
            },

            Loop { cond, body, next } => {
                // Write the loop
                writeln!(writer, "{} {}Loop {{", line_number!(i), indent!(indent))?;
                pass_edges(writer, *cond, edges, table, INDENT_SIZE + indent, done)?;
                write!(writer, "{} {}}} {{", indent!(LINE_SIZE), indent!(indent))?;
                if next.is_none() || body != next.as_ref().unwrap() {
                    writeln!(writer)?;
                    pass_edges(writer, *body, edges, table, INDENT_SIZE + indent, done)?;
                    write!(writer, "{} {}", indent!(LINE_SIZE), indent!(indent))?;
                }
                writeln!(writer, "}}")?;

                // Move to the next node
                match next {
                    Some(next) => {
                        i = *next;
                    },
                    None => {
                        i += 1;
                    },
                }
            },

            Call { input, result, next } => {
                // Just print it
                writeln!(
                    writer,
                    "{} {}Call{}",
                    line_number!(i),
                    indent!(indent),
                    if !input.is_empty() || !result.is_empty() {
                        format!(
                            " [{} -> {}]",
                            if !input.is_empty() {
                                input.iter().map(|name| format!("'{name}'")).collect::<Vec<String>>().join(" or ").to_string()
                            } else {
                                "<none>".into()
                            },
                            if !result.is_empty() {
                                result.iter().map(|name| format!("'{name}'")).collect::<Vec<String>>().join(" or ").to_string()
                            } else {
                                "<none>".into()
                            },
                        )
                    } else {
                        String::new()
                    },
                )?;

                // Move to the next node
                i = *next;
            },
            Return { result } => {
                writeln!(
                    writer,
                    "{} {}Return{}",
                    line_number!(i),
                    indent!(indent),
                    if !result.is_empty() {
                        format!(
                            " [returns {}]",
                            if !result.is_empty() {
                                result.iter().map(|name| format!("'{name}'")).collect::<Vec<String>>().join(" or ").to_string()
                            } else {
                                "<none>".into()
                            },
                        )
                    } else {
                        String::new()
                    }
                )?;
                i += 1
            },
        }
    }

    // Done
    Ok(())
}

/// Prints a given EdgeInstr to stdout.
///
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `instr`: The EdgeInstr to print.
/// - `table`: The VirtualSymTable we use to resolve indices.
///
/// # Returns
/// Nothing, but does print the instruction to stdout.
fn pass_edge_instr(writer: &mut impl Write, instr: &EdgeInstr, table: &SymTable) -> std::io::Result<()> {
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
        VarGet { def } => {
            write!(writer, "{} {}", instr, table.var(*def).name)?;
        },
        VarSet { def } => {
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
                value.replace('\\', "\\\\").replace('\n', "\\n").replace('\t', "\\t").replace('\r', "\\r").replace('\"', "\\\"")
            )?;
        },
        Function { def } => {
            write!(writer, "{} {}", instr, table.func(FunctionId::Func(*def)).name)?;
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
/// Starts printing the root of the AST (i.e., a Workflow).
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
/// - `writer`: The `Write`r to write to.
///
/// # Errors
/// This pass may error if we failed to write to the given writer.
pub fn do_traversal(root: &Workflow, mut writer: impl Write) -> Result<(), Vec<Error>> {
    let Workflow { id, table, metadata, user, graph, funcs } = root;

    writeln!(&mut writer, "Workflow '{id}' {{").map_err(|source| vec![Error::WriteError { source }])?;

    // Print parsed metadata
    if user.is_some() || !metadata.is_empty() {
        // Print the user
        if let Some(user) = &**user {
            // Write it
            writeln!(&mut writer, "{}User: '{}'", indent!(INDENT_SIZE), user).map_err(|source| vec![Error::WriteError { source }])?;

            // Write a newline separating the tags
            if !metadata.is_empty() {
                writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
            }
        }

        // Print the metadata
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

    // First up: print the workflow table
    pass_table(&mut writer, table, INDENT_SIZE).map_err(|source| vec![Error::WriteError { source }])?;

    if !root.table.vars.is_empty()
        || !root.table.funcs.is_empty()
        || !root.table.tasks.is_empty()
        || !root.table.classes.is_empty()
        || !root.table.results.is_empty()
    {
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
    }

    // Print the main function body (and thus all function bodies)
    writeln!(&mut writer, "{}<Main>", indent!(INDENT_SIZE)).map_err(|source| vec![Error::WriteError { source }])?;
    pass_edges(&mut writer, 0, graph, table, INDENT_SIZE, &mut HashSet::new()).map_err(|source| vec![Error::WriteError { source }])?;

    // Print the functions
    for (i, f) in funcs.iter() {
        writeln!(&mut writer).map_err(|source| vec![Error::WriteError { source }])?;
        writeln!(&mut writer, "{}<Function {} ({})>", indent!(INDENT_SIZE), *i, table.funcs[*i].name)
            .map_err(|source| vec![Error::WriteError { source }])?;
        pass_edges(&mut writer, 0, f, table, INDENT_SIZE, &mut HashSet::new()).map_err(|source| vec![Error::WriteError { source }])?;
    }

    // Done
    writeln!(&mut writer, "}}").map_err(|source| vec![Error::WriteError { source }])?;

    Ok(())
}
