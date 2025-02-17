//  WORKFLOW RESOLVE.rs
//    by Lut99
//
//  Created:
//    05 Sep 2022, 17:36:21
//  Last edited:
//    06 Feb 2024, 11:36:49
//  Auto updated?
//    Yes
//
//  Description:
//!   Final traversal in the compiler that takes an UnresolvedWorkflow and
//!   resolves all references to new edges.
//

use std::cell::Ref;
use std::collections::HashMap;

use log::debug;

use crate::ast::{Edge, SymTable, Workflow};
use crate::ast_unresolved::UnresolvedWorkflow;
use crate::edgebuffer::{EdgeBuffer, EdgeBufferNode, EdgeBufferNodeLink, EdgeBufferNodePtr};
use crate::errors::AstError;
use crate::state::CompileState;


/***** HELPER MACROS *****/
/// Efficiently writes an edge to the given buffer. Also returns the index written.
macro_rules! write_edge {
    ($buffer:expr, $edge:expr) => {{
        // Resize if necessary
        let idx: usize = $buffer.len();
        if idx == $buffer.capacity() {
            $buffer.reserve(32);
        }

        // Write the edge now there's enough space
        $buffer.push($edge);
        idx
    }};
}





/***** HELPER FUNCTIONS *****/
/// Updates the 'next' field in the given edge to the given value if it has any.
///
/// # Arguments
/// - `edge`: The Edge to update.
/// - `index`: The index to update the Edge with.
///
/// # Returns
/// Nothing, but does alter any `next` field in the given Edge.
///
/// # Panics
/// This function panics if the given Edge was one without edge-field, since that means writing edges was ill-formed.
#[inline]
fn update_link(edge: &mut Edge, index: usize) {
    // Match on the Edge
    use Edge::*;
    match edge {
        Node { ref mut next, .. } | Linear { ref mut next, .. } | Join { ref mut next, .. } | Call { ref mut next, .. } => {
            *next = index;
        },

        Loop { ref mut next, .. } => {
            // Match the next one
            if let Some(next) = next {
                *next = index;
            } else {
                panic!("Attempted to update the linear link on a fully returning Loop");
            }
        },

        Return { .. } => {},
        edge => {
            panic!("Attempted to update the linear link on edge '{edge:?}'");
        },
    }
}





/***** TRAVERSAL FUNCTIONS *****/
/// Traverses a list of edges, which will resolve all of the compiled edges in it to executable ones.
///
/// # Arguments
/// - `edges`: The EdgeBuffer to traverse.
/// - `target`: The target Vec<Edge> to resolve the edges in.
/// - `map`: A map of EdgeBufferPtrs to indices in the resulting edge list.
/// - `offset`: An offset to apply to all edge indices written.
///
/// # Returns
/// Nothing, but does add the edges in the `target` structure.
// Clippy: Hash of EdgeBufferNodePtr is not mutable
#[allow(clippy::mutable_key_type)]
fn pass_edges(edges: EdgeBuffer, target: &mut Vec<Edge>, map: &mut HashMap<EdgeBufferNodePtr, usize>, offset: usize) {
    // Early quit if there's nothing to compile
    let mut edges_start: EdgeBufferNodePtr = match edges.start() {
        Some(start) => start.clone(),
        None => {
            return;
        },
    };

    // Iterate over each of the edges in the EdgeBuffer
    loop {
        // Stop if we've had this edge before
        if map.contains_key(&edges_start) {
            break;
        }

        // Switch on the edge to assume the linkage
        let next: EdgeBufferNodePtr = {
            let e: Ref<EdgeBufferNode> = edges_start.borrow();

            use Edge::*;
            match &e.edge {
                Node { task, locs, at: _, input, result, metadata, next: _ } => {
                    // The connection must be linear
                    let next: Option<EdgeBufferNodePtr> = match &e.next {
                        EdgeBufferNodeLink::Linear(next) => Some(next.clone()),
                        EdgeBufferNodeLink::End => None,
                        link => {
                            panic!("Encountered a Node '{:?}' with a non-Linear connection '{:?}' after {:?}", e.next, link, edges_start);
                        },
                    };

                    // Resolve the index of this next one (either already defined or the next edge)
                    let next_idx: usize = match &next {
                        Some(next) => match map.get(next) {
                            Some(idx) => *idx,
                            None => offset + target.len() + 1,
                        },
                        None => usize::MAX,
                    };

                    // The task ID should already be valid, so write that to the new buffer
                    let index: usize = write_edge!(target, Edge::Node {
                        task: *task,
                        locs: locs.clone(),
                        at: None,
                        input: input.clone(),
                        result: result.clone(),
                        metadata: metadata.clone(),
                        next: next_idx,
                    });
                    map.insert(edges_start.clone(), index);

                    // Move to the next edge if there was one
                    match next {
                        Some(next) => next,
                        None => {
                            break;
                        },
                    }
                },
                Linear { instrs, .. } => {
                    // The connection must be linear
                    let next: Option<EdgeBufferNodePtr> = match &e.next {
                        EdgeBufferNodeLink::Linear(next) => Some(next.clone()),
                        EdgeBufferNodeLink::End => None,
                        link => {
                            panic!("Encountered a Linear '{:?}' with a non-Linear connection '{:?}' after {:?}", e.next, link, edges_start);
                        },
                    };

                    // Resolve the index of this next one (either already defined or the next edge)
                    let next_idx: usize = match &next {
                        Some(next) => match map.get(next) {
                            Some(idx) => *idx,
                            None => offset + target.len() + 1,
                        },
                        None => usize::MAX,
                    };

                    // We don't have to resolve instructions, so instead just write the edge
                    let index: usize = write_edge!(target, Edge::Linear { instrs: instrs.clone(), next: next_idx });
                    map.insert(edges_start.clone(), index);

                    // Move to the next edge if there was one
                    match next {
                        Some(next) => next,
                        None => {
                            break;
                        },
                    }
                },
                Stop {} => {
                    // We expect an explicit no connection
                    if let EdgeBufferNodeLink::Stop = &e.next {
                    } else {
                        panic!("Encountered a Stop with a non-End connection");
                    };

                    // Write the stop
                    let index = write_edge!(target, Edge::Stop {});
                    map.insert(edges_start.clone(), index);

                    // No next index; just stop loopin'
                    break;
                },

                Branch { .. } => {
                    // Get the pair of three edges that make up a Branch
                    let (true_branch, false_branch, next): (Option<EdgeBufferNodePtr>, Option<EdgeBufferNodePtr>, Option<EdgeBufferNodePtr>) =
                        if let EdgeBufferNodeLink::Branch(t, f, n) = &e.next {
                            (t.clone(), f.clone(), n.clone())
                        } else {
                            panic!("Encountered a Branch with a non-Branch connection");
                        };

                    // Write the true branch to a separate buffer but with correct indices (the current buffer index + 1 for the branch edges itself)
                    let true_idx: usize = offset + target.len() + 1;
                    let mut true_edges: Vec<Edge> = vec![];
                    if let Some(true_branch) = &true_branch {
                        pass_edges(true_branch.into(), &mut true_edges, map, true_idx);
                    }

                    // Write the false branch to a separate buffer but with correct indices (the true branch offset); unless it points
                    let false_idx: usize = true_idx + true_edges.len();
                    let mut false_edges: Vec<Edge> = vec![];
                    if let Some(false_branch) = &false_branch {
                        pass_edges(false_branch.into(), &mut false_edges, map, false_idx);
                    }

                    // If we were to write everything, all was correct except for the last instruction of the true branch; that must point to the next instead
                    let next_idx: usize = false_idx + false_edges.len();
                    if next.is_some() && !true_edges.is_empty() {
                        let true_edges_len: usize = true_edges.len();
                        update_link(&mut true_edges[true_edges_len - 1], next_idx);
                    }
                    if next.is_some() && !false_edges.is_empty() {
                        let false_edges_len: usize = false_edges.len();
                        update_link(&mut false_edges[false_edges_len - 1], next_idx);
                    }

                    // Now write the lot. First, do the branch edge itself
                    let index = write_edge!(target, Edge::Branch {
                        true_next:  if true_branch.is_some() { true_idx } else { next_idx },
                        false_next: if false_branch.is_some() { Some(false_idx) } else { Some(next_idx) },
                        merge:      if next.is_some() { Some(next_idx) } else { None },
                    });
                    map.insert(edges_start.clone(), index);

                    // Write the two branches, in-order
                    target.append(&mut true_edges);
                    target.append(&mut false_edges);

                    // Finally, set the next as the next edge if any, or quit otherwise
                    if let Some(next) = next {
                        next
                    } else {
                        break;
                    }
                },
                Parallel { .. } => {
                    // Get the pair of edges(-ish) that make up a Parallel
                    let (branches, join): (&Vec<EdgeBufferNodePtr>, EdgeBufferNodePtr) = if let EdgeBufferNodeLink::Parallel(b, j) = &e.next {
                        (b, j.clone())
                    } else {
                        panic!("Encountered a Parallel with a non-Parallel connection");
                    };

                    // Write each of them to a buffer of edges (offset: we skip the current offset + the space for the parallel edge itself)
                    let first_idx: usize = offset + target.len() + 1;
                    let mut last_offset: usize = first_idx;
                    let mut bs_idx: Vec<usize> = Vec::with_capacity(branches.len());
                    let mut bs: Vec<Vec<Edge>> = Vec::with_capacity(branches.len());
                    for b in branches {
                        // Write the branch to its own buffer
                        let mut b_edges: Vec<Edge> = vec![];
                        pass_edges(b.into(), &mut b_edges, map, last_offset);
                        bs_idx.push(last_offset);

                        // Update the offset for the next branch, then add it to the list
                        last_offset += b_edges.len();
                        bs.push(b_edges);
                    }

                    // After all branches are written to buffers, update their last edge to point to the join and mark their start indices in a buffer
                    let join_idx: usize = last_offset;
                    for (i, b) in bs.iter_mut().enumerate() {
                        let b_len: usize = b.len();
                        if !b.is_empty() {
                            update_link(&mut b[b_len - 1], join_idx);
                        } else {
                            bs_idx[i] = join_idx;
                        }
                    }

                    // Armed with the branches, we can write the parallel branch first
                    let index = write_edge!(target, Edge::Parallel { branches: bs_idx.clone(), merge: join_idx });
                    map.insert(edges_start.clone(), index);

                    // Write each of the branches
                    for b in bs {
                        let mut b = b;
                        target.append(&mut b);
                    }

                    // Now do the join, after secretly injecting the list of edges into it
                    join
                },
                Join { merge, .. } => {
                    // The connection must be linear
                    let next: Option<EdgeBufferNodePtr> = match &e.next {
                        EdgeBufferNodeLink::Linear(next) => Some(next.clone()),
                        EdgeBufferNodeLink::End => None,
                        link => {
                            panic!("Encountered a Join '{:?}' with a non-Linear connection '{:?}' after {:?}", e.next, link, edges_start);
                        },
                    };

                    // Resolve the index of this next one (either already defined or the next edge)
                    let next_idx: usize = match &next {
                        Some(next) => match map.get(next) {
                            Some(idx) => *idx,
                            None => offset + target.len() + 1,
                        },
                        None => usize::MAX,
                    };

                    // We already have the branches and merge; so just write the Join
                    let index = write_edge!(target, Edge::Join { merge: *merge, next: next_idx });
                    map.insert(edges_start.clone(), index);

                    // Move to the next edge if there was one
                    match next {
                        Some(next) => next,
                        None => {
                            break;
                        },
                    }
                },

                Loop { .. } => {
                    // Get the triplet of edges that make up a Loop
                    let (cond, body, next): (EdgeBufferNodePtr, Option<EdgeBufferNodePtr>, Option<EdgeBufferNodePtr>) =
                        if let EdgeBufferNodeLink::Loop(c, b, n) = &e.next {
                            (c.clone(), b.clone(), n.clone())
                        } else {
                            panic!("Encountered a Loop with a non-Loop connection");
                        };

                    // First, write the condition (offset: we skip the current offset and a single space for the Loop edge itself)
                    let cond_idx: usize = offset + target.len() + 1;
                    let mut cond_edges: Vec<Edge> = vec![];
                    pass_edges(cond.into(), &mut cond_edges, map, cond_idx);

                    // Next, write the body (if any). Offset: we skip over the conditional edges + a branch following them.
                    let body_idx: usize = cond_idx + cond_edges.len() + 1;
                    let mut body_edges: Vec<Edge> = vec![];
                    if let Some(body) = body {
                        pass_edges(body.into(), &mut body_edges, map, body_idx);
                    }

                    // Before we do anything, resolve the next index
                    let next_idx: Option<usize> = match &next {
                        Some(next) => match map.get(next) {
                            Some(idx) => Some(*idx),
                            None => Some(body_idx + body_edges.len()),
                        },
                        None => None,
                    };

                    // We now have all indices. Add the branches and such at the end of the current body edges.
                    if !cond_edges.is_empty() {
                        // Link it first, due to it already being written without
                        let cond_edges_len: usize = cond_edges.len();
                        update_link(&mut cond_edges[cond_edges_len - 1], cond_idx + cond_edges_len);

                        // Write the branch itself
                        write_edge!(cond_edges, Edge::Branch { true_next: body_idx, false_next: next_idx, merge: next_idx });
                    }
                    if !body_edges.is_empty() {
                        let body_edges_len: usize = body_edges.len();
                        update_link(&mut body_edges[body_edges_len - 1], cond_idx);
                    }

                    // Now we can write the loop node
                    let index = write_edge!(target, Edge::Loop { cond: cond_idx, body: body_idx, next: next_idx });
                    map.insert(edges_start.clone(), index);

                    // Write the condition and body
                    target.append(&mut cond_edges);
                    target.append(&mut body_edges);

                    // Then move on to the next (if any)
                    match next {
                        Some(next) => next,
                        None => {
                            break;
                        },
                    }
                },

                Call { input, result, .. } => {
                    // The connection must be linear
                    let next: Option<EdgeBufferNodePtr> = match &e.next {
                        EdgeBufferNodeLink::Linear(next) => Some(next.clone()),
                        EdgeBufferNodeLink::End => None,
                        link => {
                            panic!("Encountered a Call '{:?}' with a non-Linear connection '{:?}' after {:?}", e.next, link, edges_start);
                        },
                    };

                    // Resolve the index of this next one (either already defined or the next edge)
                    let next_idx: usize = match &next {
                        Some(next) => match map.get(next) {
                            Some(idx) => *idx,
                            None => offset + target.len() + 1,
                        },
                        None => usize::MAX,
                    };

                    // We already have the branches and merge; so just write the Join
                    let index: usize = write_edge!(target, Edge::Call { input: input.clone(), result: result.clone(), next: next_idx });
                    map.insert(edges_start.clone(), index);

                    // Move to the next edge if there was one
                    match next {
                        Some(next) => next,
                        None => {
                            break;
                        },
                    }
                },
                Return { result } => {
                    // We expect an explicit no connection
                    if let EdgeBufferNodeLink::Stop = &e.next {
                    } else {
                        panic!("Encountered a Return with a non-End connection");
                    };

                    // Write the return
                    let index = write_edge!(target, Edge::Return { result: result.clone() });
                    map.insert(edges_start.clone(), index);

                    // No next index; just stop loopin'
                    break;
                },
            }
        };

        // Move to next
        edges_start = next;
    }
}





/***** LIBRARY *****/
/// Compiles the given UnresolvedWorkflow to a ResolvedWorkflow.
///
/// Note that the unresolved workflow already has to be compiled, obviously.
///
/// # Arguments
/// - `state`: The CompileState that contains function bodies of previously defined functions (definitions are already implicitly transferred from the symbol table).
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// A new Workflow that contains the compiled program, ready for execution.
///
/// # Errors
/// This pass doesn't error, but might return one for convention purposes.
///
/// # Panics
/// This function may panic if any of the previous passes did not do its job, and the given UnresolvedWorkflow is ill-formed.
pub fn do_traversal(state: &mut CompileState, mut root: UnresolvedWorkflow) -> Result<Workflow, Vec<AstError>> {
    // Convert the CompileState into a symbol table
    let table: SymTable = (&state.table).into();

    // First we'll want to write the main edges
    let mut graph: Vec<Edge> = vec![];
    pass_edges(root.main_edges, &mut graph, &mut HashMap::new(), 0);

    // Then, inject the bodies for all of the functions
    let mut funcs: HashMap<usize, Vec<Edge>> = HashMap::new();
    for (i, def) in table.funcs.iter().enumerate() {
        // Find the definition in the f_edges or in the state (it should be mutually exclusive)
        if let Some(body) = state.bodies.get(&def.name) {
            debug!("Linking function '{}' from previous snippet", def.name);
            funcs.insert(i, body.clone());
        } else if let Some(body) = root.f_edges.remove(&i) {
            debug!("Linking function '{}' from current snippet", def.name);

            // Compile the function body
            let mut f_graph: Vec<Edge> = vec![];
            pass_edges(body, &mut f_graph, &mut HashMap::new(), 0);

            // Insert it in the table's functions
            funcs.insert(i, f_graph.clone());
            // And into the state (for future reference)
            state.bodies.insert(def.name.clone(), f_graph);
        } else {
            debug!("Not linking function '{}' (builtin)", def.name);
        }
    }

    // Done; create the workflow and return it
    // Note: don't forget to transfer metadata before doing so
    let mut wf: Workflow = Workflow::with_random_id(table, graph, funcs);
    wf.metadata = root.metadata;
    Ok(wf)
}


/***** TESTS *****/
#[cfg(test)]
mod tests {
    use brane_dsl::ParserOptions;
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::super::print::ast;
    use super::*;
    use crate::{CompileResult, CompileStage, compile_program_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_workflow_resolve() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // Run up to this traversal
            let workflow: Workflow =
                match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::WorkflowResolve) {
                    CompileResult::Workflow(wf, warns) => {
                        // Print warnings if any
                        for w in warns {
                            w.prettyprint(path.to_string_lossy(), &code);
                        }
                        wf
                    },
                    CompileResult::Eof(err) => {
                        // Print the error
                        err.prettyprint(path.to_string_lossy(), &code);
                        panic!("Failed to resolve workflow (see output above)");
                    },
                    CompileResult::Err(errs) => {
                        // Print the errors
                        for e in errs {
                            e.prettyprint(path.to_string_lossy(), &code);
                        }
                        panic!("Failed to resolve workflow (see output above)");
                    },

                    _ => {
                        unreachable!();
                    },
                };

            // Now print the file for prettyness
            ast::do_traversal(&workflow, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
