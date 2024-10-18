//  UTILS.rs
//    by Lut99
//
//  Created:
//    18 Oct 2024, 11:13:13
//  Last edited:
//    18 Oct 2024, 11:13:43
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines a few utilities using across compilation modules.
//

use brane_exe::pc::ProgramCounter;


/***** LIBRARY FUNCTIONS *****/
/// Gets a workflow edge from a PC.
///
/// # Arguments
/// - `wir`: The [`ast::Workflow`] to get the edge from.
/// - `pc`: The program counter that points to the edge (hopefully).
///
/// # Returns
/// The edge the `pc` pointed to, or [`None`] if it was out-of-bounds.
#[inline]
pub fn get_edge(wir: &brane_ast::Workflow, pc: ProgramCounter) -> Option<&brane_ast::ast::Edge> {
    if pc.func_id.is_main() { wir.graph.get(pc.edge_idx) } else { wir.funcs.get(&pc.func_id.id()).and_then(|edges| edges.get(pc.edge_idx)) }
}
