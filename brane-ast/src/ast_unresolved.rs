//  AST UNRESOLVED.rs
//    by Lut99
//
//  Created:
//    03 Sep 2022, 12:31:20
//  Last edited:
//    14 Nov 2024, 17:20:23
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains special patches / overwrites for the normal `brane-ast` AST
//!   that make compilation life a super-duper amount easier.
//

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use specifications::wir::Metadata;

use crate::edgebuffer::EdgeBuffer;


/***** LIBRARY *****/
/// Defines a variant of a normal Workflow, which is meant to be an 'executable but reasonable' graph but with inter-edge links in an unserializable state. They have to be resolved to indices before they can be run.
#[derive(Clone, Debug)]
pub struct UnresolvedWorkflow {
    // Note that the workflow table is actually represented in the state itself.
    /// The main buffer to start executing, which references all other buffers.
    pub main_edges: EdgeBuffer,
    /// The list of EdgeBuffers that implement functions. Every buffer is mapped by the function's ID in the workflow table.
    pub f_edges:    HashMap<usize, EdgeBuffer>,
    /// Toplevel metadata
    pub metadata:   Arc<HashSet<Metadata>>,
}

impl UnresolvedWorkflow {
    /// Constructor for the Workflow that initializes it to values that have already been computed.
    ///
    /// # Arguments
    /// - `main_edges`: The main buffer containing toplevel code.
    /// - `f_edges`: The buffers that detail the code per-function.
    ///
    /// # Returns
    /// A new Workflow instance.
    #[inline]
    pub fn new(main_edges: EdgeBuffer, f_edges: HashMap<usize, EdgeBuffer>) -> Self {
        Self { main_edges, f_edges, metadata: Arc::new(HashSet::new()) }
    }
}
