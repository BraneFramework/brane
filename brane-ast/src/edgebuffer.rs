//  EDGEBUFFER.rs
//    by Lut99
//
//  Created:
//    05 Sep 2022, 09:27:32
//  Last edited:
//    02 Nov 2023, 14:25:07
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements an EdgeBuffer, which is a structure we use to write Edges
//!   during compilation.
//

use std::borrow::Cow;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::mem;
use std::rc::Rc;

use brane_dsl::spec::MergeStrategy;

use crate::ast::Edge;


/***** TESTS *****/
#[cfg(test)]
mod tests {
    use super::*;


    /// Tests whether the EdgeBuffer creates linked lists as expected.
    #[test]
    fn test_edgebuffer() {
        // Create a new edgebuffer
        let mut edges1: EdgeBuffer = EdgeBuffer::new();
        // Write a couple of things
        edges1.write(Edge::Linear { instrs: vec![], next: usize::MAX });
        edges1.write(Edge::Linear { instrs: vec![], next: usize::MAX });
        edges1.write(Edge::Linear { instrs: vec![], next: usize::MAX });
        edges1.write_stop(Edge::Return { result: HashSet::new() });
        // Test if it's valid
        let mut node: Option<EdgeBufferNodePtr> = edges1.start().clone();
        let mut i = 0;
        while node.is_some() {
            // Make sure this node is what we expect from it
            if (0..=2).contains(&i) {
                let n: Ref<EdgeBufferNode> = node.as_ref().unwrap().borrow();
                if let Edge::Linear { .. } = &n.edge {
                } else {
                    panic!("{}: Encountered non-linear edge '{:?}'", i, n.edge);
                }
            } else if i == 3 {
                let n: Ref<EdgeBufferNode> = node.as_ref().unwrap().borrow();
                if let Edge::Return { .. } = &n.edge {
                } else {
                    panic!("{}: Encountered non-return edge '{:?}'", i, n.edge);
                }
            } else {
                let n: Ref<EdgeBufferNode> = node.as_ref().unwrap().borrow();
                panic!("{}: Encountered unexpected edge '{:?}' (too many)", i, n.edge);
            }

            // Move to the next
            node = node.unwrap().borrow().next();
            i += 1;
        }
        if i < 4 {
            panic!("Encountered not enough edges (got {}, expected {})", i, 4);
        }

        // Create another buffer with a branch in it
        let mut edges2: EdgeBuffer = EdgeBuffer::new();
        // Write a couple of things
        edges2.write(Edge::Linear { instrs: vec![], next: usize::MAX });
        edges2.write_branch(Some(edges1), None);
        // Note the branch introduces an implicit linear to which it writes
        edges2.write(Edge::Linear { instrs: vec![], next: usize::MAX });
        edges2.write_stop(Edge::Stop {});
        // Test if it's valid
        let mut node: Option<EdgeBufferNodePtr> = edges2.start().clone();
        let mut i = 0;
        while node.is_some() {
            // Make sure this node is what we expect from it
            if i == 0 || i == 2 || i == 3 {
                let n: Ref<EdgeBufferNode> = node.as_ref().unwrap().borrow();
                if let Edge::Linear { .. } = &n.edge {
                } else {
                    panic!("{}: Encountered non-linear edge '{:?}'", i, n.edge);
                }
            } else if i == 1 {
                let n: Ref<EdgeBufferNode> = node.as_ref().unwrap().borrow();
                if let Edge::Branch { .. } = &n.edge {
                } else {
                    panic!("{}: Encountered non-branch edge '{:?}'", i, n.edge);
                }
            } else if i == 4 {
                let n: Ref<EdgeBufferNode> = node.as_ref().unwrap().borrow();
                if let Edge::Stop {} = &n.edge {
                } else {
                    panic!("{}: Encountered non-stop edge '{:?}'", i, n.edge);
                }
            } else {
                let n: Ref<EdgeBufferNode> = node.as_ref().unwrap().borrow();
                panic!("{}: Encountered unexpected edge '{:?}' (too many)", i, n.edge);
            }

            // Move to the next
            node = node.unwrap().borrow().next();
            i += 1;
        }
        if i < 5 {
            panic!("Encountered not enough edges (got {}, expected {})", i, 5);
        }
    }
}





/***** AUXILLARY *****/
/// Defines how one node links to the next and should thus be traversed.
#[derive(Clone, Debug)]
pub enum EdgeBufferNodeLink {
    /// It's a simple, linear link.
    Linear(EdgeBufferNodePtr),
    /// It's a branching link (i.e., two options).
    ///
    /// # Layout
    /// - `0`: The edges that represent the true-branch if there is any.
    /// - `1`: The edges that represent the false-branch if there is any.
    /// - `2`: The edges that represent the joining edge, i.e., the first one _after_ the branch. If there is none, that means that the branch is actually fully returning.
    Branch(Option<EdgeBufferNodePtr>, Option<EdgeBufferNodePtr>, Option<EdgeBufferNodePtr>),
    /// It's a parallel link (i.e., multiple ways taken concurrently).
    ///
    /// # Layout
    /// - `0`: The edges that represent the branches. Every pointer in the vector is a branch.
    /// - `1`: The edges that represent the joining edge.
    Parallel(Vec<EdgeBufferNodePtr>, EdgeBufferNodePtr),
    /// It's a repeating link (i.e., a given set of edges is taken repeatedly).
    ///
    /// # Layout
    /// - `0`: The edges that represent the condition-computation.
    /// - `1`: The edges that represent the repeated loop (unless there are no edges in it).
    /// - `2`: The edges that are taken after the loop (unless the while actually returns).
    Loop(EdgeBufferNodePtr, Option<EdgeBufferNodePtr>, Option<EdgeBufferNodePtr>),
    /// A special kind of connection that is not a placeholder but expliticly means "it just stops".
    End,
    /// A special kind of connection that is not a placeholder but really means 'returns'.
    Stop,

    /// No link (yet)
    None,
}

impl EdgeBufferNodeLink {
    /// Returns whether this EdgeBufferNodeLink is a link (i.e., is _not_ `EdgeBufferNodeLink::None`).
    #[inline]
    pub fn is_some(&self) -> bool { !self.is_none() }

    /// Returns whether this EdgeBufferNodeLink is _not_ a link (i.e., is `EdgeBufferNodeLink::None`).
    #[inline]
    pub fn is_none(&self) -> bool { matches!(self, Self::None) }
}





/// Defines a shortcut for an EdgeBufferNode 'pointer'.
#[derive(Clone, Debug)]
pub struct EdgeBufferNodePtr(Rc<RefCell<EdgeBufferNode>>);

impl EdgeBufferNodePtr {
    /// Borrows the underlying EdgeBuffer.
    ///
    /// # Returns
    /// A `Ref` that represents the borrow to the buffer.
    #[inline]
    pub fn borrow(&self) -> Ref<EdgeBufferNode> { self.0.borrow() }

    /// Borrows the underlying EdgeBuffer mutably.
    ///
    /// # Returns
    /// A `Ref` that represents the mutable borrow to the buffer.
    #[inline]
    pub fn borrow_mut(&self) -> RefMut<EdgeBufferNode> { self.0.borrow_mut() }
}

impl Eq for EdgeBufferNodePtr {}

impl Hash for EdgeBufferNodePtr {
    fn hash<H: Hasher>(&self, state: &mut H) { self.0.as_ptr().hash(state); }
}

impl PartialEq for EdgeBufferNodePtr {
    fn eq(&self, other: &Self) -> bool { Rc::ptr_eq(&self.0, &other.0) }
}



/// Defines a node in the EdgeBuffer linked list.
#[derive(Clone, Debug)]
pub struct EdgeBufferNode {
    /// The Edge this node wraps.
    pub edge: Edge,
    /// The pointer to the next in the buffer.
    pub next: EdgeBufferNodeLink,
}

impl EdgeBufferNode {
    /// Constructor for the EdgeBufferNode that initializes it with the given Edge.
    ///
    /// # Arguments
    /// - `edge`: The Edge to put in the node.
    ///
    /// # Returns
    /// An EdgeBufferNodePtr that refers to the newly instantiated object.
    #[allow(clippy::new_ret_no_self)]
    #[inline]
    fn new(edge: Edge) -> EdgeBufferNodePtr { EdgeBufferNodePtr(Rc::new(RefCell::new(Self { edge, next: EdgeBufferNodeLink::None }))) }

    /// Helper function that asserts the given Edge is linearly connectible.
    ///
    /// # Arguments
    /// - `edge`: The Edge to analyse.
    ///
    /// # Returns
    /// Nothing, which, if it does, means the assertion succeeded.
    ///
    /// # Panics
    /// This function panics if the assertion fails.
    #[inline]
    fn assert_linear(edge: &Edge) {
        match edge {
            Edge::Node { .. } | Edge::Linear { .. } | Edge::Join { .. } | Edge::Call { .. } => {},
            edge => {
                panic!("Attempted to connect an edge of type '{edge:?}' linearly");
            },
        }
    }

    /// Helper function that asserts the given Edge is connectible as a branch.
    ///
    /// # Arguments
    /// - `edge`: The Edge to analyse.
    ///
    /// # Returns
    /// Nothing, which, if it does, means the assertion succeeded.
    ///
    /// # Panics
    /// This function panics if the assertion fails.
    #[inline]
    fn assert_branch(edge: &Edge) {
        match edge {
            Edge::Branch { .. } => {},
            edge => {
                panic!("Attempted to connect an edge of type '{edge:?}' branching");
            },
        }
    }

    /// Helper function that asserts the given Edge is connectible as parallel.
    ///
    /// # Arguments
    /// - `edge`: The Edge to analyse.
    ///
    /// # Returns
    /// Nothing, which, if it does, means the assertion succeeded.
    ///
    /// # Panics
    /// This function panics if the assertion fails.
    #[inline]
    fn assert_parallel(edge: &Edge) {
        match edge {
            Edge::Parallel { .. } => {},
            edge => {
                panic!("Attempted to connect an edge of type '{edge:?}' parallel");
            },
        }
    }

    /// Helper function that asserts the given Edge is connectible as a loop.
    ///
    /// # Arguments
    /// - `edge`: The Edge to analyse.
    ///
    /// # Returns
    /// Nothing, which, if it does, means the assertion succeeded.
    ///
    /// # Panics
    /// This function panics if the assertion fails.
    #[inline]
    fn assert_loop(edge: &Edge) {
        match edge {
            Edge::Loop { .. } => {},
            edge => {
                panic!("Attempted to connect an edge of type '{edge:?}' as a loop");
            },
        }
    }

    /// Helper function that asserts the given Edge is not connectible at all.
    ///
    /// # Arguments
    /// - `edge`: The Edge to analyse.
    ///
    /// # Returns
    /// Nothing, which, if it does, means the assertion succeeded.
    ///
    /// # Panics
    /// This function panics if the assertion fails.
    #[inline]
    fn assert_stop(edge: &Edge) {
        match edge {
            Edge::Stop { .. } | Edge::Return { .. } => {},
            edge => {
                panic!("Attempted to mark an edge of type '{edge:?}' as a stop node");
            },
        }
    }

    /// Connects this node to the given one using a linear connection.
    ///
    /// # Arguments
    /// - `other`: The pointer to the other node to connect to.
    ///
    /// # Panics
    /// This function panics if the underlying Edge semantically cannot connect linearly.
    fn connect_linear(&mut self, other: EdgeBufferNodePtr) {
        // Sanity check: only do if semantically correct
        Self::assert_linear(&self.edge);

        // If there was already a link, move it to the other link
        if self.next.is_some() {
            // Get the last pointer in the other branch
            let mut last: Cow<EdgeBufferNodePtr> = Cow::Borrowed(&other);
            loop {
                let next: Option<EdgeBufferNodePtr> = last.borrow().next();
                match next {
                    Some(next) => {
                        last = Cow::Owned(next);
                    },
                    None => {
                        break;
                    },
                }
            }

            // Sanity check this one can accept linear edges.
            let mut l: RefMut<EdgeBufferNode> = last.borrow_mut();
            Self::assert_linear(&l.edge);

            // Now set it
            mem::swap(&mut l.next, &mut self.next);
        }

        // We can set the link to the other branch
        self.next = EdgeBufferNodeLink::Linear(other);

        // Done
    }

    /// Connects this node to the given one using a branching connection.
    ///
    /// # Arguments
    /// - `true_branch`: The pointer to the node to connect to in the true-case (if any).
    /// - `false_branch`: The pointer to the node to connect to in the false-case (if any).
    /// - `next`: The pointer to the node to which both branches join (if any).
    ///
    /// # Panics
    /// This function panics if the underlying Edge semantically cannot connect as a branch.
    fn connect_branch(&mut self, true_branch: Option<EdgeBufferNodePtr>, false_branch: Option<EdgeBufferNodePtr>, next: Option<EdgeBufferNodePtr>) {
        // Sanity check: only do if semantically correct
        Self::assert_branch(&self.edge);

        // If there was already a link, move it to the next link
        if self.next.is_some() {
            // If there is no next, yes, that's tough
            if next.is_none() {
                panic!("Cannot transfer existing connection of type '{:?}' on branch when it has no 'next' part", self.next);
            }

            // Get the last pointer in the next branch
            let mut last: EdgeBufferNodePtr = next.as_ref().unwrap().clone();
            loop {
                let next: Option<EdgeBufferNodePtr> = last.borrow().next();
                match next {
                    Some(next) => {
                        last = next;
                    },
                    None => {
                        break;
                    },
                }
            }

            // Sanity check this one can accept linear edges.
            let mut l: RefMut<EdgeBufferNode> = last.borrow_mut();
            Self::assert_branch(&l.edge);

            // Now set it
            mem::swap(&mut l.next, &mut self.next);
        }

        // We can set the link to the other branch
        self.next = EdgeBufferNodeLink::Branch(true_branch, false_branch, next);

        // Done
    }

    /// Connects this node to the given one using a parallel connection.
    ///
    /// # Arguments
    /// - `branches`: The branches that are taken concurrently.
    /// - `join`: The pointer to the node that joins the parallel branches.
    ///
    /// # Panics
    /// This function panics if the underlying Edge semantically cannot connect as a parallel.
    fn connect_parallel(&mut self, branches: Vec<EdgeBufferNodePtr>, join: EdgeBufferNodePtr) {
        // Sanity check: only do if semantically correct
        Self::assert_parallel(&self.edge);

        // If there was already a link, move it to the other link
        if self.next.is_some() {
            // Get the last pointer in the other branch
            let mut last: Cow<EdgeBufferNodePtr> = Cow::Borrowed(&join);
            loop {
                let next: Option<EdgeBufferNodePtr> = last.borrow().next();
                match next {
                    Some(next) => {
                        last = Cow::Owned(next);
                    },
                    None => {
                        break;
                    },
                }
            }

            // Sanity check this one can accept parallel edges.
            let mut l: RefMut<EdgeBufferNode> = last.borrow_mut();
            Self::assert_parallel(&l.edge);

            // Now set it
            mem::swap(&mut l.next, &mut self.next);
        }

        // We can set the link to the other branch
        self.next = EdgeBufferNodeLink::Parallel(branches, join);
    }

    /// Connects this node to the given one as a looping node.
    ///
    /// # Arguments
    /// - `condition`: The branches that compute the condition at the start of every loop.
    /// - `body`: The branches that are taken repeatedly.
    /// - `next`: The branches to take when the loop has completed.
    ///
    /// # Panics
    /// This function panics if the underlying Edge semantically cannot connect as a parallel.
    fn connect_loop(&mut self, condition: EdgeBufferNodePtr, body: Option<EdgeBufferNodePtr>, next: Option<EdgeBufferNodePtr>) {
        // Sanity check: only do if semantically correct
        Self::assert_loop(&self.edge);

        // If there was already a link, move it to the other link
        if self.next.is_some() {
            // If there is no next, yes, that's tough
            if next.is_none() {
                panic!("Cannot transfer existing connection of type '{:?}' on loop when it has no 'next' part", self.next);
            }

            // Get the last pointer in the other branch
            let mut last: EdgeBufferNodePtr = next.as_ref().unwrap().clone();
            loop {
                let next: Option<EdgeBufferNodePtr> = last.borrow().next();
                match next {
                    Some(next) => {
                        last = next;
                    },
                    None => {
                        break;
                    },
                }
            }

            // Sanity check this one can accept parallel edges.
            let mut l: RefMut<EdgeBufferNode> = last.borrow_mut();
            Self::assert_loop(&l.edge);

            // Now set it
            mem::swap(&mut l.next, &mut self.next);
        }

        // We can set the link to the other branch
        self.next = EdgeBufferNodeLink::Loop(condition, body, next);
    }

    /// 'Cuts off' the branch by inserting a special 'no connection here (yet)' insert.
    ///
    /// # Panics
    /// This function panics if the underlying Edge semantically cannot connect linearly.
    fn connect_end(&mut self) {
        // Sanity check: only do if semantically correct
        Self::assert_linear(&self.edge);

        // Set the connection
        self.next = EdgeBufferNodeLink::End;
    }

    /// 'Cuts off' the branch by inserting a special 'no connection here' insert.
    ///
    /// # Panics
    /// This function panics if the underlying Edge can actually connect something (i.e., is not an `Edge::Stop` or `Edge::Return`).
    fn connect_stop(&mut self) {
        // Sanity check: only do if semantically correct
        Self::assert_stop(&self.edge);

        // Set the connection
        self.next = EdgeBufferNodeLink::Stop;
    }

    /// Returns the next node. Note that, in the case of non-linear connections, this actually returns the next node where the branch has joined again.
    ///
    /// # Returns
    /// The pointer to the next node.
    pub fn next(&self) -> Option<EdgeBufferNodePtr> {
        match &self.next {
            EdgeBufferNodeLink::Linear(next) => Some(next.clone()),
            EdgeBufferNodeLink::Branch(_, _, next) => next.clone(),
            EdgeBufferNodeLink::Parallel(_, next) => Some(next.clone()),
            EdgeBufferNodeLink::Loop(_, _, next) => next.clone(),
            EdgeBufferNodeLink::End => None,
            EdgeBufferNodeLink::Stop => None,
            EdgeBufferNodeLink::None => None,
        }
    }

    /// Returns whether this node is connect by end.
    #[inline]
    pub fn is_end(&self) -> bool { matches!(self.next, EdgeBufferNodeLink::Stop) }
}





/***** LIBRARY *****/
/// Defines an EdgeBuffer, which is a muteable buffer to which we can compile edges.
///
/// Every buffer may be thought of as a single 'stream' of operations. If it branches for whatever reason, typically, multiple EdgeBuffers are involved the define each of the streams.
///
/// Because an EdgeBuffer is a single stream, it is implemented as a LinkedList of edges. Any branch is represented as links to other buffers.
#[derive(Clone, Debug)]
pub struct EdgeBuffer {
    /// The EdgeBuffer is secretly a LinkedList of edges that link to the next one.
    start: Option<EdgeBufferNodePtr>,
    /// Points to the end of the LinkedList (if any).
    end:   Option<EdgeBufferNodePtr>,
}

impl EdgeBuffer {
    /// Constructor for the EdgeBuffer that initializes it to empty.
    ///
    /// # Returns
    /// An EdgeBufferPtr that refers to the newly instantiated object.
    #[inline]
    pub fn new() -> EdgeBuffer { Self { start: None, end: None } }

    /// Adds a new edge to the end of this EdgeBuffer.
    ///
    /// Note that the function itself is agnostic to the specific kind of edge. The only requirement is that, when using `EdgeBuffer::write()`, the last edge in the buffer can linearly connect to this one. Be aware of this when writing non-Linear edges using this function.
    ///
    /// # Arguments
    /// - `edge`: The Edge to append.
    ///
    /// # Returns
    /// Nothing, but does add it internally.
    pub fn write(&mut self, edge: Edge) {
        // Create a new EdgeBufferNode for this Edge and add it
        let node = EdgeBufferNode::new(edge);
        if self.start.is_none() {
            // If there is no start node yet, set it
            self.start = Some(node.clone());
            self.end = Some(node);
        } else {
            // We can simply add the connection
            self.end.as_ref().unwrap().borrow_mut().connect_linear(node.clone());
            self.end = Some(node);
        }
    }

    /// Adds a new edge to the end of this EdgeBuffer, although it is added _before_ any stop/return/jump whatever.
    ///
    /// Note that the function itself is agnostic to the specific kind of edge. The only requirement is that, when using `EdgeBuffer::write()`, the last non-returning edge in the buffer can linearly connect to this one. Be aware of this when writing non-Linear edges using this function.
    ///
    /// # Arguments
    /// - `edge`: The Edge to append.
    ///
    /// # Returns
    /// Nothing, but does add it internally.
    pub fn insert_at_end(&mut self, edge: Edge) {
        // Create a new EdgeBufferNode for this Edge and add it
        let node: EdgeBufferNodePtr = EdgeBufferNode::new(edge);
        if self.start.is_none() {
            // If there is no start node yet, set it
            self.start = Some(node.clone());
            self.end = Some(node);
        } else if matches!(self.end.as_ref().unwrap().borrow().next, EdgeBufferNodeLink::End) {
            // Simply insert it after the last one, carrying over the link
            let prev_link: EdgeBufferNodeLink = {
                let mut end: RefMut<EdgeBufferNode> = self.end.as_ref().unwrap().borrow_mut();

                // Get the last link
                let mut prev_link: EdgeBufferNodeLink = EdgeBufferNodeLink::None;
                std::mem::swap(&mut end.next, &mut prev_link);

                // Connect & insert
                end.connect_linear(node.clone());
                prev_link
            };
            self.end = Some(node.clone());

            // Insert the link
            node.borrow_mut().next = prev_link;
        } else if matches!(self.end.as_ref().unwrap().borrow().next, EdgeBufferNodeLink::Stop) {
            // In the case of stops it's slightly more complicated since we also have to move the previous node

            // Find the node preceding the last one
            let mut prev: Option<EdgeBufferNodePtr> = None;
            let mut this: Option<EdgeBufferNodePtr> = self.start.clone();
            while let Some(this_node) = this.clone() {
                // Borrow the node
                let this_node: Ref<EdgeBufferNode> = this_node.borrow();

                // Advance it
                if let Some(next_node) = this_node.next() {
                    prev = this;
                    this = Some(next_node);
                } else {
                    break;
                }
            }

            // Now match on whether we found a prev or not
            if let Some(prev) = prev {
                // There is, so connect from that node onwards
                let mut prev: RefMut<EdgeBufferNode> = prev.borrow_mut();

                // Get its link
                let mut prev_link: EdgeBufferNodeLink = EdgeBufferNodeLink::None;
                std::mem::swap(&mut prev.next, &mut prev_link);

                // Insert the new node
                prev.connect_linear(node.clone());
                node.borrow_mut().next = prev_link;
            } else {
                // There isn't so add as start
                self.start = Some(node.clone());
                node.borrow_mut().connect_linear(self.end.as_ref().unwrap().clone());
            }
        } else {
            // We can simply add the connection
            self.end.as_ref().unwrap().borrow_mut().connect_linear(node.clone());
            self.end = Some(node);
        }
    }

    /// Adds a new (linear) edge to the end of this EdgeBuffer, but one that loops back to an earlier point in the buffer.
    ///
    /// Note that the function itself is agnostic to the specific kind of edge. The only requirement is that, when using `EdgeBuffer::write()`, the last edge in the buffer can linearly connect to this one. Be aware of this when writing non-Linear edges using this function.
    ///
    /// # Arguments
    /// - `edge`: The Edge to append.
    /// - `target`: The EdgeNode to wrap back to.
    ///
    /// # Returns
    /// Nothing, but does add it internally.
    pub fn write_jump(&mut self, target: EdgeBufferNodePtr) {
        // Create a new EdgeBufferNode for this Edge and connect it to the new node
        let node: EdgeBufferNodePtr = EdgeBufferNode::new(Edge::Linear { instrs: vec![], next: usize::MAX });
        node.borrow_mut().connect_linear(target);

        // Add it
        if self.start.is_none() {
            // If there is no start node yet, set it
            self.start = Some(node.clone());
            self.end = Some(node);
        } else {
            // We can simply add the connection
            self.end.as_ref().unwrap().borrow_mut().connect_linear(node.clone());
            self.end = Some(node);
        }
    }

    /// Adds a new branch to the end of this EdgeBuffer.
    ///
    /// It will automatically be appended by an empty linear node that marks the 'joining' node of the Branch, unless there is a true and a false branch _and_ both are returning (i.e., feature a return-branch in all paths).
    ///
    /// Note that the function requires that the top edge on the buffer is linearly connectible. However, as a tradeoff, it also makes sure that it always is (as long as it doesn't return).
    ///
    /// # Arguments
    /// - `true_branch`: The Edges to take when the branch is taken (if any).
    /// - `false_branch`: The Edges to take when the branch is _not_ taken (if any).
    ///
    /// # Returns
    /// Nothing, but does append the buffer with a new branch structure.
    pub fn write_branch(&mut self, true_branch: Option<EdgeBuffer>, false_branch: Option<EdgeBuffer>) {
        // If either branch is empty, do not write it
        if (true_branch.is_none() || true_branch.as_ref().unwrap().start.is_none())
            && (false_branch.is_none() || false_branch.as_ref().unwrap().start.is_none())
        {
            return;
        }

        // Analyse if either branch returns
        let true_returns: bool = true_branch.is_some() && true_branch.as_ref().unwrap().fully_returns();
        let false_returns: bool = false_branch.is_some() && false_branch.as_ref().unwrap().fully_returns();

        // Prepare the 'next' node
        let next: Option<EdgeBufferNodePtr> =
            if !true_returns || !false_returns { Some(EdgeBufferNode::new(Edge::Linear { instrs: vec![], next: usize::MAX })) } else { None };

        // Take the start edges of both branches
        let true_start: Option<EdgeBufferNodePtr> = true_branch.map(|b| b.start).unwrap_or(None);
        let false_start: Option<EdgeBufferNodePtr> = false_branch.map(|b| b.start).unwrap_or(None);

        // Now create a branch node with it all
        let branch: EdgeBufferNodePtr =
            EdgeBufferNode::new(Edge::Branch { true_next: usize::MAX, false_next: Some(usize::MAX), merge: Some(usize::MAX) });
        branch.borrow_mut().connect_branch(true_start, false_start, next.clone());

        // Finally, add it as linear to the end of this buffer
        let next: EdgeBufferNodePtr = next.unwrap_or_else(|| branch.clone());
        match &self.end {
            Some(end) => {
                end.borrow_mut().connect_linear(branch);
                self.end = Some(next);
            },
            None => {
                self.start = Some(branch);
                self.end = Some(next);
            },
        }
    }

    /// Adds a new parallel to the end of this EdgeBuffer.
    ///
    /// It will automatically be appended by a join.
    ///
    /// Note that the function requires that the top edge on the buffer is linearly connectible. However, as a tradeoff, it also makes sure that it always is after this call.
    ///
    /// # Arguments
    /// - `branches`: The Edges that represent each of the branches to run in parallel.
    /// - `merge`: The MergeStrategy that the generated join-edge needs to implement.
    ///
    /// # Returns
    /// Nothing, but does append the buffer with a new parallel structure.
    pub fn write_parallel(&mut self, branches: Vec<EdgeBuffer>, merge: MergeStrategy) {
        // If there are no branches, do not write it
        if branches.is_empty() {
            return;
        }

        // Prepare the 'next' node
        let next: EdgeBufferNodePtr = EdgeBufferNode::new(Edge::Join { merge, next: usize::MAX });

        // Now create a parallel node with it all
        let parallel: EdgeBufferNodePtr =
            EdgeBufferNode::new(Edge::Parallel { branches: (0..branches.len()).map(|_| usize::MAX).collect(), merge: usize::MAX });
        parallel.borrow_mut().connect_parallel(branches.into_iter().filter_map(|b| b.start).collect(), next.clone());

        // Finally, add it as linear to the end of this buffer
        match &self.end {
            Some(end) => {
                end.borrow_mut().connect_linear(parallel);
                self.end = Some(next);
            },
            None => {
                self.start = Some(parallel);
                self.end = Some(next);
            },
        }
    }

    /// Adds a new loop to the end of this EdgeBuffer.
    ///
    /// It will automatically be appended by a 'next edge to take'.
    ///
    /// Note that the function requires that the top edge on the buffer is linearly connectible. However, as a tradeoff, it also makes sure that it always is after this call.
    ///
    /// # Arguments
    /// - `condition`: The Edges that represent the condition computation.
    /// - `consequence`: The body of Edges that are actually repeated.
    ///
    /// # Returns
    /// Nothing, but does append the buffer with a new loop structure.
    pub fn write_loop(&mut self, condition: EdgeBuffer, consequence: EdgeBuffer) {
        // Fail if the condition is empty
        if condition.start.is_none() {
            panic!("Got empty condition in a loop-edge");
        }

        // Analyse if the main branch returns
        let body_returns: bool = consequence.fully_returns();

        // Prepare the 'next' node
        let next: Option<EdgeBufferNodePtr> =
            if !body_returns { Some(EdgeBufferNode::new(Edge::Linear { instrs: vec![], next: usize::MAX })) } else { None };

        // Take the start edges of the condition and consequence
        let cond_start: EdgeBufferNodePtr = match condition.start {
            Some(start) => start,
            // Otherwise, clone the edgebufferbode which _must_ return
            None => next.clone().expect("Got an empty condition-branch but also empty next; this should never happen!"),
        };
        let cons_start: Option<EdgeBufferNodePtr> = consequence.start;

        // Now create a loop node with it all
        let eloop: EdgeBufferNodePtr = EdgeBufferNode::new(Edge::Loop { cond: usize::MAX, body: usize::MAX, next: Some(usize::MAX) });
        eloop.borrow_mut().connect_loop(cond_start, cons_start, next.clone());

        // Finally, add it as linear to the end of this buffer
        let next: EdgeBufferNodePtr = next.unwrap_or_else(|| eloop.clone());
        match &self.end {
            Some(end) => {
                end.borrow_mut().connect_linear(eloop);
                self.end = Some(next);
            },
            None => {
                self.start = Some(eloop);
                self.end = Some(next);
            },
        }
    }

    /// Adds a new end connection to the end of this EdgeBuffer.
    ///
    /// Note that the function requires that the top edge on the buffer is linearly connectible. Because an end doesn't connect, that means no `EdgeBuffer::write*()` can be used again.
    ///
    /// # Arguments
    /// - `end_edge`: The edge that forms the actual end node. May be anything that linearly connects.
    ///
    /// # Returns
    /// Nothing, but does append the buffer with a new end structure.
    pub fn write_end(&mut self) {
        // Add it as linear to the end of this buffer
        match &self.end {
            Some(e) => {
                e.borrow_mut().connect_end();
            },
            None => {
                panic!("Cannot connect 'End' to an empty buffer.")
            },
        }
    }

    /// Adds a new stop to the end of this EdgeBuffer.
    ///
    /// Note that the function requires that the top edge on the buffer is linearly connectible. Because an end doesn't connect, that means no `EdgeBuffer::write*()` can be used again.
    ///
    /// # Arguments
    /// - `stop_edge`: The edge that forms the actual end node. May only be 'Edge::Return` or `Edge::Stop`.
    ///
    /// # Returns
    /// Nothing, but does append the buffer with a new end structure.
    pub fn write_stop(&mut self, stop_edge: Edge) {
        // Create the end node
        let end: EdgeBufferNodePtr = EdgeBufferNode::new(stop_edge);
        end.borrow_mut().connect_stop();

        // Add it as linear to the end of this buffer
        match &self.end {
            Some(e) => {
                e.borrow_mut().connect_linear(end.clone());
                self.end = Some(end);
            },
            None => {
                self.start = Some(end.clone());
                self.end = Some(end);
            },
        }
    }

    /// Appends the given EdgeBuffer to this one.
    ///
    /// # Arguments
    /// - `other`: The EdgeBuffer to consume and append.
    ///
    /// # Returns
    /// Nothing, but does append the buffer with the new struct in the other buffer.
    pub fn append(&mut self, other: EdgeBuffer) {
        // Get the start node from the other, if any
        let start: EdgeBufferNodePtr = match other.start {
            Some(start) => start,
            None => {
                return;
            },
        };

        // Find the end of the buffer
        // Clippy: Hash of EdgeBufferNodePtr is not mutable
        #[allow(clippy::mutable_key_type)]
        let mut done: HashSet<EdgeBufferNodePtr> = HashSet::with_capacity(32);
        let mut end: EdgeBufferNodePtr = start.clone();
        loop {
            let next: Option<EdgeBufferNodePtr> = end.borrow().next();
            match next {
                Some(next) => {
                    // Only continue if not done before
                    if done.contains(&end) {
                        break;
                    }
                    done.insert(next.clone());

                    // Set it as the next node to iterate.
                    end = next;
                },
                None => {
                    break;
                },
            }
        }

        // Write the start to ourselves
        if self.start.is_none() {
            // If there is no start node yet, set it
            self.start = Some(start);
            self.end = Some(end);
        } else {
            // We can simply add the connection
            self.end.as_ref().unwrap().borrow_mut().connect_linear(start);
            self.end = Some(end);
        }
    }

    /// Merges all of the consecutive linear edges in this buffer to one edge.
    ///
    /// # Returns
    /// Nothing, but does merge some edges if they are consecutive and linear.
    pub fn merge_linear(&mut self) {
        // Start iterating over our nodes
        let mut last_lin: Option<EdgeBufferNodePtr> = None;
        let mut this: Option<EdgeBufferNodePtr> = self.start.clone();
        while let Some(node) = this.take() {
            // Get the node
            let mut n: RefMut<EdgeBufferNode> = node.borrow_mut();

            // Do special stuff if it's linear
            if let Edge::Linear { instrs, .. } = &mut n.edge {
                // Either set it, or merge it
                if let Some(last_lin) = &mut last_lin {
                    // We merge it
                    let mut ln: RefMut<EdgeBufferNode> = last_lin.borrow_mut();
                    if let Edge::Linear { instrs: last_instrs, .. } = &mut ln.edge {
                        last_instrs.append(instrs);
                    } else {
                        panic!("last_lin should never be a non-Edge::Linear!");
                    }

                    // Now remove the second edge from the edge buffer
                    ln.next = n.next.clone();
                } else {
                    // We set it
                    last_lin = Some(node.clone());
                }
            } else {
                // No more linear edge
                last_lin = None;
            }

            // Go to the next one
            this = n.next();
        }
    }

    /// Helper function that traverses the EdgeBuffer to see if it fully returns.
    ///
    /// # Returns
    /// Whether or not this buffer fully returns (true) or not (false).
    pub fn fully_returns(&self) -> bool {
        // Clippy: EdgeBufferNodePtr hash implementation only hashes the pointer, not the content
        // of the key, so the hash of the pointer should stay consistent.
        #[allow(clippy::mutable_key_type)]
        let mut done: HashSet<EdgeBufferNodePtr> = HashSet::new();

        // Iterate as long as we can
        let mut this: Option<EdgeBufferNodePtr> = self.start.clone();
        while this.is_some() {
            // Attempt to continue to branch
            this = {
                let node: Ref<EdgeBufferNode> = this.as_ref().unwrap().borrow();
                let this_next: Option<EdgeBufferNodePtr>;
                match &node.next {
                    EdgeBufferNodeLink::Linear(next) => {
                        // Make sure we did not do the next yet
                        if done.contains(next) {
                            return false;
                        }
                        done.insert(next.clone());
                        this_next = Some(next.clone());
                    },
                    EdgeBufferNodeLink::Branch(_, _, next) => {
                        // If 'next' is none, then it returns; otherwise, we know both of the branches don't, so continue with next
                        match next {
                            Some(next) => {
                                if done.contains(next) {
                                    return false;
                                }
                                done.insert(next.clone());
                                this_next = Some(next.clone());
                            },
                            None => {
                                return true;
                            },
                        };
                    },
                    EdgeBufferNodeLink::Parallel(_, next) => {
                        // Always continue since parallels cannot return
                        if done.contains(next) {
                            return false;
                        }
                        done.insert(next.clone());
                        this_next = Some(next.clone());
                    },
                    EdgeBufferNodeLink::Loop(_, _, next) => {
                        // If 'next' is none, then it returns; otherwise, we know the loop doesn't, so continue
                        match next {
                            Some(next) => {
                                if done.contains(next) {
                                    return false;
                                }
                                done.insert(next.clone());
                                this_next = Some(next.clone());
                            },
                            None => {
                                return true;
                            },
                        };
                    },
                    EdgeBufferNodeLink::End => {
                        // Resolved; does not return
                        return false;
                    },
                    EdgeBufferNodeLink::Stop => {
                        // Yep this one returns, I'd say
                        return true;
                    },

                    EdgeBufferNodeLink::None => {
                        // Unresolved; does not return
                        return false;
                    },
                };
                this_next
            };
        }

        // We made it through so it's not fully returning
        false
    }

    /// Returns the start node of the EdgeBuffer, if any. This may be used for iteration.
    pub fn start(&self) -> &Option<EdgeBufferNodePtr> { &self.start }
}

impl Default for EdgeBuffer {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl From<EdgeBufferNodePtr> for EdgeBuffer {
    fn from(value: EdgeBufferNodePtr) -> Self {
        // Find the end of the given array
        let mut end: EdgeBufferNodePtr = value.clone();
        loop {
            let next: Option<EdgeBufferNodePtr> = end.borrow().next();
            match next {
                Some(next) => {
                    end = next;
                },
                None => {
                    break;
                },
            }
        }

        // Use that to mark the start and end of the new Buffer
        Self { start: Some(value), end: Some(end) }
    }
}

impl From<&EdgeBufferNodePtr> for EdgeBuffer {
    fn from(value: &EdgeBufferNodePtr) -> Self {
        // Find the end of the given array
        let mut end: EdgeBufferNodePtr = value.clone();
        loop {
            let next: Option<EdgeBufferNodePtr> = end.borrow().next();
            match next {
                Some(next) => {
                    end = next;
                },
                None => {
                    break;
                },
            }
        }

        // Use that to mark the start and end of the new Buffer
        Self { start: Some(value.clone()), end: Some(end) }
    }
}
