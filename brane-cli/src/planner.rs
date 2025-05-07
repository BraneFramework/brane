//  PLANNER.rs
//    by Lut99
//
//  Created:
//    24 Oct 2022, 16:40:21
//  Last edited:
//    14 Nov 2024, 17:58:30
//  Auto updated?
//    Yes
//
//  Description:
//!   A very trivial planner, that simple plans every dataset to run on
//!   'localhost'.
//

use std::collections::{HashMap, HashSet};
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;

use brane_tsk::errors::PlanError;
use brane_tsk::spec::{LOCALHOST, Planner};
use log::debug;
use parking_lot::Mutex;
use specifications::data::{AccessKind, AvailabilityKind, DataIndex, DataName};
use specifications::wir::{Edge, SymTable, Workflow};


/***** HELPER FUNCTIONS *****/
/// Helper function that plans the given list of edges.
///
/// # Arguments
/// - `table`: The SymbolTable these edges live in.
/// - `edges`: The given list to plan.
/// - `dindex`: The DataIndex we use to resolve data references.
/// - `pc`: The started index for the program counter. Should be '0' when called manually, the rest is handled during recursion.
/// - `merge`: If given, then we will stop analysing once we reach that point.
/// - `deferred`: Whether or not to show errors when an intermediate result is not generated yet (false) or not (true).
/// - `done`: A list we use to keep track of edges we've already analyzed (to prevent endless loops).
///
/// # Returns
/// Nothing, but does change the given list.
///
/// # Errors
/// This function may error if the given list of edges was malformed (usually due to unknown or inaccessible datasets or results).
fn plan_edges(
    table: &mut SymTable,
    edges: &mut [Edge],
    dindex: &Arc<DataIndex>,
    pc: usize,
    merge: Option<usize>,
    deferred: bool,
    done: &mut HashSet<usize>,
) -> Result<(), PlanError> {
    // We cannot get away simply examining all edges in-order; we have to follow their execution structure
    let mut pc: usize = pc;
    while pc < edges.len() && (merge.is_none() || pc != merge.unwrap()) {
        // Match on the edge to progress
        let edge: &mut Edge = &mut edges[pc];
        if done.contains(&pc) {
            break;
        }
        done.insert(pc);
        match edge {
            // This is the node where it all revolves around, in the end
            Edge::Node { task, at, input, result, next, .. } => {
                // We simply assign all locations to localhost
                *at = Some(LOCALHOST.into());
                debug!("Task '{}' planned at '{}'", table.tasks[*task].name(), LOCALHOST);

                // For all dataset/intermediate result inputs, we assert they are available on the local location
                for (name, avail) in input {
                    OfflinePlanner::plan_data(name, avail, dindex, &table.results, deferred)?;
                }

                // Then, we make the intermediate result available at the location where the function is being run (if there is any)
                if let Some(name) = result {
                    // Insert an entry in the list detailling where to access it and how
                    debug!("Making intermediate result '{}' accessible after execution of '{}' on '{}'", name, table.tasks[*task].name(), LOCALHOST);
                    table.results.insert(name.clone(), LOCALHOST.into());
                }

                // Finally, don't forget to move to the next one
                pc = *next;
            },
            Edge::Linear { next, .. } => {
                // Simply move to the next one
                pc = *next;
            },
            Edge::Stop {} => {
                // We've reached the end of the program
                break;
            },

            Edge::Branch { true_next, false_next, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let true_next: usize = *true_next;
                let false_next: Option<usize> = *false_next;
                let merge: Option<usize> = *merge;

                // First analyse the true_next branch, until it reaches the merge (or quits)
                plan_edges(table, edges, dindex, true_next, merge, deferred, done)?;
                // If there is a false branch, do that one too
                if let Some(false_next) = false_next {
                    plan_edges(table, edges, dindex, false_next, merge, deferred, done)?;
                }

                // If there is a merge, continue there; otherwise, we can assume that we've returned fully in the branch
                if let Some(merge) = merge {
                    pc = merge;
                } else {
                    break;
                }
            },
            Edge::Parallel { branches, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let branches: Vec<usize> = branches.clone();
                let merge: usize = *merge;

                // Analyse any of the branches
                for b in branches {
                    // No merge needed since we can be safe in assuming parallel branches end with returns
                    plan_edges(table, edges, dindex, b, None, deferred, done)?;
                }

                // Continue at the merge
                pc = merge;
            },
            Edge::Join { next, .. } => {
                // Move to the next instruction (joins are not relevant for planning)
                pc = *next;
            },

            Edge::Loop { cond, body, next, .. } => {
                // Dereference the numbers to dodge the borrow checker
                let cond: usize = *cond;
                let body: usize = *body;
                let next: Option<usize> = *next;

                // Run the conditions and body in a first pass, with deferation enabled, to do as much as we can
                plan_edges(table, edges, dindex, cond, Some(body), true, done)?;
                plan_edges(table, edges, dindex, body, Some(cond), true, done)?;

                // Then we run through the condition and body again to resolve any unknown things
                plan_deferred(table, edges, cond, Some(body), &mut HashSet::new())?;
                plan_deferred(table, edges, cond, Some(cond), &mut HashSet::new())?;

                // When done, move to the next if there is any (otherwise, the body returns and then so can we)
                if let Some(next) = next {
                    pc = next;
                } else {
                    break;
                }
            },

            Edge::Call { input: _, result: _, next } => {
                // We can ignore calls for now, but...
                // TODO: Check if this planning works across functions *screams*
                pc = *next;
            },
            Edge::Return { result: _ } => {
                // We will stop analysing here too, since we assume we have been called in recursion mode or something
                break;
            },
        }
    }

    // // We can ignore the structure; we can get away simply examining the edges in-order
    // for (i, e) in edges.iter_mut().enumerate() {
    //     if let Edge::Node{ task, at, input, result, .. } = e {
    //         debug!("Planning task '{}' (edge {})...", table.tasks[*task].name(), i);

    //         // We simply assign all locations to localhost
    //         *at = Some(LOCALHOST.into());
    //         debug!("Task '{}' planned at '{}'", table.tasks[*task].name(), LOCALHOST);

    //         // For all dataset/intermediate result inputs, we assert they are available on the local location
    //         for (name, avail) in input {
    //             OfflinePlanner::plan_data(name, avail, dindex, &table.results)?;
    //         }

    //         // Then, we make the intermediate result available at the location where the function is being run (if there is any)
    //         if let Some(name) = result {
    //             // Insert an entry in the list detailling where to access it and how
    //             debug!("Making intermediate result '{}' accessible after execution of '{}' on '{}'", name, table.tasks[*task].name(), LOCALHOST);
    //             table.results.insert(name.clone(), LOCALHOST.into());
    //         }
    //     }
    // }

    // Done
    Ok(())
}

/// Helper function that populates the availability of results right after a first planning round, to catch those that needed to be deferred (i.e., loop variables).
///
/// # Arguments
/// - `table`: The SymbolTable these edges live in.
/// - `edges`: The given list to plan.
/// - `pc`: The started index for the program counter. Should be '0' when called manually, the rest is handled during recursion.
/// - `merge`: If given, then we will stop analysing once we reach that point.
///
/// # Returns
/// Nothing, but does change the given list.
///
/// # Errors
/// This function may error if there were still results that couldn't be populated even after we've seen all edges.
fn plan_deferred(table: &SymTable, edges: &mut [Edge], pc: usize, merge: Option<usize>, done: &mut HashSet<usize>) -> Result<(), PlanError> {
    // We cannot get away simply examining all edges in-order; we have to follow their execution structure
    let mut pc: usize = pc;
    while pc < edges.len() && (merge.is_none() || pc != merge.unwrap()) {
        // Match on the edge to progress
        let edge: &mut Edge = &mut edges[pc];
        if done.contains(&pc) {
            break;
        }
        done.insert(pc);
        match edge {
            // This is the node where it all revolves around, in the end
            Edge::Node { input, next, .. } => {
                // This next trick involves checking if the node has any unresolved results as input, then trying to resolve them
                for (name, avail) in input {
                    // Continue if it already has a resolved availability
                    if avail.is_some() {
                        continue;
                    }

                    // Get the name of the result
                    if let DataName::IntermediateResult(name) = name {
                        // We have to know of it, i.e., it has to be declared somewhere where it makes sense
                        if let Some(loc) = table.results.get(name) {
                            // Match on whether it is available locally or not
                            if LOCALHOST == loc {
                                debug!("Input intermediate result '{}' is locally available", name);
                                *avail = Some(AvailabilityKind::Available { how: AccessKind::File { path: PathBuf::from(name) } });
                            } else {
                                // We don't download, so always unavailable
                                return Err(PlanError::IntermediateResultUnavailable { name: name.clone(), locs: vec![] });
                            }
                        } else {
                            return Err(PlanError::UnknownIntermediateResult { name: name.clone() });
                        }
                    } else {
                        panic!("Should never see an unresolved Data in the workflow");
                    }
                }

                // Finally, don't forget to move to the next one
                pc = *next;
            },
            Edge::Linear { next, .. } => {
                // Simply move to the next one
                pc = *next;
            },
            Edge::Stop {} => {
                // We've reached the end of the program
                break;
            },

            Edge::Branch { true_next, false_next, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let true_next: usize = *true_next;
                let false_next: Option<usize> = *false_next;
                let merge: Option<usize> = *merge;

                // First analyse the true_next branch, until it reaches the merge (or quits)
                plan_deferred(table, edges, true_next, merge, done)?;
                // If there is a false branch, do that one too
                if let Some(false_next) = false_next {
                    plan_deferred(table, edges, false_next, merge, done)?;
                }

                // If there is a merge, continue there; otherwise, we can assume that we've returned fully in the branch
                if let Some(merge) = merge {
                    pc = merge;
                } else {
                    break;
                }
            },
            Edge::Parallel { branches, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let branches: Vec<usize> = branches.clone();
                let merge: usize = *merge;

                // Analyse any of the branches
                for b in branches {
                    // No merge needed since we can be safe in assuming parallel branches end with returns
                    plan_deferred(table, edges, b, None, done)?;
                }

                // Continue at the merge
                pc = merge;
            },
            Edge::Join { next, .. } => {
                // Move to the next instruction (joins are not relevant for planning)
                pc = *next;
            },

            Edge::Loop { cond, body, next, .. } => {
                // Dereference the numbers to dodge the borrow checker
                let cond: usize = *cond;
                let body: usize = *body;
                let next: Option<usize> = *next;

                // We only have to analyse further deferrence; the actual planning should have been done before `plan_deferred()` is called
                plan_deferred(table, edges, cond, Some(body), done)?;
                plan_deferred(table, edges, cond, Some(cond), done)?;

                // When done, move to the next if there is any (otherwise, the body returns and then so can we)
                if let Some(next) = next {
                    pc = next;
                } else {
                    break;
                }
            },

            Edge::Call { input: _, result: _, next } => {
                // We can ignore calls for now, but...
                // TODO: Check if this planning works across functions *screams*
                pc = *next;
            },
            Edge::Return { result: _ } => {
                // We will stop analysing here too, since we assume we have been called in recursion mode or something
                break;
            },
        }
    }

    // Done
    Ok(())
}





/***** LIBRARY *****/
/// The planner is in charge of assigning locations to tasks in a workflow. This one is very simple, assigning 'localhost' to whatever it sees.
#[derive(Debug)]
pub struct OfflinePlanner {
    /// The local data index to resolve datasets with.
    data_index:  Arc<DataIndex>,
    /// The results we planned last time (or whatever).
    pub results: Arc<Mutex<HashMap<String, String>>>,
}

impl OfflinePlanner {
    /// Constructor for the OfflinePlanner.
    ///
    /// # Arguments
    /// - `data_index`: The DataIndex that is used to resolve datasets at plantime.
    /// - `results`: A map of results to where they are, which we planned last time around.
    ///
    /// # Returns
    /// A new OfflinePlanner instance.
    #[inline]
    pub fn new(data_index: Arc<DataIndex>, results: Arc<Mutex<HashMap<String, String>>>) -> Self { Self { data_index, results } }

    /// Plans the given task offline.
    ///
    /// # Arguments
    /// - `name`: The name of the dataset or intermediate result, as a DataName (so we can distinguish between the two).
    /// - `avail`: The availability for this dataset that we will be updating.
    /// - `dindex`: The DataIndex we use to see what datasets are actually available where.
    /// - `results`: The map of results that are known in this workflow.
    /// - `deferred`: If `true`, then will not error if we failed to find a result yet (its declaration might come later, in that case).
    ///
    /// # Returns
    /// Nothing, but does change the dataset's availability.
    pub fn plan_data(
        name: &DataName,
        avail: &mut Option<AvailabilityKind>,
        dindex: &Arc<DataIndex>,
        results: &HashMap<String, String>,
        deferred: bool,
    ) -> Result<(), PlanError> {
        match name {
            DataName::Data(name) => {
                if let Some(info) = dindex.get(name) {
                    // Check if it is local or remote
                    if let Some(access) = info.access.get(LOCALHOST) {
                        debug!("Input dataset '{}' is locally available", name);
                        *avail = Some(AvailabilityKind::Available { how: access.clone() });
                    } else {
                        // We don't download, so always unavailable
                        return Err(PlanError::DatasetUnavailable { name: name.clone(), locs: vec![] });
                    }
                } else {
                    return Err(PlanError::UnknownDataset { name: name.clone() });
                }
            },

            DataName::IntermediateResult(name) => {
                // We have to know of it, i.e., it has to be declared somewhere where it makes sense
                if let Some(loc) = results.get(name) {
                    // Match on whether it is available locally or not
                    if LOCALHOST == loc {
                        debug!("Input intermediate result '{}' is locally available", name);
                        *avail = Some(AvailabilityKind::Available { how: AccessKind::File { path: PathBuf::from(name) } });
                    } else {
                        // We don't download, so always unavailable
                        return Err(PlanError::IntermediateResultUnavailable { name: name.clone(), locs: vec![] });
                    }
                } else if !deferred {
                    return Err(PlanError::UnknownIntermediateResult { name: name.clone() });
                } else {
                    debug!("Input intermediate result '{}' is not yet available, but it might be later (deferred)", name);
                }
            },
        }

        // Done
        Ok(())
    }
}

#[async_trait::async_trait]
impl Planner for OfflinePlanner {
    async fn plan(&self, workflow: specifications::wir::Workflow) -> Result<Workflow, PlanError> {
        let mut workflow = workflow;

        // Get the symbol table muteable, so we can... mutate... it
        let mut table: Arc<SymTable> = Arc::new(SymTable::new());
        mem::swap(&mut workflow.table, &mut table);
        let mut table: SymTable = Arc::try_unwrap(table).unwrap();

        // Update the table with results from last time 'round
        table.results.extend(self.results.lock().iter().map(|(k, v)| (k.clone(), v.clone())));

        // Do the main edges first
        {
            // Start by getting a list of all the edges
            let mut edges: Arc<Vec<Edge>> = Arc::new(vec![]);
            mem::swap(&mut workflow.graph, &mut edges);
            let mut edges: Vec<Edge> = Arc::try_unwrap(edges).unwrap();

            // Plan them
            debug!("Planning main edges...");
            plan_edges(&mut table, &mut edges, &self.data_index, 0, None, false, &mut HashSet::new())?;

            // Move the edges back
            let mut edges: Arc<Vec<Edge>> = Arc::new(edges);
            mem::swap(&mut edges, &mut workflow.graph);
        }

        // Then we do the function edges
        {
            // Start by getting the map
            let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(HashMap::new());
            mem::swap(&mut workflow.funcs, &mut funcs);
            let mut funcs: HashMap<usize, Vec<Edge>> = Arc::try_unwrap(funcs).unwrap();

            // Iterate through all of the edges
            for (idx, edges) in &mut funcs {
                debug!("Planning '{}' edges...", table.funcs[*idx].name);
                plan_edges(&mut table, edges, &self.data_index, 0, None, false, &mut HashSet::new())?;
            }

            // Put the map back
            let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(funcs);
            mem::swap(&mut funcs, &mut workflow.funcs);
        }

        // Flush the results back to the internal results table
        self.results.lock().clone_from(&table.results);

        // Then, put the table back
        let mut table: Arc<SymTable> = Arc::new(table);
        mem::swap(&mut table, &mut workflow.table);

        // Done
        debug!("Planning success");
        Ok(workflow)
    }
}
