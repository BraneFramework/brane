//  PLANNER.rs
//    by Lut99
//
//  Created:
//    25 Oct 2022, 11:35:00
//  Last edited:
//    08 Feb 2024, 17:33:49
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a planner for the instance use-case.
//


/***** LIBRARY *****/
use std::collections::{HashMap, HashSet};
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_recursion::async_recursion;
use brane_ast::Workflow;
use brane_ast::ast::{ComputeTaskDef, Edge, SymTable, TaskDef};
use brane_ast::locations::Locations;
use brane_cfg::info::Info as _;
use brane_cfg::infra::{InfraFile, InfraLocation};
use brane_cfg::node::{CentralConfig, NodeConfig};
use brane_prx::client::ProxyClient;
use brane_tsk::api::get_data_index;
use brane_tsk::errors::PlanError;
use error_trace::trace;
use log::{debug, error, info};
use rand::prelude::IteratorRandom;
use serde_json::Value;
use specifications::address::Address;
use specifications::data::{AccessKind, AvailabilityKind, DataIndex, DataName, PreprocessKind};
use specifications::package::Capability;
use specifications::planning::{PlanningDeniedReply, PlanningReply, PlanningRequest};
use specifications::profiling::ProfileReport;
use specifications::working::{CheckReply, CheckWorkflowRequest, JobServiceClient};
use warp::http::StatusCode;
use warp::reject::Rejection;
use warp::reply::Response;

use crate::context::Context;


/***** CONSTANTS *****/
/// Time that a session has to be inactive before we deleted it (in seconds)
const SESSION_TIMEOUT_S: u64 = 12 * 3600;





/***** HELPER MACROS *****/
/// Sends back an error as a Response.
macro_rules! err_response {
    (bad_request $(,)? $($msg:tt)* ) => {{
        let msg: String = format!($($msg)*);
        debug!("{msg}");
        let mut res: Response = Response::new(msg.into());
        *res.status_mut() = StatusCode::BAD_REQUEST;
        Ok(res)
    }};

    (internal_error $(,)? $($msg:tt)* ) => {{
        error!($($msg)*);
        let mut res: Response = Response::new("An internal server error has occurred".into());
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        Ok(res)
    }};

    (unauthorized $(,)? $req:expr ) => {{
        let mut res: Response = Response::new($req);
        *res.status_mut() = StatusCode::UNAUTHORIZED;
        Ok(res)
    }};
}





/***** HELPER FUNCTIONS *****/
/// Helper function that plans the given list of edges.
///
/// # Arguments
/// - `table`: The SymbolTable where this edge lives in.
/// - `edges`: The given list to plan.
/// - `api_addr`: The address where we can reach the `brane-api` service on. Used for asserting that the target domain supports what the package needs.
/// - `dindex`: The DataIndex we use to resolve data references.
/// - `infra`: The infrastructure to resolve locations.
/// - `pc`: The initial value for the program counter. You should use '0' if you're calling this function.
/// - `merge`: The number of the edge until which we will run. You should use 'None' if you're calling this function.
/// - `deferred`: Whether or not to show errors when an intermediate result is not generated yet (false) or not (true).
/// - `done`: A list we use to keep track of edges we've already analyzed (to prevent endless loops).
///
/// # Returns
/// Nothing, but does change the given list.
///
/// # Errors
/// This function may error if the given list of edges was malformed (usually due to unknown or inaccessible datasets or results).
#[allow(clippy::too_many_arguments)]
#[async_recursion]
async fn plan_edges(
    table: &mut SymTable,
    edges: &mut [Edge],
    api_addr: &Address,
    dindex: &DataIndex,
    infra: &InfraFile,
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
            Edge::Node { task, locs, at, input, result, metadata: _, next } => {
                // This is the node where it all revolves around, in the end
                debug!("Planning task '{}' (edge {})...", table.tasks[*task].name(), pc);

                // If everything is allowed, we make it one easier for the planner by checking we happen to find only one occurrance based on the datasets
                if locs.is_all() {
                    // Search all of the input to collect a list of possible locations
                    let mut data_locs: Vec<&String> = vec![];
                    for (d, _) in input.iter() {
                        // We only take data into account (for now, at least)
                        if let DataName::Data(name) = d {
                            // Attempt to find it
                            if let Some(info) = dindex.get(name) {
                                // Simply add all locations where it lives
                                data_locs.append(&mut info.access.keys().collect::<Vec<&String>>());
                            } else {
                                return Err(PlanError::UnknownDataset { name: name.clone() });
                            }
                        }
                    }

                    // If there is only one location, then we override locs
                    if data_locs.len() == 1 {
                        *locs = Locations::Restricted(vec![data_locs[0].clone()]);
                    }
                }

                // We resolve all locations by collapsing them to the only possibility indicated by the user. More or less than zero? Error!
                if !locs.is_restrictive() || locs.restricted().len() != 1 {
                    return Err(PlanError::AmbigiousLocationError { name: table.tasks[*task].name().into(), locs: locs.clone() });
                }
                let location: &str = &locs.restricted()[0];

                // Fetch the list of capabilities supported by the planned location
                let address: String = format!("{api_addr}/infra/capabilities/{location}");
                let res: reqwest::Response = match reqwest::get(&address).await {
                    Ok(req) => req,
                    Err(err) => {
                        return Err(PlanError::RequestError { address, err });
                    },
                };
                if !res.status().is_success() {
                    return Err(PlanError::RequestFailure { address, code: res.status(), err: res.text().await.ok() });
                }
                let capabilities: String = match res.text().await {
                    Ok(caps) => caps,
                    Err(err) => {
                        return Err(PlanError::RequestBodyError { address, err });
                    },
                };
                let capabilities: HashSet<Capability> = match serde_json::from_str(&capabilities) {
                    Ok(caps) => caps,
                    Err(err) => {
                        return Err(PlanError::RequestParseError { address, raw: capabilities, err });
                    },
                };

                // Assert that this is what we need
                if let TaskDef::Compute(ComputeTaskDef { function, requirements, .. }) = &table.tasks[*task] {
                    if !capabilities.is_superset(requirements) {
                        return Err(PlanError::UnsupportedCapabilities {
                            task:     function.name.clone(),
                            loc:      location.into(),
                            expected: requirements.clone(),
                            got:      capabilities,
                        });
                    }
                } else {
                    panic!("Non-compute tasks are not (yet) supported.");
                };

                // It checks out, plan it
                *at = Some(location.into());
                debug!("Task '{}' planned at '{}'", table.tasks[*task].name(), location);

                // For all dataset/intermediate result inputs, we check if these are available on the planned location.
                for (name, avail) in input {
                    match name {
                        DataName::Data(dname) => {
                            if let Some(info) = dindex.get(dname) {
                                // Check if it is local or remote
                                if let Some(access) = info.access.get(location) {
                                    debug!("Input dataset '{}' is locally available", dname);
                                    *avail = Some(AvailabilityKind::Available { how: access.clone() });
                                } else {
                                    // Select one of the other locations it's available (for now, random?)
                                    if info.access.is_empty() {
                                        return Err(PlanError::DatasetUnavailable { name: dname.clone(), locs: vec![] });
                                    }
                                    let mut rng = rand::rng();
                                    let location: &str = info.access.keys().choose(&mut rng).unwrap();

                                    // That's the location where to pull the dataset from
                                    *avail = Some(AvailabilityKind::Unavailable {
                                        how: PreprocessKind::TransferRegistryTar { location: location.into(), dataname: name.clone() },
                                    });
                                }
                            } else {
                                return Err(PlanError::UnknownDataset { name: dname.clone() });
                            }
                        },

                        DataName::IntermediateResult(iname) => {
                            // It has to be declared before
                            if let Some(loc) = table.results.get(iname) {
                                // Match on whether it is available locally or not
                                if location == loc {
                                    debug!("Input intermediate result '{}' is locally available", iname);
                                    *avail = Some(AvailabilityKind::Available { how: AccessKind::File { path: PathBuf::from(iname) } });
                                } else {
                                    // Find the remote location in the infra file
                                    let registry: &Address = &infra
                                        .get(loc)
                                        .unwrap_or_else(|| panic!("IntermediateResult advertises location '{}', but that location is unknown", loc))
                                        .registry;

                                    // Compute the registry access method
                                    let address: String = format!("{registry}/results/download/{iname}");
                                    debug!("Input intermediate result '{}' will be transferred in from '{}'", iname, address);

                                    // That's the location where to pull the dataset from
                                    *avail = Some(AvailabilityKind::Unavailable {
                                        how: PreprocessKind::TransferRegistryTar { location: loc.clone(), dataname: name.clone() },
                                    });
                                }
                            } else if !deferred {
                                return Err(PlanError::UnknownIntermediateResult { name: iname.clone() });
                            } else {
                                debug!("Cannot determine value of intermediate result '{}' yet; it might be declared later (deferred)", iname);
                            }
                        },
                    }
                }

                // Then, we make the intermediate result available at the location where the function is being run (if there is any)
                if let Some(name) = result {
                    // Insert an entry in the list detailling where to access it and how
                    debug!("Making intermediate result '{}' accessible after execution of '{}' on '{}'", name, table.tasks[*task].name(), location);
                    table.results.insert(name.clone(), location.into());
                }

                // Move to the one indicated by 'next'
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
                plan_edges(table, edges, api_addr, dindex, infra, true_next, merge, deferred, done).await?;
                // If there is a false branch, do that one too
                if let Some(false_next) = false_next {
                    plan_edges(table, edges, api_addr, dindex, infra, false_next, merge, deferred, done).await?;
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
                    plan_edges(table, edges, api_addr, dindex, infra, b, None, deferred, done).await?;
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
                plan_edges(table, edges, api_addr, dindex, infra, cond, Some(body), true, done).await?;
                plan_edges(table, edges, api_addr, dindex, infra, body, Some(cond), true, done).await?;

                // Then we run through the condition and body again to resolve any unknown things
                plan_deferred(table, edges, infra, cond, Some(body), &mut HashSet::new())?;
                plan_deferred(table, edges, infra, cond, Some(cond), &mut HashSet::new())?;

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
    debug!("Planning success");
    Ok(())
}

/// Helper function that populates the availability of results right after a first planning round, to catch those that needed to be deferred (i.e., loop variables).
///
/// # Arguments
/// - `table`: The SymbolTable these edges live in.
/// - `edges`: The given list to plan.
/// - `infra`: The infrastructure to resolve locations.
/// - `pc`: The started index for the program counter. Should be '0' when called manually, the rest is handled during recursion.
/// - `merge`: If given, then we will stop analysing once we reach that point.
///
/// # Returns
/// Nothing, but does change the given list.
///
/// # Errors
/// This function may error if there were still results that couldn't be populated even after we've seen all edges.
fn plan_deferred(
    table: &SymTable,
    edges: &mut [Edge],
    infra: &InfraFile,
    pc: usize,
    merge: Option<usize>,
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
            Edge::Node { at, input, next, .. } => {
                // This next trick involves checking if the node has any unresolved results as input, then trying to resolve them
                for (name, avail) in input {
                    // Continue if it already has a resolved availability
                    if avail.is_some() {
                        continue;
                    }

                    // Get the name of the result
                    if let DataName::IntermediateResult(iname) = name {
                        // Extract the planned location
                        let location: &str = at.as_ref().unwrap();

                        // It has to be declared before
                        if let Some(loc) = table.results.get(iname) {
                            // Match on whether it is available locally or not
                            if location == loc {
                                debug!("Input intermediate result '{}' is locally available", iname);
                                *avail = Some(AvailabilityKind::Available { how: AccessKind::File { path: PathBuf::from(iname) } });
                            } else {
                                // Find the remote location in the infra file
                                let registry: &Address = &infra
                                    .get(loc)
                                    .unwrap_or_else(|| panic!("IntermediateResult advertises location '{}', but that location is unknown", loc))
                                    .registry;

                                // Compute the registry access method
                                let address: String = format!("{registry}/results/download/{iname}");
                                debug!("Input intermediate result '{}' will be transferred in from '{}'", iname, address);

                                // That's the location where to pull the dataset from
                                *avail = Some(AvailabilityKind::Unavailable {
                                    how: PreprocessKind::TransferRegistryTar { location: loc.clone(), dataname: name.clone() },
                                });
                            }
                        } else {
                            // No more second chances
                            return Err(PlanError::UnknownIntermediateResult { name: iname.clone() });
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
                plan_deferred(table, edges, infra, true_next, merge, done)?;
                // If there is a false branch, do that one too
                if let Some(false_next) = false_next {
                    plan_deferred(table, edges, infra, false_next, merge, done)?;
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
                    plan_deferred(table, edges, infra, b, None, done)?;
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
                plan_deferred(table, edges, infra, cond, Some(body), done)?;
                plan_deferred(table, edges, infra, cond, Some(cond), done)?;

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



/// Contacts a checker of a domain to see if it's OK with the current workflow.
///
/// # Arguments
/// - `proxy`: A [`ProxyClient`] that we use to connect to the checker.
/// - `splan`: An (already serialized) planned [`Workflow`] to validate.
/// - `location`: The name of the location on which we're resolving (used for debugging purposes only).
/// - `info`: The addresses where we find this location.
///
/// # Errors
/// This function errors if either we field to access any of the checkers, or they denied the workflow.
async fn validate_workflow_with(proxy: &ProxyClient, splan: &str, location: &str, info: &InfraLocation) -> Result<(), PlanError> {
    debug!("Consulting checker of '{location}' for plan validity...");

    let message: CheckWorkflowRequest = CheckWorkflowRequest {
        // NOTE: For now, we hardcode the central orchestrator as only "use-case" (registry)
        use_case: "central".into(),
        workflow: splan.into(),
    };

    // Create the client
    let mut client: JobServiceClient = match proxy.connect_to_job(info.delegate.to_string()).await {
        Ok(result) => match result {
            Ok(client) => client,
            Err(err) => {
                return Err(PlanError::GrpcConnectError { endpoint: info.delegate.clone(), err });
            },
        },
        Err(err) => {
            return Err(PlanError::ProxyError { err: Box::new(err) });
        },
    };

    // Send the request to the job node
    let response: tonic::Response<CheckReply> = match client.check_workflow(message).await {
        Ok(response) => response,
        Err(err) => {
            return Err(PlanError::GrpcRequestError { what: "CheckRequest", endpoint: info.delegate.clone(), err });
        },
    };
    let result: CheckReply = response.into_inner();

    // Examine if it was OK
    if !result.verdict {
        debug!("Checker of '{location}' DENIES plan");
        return Err(PlanError::CheckerDenied { domain: location.into(), reasons: result.reasons });
    }

    // Otherwise, OK!
    debug!("Checker of '{location}' ALLOWS plan");
    Ok(())
}





/***** LIBRARY *****/
/// This function hosts the actual planner, which uses an event monitor to receive plans which are then planned.
///
/// # Arguments
/// - `context`: The general context for this service itself.
/// - `body`: The body given in the planning request.
///
/// # Returns
/// This function doesn't really return, unless the warp server closes.
///
/// # Errors
/// This function only errors if we fail to listen for events. Otherwise, errors are logged to stderr using the `error!` macro.
pub async fn handle(context: Arc<Context>, body: PlanningRequest) -> Result<Response, Rejection> {
    info!("Handling incoming request at '/plan' (i.e., plan new workflow)");

    // Start profiling
    let report = ProfileReport::auto_reporting_file("brane-plr plan::handle", "brane-drv_plan");
    let _total = report.time("Total");

    // Parse the incoming request workflow
    let mut workflow: Workflow = match report.time_func("Request parsing", || serde_json::from_value(body.workflow)) {
        Ok(workflow) => workflow,
        Err(err) => {
            return err_response!(bad_request "{}", trace!(("Failed to deserialize incoming workflow"), err));
        },
    };
    debug!("Planning workflow with ID '{}' in app '{}'", workflow.id, body.app_id);

    // Fetch the most recent NodeConfig
    let oh = report.time("Environment loading");
    debug!("Loading node.yml file '{}'...", context.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            return err_response!(internal_error "Failed to load NodeConfig file: {}", err);
        },
    };
    let central: CentralConfig = match node_config.node.try_into_central() {
        Some(central) => central,
        None => {
            return err_response!(internal_error "Provided a non-central `node.yml` file (please adapt to represent a central node for this service)");
        },
    };

    // Load the infrastructure file
    debug!("Loading infra.yml file '{}'...", central.paths.infra.display());
    let infra: InfraFile = match InfraFile::from_path(&central.paths.infra) {
        Ok(infra) => infra,
        Err(err) => {
            return err_response!(internal_error "Failed to load infrastructure file '{}': {}", central.paths.infra.display(), err);
        },
    };

    // Fetch the data index
    let url: String = format!("{}/data/info", central.services.api.address);
    debug!("Loading data index from '{url}'...");
    let dindex: DataIndex = match get_data_index(&url).await {
        Ok(dindex) => dindex,
        Err(err) => {
            return err_response!(internal_error "Failed to fetch DataIndex from '{}': {}", url, err);
        },
    };
    oh.stop();



    // Now we do the planning
    {
        let alg = report.nest("algorithm");
        let _total = alg.time("Total");

        // Get the symbol table muteable, so we can... mutate... it
        let mut table: Arc<SymTable> = Arc::new(SymTable::new());
        mem::swap(&mut workflow.table, &mut table);
        let mut table: SymTable = Arc::try_unwrap(table).unwrap();

        // Fetch any previous state for this table
        if let Some(results) = context.state.lock().get_mut(&body.app_id) {
            results.0 = Instant::now();
            table.results.extend(results.1.iter().map(|(k, v)| (k.clone(), v.clone())));
        }

        // Do the main edges first
        {
            // Start by getting a list of all the edges
            let mut edges: Arc<Vec<Edge>> = Arc::new(vec![]);
            mem::swap(&mut workflow.graph, &mut edges);
            let mut edges: Vec<Edge> = Arc::try_unwrap(edges).unwrap();

            // Plan them
            debug!("Planning main edges...");
            if let Err(err) = alg
                .time_fut(
                    "<<<main>>>",
                    plan_edges(&mut table, &mut edges, &central.services.api.address, &dindex, &infra, 0, None, false, &mut HashSet::new()),
                )
                .await
            {
                return err_response!(bad_request "{}", trace!(("Failed to plan main edges for workflow with ID '{}:{}'", body.app_id, workflow.id), err));
            };

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
                if let Err(err) = alg
                    .time_fut(
                        workflow.table.funcs[*idx].name.to_string(),
                        plan_edges(&mut table, edges, &central.services.api.address, &dindex, &infra, 0, None, false, &mut HashSet::new()),
                    )
                    .await
                {
                    return err_response!(bad_request "{}", trace!(("Failed to plan function '{}' edges for workflow with correlation ID '{}:{}'", table.funcs[*idx].name, body.app_id, workflow.id), err));
                }
            }

            // Put the map back
            let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(funcs);
            mem::swap(&mut funcs, &mut workflow.funcs);
        }

        // Write the results back for this session
        context
            .state
            .lock()
            .entry(body.app_id.clone())
            .and_modify(|results| *results = (Instant::now(), table.results.clone()))
            .or_insert_with(|| (Instant::now(), table.results.clone()));

        // Then, put the table back
        let mut table: Arc<SymTable> = Arc::new(table);
        mem::swap(&mut table, &mut workflow.table);
    }

    // With the planning done, re-serialize
    debug!("Serializing plan...");
    let ser = report.time("Serialization");
    let vplan: Value = match serde_json::to_value(&workflow) {
        Ok(vplan) => vplan,
        Err(err) => {
            return err_response!(internal_error "{}", trace!(("Failed to serialize plan"), err));
        },
    };
    let reply: PlanningReply = PlanningReply { plan: vplan };
    let sreply: String = match serde_json::to_string(&reply) {
        Ok(sreply) => sreply,
        Err(err) => {
            return err_response!(internal_error "{}", trace!(("Failed to serialize request result"), err));
        },
    };
    let splan: String = match serde_json::to_string(&reply.plan) {
        Ok(splan) => splan,
        Err(err) => {
            return err_response!(internal_error "{}", trace!(("Failed to serialize plan JSON"), err));
        },
    };
    ser.stop();

    // Check with the checker(s) if this plan is OK!
    debug!("Consulting {} checkers with plan validity...", infra.len());
    let val = report.nest("Policy validation");
    for (location, info) in infra.iter() {
        match val.time_fut(format!("Domain '{}' ({})", location, info.registry), validate_workflow_with(&context.proxy, &splan, location, info)).await
        {
            Ok(_) => {},
            Err(PlanError::CheckerDenied { domain, reasons }) => {
                return err_response!(unauthorized serde_json::to_string(&PlanningDeniedReply { domain, reasons }).unwrap().into());
            },
            Err(err) => return err_response!(internal_error "{}", trace!(("Failed to consult checker of domain '{location}'"), err)),
        }
    }
    val.finish();

    // Clean the list for old things and nobody else is using it
    if let Some(mut state) = context.state.try_lock() {
        let clean = report.time("Garbage collector");
        info!("Running garbage collector on old {} planning sessions...", state.len());
        state.retain(|_, (last_used, _)| last_used.elapsed() < Duration::from_secs(SESSION_TIMEOUT_S));
        debug!("{} planning sessions left after GC run", state.len());
        clean.stop();
    }

    // Send the result
    debug!("Planning of '{}:{}' OK", body.app_id, workflow.id);
    Ok(Response::new(sreply.into()))
}
