//  CHECK.rs
//    by Lut99
//
//  Created:
//    06 Feb 2024, 11:46:14
//  Last edited:
//    02 May 2025, 15:09:05
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements helper functions for the `check`-request.
//

use std::error;
use std::fmt::{Display, Formatter, Result as FResult};

use brane_cfg::infra::{InfraFile, InfraLocation};
use brane_shr::formatters::BlockFormatter;
use enum_debug::EnumDebug as _;
use log::{debug, info};
use policy_reasoner::spec::reasonerconn::ReasonerResponse;
use policy_reasoner::spec::reasons::ManyReason;
use reqwest::{Client, Request, Response, StatusCode};
use specifications::address::Address;
use specifications::checking::deliberation::{CheckResponse, CheckTaskRequest, CheckTransferRequest, CheckWorkflowRequest, Prost};
use specifications::data::{AvailabilityKind, DataName, PreprocessKind};
use specifications::pc::ProgramCounter;
use specifications::wir::func_id::FunctionId;
use specifications::wir::{Edge, Workflow};
use specifications::working::JobServiceClient;
use tokio::task::JoinHandle;


/***** TYPE ALIASES *****/
/// The output for one of the request features.
pub type RequestOutput = Result<Option<(String, Vec<String>)>, Error>;





/***** ERRORS *****/
/// Defines errors originating from the check function & check futures.
#[derive(Debug)]
pub enum Error {
    /// A given edge index was out-of-range for the given function.
    UnknownEdgeIdx { id: String, func_id: FunctionId, edge_idx: usize, max: usize },
    /// The location at which a node was planned was unknown to us.
    UnknownExecutor { id: String, node: ProgramCounter, domain: String },
    /// A given function ID was not known for the given workflow.
    UnknownFuncId { id: String, func_id: FunctionId },
    /// The location which was planned to provide an input was unknown to us.
    UnknownProvider { id: String, node: ProgramCounter, domain: String, dataname: DataName },
    /// An input to a given node was unplanned.
    UnplannedInput { id: String, node: ProgramCounter, input: DataName },
    /// A node was unplanned.
    UnplannedNode { id: String, node: ProgramCounter },
    /// Failed to serialize the [`Workflow`].
    WorkflowSerialize { id: String, err: serde_json::Error },

    /// Failed to build a request to the given registry.
    RegistryRequest { domain: String, addr: Address, err: reqwest::Error },
    /// Failed to send a request to the given registry.
    RegistryRequestSend { domain: String, addr: Address, err: reqwest::Error },
    /// Failed to download the response of the given registry.
    RegistryResponseDownload { domain: String, addr: Address, err: reqwest::Error },
    /// The response of the given registry was not a success.
    RegistryResponseFailure { domain: String, addr: Address, code: StatusCode, response: Option<String> },
    /// Failed to parse the response of the given registry.
    RegistryResponseParse { domain: String, addr: Address, raw: String, err: serde_json::Error },
    /// Failed to send the CheckRequest to the worker.
    WorkerCheck { domain: String, addr: Address, err: tonic::Status },
    /// Failed to connect to the given worker.
    WorkerConnect { domain: String, addr: Address, err: specifications::working::JobServiceError },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            UnknownEdgeIdx { id, func_id, edge_idx, max } => {
                write!(f, "Edge index {edge_idx} is out-of-bounds for function {func_id} in workflow '{id}' that has {max} edges")
            },
            UnknownExecutor { id, node, domain } => write!(f, "Unknown domain '{domain}' that is planned to execute task {node} in workflow '{id}'"),
            UnknownFuncId { id, func_id } => write!(f, "Unknown function ID {func_id} in workflow '{id}'"),
            UnknownProvider { id, node, domain, dataname } => {
                write!(f, "Unknown domain '{domain}' that is planned to provide dataset '{dataname}' for task {node} in workflow '{id}'")
            },
            UnplannedInput { id, node, input } => write!(f, "Input '{input}' to node {node} in workflow '{id}' is unplanned"),
            UnplannedNode { id, node } => write!(f, "Node {node} in workflow '{id}' is unplanned"),
            WorkflowSerialize { id, .. } => write!(f, "Failed to serialize workflow '{id}' to JSON"),

            RegistryRequest { domain, addr, .. } => write!(f, "Failed to build a request to registry of '{domain}' at '{addr}'"),
            RegistryRequestSend { domain, addr, .. } => write!(f, "Failed to send a request to registry of '{domain}' at '{addr}'"),
            RegistryResponseDownload { domain, addr, .. } => write!(f, "Failed to download response of registry of '{domain}' at '{addr}'"),
            RegistryResponseFailure { domain, addr, code, response } => write!(
                f,
                "Registry of '{}' at '{}' returned {} ({}){}",
                domain,
                addr,
                code.as_u16(),
                code.canonical_reason().unwrap_or("???"),
                if let Some(res) = response { format!("\n\nResponse:\n{}\n", BlockFormatter::new(res)) } else { String::new() }
            ),
            RegistryResponseParse { domain, addr, raw, .. } => {
                write!(f, "Failed to parse response of registry of '{}' at '{}'\n\nResponse:\n{}\n", domain, addr, BlockFormatter::new(raw))
            },
            WorkerCheck { domain, addr, .. } => write!(f, "Failed to send CheckRequest to worker of '{domain}' at '{addr}'"),
            WorkerConnect { domain, addr, .. } => write!(f, "Failed to connect to worker of '{domain}' at '{addr}'"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            UnknownEdgeIdx { .. } => None,
            UnknownExecutor { .. } => None,
            UnknownFuncId { .. } => None,
            UnknownProvider { .. } => None,
            UnplannedInput { .. } => None,
            UnplannedNode { .. } => None,
            WorkflowSerialize { err, .. } => Some(err),

            RegistryRequest { err, .. } => Some(err),
            RegistryRequestSend { err, .. } => Some(err),
            RegistryResponseDownload { err, .. } => Some(err),
            RegistryResponseFailure { .. } => None,
            RegistryResponseParse { err, .. } => Some(err),
            WorkerCheck { err, .. } => Some(err),
            WorkerConnect { err, .. } => Some(err),
        }
    }
}





/***** REQUEST FUNCTIONS *****/
/// The future that sends a request to assert workflow permission as a whole.
///
/// # Arguments
/// - `checker`: The checker to send the request to (only used for debugging).
/// - `address`: The [`Address`] of the worker that will handle this request for us.
/// - `id`: The identifier of the workflow we're validating.
/// - `sworkflow`: A(n already serialized) [`Workflow`] to validate.
///
/// # Returns
/// An Option that, if [`Some(...)`], denotes the named checker denied it for the given reasons. If [`None`], then everything went well.
///
/// # Errors
/// This future may error if it failed to send the request.
async fn request_workflow(checker: String, address: Address, id: String, workflow: Workflow) -> RequestOutput {
    info!("Spawning workflow-validation request to validate workflow '{id}' with checker '{checker}'");

    // Create the request
    let req: CheckWorkflowRequest = CheckWorkflowRequest { usecase: "central".into(), workflow: workflow.clone() };

    // Connect to the worker
    debug!("[workflow '{id}' -> '{checker}'] Connecting to worker '{address}'...");
    let mut client: JobServiceClient = match JobServiceClient::connect(address.to_string()).await {
        Ok(client) => client,
        Err(err) => return Err(Error::WorkerConnect { domain: checker, addr: address, err }),
    };

    // Send the request
    debug!("[workflow '{id}' -> '{checker}'] Sending CheckRequest to worker '{address}'...");
    let res: CheckResponse<ManyReason<String>> = match client.check_workflow(Prost::<CheckWorkflowRequest>::new(req)).await {
        Ok(res) => res.into_inner().into_inner(),
        Err(err) => return Err(Error::WorkerCheck { domain: checker, addr: address, err }),
    };

    // Evaluate the worker's response
    debug!(
        "[workflow '{id}' -> '{checker}'] Worker '{address}' replied with {}",
        if matches!(res.verdict, ReasonerResponse::Success) { "ALLOW" } else { "DENY" }
    );
    if let ReasonerResponse::Violated(reasons) = res.verdict { Ok(Some((checker, reasons.into_iter().collect()))) } else { Ok(None) }
}

/// The future that sends a request to assert a dataset transfer's permission.
///
/// # Arguments
/// - `checker`: The checker to send the request to (only used for debugging).
/// - `address`: The [`Address`] of the worker that will handle this request for us.
/// - `id`: The identifier of the workflow we're validating.
/// - `sworkflow`: A(n already serialized) [`Workflow`] to validate.
/// - `task`: The [`ProgramCounter`] that points to the task to ask for.
/// - `data`: The [`DataName`] of the data to ask for.
///
/// # Returns
/// An Option that, if [`Some(...)`], denotes the named checker denied it for the given reasons. If [`None`], then everything went well.
///
/// # Errors
/// This future may error if it failed to send the request.
async fn request_transfer(checker: String, address: Address, id: String, workflow: Workflow, task: ProgramCounter, data: DataName) -> RequestOutput {
    info!("Spawning task-execute request to validate task '{task}' in workflow '{id}' with checker '{checker}'");

    // Create the request
    let url: String = format!("{address}/{}/check/{}", if data.is_data() { "data" } else { "results" }, data.name());
    let req: CheckTransferRequest = CheckTransferRequest { usecase: "central".into(), workflow, task: Some(task), input: data.name().into() };

    // Create the request
    debug!("[task '{id}' -> '{checker}'] Connecting to worker '{address}'...");
    let client: Client = Client::new();
    let req: Request = match client.get(&url).json(&req).build() {
        Ok(client) => client,
        Err(err) => return Err(Error::RegistryRequest { domain: checker, addr: address, err }),
    };

    // Send the request
    debug!("[task '{id}' -> '{checker}'] Sending data transfer request to worker '{address}'...");
    let res: Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RegistryRequestSend { domain: checker, addr: address, err }),
    };
    if !res.status().is_success() {
        return Err(Error::RegistryResponseFailure { domain: checker, addr: address, code: res.status(), response: res.text().await.ok() });
    }

    // Parse the request
    let res: String = match res.text().await {
        Ok(res) => res,
        Err(err) => return Err(Error::RegistryResponseDownload { domain: checker, addr: address, err }),
    };
    let res: CheckResponse<ManyReason<String>> = match serde_json::from_str(&res) {
        Ok(res) => res,
        Err(err) => return Err(Error::RegistryResponseParse { domain: checker, addr: address, raw: res, err }),
    };

    // Evaluate the worker's response
    debug!(
        "[task '{id}' -> '{checker}'] Worker '{address}' replied with {}",
        if matches!(res.verdict, ReasonerResponse::Success) { "ALLOW" } else { "DENY" }
    );
    if let ReasonerResponse::Violated(reasons) = res.verdict { Ok(Some((checker, reasons.into_iter().collect()))) } else { Ok(None) }
}

/// The future that sends a request to assert a task execution's permission.
///
/// # Arguments
/// - `checker`: The checker to send the request to (only used for debugging).
/// - `address`: The [`Address`] of the worker that will handle this request for us.
/// - `id`: The identifier of the workflow we're validating.
/// - `sworkflow`: A(n already serialized) [`Workflow`] to validate.
/// - `task`: The [`ProgramCounter`] that points to the task to ask for.
///
/// # Returns
/// An Option that, if [`Some(...)`], denotes the named checker denied it for the given reasons. If [`None`], then everything went well.
///
/// # Errors
/// This future may error if it failed to send the request.
async fn request_execute(checker: String, address: Address, id: String, workflow: Workflow, task: ProgramCounter) -> RequestOutput {
    info!("Spawning task-execute request to validate task '{task}' in workflow '{id}' with checker '{checker}'");

    // Create the request
    let req: CheckTaskRequest = CheckTaskRequest { usecase: "central".into(), workflow, task };

    // Connect to the worker
    debug!("[task '{id}' -> '{checker}'] Connecting to worker '{address}'...");
    let mut client: JobServiceClient = match JobServiceClient::connect(address.to_string()).await {
        Ok(client) => client,
        Err(err) => return Err(Error::WorkerConnect { domain: checker, addr: address, err }),
    };

    // Send the request
    debug!("[task '{id}' -> '{checker}'] Sending CheckTaskRequest to worker '{address}'...");
    let res: CheckResponse<ManyReason<String>> = match client.check_task(Prost::<CheckTaskRequest>::new(req)).await {
        Ok(res) => res.into_inner().into_inner(),
        Err(err) => return Err(Error::WorkerCheck { domain: checker, addr: address, err }),
    };

    // Evaluate the worker's response
    debug!(
        "[task '{id}' -> '{checker}'] Worker '{address}' replied with {}",
        if matches!(res.verdict, ReasonerResponse::Success) { "ALLOW" } else { "DENY" }
    );
    if let ReasonerResponse::Violated(reasons) = res.verdict { Ok(Some((checker, reasons.into_iter().collect()))) } else { Ok(None) }
}





/***** HELPER FUNCTIONS *****/
/// Traverses the given workflow and launches data-transfer- and task-execute-requests as it goes.
///
/// # Arguments
/// - `infra`: An [`InfraFile`] that determines all workers known to us.
/// - `workflow`: The [`Workflow`] to generate requests for.
/// - `pc`: A [`ProgramCounter`] that denotes which edge we're investigating.
/// - `breakpoint`: An optional [`ProgramCounter`] that, when given, will force termination once `pc` is the same.
/// - `handles`: The list of [`JoinHandle`]s on which to push new ones for every request we find.
///
/// # Errors
/// This function may error if we failed to traverse the workflow somehow.
fn traverse_and_request(
    infra: &InfraFile,
    workflow: &Workflow,
    mut pc: ProgramCounter,
    breakpoint: Option<ProgramCounter>,
    handles: &mut Vec<(String, JoinHandle<RequestOutput>)>,
) -> Result<(), Error> {
    loop {
        // Stop on breakpoints
        if let Some(breakpoint) = breakpoint {
            if pc == breakpoint {
                return Ok(());
            }
        }

        // Find the edge
        let edge: &Edge = if pc.is_main() {
            match workflow.graph.get(pc.edge_idx) {
                Some(edge) => edge,
                None => {
                    return Err(Error::UnknownEdgeIdx {
                        id: workflow.id.clone(),
                        func_id: pc.func_id,
                        edge_idx: pc.edge_idx,
                        max: workflow.graph.len(),
                    });
                },
            }
        } else {
            match workflow.funcs.get(&pc.func_id.id()) {
                Some(graph) => match graph.get(pc.edge_idx) {
                    Some(edge) => edge,
                    None => {
                        return Err(Error::UnknownEdgeIdx { id: workflow.id.clone(), func_id: pc.func_id, edge_idx: pc.edge_idx, max: graph.len() });
                    },
                },
                None => return Err(Error::UnknownFuncId { id: workflow.id.clone(), func_id: pc.func_id }),
            }
        };

        // Match on the edge
        log::trace!("Spawning requests in {:?}", edge.variant());
        use Edge::*;
        match edge {
            Node { task: _, locs: _, at, input, result: _, metadata: _, next } => {
                // Get the checker that is scheduled to execute the node
                let at: &String = match at {
                    Some(at) => at,
                    None => return Err(Error::UnplannedNode { id: workflow.id.clone(), node: pc }),
                };

                // Ask all input checkers to get their data
                for (dataname, from) in input {
                    match from {
                        // Ask the person we are scheduled to get it from
                        Some(AvailabilityKind::Unavailable { how }) => match how {
                            PreprocessKind::TransferRegistryTar { location, dataname } => {
                                // Resolve the location name to an address
                                let info: &InfraLocation = match infra.get(location) {
                                    Some(info) => info,
                                    None => {
                                        return Err(Error::UnknownProvider {
                                            id: workflow.id.clone(),
                                            node: pc,
                                            domain: at.clone(),
                                            dataname: dataname.clone(),
                                        });
                                    },
                                };

                                // Done
                                handles.push((
                                    at.clone(),
                                    tokio::spawn(request_transfer(
                                        location.clone(),
                                        info.registry.clone(),
                                        workflow.id.clone(),
                                        workflow.clone(),
                                        pc,
                                        dataname.clone(),
                                    )),
                                ));
                            },
                        },
                        // Else, no need to ask beyond the execute question (see below)
                        Some(AvailabilityKind::Available { .. }) => continue,

                        // If it's [`None`], then unplannedness strikes
                        None => return Err(Error::UnplannedInput { id: workflow.id.clone(), node: pc, input: dataname.clone() }),
                    }
                }

                // Ask the executing checker if it is OK executing it
                let info: &InfraLocation = match infra.get(at) {
                    Some(info) => info,
                    None => return Err(Error::UnknownExecutor { id: workflow.id.clone(), node: pc, domain: at.clone() }),
                };
                handles
                    .push((at.clone(), tokio::spawn(request_execute(at.clone(), info.delegate.clone(), workflow.id.clone(), workflow.clone(), pc))));

                // Alright done continue
                pc = pc.jump(*next);
                continue;
            },
            Linear { instrs: _, next } => {
                pc = pc.jump(*next);
                continue;
            },
            Stop {} => return Ok(()),

            Branch { true_next, false_next, merge } => {
                // Recurse into the true next
                traverse_and_request(infra, workflow, pc.jump(*true_next), merge.map(|m| pc.jump(m)), handles)?;
                // Recurse into the false next, if any
                if let Some(false_next) = false_next {
                    traverse_and_request(infra, workflow, pc.jump(*false_next), merge.map(|m| pc.jump(m)), handles)?;
                }

                // Continue with the merge, if any
                if let Some(merge) = merge {
                    pc = pc.jump(*merge);
                    continue;
                } else {
                    return Ok(());
                }
            },
            Parallel { branches, merge } => {
                // Recurse into each branch
                for b in branches {
                    traverse_and_request(infra, workflow, pc.jump(*b), Some(pc.jump(*merge)), handles)?;
                }
                pc = pc.jump(*merge);
                continue;
            },
            Join { merge: _, next } => {
                pc = pc.jump(*next);
                continue;
            },

            Loop { cond, body, next } => {
                // Recurse into the condition
                traverse_and_request(infra, workflow, pc.jump(*cond), Some(pc.jump(*body - 1)), handles)?;
                // Recurse into the body
                traverse_and_request(infra, workflow, pc.jump(*body), Some(pc.jump(*cond)), handles)?;
                // Continue with next
                if let Some(next) = next {
                    pc = pc.jump(*next);
                    continue;
                } else {
                    return Ok(());
                }
            },

            Call { input: _, result: _, next } => {
                // We don't directly do calls, but do multiple runs of this function for functions
                pc = pc.jump(*next);
                continue;
            },
            Return { result: _ } => return Ok(()),
        }
    }
}





/***** LIBRARY *****/
/// Given a workflow, traverses it and launches requests to check the necessary parts of it with local checkers.
///
/// # Arguments
/// - `infra`: An [`InfraFile`] that determines all workers known to us.
/// - `workflow`: The [`Workflow`] to generate requests for.
///
/// # Returns
/// Handles for every launched request, as a tuple of the name of the checker to which the request is sent and a [`JoinHandle`] to wait for the request to complete.
///
/// Note that this abstracts over the type of request.
///
/// # Errors
/// This function may error if it failed to traverse the workflow.
///
/// Request failure must be checked at join time.
pub fn spawn_requests(infra: &InfraFile, workflow: &Workflow) -> Result<Vec<(String, JoinHandle<RequestOutput>)>, Error> {
    // Spawn the workflow-global requests for every checker
    let mut handles: Vec<(String, JoinHandle<RequestOutput>)> = Vec::with_capacity(4 * infra.len());
    for (name, info) in infra {
        handles.push((name.clone(), tokio::spawn(request_workflow(name.clone(), info.delegate.clone(), workflow.id.clone(), workflow.clone()))));
    }

    // Delegate to a recursive function that traverses the workflow that does the other two types
    traverse_and_request(infra, workflow, ProgramCounter::start(), None, &mut handles)?;
    for id in workflow.funcs.keys() {
        traverse_and_request(infra, workflow, ProgramCounter::start_of(*id), None, &mut handles)?;
    }

    // Done
    Ok(vec![])
}
