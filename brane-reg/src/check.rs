//  CHECK.rs
//    by Lut99
//
//  Created:
//    07 Feb 2024, 13:40:32
//  Last edited:
//    02 May 2025, 15:12:24
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements handlers for validation-only request endpoints.
//

use std::sync::Arc;

use brane_cfg::info::Info as _;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig, WorkerConfig};
use brane_shr::formatters::BlockFormatter;
use enum_debug::EnumDebug as _;
use error_trace::trace;
use log::{debug, error, info};
use policy_reasoner::spec::reasons::ManyReason;
use specifications::data::DataName;
use specifications::pc::ProgramCounter;
use specifications::profiling::ProfileReport;
use specifications::registering::{CheckTransferReply, CheckTransferRequest};
use specifications::wir::func_id::FunctionId;
use specifications::wir::{Edge, Workflow};
use warp::hyper::StatusCode;
use warp::reject::Rejection;
use warp::reply::{self, Reply, Response};

use crate::data::assert_asset_permission;
use crate::spec::Context;


/***** HELPER FUNCTION *****/
/// Abstracts over validating data or results.
///
/// # Arguments
/// - `name`: The [`DataName`] of the dataset or result to check.
async fn check_data_or_result(name: DataName, body: CheckTransferRequest, context: Arc<Context>) -> Result<impl Reply, Rejection> {
    let CheckTransferRequest { use_case, workflow, task } = body;

    // Load the config file
    debug!("Loading node.yml file '{}'...", context.node_config_path.display());
    let node_config: NodeConfig = match NodeConfig::from_path(&context.node_config_path) {
        Ok(config) => config,
        Err(err) => {
            error!("{}", trace!(("Failed to load NodeConfig file"), err));
            return Err(warp::reject::reject());
        },
    };
    let worker_config: WorkerConfig = if let NodeSpecificConfig::Worker(worker) = node_config.node {
        worker
    } else {
        error!("Given NodeConfig file '{}' does not have properties for a worker node.", context.node_config_path.display());
        return Err(warp::reject::reject());
    };

    // Start profiling (F first function, but now we can use the location)
    let report = ProfileReport::auto_reporting_file(
        format!("brane-reg /check/{}/{}", if name.is_data() { "data" } else { "result" }, name.name()),
        format!("brane-reg_{}_check-{}-{}", worker_config.name, if name.is_data() { "data" } else { "result" }, name.name()),
    );

    // Parse if a valid workflow is given
    debug!("Parsing workflow in request body...\n\nWorkflow:\n{}\n", BlockFormatter::new(serde_json::to_string_pretty(&workflow).unwrap()));
    let prep = report.time("Request parsing");
    let workflow: Workflow = match serde_json::from_value(workflow) {
        Ok(wf) => wf,
        Err(err) => {
            debug!("{}", trace!(("Given request has an invalid workflow"), err));
            return Ok(warp::reply::with_status(Response::new("Invalid workflow".to_string().into()), StatusCode::BAD_REQUEST));
        },
    };

    // Check if we can find the given task to find who will get this data
    let task: Option<ProgramCounter> =
        task.map(|t| ProgramCounter::new(if let Some(id) = t.0 { FunctionId::Func(id as usize) } else { FunctionId::Main }, t.1 as usize));
    let target: String = if let Some(task) = task {
        // Attempt to find that index in the Workflow
        let edge: &Edge = if task.is_main() {
            match workflow.graph.get(task.edge_idx) {
                Some(edge) => edge,
                None => {
                    let msg: String = format!(
                        "Given request has an invalid workflow: edge index {} is out-of-bounds for '<main>' of {} edges",
                        task.edge_idx,
                        workflow.graph.len()
                    );
                    debug!("{}", msg);
                    return Ok(warp::reply::with_status(Response::new(msg.into()), StatusCode::BAD_REQUEST));
                },
            }
        } else {
            match workflow.funcs.get(&task.func_id.id()) {
                Some(graph) => match graph.get(task.edge_idx) {
                    Some(edge) => edge,
                    None => {
                        let msg: String = format!(
                            "Given request has an invalid workflow: edge index {} is out-of-bounds for '{}' of {} edges",
                            task.func_id,
                            task.edge_idx,
                            graph.len()
                        );
                        debug!("{}", msg);
                        return Ok(warp::reply::with_status(Response::new(msg.into()), StatusCode::BAD_REQUEST));
                    },
                },
                None => {
                    let msg: String = format!("Given request has an invalid workflow: unknown function ID '{}'", task.func_id);
                    debug!("{}", msg);
                    return Ok(warp::reply::with_status(Response::new(msg.into()), StatusCode::BAD_REQUEST));
                },
            }
        };

        // Assert it is a Node that implies a transfer
        if let Edge::Node { task: _, locs: _, at, input, result: _, metadata: _, next: _ } = edge {
            // Ensure the requested dataset is the input of the request
            // NOTE: Might one day be extended to also check if we own that dataset, but only at that point
            if !input.contains_key(&name) {
                let msg: String = format!("Bad request: requested dataset '{}' not part of input to node '{}'", name, task);
                debug!("{}", msg);
                return Ok(warp::reply::with_status(Response::new(msg.into()), StatusCode::BAD_REQUEST));
            }

            // Unwrap the 'at'
            match at {
                Some(at) => at.clone(),
                None => {
                    let msg: String = format!("Given request has an invalid workflow: encountered unplanned Node '{}'", task);
                    debug!("{}", msg);
                    return Ok(warp::reply::with_status(Response::new(msg.into()), StatusCode::BAD_REQUEST));
                },
            }
        } else {
            let msg: String = format!("Given task ID '{}' is invalid: expected Node, got {}", task, edge.variant());
            debug!("{}", msg);
            return Ok(warp::reply::with_status(Response::new(msg.into()), StatusCode::BAD_REQUEST));
        }
    } else {
        // Instead, we use the workflow receiver and assume it's the last task
        match &*workflow.user {
            Some(user) => user.clone(),
            None => {
                debug!("Given request has an invalid workflow: no task given and no final result receiver defined");
                return Ok(warp::reply::with_status(
                    Response::new("No task ID specified and no result receiver in workflow".to_string().into()),
                    StatusCode::BAD_REQUEST,
                ));
            },
        }
    };
    prep.stop();

    // Attempt to parse the certificate to get the client's name (which tracks because it's already authenticated)
    match report
        .time_fut("Checker", assert_asset_permission(&worker_config, &use_case, &context.delib_token, &workflow, &target, name.clone(), task))
        .await
    {
        Ok(None) => {
            info!("Checker authorized transfer of dataset '{}' to '{}'", name, target);

            // Serialize the response
            let res: String = match serde_json::to_string(&CheckTransferReply { verdict: true, reasons: ManyReason::new() }) {
                Ok(res) => res,
                Err(err) => {
                    error!("{}", trace!(("Failed to serialize ChecKTransferReply"), err));
                    return Ok(warp::reply::with_status(
                        Response::new("Internal server error".to_string().into()),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ));
                },
            };

            // Return it
            Ok(reply::with_status(Response::new(res.into()), StatusCode::OK))
        },

        Ok(Some(reasons)) => {
            info!("Checker denied transfer of dataset '{}' to '{}'", name, target);
            if !reasons.is_empty() {
                debug!("Reasons:\n{}\n", reasons.iter().map(|r| format!(" - {r}")).collect::<Vec<String>>().join("\n"));
            }

            // Serialize the response
            let res: String = match serde_json::to_string(&CheckTransferReply { verdict: false, reasons }) {
                Ok(res) => res,
                Err(err) => {
                    error!("{}", trace!(("Failed to serialize ChecKTransferReply"), err));
                    return Ok(warp::reply::with_status(
                        Response::new("Internal server error".to_string().into()),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ));
                },
            };

            // Return it
            Ok(reply::with_status(Response::new(res.into()), StatusCode::OK))
        },
        Err(err) => {
            error!("{}", trace!(("Failed to consult the checker"), err));
            Err(warp::reject::reject())
        },
    }
}





/***** LIBRARY *****/
/// Handles a GET that checks if a dataset is allowed to be downloaded.
///
/// # Arguments
/// - `name`: The name of the dataset to check.
/// - `body`: The body given with the request.
/// - `context`: The context that carries options and some shared structures between the warp paths.
///
/// # Returns
/// The response that can be sent back to the client, effectively encoding the checker's response.
///
/// # Errors
/// This function may error (i.e., reject) if we didn't know the given name or we failed to serialize the relevant AssetInfo.
pub async fn check_data(name: String, body: CheckTransferRequest, context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling GET on `/data/check/{name}` (i.e., check transfer permission)...");

    // Pass to the more generic function
    check_data_or_result(DataName::Data(name), body, context).await
}

/// Handles a GET that checks if a result is allowed to be downloaded.
///
/// # Arguments
/// - `name`: The name of the result to check.
/// - `body`: The body given with the request.
/// - `context`: The context that carries options and some shared structures between the warp paths.
///
/// # Returns
/// The response that can be sent back to the client, effectively encoding the checker's response.
///
/// # Errors
/// This function may error (i.e., reject) if we didn't know the given name or we failed to serialize the relevant AssetInfo.
pub async fn check_result(name: String, body: CheckTransferRequest, context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling GET on `/results/check/{name}` (i.e., check transfer permission)...");

    // Pass to the more generic function
    check_data_or_result(DataName::IntermediateResult(name), body, context).await
}
