//  HANDLER.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 16:18:11
//  Last edited:
//    07 Mar 2024, 14:20:06
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the command handler from the client.
//

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use brane_ast::Workflow;
use brane_cfg::info::Info;
use brane_cfg::infra::InfraFile;
use brane_cfg::node::{CentralConfig, NodeConfig, NodeSpecificConfig};
use brane_exe::FullValue;
use brane_prx::client::ProxyClient;
use brane_tsk::errors::PlanError;
use brane_tsk::spec::AppId;
use dashmap::DashMap;
use enum_debug::EnumDebug as _;
use error_trace::{ErrorTrace as _, trace};
use specifications::driving::{CheckReply, CheckRequest, CreateSessionReply, CreateSessionRequest, DriverService, ExecuteReply, ExecuteRequest};
use specifications::profiling::ProfileReport;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};

use crate::check::RequestOutput;
use crate::errors::RemoteVmError;
use crate::planner::InstancePlanner;
use crate::vm::InstanceVm;
use crate::{check, gc};


/***** HELPER MACROS *****/
/// Sends an error back to the client, also logging it here. Is like `err!` but returning the stream.
macro_rules! fatal_err {
    ($tx:ident,Status:: $status:ident, $err:expr) => {{
        // Always log to stderr
        tracing::error!("{}", $err.trace());
        // Attempt to log on tx
        let serr: String = $err.to_string();
        if let Err(err) = $tx.send(Err(Status::$status(serr))).await {
            tracing::error!("{}", trace!(("Failed to notify client of error"), err));
        }
        // Return
        return;
    }};
    ($tx:ident, $status:expr) => {{
        // Always log to stderr
        tracing::error!("Aborting incoming request: {}", $status);
        // Attempt to log on tx
        if let Err(err) = $tx.send(Err($status)).await {
            tracing::error!("{}", trace!(("Failed to notify client of error"), err));
        }
        // Return
        return;
    }};

    ($tx:ident, $rx:ident,Status:: $status:ident, $err:expr) => {{
        // Always log to stderr
        tracing::error!("{}", $err.trace());
        // Attempt to log on tx
        if let Err(err) = $tx.send(Err(Status::$status($err.to_string()))).await {
            tracing::error!("{}", trace!(("Failed to notify client of error"), err));
        }
        // Return
        return Ok(Response::new(ReceiverStream::new($rx)));
    }};
    ($tx:ident, $rx:ident, $status:expr) => {{
        // Always log to stderr
        tracing::error!("Aborting incoming request: {}", $status);
        // Attempt to log on tx
        if let Err(err) = $tx.send(Err($status)).await {
            tracing::error!("{}", trace!(("Failed to notify client of error"), err));
        }
        // Return
        return Ok(Response::new(ReceiverStream::new($rx)));
    }};
}





/***** LIBRARY *****/
/// The DriverHandler handles incoming gRPC requests. This is effectively what 'drives' the driver.
#[derive(Clone)]
pub struct DriverHandler {
    /// The path to the `node.yml` file that describes this node's environment. For the handler, this is the path to the `infra.yml` file (and an optional `secrets.yml`) and the topic to send commands to the planner on.
    node_config_path: PathBuf,
    /// The ProxyClient that we use to connect to/through `brane-prx`.
    proxy: Arc<ProxyClient>,

    /// Current sessions and active VMs. Note that this only concerns states if connected via a REPL-session; any in-statement state (i.e., calling nodes) is handled by virtue of the VM being implemented as `async`.
    sessions: Arc<DashMap<AppId, (InstanceVm, Instant)>>,
}

impl DriverHandler {
    /// Constructor for the DriverHandler.
    ///
    /// # Arguments
    /// - `node_config_path`: The path to the `node.yml` file that describes this node's environment. For the handler, this is the path to the `infra.yml` file (and an optional `secrets.yml`) and the topic to send commands to the planner on.
    /// - `proxy`: The (shared) ProxyClient that we use to connect to/through `brane-prx`.
    /// - `planner`: The InstancePlanner that handles our side of planning.
    ///
    /// # Returns
    /// A new DriverHandler instance.
    #[inline]
    pub fn new(node_config_path: impl Into<PathBuf>, proxy: Arc<ProxyClient>) -> Self {
        // Create the new sessions list with its Garbage Collector (GC)
        let sessions: Arc<DashMap<AppId, (InstanceVm, Instant)>> = Arc::new(DashMap::new());
        tokio::spawn(gc::sessions(Arc::downgrade(&sessions)));

        // Now use that as this handler's sessions
        Self { node_config_path: node_config_path.into(), proxy, sessions }
    }
}

#[tonic::async_trait]
impl DriverService for DriverHandler {
    type ExecuteStream = ReceiverStream<Result<ExecuteReply, Status>>;

    /// Creates a new BraneScript session.
    ///
    /// # Arguments
    /// - `request`: The request to create a response to.
    ///
    /// # Returns
    /// The response to the request, which only contains a new AppId.
    ///
    /// # Errors
    /// This function doesn't typically error.
    async fn create_session(&self, _request: Request<CreateSessionRequest>) -> Result<Response<CreateSessionReply>, Status> {
        let report = ProfileReport::auto_reporting_file("brane-drv DriverHandler::create_session", "brane-drv_create-session");
        let _guard = report.time("Total");

        // Create a new VM for this session
        let app_id: AppId = AppId::generate();
        self.sessions.insert(app_id.clone(), (InstanceVm::new(&self.node_config_path, app_id.clone(), self.proxy.clone()), Instant::now()));

        // Now return the ID to the user for future reference
        debug!("Created new session '{}'", app_id);
        let reply = CreateSessionReply { uuid: app_id.into() };
        Ok(Response::new(reply))
    }

    /// Checks a workflow's validity in the backing instance.
    ///
    /// # Arguments
    /// - `request`: The request with the new (already compiled) snippet to validate.
    ///
    /// # Returns
    /// The response to the request, which contains the verdict of all checkers.
    ///
    /// # Errors
    /// This function may error for any reason a job might fail.
    async fn check(&self, request: Request<CheckRequest>) -> Result<Response<CheckReply>, Status> {
        let report = ProfileReport::auto_reporting_file("brane-drv DriverHandler::check", "brane-drv_check");
        let overhead = report.time("Handle overhead");

        let CheckRequest { workflow } = request.into_inner();
        debug!("Receiving check request");

        // Deserialize the workflow
        debug!("Deserializing input workflow...");
        let workflow: Workflow = match serde_json::from_str(&workflow) {
            Ok(workflow) => workflow,
            Err(err) => {
                debug!("{}", trace!(("Incoming request has invalid workflow"), err));
                return Err(Status::invalid_argument("Invalid workflow"));
            },
        };

        // Read the node file
        debug!("Loading node config file '{}'...", self.node_config_path.display());
        let central_cfg: CentralConfig = match NodeConfig::from_path_async(&self.node_config_path).await {
            Ok(cfg) => match cfg.node {
                NodeSpecificConfig::Central(central) => central,
                NodeSpecificConfig::Worker(_) | NodeSpecificConfig::Proxy(_) => {
                    error!("Given node config file '{}' is for a {}, but expected a Central", self.node_config_path.display(), cfg.node.variant());
                    return Err(Status::internal("An internal error has occurred"));
                },
            },
            Err(err) => {
                error!("{}", trace!(("Failed to read node config file '{}'", self.node_config_path.display()), err));
                return Err(Status::internal("An internal error has occurred"));
            },
        };

        // Read the infra file
        debug!("Loading infra file '{}'...", central_cfg.paths.infra.display());
        let infra: InfraFile = match InfraFile::from_path_async(&central_cfg.paths.infra).await {
            Ok(infra) => infra,
            Err(err) => {
                error!("{}", trace!(("Failed to read infra file '{}'", central_cfg.paths.infra.display()), err));
                return Err(Status::internal("An internal error has occurred"));
            },
        };
        overhead.stop();

        // Plan the workflow first
        debug!("Planning workflow on instance `brane-plr`...");
        let wf_id: String = workflow.id.clone();
        let workflow: Workflow =
            match InstancePlanner::plan(&central_cfg.services.plr.address, AppId::generate(), workflow, report.nest("Planning")).await {
                Ok(wf) => wf,
                Err(PlanError::CheckerDenied { domain, reasons }) => {
                    debug!("Checker denied workflow during planning already");
                    return Ok(Response::new(CheckReply {
                        verdict: false,
                        who: Some(domain),
                        reasons,
                        profile: serde_json::to_string(report.scope()).ok(),
                    }));
                },
                Err(err) => {
                    error!("{}", trace!(("Failed to plan workflow '{wf_id}'"), err));
                    return Err(Status::internal("An internal error has occurred"));
                },
            };

        // Generate futures for handling everything
        debug!("Generating requests for workflow '{}'...", workflow.id);
        let req_gen = report.time("Spawning requests");
        let handles: Vec<(String, JoinHandle<RequestOutput>)> = match check::spawn_requests(&infra, &workflow) {
            Ok(reqs) => reqs,
            Err(err) => {
                error!("{}", trace!(("Failed to spawn requests for workflow '{}'", workflow.id), err));
                return Err(Status::internal("An internal error has occurred"));
            },
        };
        req_gen.stop();

        // Next, join them all
        debug!("Waiting for requests for workflow '{}' to complete...", workflow.id);
        let req_join = report.time("Joining requests");
        let mut result: Option<(String, Vec<String>)> = None;
        for (checker, handle) in handles {
            // Attempt to await the handle
            let res: RequestOutput = match handle.await {
                Ok(res) => res,
                Err(err) => {
                    error!("{}", trace!(("Failed to await JoinHandle for workflow '{}'", workflow.id), err));
                    return Err(Status::internal("An internal error has occurred"));
                },
            };

            // Match on the result to propagate appropriately
            match res {
                // Keep going if this request is OK
                Ok(None) => continue,
                Ok(Some(who)) => {
                    // Stop if the first checker denied it
                    result = Some(who);
                    break;
                },
                Err(err) => {
                    // Stop if any request failed
                    error!("{}", trace!(("Failed to ask checker '{checker}' for permission for workflow '{}'", workflow.id), err));
                    return Err(Status::internal("An internal error has occurred"));
                },
            }
        }
        req_join.stop();

        // Send back the verdict to the user!
        info!("Checkers verdict for workflow '{}' is {}", workflow.id, if result.is_none() { "ALLOW" } else { "DENY" });
        if let Some((who, reasons)) = result {
            Ok(Response::new(CheckReply { verdict: false, who: Some(who), reasons, profile: serde_json::to_string(report.scope()).ok() }))
        } else {
            Ok(Response::new(CheckReply { verdict: true, who: None, reasons: vec![], profile: serde_json::to_string(report.scope()).ok() }))
        }
    }

    /// Executes a new job in an existing BraneScript session.
    ///
    /// # Arguments
    /// - `request`: The request with the new (already compiled) snippet to execute.
    ///
    /// # Returns
    /// The response to the request, which contains the result of this workflow (if any).
    ///
    /// # Errors
    /// This function may error for any reason a job might fail.
    async fn execute(&self, request: Request<ExecuteRequest>) -> Result<Response<Self::ExecuteStream>, Status> {
        let report = ProfileReport::auto_reporting_file("brane-drv DriverHandler::execute", "brane-drv_execute");
        let overhead = report.time("Handle overhead");

        let request = request.into_inner();
        debug!("Receiving execute request for session '{}'", request.uuid);

        // Prepare gRPC stream between client and (this) driver.
        let (tx, rx) = mpsc::channel::<Result<ExecuteReply, Status>>(10);

        // Parse the given ID
        let app_id: AppId = match AppId::from_str(&request.uuid) {
            Ok(app_id) => app_id,
            Err(err) => {
                fatal_err!(tx, rx, Status::invalid_argument, err);
            },
        };

        // Fetch the VM
        let sessions: Arc<DashMap<AppId, (InstanceVm, Instant)>> = self.sessions.clone();
        let vm: InstanceVm = match sessions.get(&app_id) {
            Some(vm) => vm.0.clone(),
            None => {
                fatal_err!(tx, rx, Status::internal(format!("No session with ID '{app_id}' found")));
            },
        };

        // We're gonna run the rest asynchronous, to allow the client to earlier receive callbacks
        overhead.stop();
        tokio::spawn(async move {
            debug!("Executing workflow for session '{}'", app_id);

            // We assume that the input is an already compiled workflow; so no need to fire up any parsers/compilers

            // We only have to use JSON magic
            let par = report.time("Workflow parsing");
            debug!("Parsing workflow of {} characters", request.input.len());
            let workflow: Workflow = match serde_json::from_str(&request.input) {
                Ok(workflow) => workflow,
                Err(err) => {
                    debug!(
                        "Workflow:\n{}\n{}\n{}\n\n",
                        (0..80).map(|_| '-').collect::<String>(),
                        request.input,
                        (0..80).map(|_| '-').collect::<String>()
                    );
                    fatal_err!(tx, Status::invalid_argument, err);
                },
            };
            par.stop();

            // We now have a runnable plan ( ͡° ͜ʖ ͡°), so run it
            debug!("Executing workflow of {} edges", workflow.graph.len());
            let (vm, res): (InstanceVm, Result<FullValue, RemoteVmError>) =
                report.nest_fut("VM execution", |scope| vm.exec(tx.clone(), app_id.clone(), workflow, scope)).await;

            // Insert the VM again
            debug!("Saving state session state");
            sessions.insert(app_id, (vm, Instant::now()));

            // Switch on the actual result and send that back to the user
            match res {
                Ok(res) => {
                    debug!("Completed execution.");
                    let _ret = report.time("Returning value");

                    // Serialize the value
                    let sres: String = match serde_json::to_string(&res) {
                        Ok(sres) => sres,
                        Err(source) => {
                            fatal_err!(tx, Status::internal, source);
                        },
                    };

                    // Create the reply text
                    let msg = String::from("Driver completed execution.");
                    let reply = ExecuteReply { close: true, debug: Some(msg.clone()), stderr: None, stdout: None, value: Some(sres) };

                    // Send it
                    if let Err(err) = tx.send(Ok(reply)).await {
                        error!("{}", trace!(("Failed to send workflow result back to client"), err));
                    }
                },
                Err(RemoteVmError::PlanError { source: PlanError::CheckerDenied { domain, reasons } }) => {
                    fatal_err!(
                        tx,
                        Status::permission_denied(format!(
                            "Checker of domain '{domain}' denied execution{}",
                            if !reasons.is_empty() {
                                format!("\n\nReasons:\n{}\n", reasons.iter().map(|r| format!(" - {r}")).collect::<Vec<String>>().join("\n"))
                            } else {
                                String::new()
                            }
                        ))
                    );
                },
                Err(source) => {
                    fatal_err!(tx, Status::internal, source);
                },
            };
        });

        // Return the receiver stream so the client can find us
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
