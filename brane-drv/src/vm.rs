//  VM.rs
//    by Lut99
//
//  Created:
//    27 Oct 2022, 10:14:26
//  Last edited:
//    07 Mar 2024, 14:18:12
//  Auto updated?
//    Yes
//
//  Description:
//!   The InstanceVm provides the `brane-exe` plugin for communicating
//!   with an external planner and an external worker. Moreover, the
//!   client (i.e., the submitter of the workflow) is remote as well,
//!   complicating the `stdout()` function.
//

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use async_trait::async_trait;
use brane_ast::Workflow;
use brane_ast::func_id::FunctionId;
use brane_ast::locations::Location;
use brane_cfg::info::Info as _;
use brane_cfg::infra::InfraFile;
use brane_cfg::node::{CentralConfig, NodeConfig, NodeSpecificConfig};
use brane_exe::pc::ProgramCounter;
use brane_exe::spec::{TaskInfo, VmPlugin};
use brane_exe::{Error as VmError, FullValue, RunState, Vm};
use brane_prx::client::ProxyClient;
use brane_tsk::errors::{CommitError, ExecuteError, PreprocessError, StdoutError, StringError};
use brane_tsk::spec::{AppId, JobStatus};
use enum_debug::EnumDebug as _;
use serde_json_any_key::MapIterToJson;
use specifications::address::Address;
use specifications::data::{AccessKind, DataName, PreprocessKind};
use specifications::profiling::ProfileScopeHandle;
use specifications::working::TransferRegistryTar;
use specifications::{driving as driving_grpc, working as working_grpc};
use tokio::sync::mpsc::Sender;
use tonic::{Response, Status, Streaming};
use tracing::{debug, info, warn};

pub use crate::errors::RemoteVmError as Error;
use crate::planner::InstancePlanner;
use crate::spec::{GlobalState, LocalState};


/***** HELPER MACROS *****/
/// Does a status update on a JobStatus received from the `brane-job` node, but one that does not return yet.
macro_rules! mundane_status_update {
    ($state:ident, $status:expr) => {
        if $status.progress_index() > $state.progress_index() {
            $state = $status;
        }
    };
}





/***** LIBRARY *****/
/// The InstancePlugin provides `brane-exe` functions for task execution.
pub struct InstancePlugin;

#[async_trait]
impl VmPlugin for InstancePlugin {
    type CommitError = CommitError;
    type ExecuteError = ExecuteError;
    type GlobalState = GlobalState;
    type LocalState = LocalState;
    type PreprocessError = PreprocessError;
    type StdoutError = StdoutError;

    async fn preprocess(
        global: Arc<RwLock<Self::GlobalState>>,
        _local: Self::LocalState,
        pc: ProgramCounter,
        loc: Location,
        name: DataName,
        preprocess: PreprocessKind,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<AccessKind, Self::PreprocessError> {
        info!("Preprocessing {} '{}' on '{}' in a distributed environment...", name.variant(), name.name(), loc);
        debug!("Preprocessing to be done: {:?}", preprocess);

        // Resolve the location to an address (and get the proxy while we have a lock anyway)
        let disk = prof.time("File loading");
        let (proxy, delegate_address, workflow): (Arc<ProxyClient>, Address, String) = {
            // Load the node config file to get the path to...
            let state: RwLockReadGuard<GlobalState> = global.read().unwrap();

            // Resolve to an address
            match state.infra.as_ref().unwrap().get(&loc) {
                Some(info) => (
                    state.proxy.clone(),
                    info.delegate.clone(),
                    state.workflow.clone().unwrap_or_else(|| panic!("Workflow state not injected by the time the workflow is being executed")),
                ),
                None => {
                    return Err(PreprocessError::UnknownLocationError { loc });
                },
            }
        };
        disk.stop();

        // Unpack the preprocesskind
        let transfer: TransferRegistryTar = match preprocess {
            PreprocessKind::TransferRegistryTar { location, dataname } => TransferRegistryTar { location, dataname: Some(dataname.into()) },
        };

        // Prepare the request to send to the delegate node
        debug!("Sending preprocess request to job node '{}'...", delegate_address);
        let job = prof.time(format!("on {delegate_address}"));
        let message: working_grpc::PreprocessRequest = working_grpc::PreprocessRequest {
            // NOTE: For now, we hardcode the central orchestrator as only "use-case" (registry)
            use_case: "central".into(),

            kind: transfer,

            workflow,
            pc: Some(specifications::working::ProgramCounter {
                func_id:  if let FunctionId::Func(id) = pc.func_id { id as u64 } else { u64::MAX },
                edge_idx: pc.edge_idx as u64,
            }),
        };

        // Create the client
        let mut client: working_grpc::JobServiceClient = proxy
            .connect_to_job(delegate_address.to_string())
            .await
            .map_err(|source| PreprocessError::ProxyError { source: Box::new(source) })?
            .map_err(|source| PreprocessError::GrpcConnectError { endpoint: delegate_address.clone(), source })?;

        // Send the request to the job node
        let response: Response<working_grpc::PreprocessReply> = client
            .preprocess(message)
            .await
            .map_err(|source| PreprocessError::GrpcRequestError { what: "PreprocessRequest", endpoint: delegate_address.clone(), source })?;
        let result: working_grpc::PreprocessReply = response.into_inner();
        job.stop();

        // If it was, attempt to deserialize the accesskind
        let par = prof.time("Result parsing");
        let access: AccessKind = serde_json::from_str(&result.access).map_err(|source| PreprocessError::AccessKindParseError {
            endpoint: delegate_address.clone(),
            raw: result.access,
            source,
        })?;
        par.stop();

        // Done
        Ok(access)
    }

    async fn execute(
        global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        info: TaskInfo<'_>,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<Option<FullValue>, Self::ExecuteError> {
        info!("Executing task '{}' at '{}' in a distributed environment...", info.name, info.location);
        debug!("Package: '{}' v{}", info.package_name, info.package_version);
        debug!("Input data: {:?}", info.input.keys().map(|k| format!("{k}")).collect::<Vec<String>>());
        debug!("Result: {:?}", info.result);
        debug!("Input arguments: {:#?}", info.args);
        debug!("Requirements: {:?}", info.requirements);

        // Resolve the location to an address (and get the proxy and the workflow while we have a lock anyway)
        let disk = prof.time("File loading");
        let (proxy, delegate_address, workflow): (Arc<ProxyClient>, Address, String) = {
            let state: RwLockReadGuard<GlobalState> = global.read().unwrap();

            // Resolve to an address and return that with the other addresses
            (
                state.proxy.clone(),
                match state.infra.as_ref().unwrap().get(info.location) {
                    Some(info) => info.delegate.clone(),
                    None => {
                        return Err(ExecuteError::UnknownLocationError { loc: info.location.clone() });
                    },
                },
                state.workflow.as_ref().unwrap().clone(),
            )
        };
        disk.stop();

        // Prepare the request to send to the delegate node
        debug!("Sending execute request to job node '{}'...", delegate_address);
        let job = prof.time(format!("on {delegate_address}"));
        let message: working_grpc::ExecuteRequest = working_grpc::ExecuteRequest {
            // NOTE: For now, we hardcode the central orchestrator as only "use-case" (registry)
            use_case: "central".into(),

            workflow,
            call_pc: specifications::working::ProgramCounter {
                func_id:  if let FunctionId::Func(id) = info.pc.func_id { id as u64 } else { u64::MAX },
                edge_idx: info.pc.edge_idx as u64,
            },
            task_def: info.def as u64,

            input: info.input.to_json_map().unwrap(),
            result: info.result.clone(),
            args: serde_json::to_string(&info.args).unwrap(),
        };

        // Create the client
        let mut client: working_grpc::JobServiceClient = proxy
            .connect_to_job(delegate_address.to_string())
            .await
            .map_err(|source| ExecuteError::ProxyError { source: Box::new(source) })?
            .map_err(|source| ExecuteError::GrpcConnectError { endpoint: delegate_address.clone(), source })?;

        // Send the request to the job node
        let response: Response<Streaming<working_grpc::ExecuteReply>> = client
            .execute(message)
            .await
            .map_err(|source| ExecuteError::GrpcRequestError { what: "ExecuteRequest", endpoint: delegate_address.clone(), source })?;
        let mut stream: Streaming<working_grpc::ExecuteReply> = response.into_inner();

        // Now we tick off incoming messages
        let mut state: JobStatus = JobStatus::Unknown;
        // let mut error : Option<String> = None;
        let mut result: Result<FullValue, String> = Err("No response".into());
        #[allow(irrefutable_let_patterns)]
        while let message = stream.message().await {
            match message {
                // The message itself went alright
                Ok(Some(reply)) => {
                    // Create a JobStatus based on the given ExecuteStatus
                    let status: JobStatus = match JobStatus::from_status(
                        match working_grpc::TaskStatus::try_from(reply.status) {
                            Ok(status) => status,
                            Err(_) => {
                                warn!("Unknown job status '{}' (skipping message)", reply.status);
                                continue;
                            },
                        },
                        reply.value,
                    ) {
                        Ok(status) => status,
                        Err(err) => {
                            warn!("Incoming message does not have a parseable job status: {} (skipping message)", err);
                            continue;
                        },
                    };

                    // Match it
                    debug!("Received status update: {:?}", working_grpc::TaskStatus::from(&status));
                    match &status {
                        JobStatus::Unknown => {
                            warn!("Received JobStatus::Unknown, which doesn't make a whole lot of sense");
                        },

                        JobStatus::Received => {
                            mundane_status_update!(state, status);
                        },

                        JobStatus::Authorized => {
                            mundane_status_update!(state, status);
                        },
                        JobStatus::Denied => {
                            result = Err("Permission denied".into());
                            state = status;
                            break;
                        },
                        JobStatus::AuthorizationFailed(err) => {
                            result = Err(err.clone());
                            state = status;
                            break;
                        },

                        JobStatus::Created => {
                            mundane_status_update!(state, status);
                        },
                        JobStatus::CreationFailed(err) => {
                            result = Err(err.clone());
                            state = status;
                            break;
                        },

                        JobStatus::Ready => {
                            mundane_status_update!(state, status);
                        },
                        JobStatus::Initialized => {
                            mundane_status_update!(state, status);
                        },
                        JobStatus::InitializationFailed(err) => {
                            result = Err(err.clone());
                            state = status;
                            break;
                        },
                        JobStatus::Started => {
                            mundane_status_update!(state, status);
                        },
                        JobStatus::StartingFailed(err) => {
                            result = Err(err.clone());
                            state = status;
                            break;
                        },

                        JobStatus::Heartbeat => {
                            mundane_status_update!(state, status);
                        },
                        JobStatus::Completed => {
                            mundane_status_update!(state, status);
                        },
                        JobStatus::CompletionFailed(err) => {
                            result = Err(err.clone());
                            state = status;
                            break;
                        },

                        JobStatus::Finished(value) => {
                            result = Ok(value.clone());
                            state = status;
                            break;
                        },
                        JobStatus::Stopped => {
                            result = Err("Job was stopped".into());
                            state = status;
                            break;
                        },
                        JobStatus::DecodingFailed(err) => {
                            result = Err(err.clone());
                            state = status;
                            break;
                        },
                        JobStatus::Failed(code, stdout, stderr) => {
                            result = Err(format!(
                                "Job failed with exit code {}\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n",
                                code,
                                (0..80).map(|_| '-').collect::<String>(),
                                stdout,
                                (0..80).map(|_| '-').collect::<String>(),
                                (0..80).map(|_| '-').collect::<String>(),
                                stderr,
                                (0..80).map(|_| '-').collect::<String>()
                            ));
                            state = status;
                            break;
                        },
                    }
                },
                Ok(None) => {
                    // Stream closed
                    break;
                },

                Err(status) => {
                    // Something went wrong
                    result = Err(format!("Status error: {status}"));
                    break;
                },
            }
        }
        job.stop();

        // Now we simply match on the value to see if we got something
        let result: FullValue = result.map_err(|source| ExecuteError::ExecuteError {
            endpoint: delegate_address,
            name:     info.name.into(),
            status:   state.into(),
            source:   StringError(source),
        })?;

        // That's it!
        debug!("Task '{}' result: {:?}", info.name, result);
        Ok(if let FullValue::Void = result { None } else { Some(result) })
    }

    async fn stdout(
        global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        text: &str,
        newline: bool,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::StdoutError> {
        info!("Writing '{}' to stdout in a distributed environment...", text);
        debug!("Newline: {}", if newline { "yes" } else { "no" });

        // Get the TX (so that the lock does not live over an `.await`)
        let tx: Arc<Sender<Result<driving_grpc::ExecuteReply, Status>>> = {
            let state: RwLockReadGuard<GlobalState> = global.read().unwrap();
            state.tx.as_ref().expect("Missing `tx` in GlobalState; did you forget to update it before this poll?").clone()
        };

        // Write stdout to the tx
        tx.send(Ok(driving_grpc::ExecuteReply {
            stdout: Some(format!("{}{}", text, if newline { "\n" } else { "" })),
            stderr: None,
            debug:  None,
            value:  None,

            close: false,
        }))
        .await
        .map_err(|source| StdoutError::TxWriteError { source })?;

        // Done
        Ok(())
    }

    async fn publicize(
        _global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        loc: &Location,
        name: &str,
        path: &Path,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError> {
        info!("Publicizing intermediate result '{}' living at '{}' in a distributed environment...", name, loc);
        debug!("File: '{}'", path.display());

        // There's nothing to do, since the registry and delegate share the same data folder

        Ok(())
    }

    async fn commit(
        global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        loc: &Location,
        name: &str,
        path: &Path,
        data_name: &str,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError> {
        info!("Committing intermediate result '{}' living at '{}' as '{}' in a distributed environment...", name, loc, data_name);
        debug!("File: '{}'", path.display());

        // We submit a commit request to the job node

        // Resolve the location to an address (and get the proxy client while at it)
        let disk = prof.time("File loading");
        let (proxy, delegate_address): (Arc<ProxyClient>, Address) = {
            let state: RwLockReadGuard<GlobalState> = global.read().unwrap();

            // Resolve to an address
            match state.infra.as_ref().unwrap().get(loc) {
                Some(info) => (state.proxy.clone(), info.delegate.clone()),
                None => {
                    return Err(CommitError::UnknownLocationError { loc: loc.clone() });
                },
            }
        };
        disk.stop();

        // Prepare the request to send to the delegate node
        debug!("Sending commit request to job node '{}'...", delegate_address);
        let job = prof.time(format!("on {delegate_address}"));
        let message: working_grpc::CommitRequest = working_grpc::CommitRequest { result_name: name.into(), data_name: data_name.into() };

        // Create the client
        let mut client: working_grpc::JobServiceClient = proxy
            .connect_to_job(delegate_address.to_string())
            .await
            .map_err(|source| CommitError::ProxyError { source: Box::new(source) })?
            .map_err(|source| CommitError::GrpcConnectError { endpoint: delegate_address.clone(), source })?;

        // Send the request to the job node
        let response: Response<working_grpc::CommitReply> = client.commit(message).await.map_err(|source| CommitError::GrpcRequestError {
            what: "CommitRequest",
            endpoint: delegate_address.clone(),
            source,
        })?;
        let _: working_grpc::CommitReply = response.into_inner();
        job.stop();

        // Done (nothing to return)
        Ok(())
    }
}



/// The instantiated Vm for the Instance use-case.
#[derive(Clone)]
pub struct InstanceVm {
    /// The runtime state for the VM
    state: RunState<GlobalState>,
}

impl InstanceVm {
    /// Constructor for the InstanceVm.
    ///
    /// # Arguments
    /// - `node_config_path`: The path to the configuration for this node's environment. For us, contains the path to the infra.yml and (optional) secrets.yml files.
    /// - `app_id`: The application ID for this session.
    /// - `proxy`: The ProxyClient that we use to connect to/through `brane-prx`.
    /// - `planner`: The client-side of a planner that we use to plan.
    ///
    /// # Returns
    /// A new InstanceVm instance.
    #[inline]
    pub fn new(node_config_path: impl Into<PathBuf>, app_id: AppId, proxy: Arc<ProxyClient>) -> Self {
        Self {
            // InfraPath::new(&node_config.node.central().paths.infra, &node_config.node.central().paths.secrets)
            state: Self::new_state(GlobalState { node_config_path: node_config_path.into(), app_id, proxy, infra: None, workflow: None, tx: None }),
        }
    }

    /// Runs the given workflow on this VM.
    ///
    /// There is a bit of ownership awkwardness going on, but that's due to the need for the struct to outlive threads.
    ///
    /// # Arguments
    /// - `tx`: The transmission channel to send feedback to the client on.
    /// - `id`: The identifier of the workflow this session is part of.
    /// - `workflow`: The Workflow to execute.
    /// - `prof`: The ProfileScope that can be used to provide additional information about the timings of the VM.
    ///
    /// # Returns
    /// The result of the workflow, if any. It also returns `self` again for subsequent runs.
    pub async fn exec(
        self,
        tx: Sender<Result<driving_grpc::ExecuteReply, Status>>,
        id: AppId,
        workflow: Workflow,
        prof: ProfileScopeHandle<'_>,
    ) -> (Self, Result<FullValue, Error>) {
        // Step 0: Load files
        let plr_addr: Address = {
            let mut global = self.state.global.write().unwrap();

            debug!("Loading node config file '{}'...", global.node_config_path.display());
            let central_cfg: CentralConfig = match NodeConfig::from_path(&global.node_config_path) {
                Ok(cfg) => match cfg.node {
                    NodeSpecificConfig::Central(central) => central,
                    NodeSpecificConfig::Worker(_) | NodeSpecificConfig::Proxy(_) => {
                        let path: PathBuf = global.node_config_path.clone();
                        drop(global);
                        return (self, Err(Error::IllegalNodeConfig { path, got: cfg.node.variant().to_string() }));
                    },
                },
                Err(source) => {
                    let path: PathBuf = global.node_config_path.clone();
                    drop(global);
                    return (self, Err(Error::NodeConfigLoad { path, source }));
                },
            };

            debug!("Loading infra file '{}'...", central_cfg.paths.infra.display());
            let infra: InfraFile = match InfraFile::from_path(&central_cfg.paths.infra) {
                Ok(infra) => infra,
                Err(source) => {
                    let path: PathBuf = global.node_config_path.clone();
                    drop(global);
                    return (self, Err(Error::InfraFileLoad { path, source }));
                },
            };

            // Inject the info into the state
            global.infra = Some(infra);

            // Done
            central_cfg.services.plr.address
        };



        // Step 1: Plan
        debug!("Planning workflow on Kafka planner...");
        let plan: Workflow = match prof.nest_fut("planning (brane-drv)", |scope| InstancePlanner::plan(&plr_addr, id, workflow, scope)).await {
            Ok(plan) => plan,
            Err(source) => {
                return (self, Err(Error::PlanError { source }));
            },
        };

        // Also update the TX & workflow in the internal state
        {
            let mut state: RwLockWriteGuard<GlobalState> = self.state.global.write().unwrap();
            state.workflow = Some(serde_json::to_string(&plan).unwrap());
            state.tx = Some(Arc::new(tx));
        }



        // Step 2: Execution
        // Now wrap ourselves in a lock so that we can run the internal vm
        let this: Arc<RwLock<Self>> = Arc::new(RwLock::new(self));

        // Run the VM and get self back
        let result: Result<FullValue, VmError> = prof.nest_fut("execution", |scope| Self::run::<InstancePlugin>(this.clone(), plan, scope)).await;
        let this: Self = match Arc::try_unwrap(this) {
            Ok(this) => this.into_inner().unwrap(),
            Err(_) => {
                panic!("Could not get self back");
            },
        };



        // Step 3: Result
        // Match the result to potentially error
        let value: FullValue = match result {
            Ok(value) => value,
            Err(source) => {
                return (this, Err(Error::ExecError { source }));
            },
        };

        // Done, return
        (this, Ok(value))
    }
}

impl Vm for InstanceVm {
    type GlobalState = GlobalState;
    type LocalState = LocalState;

    fn store_state(this: &Arc<RwLock<Self>>, state: RunState<Self::GlobalState>) -> Result<(), VmError> {
        // Get a lock and store it
        let mut lock: RwLockWriteGuard<Self> = this.write().unwrap();
        lock.state = state;
        Ok(())
    }

    fn load_state(this: &Arc<RwLock<Self>>) -> Result<RunState<Self::GlobalState>, VmError> {
        // Get a lock and read it
        let lock: RwLockReadGuard<Self> = this.read().unwrap();
        Ok(lock.state.clone())
    }
}
