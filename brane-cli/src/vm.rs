//  VM.rs
//    by Lut99
//
//  Created:
//    24 Oct 2022, 15:34:05
//  Last edited:
//    31 Jan 2024, 14:23:06
//  Auto updated?
//    Yes
//
//  Description:
//!   The VM for the local use-case is one that simply directly
//!   interacts with the planner and worker without any complicated
//!   networking.
//

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use brane_ast::Workflow;
use brane_ast::locations::Location;
use brane_exe::Vm;
use brane_exe::errors::VmError;
use brane_exe::pc::ProgramCounter;
use brane_exe::spec::{RunState, TaskInfo, VmPlugin};
use brane_exe::value::FullValue;
use brane_shr::formatters::BlockFormatter;
use brane_shr::fs::copy_dir_recursively_async;
use brane_tsk::docker::{self, DockerOptions, ExecuteInfo, ImageSource, Network};
use brane_tsk::errors::{CommitError, ExecuteError, PreprocessError, StdoutError};
use brane_tsk::spec::{LOCALHOST, Planner as _};
use brane_tsk::tools::decode_base64;
use chrono::Utc;
use parking_lot::Mutex;
use specifications::container::{Image, VolumeBind};
use specifications::data::{AccessKind, DataIndex, DataInfo, DataName, PreprocessKind};
use specifications::package::{PackageIndex, PackageInfo};
use specifications::profiling::ProfileScopeHandle;
use tokio::fs as tfs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

pub use crate::errors::OfflineVmError as Error;
use crate::planner::OfflinePlanner;
use crate::spec::{GlobalState, LocalState};


/***** AUXILLARY *****/
/// Defines the plugins used that implement offline task execution.
pub struct OfflinePlugin;

#[async_trait::async_trait]
impl VmPlugin for OfflinePlugin {
    type CommitError = CommitError;
    type ExecuteError = ExecuteError;
    type GlobalState = GlobalState;
    type LocalState = LocalState;
    type PreprocessError = PreprocessError;
    type StdoutError = StdoutError;

    async fn preprocess(
        _global: Arc<RwLock<Self::GlobalState>>,
        _local: Self::LocalState,
        pc: ProgramCounter,
        _loc: Location,
        name: DataName,
        preprocess: PreprocessKind,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<AccessKind, Self::PreprocessError> {
        info!("Preprocessing data '{name}' for call at {pc} in an offline environment");
        debug!("Method of preprocessing: {preprocess:?}");

        // Match on the type of preprocessing
        match preprocess {
            // Anything that requires transfers, fails
            PreprocessKind::TransferRegistryTar { .. } => Err(PreprocessError::UnavailableData { name }),
        }
    }

    async fn execute(
        global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        info: TaskInfo<'_>,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<Option<FullValue>, Self::ExecuteError> {
        let mut info = info;
        info!("Calling task '{}' in an offline environment", info.name);
        debug!("Package: '{}', version {}", info.package_name, info.package_version);
        debug!(
            "Task input (data-wise): {}",
            info.input.iter().map(|(name, access)| format!("'{name}' ({access:?})")).collect::<Vec<String>>().join(", ")
        );
        debug!("Task generates result? {}", if info.result.is_some() { "yes" } else { "no" });

        // First, we query the global state to find the result directory and required indices
        let get = prof.time("Information retrieval");
        let (docker_opts, package_dir, results_dir, pindex, keep_container): (DockerOptions, PathBuf, PathBuf, Arc<PackageIndex>, bool) = {
            let state: RwLockReadGuard<GlobalState> = global.read().unwrap();
            (state.docker_opts.clone(), state.package_dir.clone(), state.results_dir.clone(), state.pindex.clone(), state.keep_containers)
        };

        // Next, we resolve the package
        let pinfo: &PackageInfo =
            match pindex.get(info.package_name, if info.package_version.is_latest() { None } else { Some(info.package_version) }) {
                Some(pinfo) => pinfo,
                None => return Err(ExecuteError::UnknownPackage { name: info.package_name.into(), version: *info.package_version }),
            };
        get.stop();

        // Resolve the input arguments, generating the folders we have to bind
        let binds: Vec<VolumeBind> = prof
            .time_fut("argument preprocessing", docker::preprocess_args(&mut info.args, &info.input, info.result, None::<String>, results_dir))
            .await?;
        let params: String = serde_json::to_string(&info.args).map_err(|source| ExecuteError::ArgsEncodeError { source })?;

        // Create an ExecuteInfo with that
        let image: Image = Image::new(info.package_name, Some(info.package_version), Some(pinfo.digest.as_ref().unwrap()));
        let einfo: ExecuteInfo = ExecuteInfo {
            name: info.name.into(),
            image: image.clone(),
            image_source: ImageSource::Path(package_dir.join(info.package_name).join(info.package_version.to_string()).join("image.tar")),

            command: vec![
                "-d".into(),
                "--application-id".into(),
                "test".into(),
                "--location-id".into(),
                "localhost".into(),
                "--job-id".into(),
                "1".into(),
                pinfo.kind.into(),
                info.name.into(),
                STANDARD.encode(params),
            ],
            binds,
            network: Network::None,
            capabilities: info.requirements.clone(),
        };

        // We can now execute the task on the local Docker daemon
        debug!("Executing task '{}'...", info.name);
        let (code, stdout, stderr) = prof
            .time_fut("execution", docker::run_and_wait(docker_opts, einfo, keep_container))
            .await
            .map_err(|source| ExecuteError::DockerError { name: info.name.into(), image: Box::new(image.clone()), source })?;
        debug!("Container return code: {}", code);
        debug!("Container stdout/stderr:\n\nstdout:\n{}\n\nstderr:\n{}\n", BlockFormatter::new(&stdout), BlockFormatter::new(&stderr));

        // If the return code is no bueno, error and show stderr
        if code != 0 {
            return Err(ExecuteError::ExternalCallFailed { name: info.name.into(), image: Box::new(image), code, stdout, stderr });
        }

        // Otherwise, decode the output of branelet to the value returned
        let dec = prof.time("Decoding");
        let output = stdout.lines().last().unwrap_or_default().to_string();
        let raw: String = decode_base64(output)?;
        let value: Option<FullValue> = serde_json::from_str(&raw).map_err(|source| ExecuteError::JsonDecodeError { raw, source })?;
        dec.stop();

        // Done, return the value
        debug!("Task '{}' returned value: '{:?}'", info.name, value);
        Ok(value)
    }

    async fn stdout(
        _global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        text: &str,
        newline: bool,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::StdoutError> {
        info!("Writing '{}' to stdout (newline: {}) in an offline environment...", text, if newline { "yes" } else { "no" });

        // Simply write
        if !newline {
            print!("{text}");
        } else {
            println!("{text}");
        }

        // Done
        Ok(())
    }

    async fn publicize(
        _global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        _loc: &Location,
        name: &str,
        path: &Path,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError> {
        info!("Publicizing intermediate result '{}' in an offline environment...", name);
        debug!("Physical file(s): {}", path.display());

        // There's not really anything to do in an offline environment; the results are already known locally and ready for use

        // Done
        Ok(())
    }

    async fn commit(
        global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        _loc: &Location,
        name: &str,
        path: &Path,
        data_name: &str,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError> {
        info!("Committing intermediate result '{}' to '{}' in an offline environment...", name, data_name);
        debug!("Physical file(s): {}", path.display());

        // Check the data index to check if it exists or not
        let inf = prof.time("Information retrieval");
        let (results_dir, dataset_dir, info): (PathBuf, PathBuf, Option<DataInfo>) = {
            let state: RwLockReadGuard<GlobalState> = global.read().unwrap();
            (state.results_dir.clone(), state.dataset_dir.clone(), state.dindex.get(data_name).cloned())
        };
        inf.stop();

        // Match on whether it already exists or not
        let copy = prof.time("Copying");
        if let Some(info) = info {
            // Make sure that it has the current location (probably so)
            if let Some(access) = info.access.get(LOCALHOST) {
                debug!("Dataset '{}' already exists; overwriting file...", data_name);

                // Copy the source to the target destination (file, in this case)
                match access {
                    AccessKind::File { path: data_path } => {
                        // Simply copy the one directory over the other and it's updated
                        copy_dir_recursively_async(results_dir.join(path), data_path)
                            .await
                            .map_err(|source| CommitError::DataCopyError { source })?;
                    },
                }
            } else {
                return Err(CommitError::UnavailableDataError { name: data_name.into(), locs: info.access.keys().cloned().collect() });
            }
        } else {
            debug!("Dataset '{}' doesn't exist; creating new entry...", data_name);

            // Prepare the package directory by creating it if it doesn't exist yet
            let dir: PathBuf = dataset_dir.join(data_name);
            if !dir.is_dir() {
                if dir.exists() {
                    return Err(CommitError::DataDirNotADir { path: dir });
                }
                tfs::create_dir_all(&dir).await.map_err(|source| CommitError::DataDirCreateError { path: dir.clone(), source })?;
            }

            // Create a new DataInfo struct
            let info: DataInfo = DataInfo {
                name: data_name.into(),
                owners: None,      // TODO: Merge parent datasets??
                description: None, // TODO: Add parents & algorithm in description??
                created: Utc::now(),

                access: HashMap::from([("localhost".into(), AccessKind::File { path: dir.join("data") })]),
            };

            // Write it to the target folder
            let info_path: PathBuf = dir.join("data.yml");
            let mut handle: tfs::File =
                tfs::File::create(&info_path).await.map_err(|source| CommitError::DataInfoCreateError { path: info_path.clone(), source })?;
            let sinfo: String = serde_yaml::to_string(&info).map_err(|source| CommitError::DataInfoSerializeError { source })?;
            handle.write_all(sinfo.as_bytes()).await.map_err(|source| CommitError::DataInfoWriteError { path: info_path.clone(), source })?;

            // Finally, copy the intermediate file to the target
            let source: PathBuf = results_dir.join(path);
            let target: PathBuf = dir.join("data");
            debug!("Copying '{}' to '{}'...", source.display(), target.display());
            copy_dir_recursively_async(source, target).await.map_err(|source| CommitError::DataCopyError { source })?;

            // The dataset has now been promoted
            debug!("Dataset created successfully.");
        }
        copy.stop();

        // Done
        Ok(())
    }
}





/***** LIBRARY *****/
/// Defines a VM that has no online interaction and does everything locally.
pub struct OfflineVm {
    /// The runtime state for the VM
    state: RunState<GlobalState>,
}

impl OfflineVm {
    /// Constructor for the OfflineVm that initializes it with the initial state.
    ///
    /// # Arguments
    /// - `docker_opts`: The information we need to connect to the local Docker daemon.
    /// - `keep_containers`: Whether to keep containers after execution completes or not.
    /// - `package_dir`: The directory where packages (and thus images) are stored.
    /// - `dataset_dir`: The directory where datasets (and thus committed results) are stored.
    /// - `results_dir`: The directory where temporary results are stored.
    /// - `package_index`: The PackageIndex to use to resolve packages.
    /// - `data_index`: The DataIndex to use to resolve data indices.
    ///
    /// # Returns
    /// A new OfflineVm instance with one coherent state.
    #[inline]
    pub fn new(
        docker_opts: DockerOptions,
        keep_containers: bool,
        package_dir: impl Into<PathBuf>,
        dataset_dir: impl Into<PathBuf>,
        results_dir: impl Into<PathBuf>,
        package_index: Arc<PackageIndex>,
        data_index: Arc<DataIndex>,
    ) -> Self {
        Self {
            state: Self::new_state(GlobalState {
                docker_opts,
                keep_containers,

                package_dir: package_dir.into(),
                dataset_dir: dataset_dir.into(),
                results_dir: results_dir.into(),

                pindex: package_index,
                dindex: data_index,
                results: Arc::new(Mutex::new(HashMap::new())),
            }),
        }
    }

    /// Runs the given workflow on this VM.
    ///
    /// There is a bit of ownership awkwardness going on, but that's due to the need for the struct to outlive threads.
    ///
    /// # Arguments
    /// - `workflow`: The Workflow to execute.
    ///
    /// # Returns
    /// The result of the workflow, if any. It also returns `self` again for subsequent runs.
    pub async fn exec(self, workflow: Workflow) -> (Self, Result<FullValue, Error>) {
        // Step 1: Plan
        let plan: Result<Workflow, Error> = {
            let planner: OfflinePlanner = {
                let state: RwLockReadGuard<GlobalState> = self.state.global.read().unwrap();

                // Plan with the previous results
                OfflinePlanner::new(state.dindex.clone(), state.results.clone())
            };
            match planner.plan(workflow).await {
                Ok(plan) => Ok(plan),
                Err(source) => Err(Error::PlanError { source }),
            }
        };
        // Unwrap the result (necessary to avoid borrowing conflicts with the lock)
        let plan: Workflow = match plan {
            Ok(plan) => plan,
            Err(source) => return (self, Err(source)),
        };

        // Step 2: Execution
        // Now wrap ourselves in a lock so that we can run the internal vm
        let this: Arc<RwLock<Self>> = Arc::new(RwLock::new(self));

        // Run the VM and get self back
        let result: Result<FullValue, VmError> = Self::run::<OfflinePlugin>(this.clone(), plan, ProfileScopeHandle::dummy()).await;
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

    /// Returns the path to the internal temporary folder for results.
    #[inline]
    pub fn results_dir(&self) -> PathBuf { self.state.global.read().unwrap().results_dir.clone() }
}

impl Vm for OfflineVm {
    type GlobalState = GlobalState;
    type LocalState = LocalState;

    fn store_state(this: &Arc<RwLock<Self>>, state: RunState<Self::GlobalState>) -> Result<(), brane_exe::Error> {
        // Get a lock and store it
        let mut lock: RwLockWriteGuard<Self> = this.write().unwrap();
        lock.state = state;
        Ok(())
    }

    fn load_state(this: &Arc<RwLock<Self>>) -> Result<RunState<Self::GlobalState>, brane_exe::Error> {
        // Get a lock and read it
        let lock: RwLockReadGuard<Self> = this.read().unwrap();
        Ok(lock.state.clone())
    }
}
