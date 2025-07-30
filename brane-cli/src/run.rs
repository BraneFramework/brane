//  RUN.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 16:42:57
//  Last edited:
//    05 May 2025, 11:15:39
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements running a single BraneScript file.
//

use std::borrow::Cow;
use std::fs;
use std::io::{Read, Stderr, Stdout, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use brane_ast::ParserOptions;
use brane_ast::state::CompileState;
use brane_dsl::Language;
use brane_exe::FullValue;
use brane_exe::dummy::{DummyVm, Error as DummyVmError};
use brane_tsk::docker::DockerOptions;
use brane_tsk::errors::StringError;
use brane_tsk::spec::{AppId, LOCALHOST};
use console::style;
use parking_lot::{Mutex, MutexGuard};
use specifications::data::{AccessKind, DataIndex, DataInfo};
use specifications::driving::{CreateSessionRequest, DriverServiceClient, ExecuteRequest};
use specifications::package::PackageIndex;
use specifications::wir::Workflow;
use tempfile::{TempDir, tempdir};
use tonic::Code;

use crate::data;
use crate::errors::OfflineVmError;
pub use crate::errors::RunError as Error;
use crate::instance::InstanceInfo;
use crate::repl::{Snippet, from_source};
use crate::utils::{ensure_datasets_dir, ensure_packages_dir, get_datasets_dir, get_packages_dir};
use crate::vm::OfflineVm;


/***** AUXILLARY FUNCTIONS *****/
/// Initializes the state for an instance VM.
///
/// This implements most of [`initialize_instance_vm()`], which we separate to have some clients (\*cough\* IDE \*cough\*) able to create a VM while sharing an index.
///
/// # Arguments
/// - `stdout_writer`: Some [`Write`]-handle that we use to write stdout to.
/// - `stderr_writer`: Some [`Write`]-handle that we use to write stderr to.
/// - `drv_endpoint`: The `brane-drv` endpoint that we will connect to to run stuff.
/// - `pindex`: The [`PackageIndex`] that contains the remote's available packages.
/// - `dindex`: The [`DataIndex`] that contains the remote's available datasets.
/// - `user`: Some (tentative) identifier of the user who might receive the end result.
/// - `attach`: If given, we will try to attach to a session with that ID. Otherwise, we start a new session.
/// - `options`: The ParserOptions that describe how to parse the given source.
///
/// # Returns
/// A new [`InstanceVmState`] that represents the initialized VM.
///
/// # Errors
/// This function may error if we failed to reach the remote driver, or if the given session did not exist.
#[allow(clippy::too_many_arguments)]
pub async fn initialize_instance<O: Write, E: Write>(
    stdout_writer: O,
    stderr_writer: E,
    drv_endpoint: impl AsRef<str>,
    pindex: Arc<Mutex<PackageIndex>>,
    dindex: Arc<Mutex<DataIndex>>,
    user: Option<String>,
    attach: Option<AppId>,
    options: ParserOptions,
) -> Result<InstanceVmState<O, E>, Error> {
    let drv_endpoint: &str = drv_endpoint.as_ref();

    // Connect to the server with gRPC
    debug!("Connecting to driver '{}'...", drv_endpoint);
    let mut client = DriverServiceClient::connect(format!("grpc://{drv_endpoint}"))
        .await
        .map_err(|source| Error::ClientConnectError { address: drv_endpoint.into(), source })?;

    // Either use the given Session UUID or create a new one (with matching session)
    let session: AppId = if let Some(attach) = attach {
        debug!("Using existing session '{}'", attach);
        attach
    } else {
        // Setup a new session
        let request = CreateSessionRequest {};
        let reply = client.create_session(request).await.map_err(|source| Error::SessionCreateError { address: drv_endpoint.into(), source })?;

        // Return the UUID of this session
        let raw: String = reply.into_inner().uuid;
        debug!("Using new session '{}'", raw);
        AppId::from_str(&raw).map_err(|source| Error::AppIdError { address: drv_endpoint.into(), raw, source: Box::new(source) })?
    };

    // Prepare some states & options used across loops
    Ok(InstanceVmState {
        stdout: stdout_writer,
        stderr: stderr_writer,

        pindex,
        dindex,
        user,

        state: CompileState::new(),
        source: String::new(),
        options,

        session,
        client,
    })
}

/// Runs the given compiled workflow on the remote instance.
///
/// This implements the other half of [`run_instance_vm()`], which we separate to have some clients (\*cough\* IDE \*cough\*) do the compilation by themselves.
///
/// # Arguments
/// - `drv_endpoint`: The `brane-drv` endpoint that we will connect to to run stuff (used for debugging only).
/// - `state`: The InstanceVmState that we use to connect to the driver.
/// - `workflow`: The already compiled [`Workflow`] to execute.
/// - `profile`: If given, prints the profile timings to stdout if reported by the remote.
///
/// # Returns
/// A [`FullValue`] carrying the result of the snippet (or [`FullValue::Void`]), and a [`ProgramCounter`] in case a [`FullValue::Data`] is returned telling us which edge downloaded it.
///
/// # Errors
/// This function may error if anything in the whole shebang crashed. This can be things client-side, but also remote-side.
pub async fn run_instance<O: Write, E: Write>(
    drv_endpoint: impl AsRef<str>,
    state: &mut InstanceVmState<O, E>,
    workflow: &Workflow,
    profile: bool,
) -> Result<FullValue, Error> {
    let drv_endpoint: &str = drv_endpoint.as_ref();

    // Serialize the workflow
    let sworkflow: String = serde_json::to_string(&workflow).map_err(|source| Error::WorkflowSerializeError { source })?;

    // Prepare the request to execute this command
    let request = ExecuteRequest { uuid: state.session.to_string(), input: sworkflow };

    // Run it
    let response = state.client.execute(request).await.map_err(|source| Error::CommandRequestError { address: drv_endpoint.into(), source })?;
    let mut stream = response.into_inner();

    // Switch on the type of message that the remote returned
    let mut res: FullValue = FullValue::Void;
    loop {
        // Match on the message
        match stream.message().await {
            // The message itself went alright
            Ok(Some(reply)) => {
                // Show profile times
                if profile { /* TODO */ }

                // The remote send us some debug message
                if let Some(debug) = reply.debug {
                    debug!("Remote: {}", debug);
                }

                // The remote send us a normal text message
                if let Some(stdout) = reply.stdout {
                    debug!("Remote returned stdout");
                    write!(&mut state.stdout, "{stdout}").map_err(|source| Error::WriteError { source })?;
                }

                // The remote send us an error
                if let Some(stderr) = reply.stderr {
                    debug!("Remote returned error");
                    writeln!(&mut state.stderr, "{stderr}").map_err(|source| Error::WriteError { source })?;
                }

                // Update the value to the latest if one is sent
                if let Some(value) = reply.value {
                    debug!("Remote returned new value: '{}'", value);

                    // Parse it
                    let value: FullValue =
                        serde_json::from_str(&value).map_err(|source| Error::ValueParseError { address: drv_endpoint.into(), raw: value, source })?;

                    // Set the result, packed
                    res = value;
                }

                // The remote is done with this
                if reply.close {
                    println!();
                    break;
                }
            },
            Err(status) => match status.code() {
                Code::PermissionDenied => return Err(Error::ExecDenied { source: Box::new(StringError(status.message().into())) }),
                _ => return Err(Error::ExecError { source: Box::new(StringError(status.message().into())) }),
            },
            Ok(None) => {
                // Stream closed by the remote for some rason
                break;
            },
        }
    }

    // Done
    Ok(res)
}

/// Post-processes the result of a workflow.
///
/// This does nothing unless it's an IntermediateResult or a Dataset; it emits a warning in the first, attempts to download the referred dataset in the latter.
///
/// # Arguments
/// - `api_endpoint`: The remote endpoint where we can potentially download data from (or, that at least knows about it).
/// - `proxy_addr`: If given, proxies all data transfers through the proxy at the given location.
/// - `certs_dir`: The directory where certificates are stored. Expected to contain nested directories that store the certs by domain ID.
/// - `datasets_dir`: The directory where we will download the data to. It will be added under a new folder with its own name.
/// - `result`: The value to process, together with a program counter if it was the result of a toplevel return.
///
/// # Returns
/// Nothing, but does print any result to stdout. It may also download a remote dataset if one is given.
///
/// # Errors
/// This function may error if the given result was a dataset and we failed to retrieve it.
pub async fn process_instance(
    api_endpoint: impl AsRef<str>,
    proxy_addr: &Option<String>,
    certs_dir: impl AsRef<Path>,
    datasets_dir: impl AsRef<Path>,
    use_case: String,
    workflow: Workflow,
    result: FullValue,
) -> Result<(), Error> {
    let api_endpoint: &str = api_endpoint.as_ref();
    let certs_dir: &Path = certs_dir.as_ref();
    let datasets_dir: &Path = datasets_dir.as_ref();

    // We only print
    if !matches!(result, FullValue::Void) {
        println!("\nWorkflow returned value {}", style(format!("'{}'", result)).bold().cyan());

        // FIXME: Clean up this blob
        // Treat some values special
        match result {
            // Print sommat additional if it's an intermediate result.
            FullValue::IntermediateResult(_) => {
                println!("(Intermediate results are not available locally; promote it using 'commit_result()')");
            },

            // If it's a dataset, attempt to download it
            FullValue::Data(name) => {
                // Compute the directory to write to
                let data_dir: PathBuf = datasets_dir.join(name.to_string());

                // Fetch a new, local DataIndex to get up-to-date entries
                let data_addr: String = format!("http://{api_endpoint}/data/info");
                let index: DataIndex =
                    brane_tsk::api::get_data_index(&data_addr).await.map_err(|source| Error::RemoteDataIndexError { address: data_addr, source })?;

                // Fetch the method of its availability
                let info: &DataInfo = index.get(&name).ok_or_else(|| Error::UnknownDataset { name: name.to_string() })?;
                let access: AccessKind = match info.access.get(LOCALHOST) {
                    Some(access) => access.clone(),
                    None => {
                        // Attempt to download it instead
                        match data::download_data(api_endpoint, proxy_addr, certs_dir, data_dir, use_case, &name, workflow, &info.access).await {
                            Ok(Some(access)) => access,
                            Ok(None) => {
                                return Err(Error::UnavailableDataset { name: name.into(), locs: info.access.keys().cloned().collect() });
                            },
                            Err(source) => {
                                return Err(Error::DataDownloadError { source });
                            },
                        }
                    },
                };

                // Write the method of access
                match access {
                    AccessKind::File { path } => println!("(It's available under '{}')", path.display()),
                }
            },

            // Nothing for the rest
            _ => {},
        }
    }

    // Done
    Ok(())
}

/***** AUXILLARY *****/
/// A helper struct that contains what we need to know about a compiler + VM state for the dummy use-case.
pub struct DummyVmState {
    /// The package index for this session.
    pub pindex: Arc<PackageIndex>,
    /// The data index for this session.
    pub dindex: Arc<DataIndex>,

    /// The state of the compiler.
    pub state:   CompileState,
    /// The associated source string, which we use for debugging.
    pub source:  String,
    /// Any compiler options we apply.
    pub options: ParserOptions,

    /// The state of the VM, i.e., the VM. This is wrapped in an 'Option' so we can easily take it if the DummyVmState is only mutably borrowed.
    pub vm: Option<DummyVm>,
}

/// A helper struct that contains what we need to know about a compiler + VM state for the offline use-case.
pub struct OfflineVmState {
    /// The temporary directory where we store results.
    pub results_dir: TempDir,
    /// The package index for this session.
    pub pindex:      Arc<PackageIndex>,
    /// The data index for this session.
    pub dindex:      Arc<DataIndex>,

    /// The state of the compiler.
    pub state:   CompileState,
    /// The associated source string, which we use for debugging.
    pub source:  String,
    /// Any compiler options we apply.
    pub options: ParserOptions,

    /// The state of the VM, i.e., the VM. This is wrapped in an 'Option' so we can easily take it if the OfflineVmState is only mutably borrowed.
    pub vm: Option<OfflineVm>,
}

/// A helper struct that contains what we need to know about a compiler + VM state for the instance use-case.
pub struct InstanceVmState<O, E> {
    /// A stdout to write incoming stdout messages on.
    pub stdout: O,
    /// A stderr to write outgoing stdout messages on.
    pub stderr: E,

    /// The package index for this session.
    pub pindex: Arc<Mutex<PackageIndex>>,
    /// The data index for this session.
    pub dindex: Arc<Mutex<DataIndex>>,
    /// A username of the person doing everything rn.
    pub user:   Option<String>,

    /// The state of the compiler.
    pub state:   CompileState,
    /// The associated source string, which we use for debugging.
    pub source:  String,
    /// Any compiler options we apply.
    pub options: ParserOptions,

    /// The ID for this session.
    pub session: AppId,
    /// The client which we use to communicate to the VM.
    pub client:  DriverServiceClient,
}

/// Function that prepares a local, offline virtual machine that never runs any jobs.
///
/// It does read the local index to determine if packages are legal.
///
/// # Arguments
/// - `options`: The ParserOptions that describe how to parse the given source.
///
/// # Returns
/// The newly created virtual machine together with associated states as a DummyVmState.
///
/// # Errors
/// This function errors if we failed to get the new package indices or other information.
pub fn initialize_dummy_vm(options: ParserOptions) -> Result<DummyVmState, Error> {
    // Get the directory with the packages
    let packages_dir = ensure_packages_dir(false).map_err(|source| Error::PackagesDirError { source })?;
    // Get the directory with the datasets
    let datasets_dir = ensure_datasets_dir(false).map_err(|source| Error::DatasetsDirError { source })?;

    // Get the package index for the local repository
    let package_index: Arc<PackageIndex> = match brane_tsk::local::get_package_index(packages_dir) {
        Ok(index) => Arc::new(index),
        Err(source) => {
            return Err(Error::LocalPackageIndexError { source });
        },
    };
    // Get the data index for the local repository
    let data_index: Arc<DataIndex> = match brane_tsk::local::get_data_index(datasets_dir) {
        Ok(index) => Arc::new(index),
        Err(source) => {
            return Err(Error::LocalDataIndexError { source });
        },
    };

    // // Get the local package & dataset directories
    // let packages_dir: PathBuf = match get_packages_dir() {
    //     Ok(dir)  => dir,
    //     Err(err) => { return Err(Error::PackagesDirError{ err }); },
    // };
    // let datasets_dir: PathBuf = match get_datasets_dir() {
    //     Ok(dir)  => dir,
    //     Err(err) => { return Err(Error::DatasetsDirError{ err }); },
    // };

    // Prepare some states & options used across loops and return them
    Ok(DummyVmState {
        pindex: package_index,
        dindex: data_index,

        state: CompileState::new(),
        source: String::new(),
        options,

        vm: Some(DummyVm::new()),
    })
}

/// Function that prepares a local, offline virtual machine by initializing the proper indices and whatnot.
///
/// # Arguments
/// - `parse_opts`: The ParserOptions that describe how to parse the given source.
/// - `docker_opts`: The configuration of our Docker client.
/// - `keep_containers`: Whether to keep the containers after execution or not.
///
/// # Returns
/// The newly created virtual machine together with associated states as an OfflineVmState.
///
/// # Errors
/// This function errors if we failed to get the new package indices or other information.
pub fn initialize_offline_vm(parse_opts: ParserOptions, docker_opts: DockerOptions, keep_containers: bool) -> Result<OfflineVmState, Error> {
    // Get the directory with the packages
    let packages_dir = ensure_packages_dir(false).map_err(|source| Error::PackagesDirError { source })?;
    // Get the directory with the datasets
    let datasets_dir = ensure_datasets_dir(false).map_err(|source| Error::DatasetsDirError { source })?;

    // Get the package index for the local repository
    let package_index: Arc<PackageIndex> = match brane_tsk::local::get_package_index(packages_dir) {
        Ok(index) => Arc::new(index),
        Err(source) => {
            return Err(Error::LocalPackageIndexError { source });
        },
    };
    // Get the data index for the local repository
    let data_index: Arc<DataIndex> = match brane_tsk::local::get_data_index(datasets_dir) {
        Ok(index) => Arc::new(index),
        Err(source) => {
            return Err(Error::LocalDataIndexError { source });
        },
    };

    // Get the local package & dataset directories
    let packages_dir: PathBuf = get_packages_dir().map_err(|source| Error::PackagesDirError { source })?;
    let datasets_dir: PathBuf = get_datasets_dir().map_err(|source| Error::DatasetsDirError { source })?;

    // Create the temporary results directory for this run
    let temp_dir: TempDir = tempdir().map_err(|source| Error::ResultsDirCreateError { source })?;

    // Prepare some states & options used across loops and return them
    let temp_dir_path: PathBuf = temp_dir.path().into();
    Ok(OfflineVmState {
        results_dir: temp_dir,
        pindex:      package_index.clone(),
        dindex:      data_index.clone(),

        state:   CompileState::new(),
        source:  String::new(),
        options: parse_opts,

        vm: Some(OfflineVm::new(docker_opts, keep_containers, packages_dir, datasets_dir, temp_dir_path, package_index, data_index)),
    })
}

/// Function that prepares a remote, instance-backed virtual machine by initializing the proper indices and whatnot.
///
/// # Arguments
/// - `api_endpoint`: The `brane-api` endpoint that we download indices from.
/// - `drv_endpoint`: The `brane-drv` endpoint that we will connect to to run stuff.
/// - `user`: If given, then this is some tentative identifier of the user receiving the final workflow result.
/// - `attach`: If given, we will try to attach to a session with that ID. Otherwise, we start a new session.
/// - `options`: The ParserOptions that describe how to parse the given source.
///
/// # Returns
/// The newly created virtual machine together with associated states as an InstanceVmState.
///
/// # Errors
/// This function errors if we failed to get the new package indices or other information.
pub async fn initialize_instance_vm(
    api_endpoint: impl AsRef<str>,
    drv_endpoint: impl AsRef<str>,
    user: Option<String>,
    attach: Option<AppId>,
    options: ParserOptions,
) -> Result<InstanceVmState<Stdout, Stderr>, Error> {
    let api_endpoint: &str = api_endpoint.as_ref();
    let drv_endpoint: &str = drv_endpoint.as_ref();

    // We fetch a local copy of the indices for compiling
    debug!("Fetching global package & data indices from '{}'...", api_endpoint);
    let package_addr: String = format!("http://{api_endpoint}/graphql");
    let pindex: Arc<Mutex<PackageIndex>> = match brane_tsk::api::get_package_index(&package_addr).await {
        Ok(pindex) => Arc::new(Mutex::new(pindex)),
        Err(source) => {
            return Err(Error::RemotePackageIndexError { address: package_addr, source });
        },
    };
    let data_addr: String = format!("http://{api_endpoint}/data/info");
    let dindex: Arc<Mutex<DataIndex>> = match brane_tsk::api::get_data_index(&data_addr).await {
        Ok(dindex) => Arc::new(Mutex::new(dindex)),
        Err(source) => {
            return Err(Error::RemoteDataIndexError { address: data_addr, source });
        },
    };

    // Pass the rest to `initialize_instance`
    initialize_instance(std::io::stdout(), std::io::stderr(), drv_endpoint, pindex, dindex, user, attach, options).await
}



/// Function that executes the given workflow snippet to completion on the dummy machine, returning the result it returns.
///
/// # Arguments
/// - `state`: The DummyVmState that we use to run the dummy VM.
/// - `what`: The thing we're running. Either a filename, or something like stdin.
/// - `snippet`: The snippet (as raw text) to compile and run.
///
/// # Returns
/// The FullValue that the workflow returned, if any. If there was no value, returns FullValue::Void instead.
///
/// # Errors
/// This function errors if we failed to compile or run the workflow somehow.
pub async fn run_dummy_vm(state: &mut DummyVmState, what: impl AsRef<str>, snippet: impl AsRef<str>) -> Result<FullValue, Error> {
    let what: &str = what.as_ref();
    let snippet: &str = snippet.as_ref();

    // Compile the workflow
    let workflow: Workflow = from_source(&mut state.state, &mut state.source, &state.pindex, &state.dindex, None, &state.options, what, snippet)
        .map_err(Error::CompileError)?;

    // Run it in the local VM (which is a bit ugly do to the need to consume the VM itself)
    let res: (DummyVm, Result<FullValue, DummyVmError>) = state.vm.take().unwrap().exec(workflow).await;
    state.vm = Some(res.0);
    let res: FullValue = match res.1 {
        Ok(res) => res,
        Err(source) => {
            error!("{}", source);
            state.state.offset += 1 + snippet.chars().filter(|c| *c == '\n').count();
            return Err(Error::ExecError { source: Box::new(source) });
        },
    };

    // Done
    Ok(res)
}

/// Function that executes the given workflow snippet to completion on the local machine, returning the result it returns.
///
/// # Arguments
/// - `state`: The OfflineVmState that we use to run the local VM.
/// - `what`: The thing we're running. Either a filename, or something like stdin.
/// - `snippet`: The snippet to compile and run.
///
/// # Returns
/// The FullValue that the workflow returned, if any. If there was no value, returns FullValue::Void instead.
///
/// # Errors
/// This function errors if we failed to compile or run the workflow somehow.
pub async fn run_offline_vm(state: &mut OfflineVmState, snippet: Snippet) -> Result<FullValue, Error> {
    // Run it in the local VM (which is a bit ugly do to the need to consume the VM itself)
    let res: (OfflineVm, Result<FullValue, OfflineVmError>) = state.vm.take().unwrap().exec(snippet.workflow).await;
    state.vm = Some(res.0);
    let res: FullValue = match res.1 {
        Ok(res) => res,
        Err(source) => {
            error!("{}", source);
            state.state.offset += snippet.lines;
            return Err(Error::ExecError { source: Box::new(source) });
        },
    };

    // Done
    Ok(res)
}

/// Function that executes the given workflow snippet to completion on the Brane instance, returning the result it returns.
///
/// # Arguments
/// - `drv_endpoint`: The `brane-drv` endpoint that we will connect to to run stuff (used for debugging only).
/// - `state`: The InstanceVmState that we use to connect to the driver.
/// - `what`: The thing we're running. Either a filename, or something like stdin.
/// - `snippet`: The snippet (as raw text) to compile and run.
/// - `profile`: If given, prints the profile timings to stdout if reported by the remote.
///
/// # Returns
/// The FullValue that the workflow returned, if any. If there was no value, returns FullValue::Void instead.
///
/// # Errors
/// This function errors if we failed to compile the workflow, communicate with the remote driver or remote execution failed somehow.
#[inline]
pub async fn run_instance_vm(
    drv_endpoint: impl AsRef<str>,
    state: &mut InstanceVmState<Stdout, Stderr>,
    workflow: &Workflow,
    profile: bool,
) -> Result<FullValue, Error> {
    // Run the thing using the other function
    run_instance(drv_endpoint, state, workflow, profile).await
}



/// Processes the given result of a dummy workflow execution.
///
/// # Arguments
/// - `result`: The value to process.
///
/// # Returns
/// Nothing, but does print any result to stdout.
pub fn process_dummy_result(result: FullValue) {
    // We only print
    if result != FullValue::Void {
        println!("\nWorkflow returned value {}", style(format!("'{result}'")).bold().cyan());

        // Treat some values special
        match result {
            // Print sommat additional if it's an intermediate result.
            FullValue::IntermediateResult(_) => {
                println!("(Intermediate results are not available; promote it using 'commit_result()')");
            },

            // If it's a dataset, attempt to download it
            FullValue::Data(_) => {
                println!("(Datasets are not committed; run the workflow without '--dummy' to actually create it)");
            },

            // Nothing for the rest
            _ => {},
        }
    }

    // DOne
}

/// Processes the given result of an offline workflow execution.
///
/// # Arguments
/// - `result_dir`: The directory where temporary results are stored.
/// - `result`: The value to process.
///
/// # Returns
/// Nothing, but does print any result to stdout.
///
/// # Errors
/// This function may error if we failed to get an up-to-date data index.
pub fn process_offline_result(result: FullValue) -> Result<(), Error> {
    // We only print
    if result != FullValue::Void {
        println!("\nWorkflow returned value {}", style(format!("'{result}'")).bold().cyan());

        // Treat some values special
        match result {
            // Print sommat additional if it's an intermediate result.
            FullValue::IntermediateResult(_) => {
                println!("(Intermediate results are not available; promote it using 'commit_result()')");
            },

            // If it's a dataset, attempt to download it
            FullValue::Data(name) => {
                // Get the directory with the datasets
                let datasets_dir = ensure_datasets_dir(false).map_err(|source| Error::DatasetsDirError { source })?;

                // Fetch a new, local DataIndex to get up-to-date entries
                let index: DataIndex = brane_tsk::local::get_data_index(datasets_dir).map_err(|source| Error::LocalDataIndexError { source })?;

                // Fetch the method of its availability
                let info: &DataInfo = index.get(&name).ok_or_else(|| Error::UnknownDataset { name: name.clone().into() })?;
                let access: &AccessKind = info
                    .access
                    .get(LOCALHOST)
                    .ok_or_else(|| Error::UnavailableDataset { name: name.into(), locs: info.access.keys().cloned().collect() })?;

                // Write the method of access
                match access {
                    AccessKind::File { path } => println!("(It's available under '{}')", path.display()),
                }
            },

            // Nothing for the rest
            _ => {},
        }
    }

    // DOne
    Ok(())
}

/// Processes the given result of a remote workflow execution.
///
/// # Arguments
/// - `api_endpoint`: The remote endpoint where we can potentially download data from (or, that at least knows about it).
/// - `proxy_addr`: If given, proxies all data transfers through the proxy at the given location.
/// - `result`: The value to process.
///
/// # Returns
/// Nothing, but does print any result to stdout. It may also download a remote dataset if one is given.
///
/// # Errors
/// This function may error if the given result was a dataset and we failed to retrieve it.
pub async fn process_instance_result(
    api_endpoint: impl AsRef<str>,
    proxy_addr: &Option<String>,
    use_case: String,
    workflow: Workflow,
    result: FullValue,
) -> Result<(), Error> {
    let instance_name = InstanceInfo::get_active_name().map_err(|source| Error::ActiveInstanceReadError { source })?;
    let certs_dir =
        InstanceInfo::get_instance_path(&instance_name).map_err(|source| Error::InstancePathError { name: instance_name, source })?.join("certs");

    let datasets_dir = ensure_datasets_dir(true).map_err(|source| Error::DatasetsDirError { source })?;

    // Run the instance function
    process_instance(api_endpoint, proxy_addr, certs_dir, datasets_dir, use_case, workflow, result).await
}





/***** LIBRARY *****/
/// Runs the given workflow file with the given, optional data folder to resolve data declarations in.
///
/// # Arguments
/// - `certs_dir`: The directory with certificates proving our identity.
/// - `proxy_addr`: The address to proxy any data transfers through if they occur.
/// - `dummy`: If given, uses a Dummy VM as backend instead of actually running any jobs.
/// - `remote`: Whether to run on an remote Brane instance instead.
/// - `language`: The language with which to compile the file.
/// - `file`: The workflow file to read and run. Can also be '-', in which case it is read from stdin instead.
/// - `profile`: If given, prints the profile timings to stdout if available.
/// - `docker_opts`: The options with which we connect to the local Docker daemon.
/// - `keep_containers`: Whether to keep containers after execution or not.
///
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    proxy_addr: Option<String>,
    language: Language,
    use_case: String,
    file: PathBuf,
    dummy: bool,
    remote: bool,
    profile: bool,
    docker_opts: DockerOptions,
    keep_containers: bool,
) -> Result<(), Error> {
    // Either read the file or read stdin
    let (source, source_code): (Cow<str>, String) = if file == PathBuf::from("-") {
        let mut result: String = String::new();
        std::io::stdin().read_to_string(&mut result).map_err(|source| Error::StdinReadError { source })?;
        ("<stdin>".into(), result)
    } else {
        match fs::read_to_string(&file) {
            Ok(res) => (file.to_string_lossy(), res),
            Err(source) => {
                return Err(Error::FileReadError { path: file, source });
            },
        }
    };

    // Prepare the parser options
    let options: ParserOptions = ParserOptions::new(language);

    // Now switch on dummy, local or remote mode
    if !dummy {
        if remote {
            // Open the login file to find the remote location
            let info: InstanceInfo = InstanceInfo::from_active_path().map_err(|source| Error::InstanceInfoError { source })?;

            // Run the thing
            remote_run(info, use_case, proxy_addr, options, source, source_code, profile).await
        } else {
            local_run(options, docker_opts, source, source_code, keep_containers).await
        }
    } else {
        dummy_run(options, source, source_code).await
    }
}



/// Runs the given file in a dummy VM, that is to say, ignore jobs with some default values.
///
/// # Arguments
/// - `options`: The ParseOptions that specify how to parse the incoming source.
/// - `what`: A description of the source we're reading (e.g., the filename or stdin)
/// - `source`: The source code to read.
///
/// # Returns
/// Nothing, but does print results and such to stdout. Does not produce new datasets.
async fn dummy_run(options: ParserOptions, what: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), Error> {
    let what: &str = what.as_ref();
    let source: &str = source.as_ref();

    // First we initialize the VM
    let mut state: DummyVmState = initialize_dummy_vm(options)?;
    // Next, we run the VM (one snippet only ayway)
    let res: FullValue = run_dummy_vm(&mut state, what, source).await?;
    // Then, we collect and process the result
    process_dummy_result(res);

    // Done
    Ok(())
}

/// Runs the given file on the local machine.
///
/// # Arguments
/// - `parse_opts`: The ParseOptions that specify how to parse the incoming source.
/// - `docker_opts`: The options with which we connect to the local Docker daemon.
/// - `what`: A description of the source we're reading (e.g., the filename or stdin)
/// - `source`: The source code to read.
/// - `keep_containers`: Whether to keep containers after execution or not.
///
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
async fn local_run(
    parse_opts: ParserOptions,
    docker_opts: DockerOptions,
    what: impl AsRef<str>,
    source: impl AsRef<str>,
    keep_containers: bool,
) -> Result<(), Error> {
    let what: &str = what.as_ref();
    let source: &str = source.as_ref();

    // First we initialize the remote thing
    let mut state: OfflineVmState = initialize_offline_vm(parse_opts, docker_opts, keep_containers)?;

    // Compile the workflow
    let snippet = Snippet::from_source(&mut state.state, &mut state.source, &state.pindex, &state.dindex, None, &state.options, what, source)
        .map_err(Error::CompileError)?;

    // Next, we run the VM (one snippet only ayway)
    let res: FullValue = run_offline_vm(&mut state, snippet).await?;

    // Then, we collect and process the result
    process_offline_result(res)?;

    // Done
    Ok(())
}

/// Runs the given file on the remote instance.
///
/// # Arguments
/// - `info`: Information about the remote instance, including as who we're logged-in.
/// - `proxy_addr`: The address to proxy any data transfers through if they occur.
/// - `options`: The ParseOptions that specify how to parse the incoming source.
/// - `source`: A description of the source we're reading (e.g., the filename or stdin)
/// - `workflow_content`: The source code to read.
/// - `profile`: If given, prints the profile timings to stdout if reported by the remote.
///
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
async fn remote_run(
    info: InstanceInfo,
    use_case: String,
    proxy_addr: Option<String>,
    options: ParserOptions,
    source: impl AsRef<str>,
    workflow_content: impl AsRef<str>,
    profile: bool,
) -> Result<(), Error> {
    let api_endpoint: String = info.api.to_string();
    let drv_endpoint: String = info.drv.to_string();
    let source: &str = source.as_ref();
    let workflow_content: &str = workflow_content.as_ref();

    // First we initialize the remote thing
    let mut state: InstanceVmState<Stdout, Stderr> =
        initialize_instance_vm(&api_endpoint, &drv_endpoint, Some(info.user.clone()), None, options).await?;

    // Compile the workflow
    let snippet: Snippet = {
        // Acquire the locks
        let pindex: MutexGuard<PackageIndex> = state.pindex.lock();
        let dindex: MutexGuard<DataIndex> = state.dindex.lock();
        Snippet::from_source(&mut state.state, &mut state.source, &pindex, &dindex, state.user.as_deref(), &state.options, source, workflow_content)
            .map_err(Error::CompileError)?
    };

    // Next, we run the VM (one snippet only ayway)
    let res: FullValue = run_instance_vm(drv_endpoint, &mut state, &snippet.workflow, profile).await?;

    // Then, we collect and process the result
    process_instance_result(api_endpoint, &proxy_addr, use_case, snippet.workflow, res).await?;

    // Done
    Ok(())
}
