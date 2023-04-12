//  RUN.rs
//    by Lut99
// 
//  Created:
//    12 Sep 2022, 16:42:57
//  Last edited:
//    12 Apr 2023, 12:02:04
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements running a single BraneScript file.
// 

use std::borrow::Cow;
use std::io::Read;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use console::style;
use tempfile::{tempdir, TempDir};

use brane_ast::{compile_snippet, CompileResult, ParserOptions, Workflow};
use brane_ast::state::CompileState;
use brane_dsl::Language;
use brane_exe::FullValue;
use brane_exe::dummy::{DummyVm, Error as DummyVmError};
use brane_tsk::spec::{LOCALHOST, AppId};
use specifications::data::{AccessKind, DataIndex, DataInfo};
use specifications::driving::{CreateSessionRequest, DriverServiceClient, ExecuteRequest};
use specifications::package::PackageIndex;

pub use crate::errors::RunError as Error;
use crate::errors::OfflineVmError;
use crate::spec::DockerOpts;
use crate::data;
use crate::utils::{ensure_datasets_dir, ensure_packages_dir, get_datasets_dir, get_packages_dir};
use crate::vm::OfflineVm;
use crate::instance::InstanceInfo;


/***** HELPER FUNCTIONS *****/
/// Compiles the given worfklow string to a Workflow.
/// 
/// # Arguments
/// - `state`: The CompileState to compile with (and to update).
/// - `source`: The collected source string for now. This will be updated with the new snippet.
/// - `pindex`: The PackageIndex to resolve package imports with.
/// - `dindex`: The DataIndex to resolve data instantiations with.
/// - `options`: The ParseOptions to use.
/// - `what`: A string describing what we're parsing (e.g., a filename, `<stdin>`, ...).
/// - `snippet`: The actual snippet to parse.
/// 
/// # Returns
/// A new Workflow that is the compiled and executable version of the given snippet.
/// 
/// # Errors
/// This function errors if the given string was not a valid workflow. If that's the case, it's also pretty-printed to stdout with source context.
fn compile(state: &mut CompileState, source: &mut String, pindex: &PackageIndex, dindex: &DataIndex, options: &ParserOptions, what: impl AsRef<str>, snippet: impl AsRef<str>) -> Result<Workflow, Error> {
    let what    : &str = what.as_ref();
    let snippet : &str = snippet.as_ref();

    // Append the source with the snippet
    source.push_str(snippet);
    source.push('\n');

    // Compile the snippet, possibly fetching new ones while at it
    let workflow: Workflow = match compile_snippet(state, snippet.as_bytes(), pindex, dindex, options) {
        CompileResult::Workflow(wf, warns) => {
            // Print any warnings to stdout
            for w in warns {
                w.prettyprint(what, &source);
            }
            wf
        },

        CompileResult::Eof(err) => {
            // Prettyprint it
            err.prettyprint(what, &source);
            state.offset += 1 + snippet.chars().filter(|c| *c == '\n').count();
            return Err(Error::CompileError{ what: what.into(), errs: vec![ err ] });
        },
        CompileResult::Err(errs) => {
            // Prettyprint them
            for e in &errs {
                e.prettyprint(what, &source);
            }
            state.offset += 1 + snippet.chars().filter(|c| *c == '\n').count();
            return Err(Error::CompileError{ what: what.into(), errs });
        },

        // Any others should not occur
        _ => { unreachable!(); },
    };
    debug!("Compiled to workflow:\n\n");
    let workflow = if log::max_level() == log::LevelFilter::Debug{ brane_ast::traversals::print::ast::do_traversal(workflow, std::io::stdout()).unwrap() } else { workflow };

    // Return
    Ok(workflow)
}





/***** AUXILLARY *****/
/// A helper struct that contains what we need to know about a compiler + VM state for the dummy use-case.
pub struct DummyVmState {
    /// The package index for this session.
    pub pindex : Arc<PackageIndex>,
    /// The data index for this session.
    pub dindex : Arc<DataIndex>,

    /// The state of the compiler.
    pub state   : CompileState,
    /// The associated source string, which we use for debugging.
    pub source  : String,
    /// Any compiler options we apply.
    pub options : ParserOptions,

    /// The state of the VM, i.e., the VM. This is wrapped in an 'Option' so we can easily take it if the DummyVmState is only mutably borrowed.
    pub vm : Option<DummyVm>,
}

/// A helper struct that contains what we need to know about a compiler + VM state for the offline use-case.
pub struct OfflineVmState {
    /// The temporary directory where we store results.
    pub results_dir : TempDir,
    /// The package index for this session.
    pub pindex      : Arc<PackageIndex>,
    /// The data index for this session.
    pub dindex      : Arc<DataIndex>,

    /// The state of the compiler.
    pub state   : CompileState,
    /// The associated source string, which we use for debugging.
    pub source  : String,
    /// Any compiler options we apply.
    pub options : ParserOptions,

    /// The state of the VM, i.e., the VM. This is wrapped in an 'Option' so we can easily take it if the OfflineVmState is only mutably borrowed.
    pub vm : Option<OfflineVm>,
}

/// A helper struct that contains what we need to know about a compiler + VM state for the instance use-case.
pub struct InstanceVmState {
    /// The package index for this session.
    pub pindex : Arc<PackageIndex>,
    /// The data index for this session.
    pub dindex : Arc<DataIndex>,

    /// The state of the compiler.
    pub state   : CompileState,
    /// The associated source string, which we use for debugging.
    pub source  : String,
    /// Any compiler options we apply.
    pub options : ParserOptions,

    /// The ID for this session.
    pub session : AppId,
    /// The client which we use to communicate to the VM.
    pub client  : DriverServiceClient,
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
    let packages_dir = match ensure_packages_dir(false) {
        Ok(dir)  => dir,
        Err(err) => { return Err(Error::PackagesDirError{ err }); }
    };
    // Get the directory with the datasets
    let datasets_dir = match ensure_datasets_dir(false) {
        Ok(dir)  => dir,
        Err(err) => { return Err(Error::DatasetsDirError{ err }); }
    };

    // Get the package index for the local repository
    let package_index: Arc<PackageIndex> = match brane_tsk::local::get_package_index(packages_dir) {
        Ok(index) => Arc::new(index),
        Err(err)  => { return Err(Error::LocalPackageIndexError{ err }); }
    };
    // Get the data index for the local repository
    let data_index: Arc<DataIndex> = match brane_tsk::local::get_data_index(datasets_dir) {
        Ok(index) => Arc::new(index),
        Err(err)  => { return Err(Error::LocalDataIndexError{ err }); }
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
        pindex      : package_index,
        dindex      : data_index,

        state  : CompileState::new(),
        source : String::new(),
        options,

        vm : Some(DummyVm::new()),
    })
}

/// Function that prepares a local, offline virtual machine by initializing the proper indices and whatnot.
/// 
/// # Arguments
/// - `parse_opts`: The ParserOptions that describe how to parse the given source.
/// - `docker_opts`: The configuration of our Docker client.
/// 
/// # Returns
/// The newly created virtual machine together with associated states as an OfflineVmState.
/// 
/// # Errors
/// This function errors if we failed to get the new package indices or other information.
pub fn initialize_offline_vm(parse_opts: ParserOptions, docker_opts: impl Into<DockerOpts>) -> Result<OfflineVmState, Error> {
    // Get the directory with the packages
    let packages_dir = match ensure_packages_dir(false) {
        Ok(dir)  => dir,
        Err(err) => { return Err(Error::PackagesDirError{ err }); }
    };
    // Get the directory with the datasets
    let datasets_dir = match ensure_datasets_dir(false) {
        Ok(dir)  => dir,
        Err(err) => { return Err(Error::DatasetsDirError{ err }); }
    };

    // Get the package index for the local repository
    let package_index: Arc<PackageIndex> = match brane_tsk::local::get_package_index(packages_dir) {
        Ok(index) => Arc::new(index),
        Err(err)  => { return Err(Error::LocalPackageIndexError{ err }); }
    };
    // Get the data index for the local repository
    let data_index: Arc<DataIndex> = match brane_tsk::local::get_data_index(datasets_dir) {
        Ok(index) => Arc::new(index),
        Err(err)  => { return Err(Error::LocalDataIndexError{ err }); }
    };

    // Get the local package & dataset directories
    let packages_dir: PathBuf = match get_packages_dir() {
        Ok(dir)  => dir,
        Err(err) => { return Err(Error::PackagesDirError{ err }); },
    };
    let datasets_dir: PathBuf = match get_datasets_dir() {
        Ok(dir)  => dir,
        Err(err) => { return Err(Error::DatasetsDirError{ err }); },
    };

    // Create the temporary results directory for this run
    let temp_dir: TempDir = match tempdir() {
        Ok(temp_dir) => temp_dir,
        Err(err)     => { return Err(Error::ResultsDirCreateError{ err }); }
    };

    // Prepare some states & options used across loops and return them
    let temp_dir_path: PathBuf = temp_dir.path().into();
    Ok(OfflineVmState {
        results_dir : temp_dir,
        pindex      : package_index.clone(),
        dindex      : data_index.clone(),

        state   : CompileState::new(),
        source  : String::new(),
        options : parse_opts,

        vm : Some(OfflineVm::new(docker_opts, packages_dir, datasets_dir, temp_dir_path, package_index, data_index)),
    })
}

/// Function that prepares a remote, instance-backed virtual machine by initializing the proper indices and whatnot.
/// 
/// # Arguments
/// - `api_endpoint`: The `brane-api` endpoint that we download indices from.
/// - `drv_endpoint`: The `brane-drv` endpoint that we will connect to to run stuff.
/// - `attach`: If given, we will try to attach to a session with that ID. Otherwise, we start a new session.
/// - `options`: The ParserOptions that describe how to parse the given source.
/// 
/// # Returns
/// The newly created virtual machine together with associated states as an InstanceVmState.
/// 
/// # Errors
/// This function errors if we failed to get the new package indices or other information.
pub async fn initialize_instance_vm(api_endpoint: impl AsRef<str>, drv_endpoint: impl AsRef<str>, attach: Option<AppId>, options: ParserOptions) -> Result<InstanceVmState, Error> {
    let api_endpoint: &str = api_endpoint.as_ref();
    let drv_endpoint: &str = drv_endpoint.as_ref();

    // We fetch a local copy of the indices for compiling
    debug!("Fetching global package & data indices from '{}'...", api_endpoint);
    let package_addr: String = format!("{api_endpoint}/graphql");
    let pindex: Arc<PackageIndex> = match brane_tsk::api::get_package_index(&package_addr).await {
        Ok(pindex) => Arc::new(pindex),
        Err(err)   => { return Err(Error::RemotePackageIndexError{ address: package_addr, err }); },
    };
    let data_addr: String = format!("{api_endpoint}/data/info");
    let dindex: Arc<DataIndex> = match brane_tsk::api::get_data_index(&data_addr).await {
        Ok(dindex) => Arc::new(dindex),
        Err(err)   => { return Err(Error::RemoteDataIndexError{ address: data_addr, err }); },
    };

    // Connect to the server with gRPC
    debug!("Connecting to driver '{}'...", drv_endpoint);
    let mut client: DriverServiceClient = match DriverServiceClient::connect(drv_endpoint.to_string()).await {
        Ok(client) => client,
        Err(err)   => { return Err(Error::ClientConnectError{ address: drv_endpoint.into(), err }); }
    };

    // Either use the given Session UUID or create a new one (with matching session)
    let session: AppId = if let Some(attach) = attach {
        debug!("Using existing session '{}'", attach);
        attach
    } else {
        // Setup a new session
        let request = CreateSessionRequest {};
        let reply = match client.create_session(request).await {
            Ok(reply) => reply,
            Err(err)  => { return Err(Error::SessionCreateError{ address: drv_endpoint.into(), err }); }
        };

        // Return the UUID of this session
        let raw: String = reply.into_inner().uuid;
        debug!("Using new session '{}'", raw);
        match AppId::from_str(&raw) {
            Ok(session) => session,
            Err(err)    => { return Err(Error::AppIdError{ address: drv_endpoint.into(), raw, err: Box::new(err) }); },
        }
    };

    // Prepare some states & options used across loops
    Ok(InstanceVmState {
        pindex,
        dindex,

        state  : CompileState::new(),
        source : String::new(),
        options,

        session,
        client,
    })
}



/// Function that executes the given workflow snippet to completion on the dummy machine, returning the result it returns.
/// 
/// # Arguments
/// - `state`: The DummyVmState that we use to run the dummy VM.
/// - `what`: The thing we're running. Either a filename, or something like '<stdin>'.
/// - `snippet`: The snippet (as raw text) to compile and run.
/// 
/// # Returns
/// The FullValue that the workflow returned, if any. If there was no value, returns FullValue::Void instead.
/// 
/// # Errors
/// This function errors if we failed to compile or run the workflow somehow.
pub async fn run_dummy_vm(state: &mut DummyVmState, what: impl AsRef<str>, snippet: impl AsRef<str>) -> Result<FullValue, Error> {
    let what: &str     = what.as_ref();
    let snippet: &str  = snippet.as_ref();

    // Compile the workflow
    let workflow: Workflow = compile(&mut state.state, &mut state.source, &state.pindex, &state.dindex, &state.options, what, snippet)?;

    // Run it in the local VM (which is a bit ugly do to the need to consume the VM itself)
    let res: (DummyVm, Result<FullValue, DummyVmError>) = state.vm.take().unwrap().exec(workflow).await;
    state.vm = Some(res.0);
    let res: FullValue = match res.1 {
        Ok(res)  => res,
        Err(err) => {
            error!("{}", err);
            state.state.offset += 1 + snippet.chars().filter(|c| *c == '\n').count();
            return Err(Error::ExecError{ err: Box::new(err) });
        }
    };

    // Done
    Ok(res)
}

/// Function that executes the given workflow snippet to completion on the local machine, returning the result it returns.
/// 
/// # Arguments
/// - `state`: The OfflineVmState that we use to run the local VM.
/// - `what`: The thing we're running. Either a filename, or something like '<stdin>'.
/// - `snippet`: The snippet (as raw text) to compile and run.
/// 
/// # Returns
/// The FullValue that the workflow returned, if any. If there was no value, returns FullValue::Void instead.
/// 
/// # Errors
/// This function errors if we failed to compile or run the workflow somehow.
pub async fn run_offline_vm(state: &mut OfflineVmState, what: impl AsRef<str>, snippet: impl AsRef<str>) -> Result<FullValue, Error> {
    let what: &str     = what.as_ref();
    let snippet: &str  = snippet.as_ref();

    // Compile the workflow
    let workflow: Workflow = compile(&mut state.state, &mut state.source, &state.pindex, &state.dindex, &state.options, what, snippet)?;

    // Run it in the local VM (which is a bit ugly do to the need to consume the VM itself)
    let res: (OfflineVm, Result<FullValue, OfflineVmError>) = state.vm.take().unwrap().exec(workflow).await;
    state.vm = Some(res.0);
    let res: FullValue = match res.1 {
        Ok(res)  => res,
        Err(err) => {
            error!("{}", err);
            state.state.offset += 1 + snippet.chars().filter(|c| *c == '\n').count();
            return Err(Error::ExecError{ err: Box::new(err) });
        }
    };

    // Done
    Ok(res)
}

/// Function that executes the given workflow snippet to completion on the Brane instance, returning the result it returns.
/// 
/// # Arguments
/// - `drv_endpoint`: The `brane-drv` endpoint that we will connect to to run stuff (used for debugging only).
/// - `state`: The InstanceVmState that we use to connect to the driver.
/// - `what`: The thing we're running. Either a filename, or something like '<stdin>'.
/// - `snippet`: The snippet (as raw text) to compile and run.
/// - `profile`: If given, prints the profile timings to stdout if reported by the remote.
/// 
/// # Returns
/// The FullValue that the workflow returned, if any. If there was no value, returns FullValue::Void instead.
/// 
/// # Errors
/// This function errors if we failed to compile the workflow, communicate with the remote driver or remote execution failed somehow.
pub async fn run_instance_vm(drv_endpoint: impl AsRef<str>, state: &mut InstanceVmState, what: impl AsRef<str>, snippet: impl AsRef<str>, profile: bool) -> Result<FullValue, Error> {
    let drv_endpoint: &str = drv_endpoint.as_ref();
    let what: &str         = what.as_ref();
    let snippet: &str      = snippet.as_ref();

    // Compile the workflow
    let workflow: Workflow = compile(&mut state.state, &mut state.source, &state.pindex, &state.dindex, &state.options, what, snippet)?;

    // Serialize the workflow
    let sworkflow: String = match serde_json::to_string(&workflow) {
        Ok(sworkflow) => sworkflow,
        Err(err)      => { return Err(Error::WorkflowSerializeError{ err }); },
    };

    // Prepare the request to execute this command
    let request = ExecuteRequest {
        uuid  : state.session.to_string(),
        input : sworkflow,
    };

    // Run it
    let response = match state.client.execute(request).await {
        Ok(response) => response,
        Err(err)     => { return Err(Error::CommandRequestError{ address: drv_endpoint.into(), err }); }
    };
    let mut stream = response.into_inner();

    // Switch on the type of message that the remote returned
    let mut res: FullValue = FullValue::Void;
    loop {
        // Match on the message
        match stream.message().await {
            // The message itself went alright
            Ok(Some(reply)) => {
                // Show profile times
                if profile {
                    /* TODO */
                }

                // The remote send us some debug message
                if let Some(debug) = reply.debug {
                    debug!("Remote: {}", debug);
                }

                // The remote send us a normal text message
                if let Some(stdout) = reply.stdout {
                    debug!("Remote returned stdout");
                    print!("{stdout}");
                }

                // The remote send us an error
                if let Some(stderr) = reply.stderr {
                    debug!("Remote returned error");
                    eprintln!("{stderr}");
                }

                // Update the value to the latest if one is sent
                if let Some(value) = reply.value {
                    debug!("Remote returned new value: '{}'", value);

                    // Parse it
                    let value: FullValue = match serde_json::from_str(&value) {
                        Ok(value) => value,
                        Err(err)  => { return Err(Error::ValueParseError{ address: drv_endpoint.into(), raw: value, err }); },
                    };

                    // Set the result, packed
                    res = value;
                }

                // The remote is done with this
                if reply.close {
                    println!();
                    break;
                }
            }
            Err(status) => {
                // Did not receive the message properly
                eprintln!("\nStatus error: {}", status.message());
            }
            Ok(None) => {
                // Stream closed by the remote for some rason
                break;
            }
        }
    }

    // Done
    Ok(res)
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
                let datasets_dir = match ensure_datasets_dir(false) {
                    Ok(dir)  => dir,
                    Err(err) => { return Err(Error::DatasetsDirError{ err }); }
                };

                // Fetch a new, local DataIndex to get up-to-date entries
                let index: DataIndex = match brane_tsk::local::get_data_index(datasets_dir) {
                    Ok(index) => index,
                    Err(err)  => { return Err(Error::LocalDataIndexError{ err }); }
                };

                // Fetch the method of its availability
                let info: &DataInfo = match index.get(&name) {
                    Some(info) => info,
                    None       => { return Err(Error::UnknownDataset{ name: name.into() }); },
                };
                let access: &AccessKind = match info.access.get(LOCALHOST) {
                    Some(access) => access,
                    None         => { return Err(Error::UnavailableDataset{ name: name.into(), locs: info.access.keys().cloned().collect() }); },
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

    // DOne
    Ok(())
}

/// Processes the given result of a remote workflow execution.
/// 
/// # Arguments
/// - `api_endpoint`: The remote endpoint where we can potentially download data from (or, that at least knows about it).
/// - `proxy_addr`: If given, proxies all data transfers through the proxy at the given location.
/// - `result_dir`: The directory where temporary results are stored.
/// - `result`: The value to process.
/// 
/// # Returns
/// Nothing, but does print any result to stdout. It may also download a remote dataset if one is given.
/// 
/// # Errors
/// This function may error if the given result was a dataset and we failed to retrieve it.
pub async fn process_instance_result(api_endpoint: impl AsRef<str>, proxy_addr: &Option<String>, result: FullValue) -> Result<(), Error> {
    let api_endpoint : &str  = api_endpoint.as_ref();

    // We only print
    if result != FullValue::Void {
        println!("\nWorkflow returned value {}", style(format!("'{result}'")).bold().cyan());

        // Treat some values special
        match result {
            // Print sommat additional if it's an intermediate result.
            FullValue::IntermediateResult(_) => {
                println!("(Intermediate results are not available locally; promote it using 'commit_result()')");
            },

            // If it's a dataset, attempt to download it
            FullValue::Data(name) => {
                // Fetch a new, local DataIndex to get up-to-date entries
                let data_addr: String = format!("{api_endpoint}/data/info");
                let index: DataIndex = match brane_tsk::api::get_data_index(&data_addr).await {
                    Ok(dindex) => dindex,
                    Err(err)   => { return Err(Error::RemoteDataIndexError{ address: data_addr, err }); },
                };

                // Fetch the method of its availability
                let info: &DataInfo = match index.get(&name) {
                    Some(info) => info,
                    None       => { return Err(Error::UnknownDataset{ name: name.into() }); },
                };
                let access: AccessKind = match info.access.get(LOCALHOST) {
                    Some(access) => access.clone(),
                    None         => {
                        // Attempt to download it instead
                        match data::download_data(api_endpoint, proxy_addr, &name, &info.access).await {
                            Ok(Some(access)) => access,
                            Ok(None)         => { return Err(Error::UnavailableDataset{ name: name.into(), locs: info.access.keys().cloned().collect() }); },
                            Err(err)         => { return Err(Error::DataDownloadError{ err }); },
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

    // DOne
    Ok(())
}





/***** LIBRARY *****/
/// Runs the given file with the given, optional data folder to resolve data declarations in.
/// 
/// # Arguments
/// - `certs_dir`: The directory with certificates proving our identity.
/// - `proxy_addr`: The address to proxy any data transfers through if they occur.
/// - `dummy`: If given, uses a Dummy VM as backend instead of actually running any jobs.
/// - `remote`: Whether to run on an remote Brane instance instead.
/// - `language`: The language with which to compile the file.
/// - `file`: The file to read and run. Can also be '-', in which case it is read from stdin instead.
/// - `profile`: If given, prints the profile timings to stdout if available.
/// - `docker_opts`: The options with which we connect to the local Docker daemon.
/// 
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
pub async fn handle(proxy_addr: Option<String>, language: Language, file: PathBuf, dummy: bool, remote: bool, profile: bool, docker_opts: impl Into<DockerOpts>) -> Result<(), Error> {
    // Either read the file or read stdin
    let (what, source_code): (Cow<str>, String) = if file == PathBuf::from("-") {
        let mut result: String = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut result) { return Err(Error::StdinReadError{ err }); };
        ("<stdin>".into(), result)
    } else {
        match fs::read_to_string(&file) {
            Ok(res)  => (file.to_string_lossy(), res),
            Err(err) => { return Err(Error::FileReadError{ path: file, err }); }
        }
    };

    // Prepare the parser options
    let options: ParserOptions = ParserOptions::new(language);

    // Now switch on dummy, local or remote mode
    if !dummy {
        if remote {
            // Open the login file to find the remote location
            let info: InstanceInfo = match InstanceInfo::from_active_path() {
                Ok(config) => config,
                Err(err)   => { return Err(Error::InstanceInfoError{ err }); },
            };

            // Run the thing
            remote_run(info.api.to_string(), info.drv.to_string(), proxy_addr, options, what, source_code, profile).await
        } else {
            local_run(options, docker_opts, what, source_code).await
        }
    } else {
        dummy_run(options, what, source_code).await
    }
}



/// Runs the given file in a dummy VM, that is to say, ignore jobs with some default values.
/// 
/// # Arguments
/// - `options`: The ParseOptions that specify how to parse the incoming source.
/// - `what`: A description of the source we're reading (e.g., the filename or `<stdin>`)
/// - `source`: The source code to read.
/// 
/// # Returns
/// Nothing, but does print results and such to stdout. Does not produce new datasets.
async fn dummy_run(options: ParserOptions, what: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), Error> {
    let what      : &str  = what.as_ref();
    let source    : &str  = source.as_ref();

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
/// - `what`: A description of the source we're reading (e.g., the filename or `<stdin>`)
/// - `source`: The source code to read.
/// 
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
async fn local_run(parse_opts: ParserOptions, docker_opts: impl Into<DockerOpts>, what: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), Error> {
    let what      : &str  = what.as_ref();
    let source    : &str  = source.as_ref();

    // First we initialize the remote thing
    let mut state: OfflineVmState = initialize_offline_vm(parse_opts, docker_opts)?;
    // Next, we run the VM (one snippet only ayway)
    let res: FullValue = run_offline_vm(&mut state, what, source).await?;
    // Then, we collect and process the result
    process_offline_result(res)?;

    // Done
    Ok(())
}

/// Runs the given file on the remote instance.
/// 
/// # Arguments
/// - `api_endpoint`: The `brane-api` endpoint to connect to.
/// - `drv_endpoint`: The `brane-drv` endpoint to connect to.
/// - `proxy_addr`: The address to proxy any data transfers through if they occur.
/// - `options`: The ParseOptions that specify how to parse the incoming source.
/// - `what`: A description of the source we're reading (e.g., the filename or `<stdin>`)
/// - `source`: The source code to read.
/// - `profile`: If given, prints the profile timings to stdout if reported by the remote.
/// 
/// # Returns
/// Nothing, but does print results and such to stdout. Might also produce new datasets.
async fn remote_run(api_endpoint: impl AsRef<str>, drv_endpoint: impl AsRef<str>, proxy_addr: Option<String>, options: ParserOptions, what: impl AsRef<str>, source: impl AsRef<str>, profile: bool) -> Result<(), Error> {
    let api_endpoint : &str  = api_endpoint.as_ref();
    let drv_endpoint : &str  = drv_endpoint.as_ref();
    let what         : &str  = what.as_ref();
    let source       : &str  = source.as_ref();

    // First we initialize the remote thing
    let mut state: InstanceVmState = initialize_instance_vm(api_endpoint, drv_endpoint, None, options).await?;
    // Next, we run the VM (one snippet only ayway)
    let res: FullValue = run_instance_vm(drv_endpoint, &mut state, what, source, profile).await?;
    // Then, we collect and process the result
    process_instance_result(api_endpoint, &proxy_addr, res).await?;

    // Done
    Ok(())
}
