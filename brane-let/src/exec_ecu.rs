//  EXEC ECU.rs
//    by Lut99
//
//  Created:
//    20 Sep 2022, 13:55:30
//  Last edited:
//    04 Nov 2024, 11:19:13
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains code that can execute any containers (i.e., the
//!   Ecu/Code-type).
//

use std::collections::HashMap;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use brane_exe::FullValue;
use log::{debug, info};
use specifications::container::{Action, ActionCommand, LocalContainerInfo};
use tokio::io::AsyncReadExt as _;
use tokio::process::{Child as TokioChild, Command as TokioCommand};

// use crate::callback::Callback;
use crate::common::{Map, PackageResult, PackageReturnState, assert_input};
use crate::errors::LetError;


/***** CONSTANTS *****/
/// Initial capacity for the buffers for stdout and stderr
const DEFAULT_STD_BUFFER_SIZE: usize = 2048;
/// The start marker of a capture area
const MARK_START: &str = "--> START CAPTURE";
/// The end marker of a capture area
const MARK_END: &str = "--> END CAPTURE";
/// The single-line marker of a capture line
const PREFIX: &str = "~~>";





/***** ENTRYPOINT *****/
/// Handles a package containing ExeCUtable code (ECU).
///
/// **Arguments**
///  * `function`: The function name to execute in the package.
///  * `arguments`: The arguments, as a map of argument name / value pairs.
///  * `working_dir`: The wokring directory for this package.
///  * `callback`: The callback object we use to keep in touch with the driver.
///
/// **Returns**  
/// The return state of the package call on success, or a LetError otherwise.
pub async fn handle(
    function: String,
    arguments: Map<FullValue>,
    working_dir: PathBuf,
    // callback: &mut Option<&mut Callback>,
) -> Result<PackageResult, LetError> {
    debug!("Executing '{}' (ecu) using arguments:\n{:#?}", function, arguments);

    // Initialize the package
    let (container_info, function) = initialize(&function, &arguments, &working_dir)?;
    info!("Reached target 'Initialized'");

    // Launch the job
    let (command, process) = start(&container_info, &function, &arguments, &working_dir)?;
    info!("Reached target 'Started'");

    // Wait until the job is completed
    let result = complete(process).await?;
    info!("Reached target 'Completed'");

    // Convert the call to a PackageReturn value instead of state
    let result = decode(result, &command.capture)?;
    info!("Reached target 'Decode'");

    // Return the package call result!
    Ok(result)
}





/***** INITIALIZATION *****/
/// Initializes the environment for the nested package by reading the container.yml and preparing the working directory.
///
/// Arguments:
/// * `function`: The function name to execute in the package.
/// * `arguments`: The arguments, as a map of argument name / value pairs.
/// * `working_dir`: The wokring directory for this package.
///
/// Returns:
/// * On success, a tuple with (in order):
///   * The LocalContainerInfo struct representing the local_container.yml in this package
///   * The function represented as an Action that we should execute
///   * A list of Parmaters describing the function's _output_
/// * On failure:
///   * A LetError describing what went wrong.
fn initialize(function: &str, arguments: &Map<FullValue>, working_dir: &Path) -> Result<(LocalContainerInfo, Action), LetError> {
    debug!("Reading local_container.yml...");
    // Get the container info from the path
    let container_info_path = working_dir.join("local_container.yml");
    let container_info = LocalContainerInfo::from_path(container_info_path.clone())
        .map_err(|err| LetError::LocalContainerInfoError { path: container_info_path, err })?;

    // Resolve the function we're supposed to call
    let action = match container_info.actions.get(function) {
        Some(action) => action.clone(),
        None => {
            return Err(LetError::UnknownFunction { function: function.to_string(), package: container_info.name, kind: container_info.kind });
        },
    };

    // Extract the list of function parameters
    let function_input = action.input.clone().unwrap_or_default();
    // Make sure the input matches what we expect
    assert_input(&function_input, arguments, function, &container_info.name, container_info.kind)?;

    debug!("Preparing working directory...");
    let init_sh = working_dir.join("init.sh");
    if !init_sh.exists() {
        // No need; the user doesn't require an additional setup
        return Ok((container_info, action));
    }

    // Otherwise, run the init.sh script
    let mut command = Command::new(init_sh);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let result = command.output().map_err(|err| LetError::WorkdirInitLaunchError { command: format!("{command:?}"), err })?;

    if !result.status.success() {
        return Err(LetError::WorkdirInitError {
            command: format!("{command:?}"),
            code:    result.status.code().unwrap_or(-1),
            stdout:  String::from_utf8_lossy(&result.stdout).to_string(),
            stderr:  String::from_utf8_lossy(&result.stderr).to_string(),
        });
    }

    // Initialization complete!
    Ok((container_info, action))
}





/***** EXECUTION *****/
/// Starts the given function in the background, returning the process handle.
///
/// **Arguments**
///  * `container_info`: The LocalContainerInfo representing the container.yml of this package.
///  * `function`: The function to call.
///  * `arguments`: The arguments to pass to the function.
///  * `working_dir`: The working directory for the function.
///
/// **Returns**  
/// The ActionCommand used + a process handle on success, or a LetError on failure.
fn start(
    container_info: &LocalContainerInfo,
    function: &Action,
    arguments: &Map<FullValue>,
    working_dir: &Path,
) -> Result<(ActionCommand, TokioChild), LetError> {
    // Determine entrypoint and, optionally, command and arguments
    let entrypoint = &container_info.entrypoint.exec;
    let command = function.command.clone().unwrap_or_else(|| ActionCommand { args: Default::default(), capture: None });
    let entrypoint_path = working_dir.join(entrypoint);
    let entrypoint_path = entrypoint_path.canonicalize().map_err(|err| LetError::EntrypointPathError { path: entrypoint_path, err })?;

    let mut exec_command = TokioCommand::new(entrypoint_path);

    // Construct the environment variables
    let envs = construct_envs(arguments)?;
    debug!("Using environment variables:\n{:#?}", envs);
    let envs: Vec<_> = envs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    // Finally, prepare the subprocess
    exec_command.args(&command.args);
    exec_command.envs(envs);
    exec_command.stdout(Stdio::piped());
    exec_command.stderr(Stdio::piped());
    let process = exec_command.spawn().map_err(|err| LetError::PackageLaunchError { command: format!("{exec_command:?}"), err })?;

    Ok((command, process))
}

/// Creates a map with enviroment variables for the nested package based on the given arguments.
///
/// **Arguments**
///  * `variables`: The arguments to pass to the nested package.
///
/// **Returns**  
/// A new map with the environment on success, or a LetError on failure.
fn construct_envs(variables: &Map<FullValue>) -> Result<Map<String>, LetError> {
    // Simply add the values one-by-one
    // FIXME: Use iterators
    let mut envs = Map::<String>::new();
    for (name, variable) in variables.iter() {
        // Get an UPPERCASE equivalent of the variable name for proper environment variable naming scheme
        let name = name.to_ascii_uppercase();
        // Note: make sure this doesn't cause additional conflicts
        if envs.contains_key(&name) {
            return Err(LetError::DuplicateArgument { name });
        }

        // Convert the argument's value to some sort of valid string
        envs.insert(
            name.clone(),
            serde_json::to_string(variable).map_err(|err| LetError::SerializeError { argument: name, data_type: variable.data_type(), err })?,
        );
    }

    Ok(envs)
}





/***** WAITING FOR RESULT *****/
/// Waits for the given process to complete, then returns its result.
///
/// **Arguments**
///  * `process`: The handle to the asynchronous tokio process.
///  * `callback`: A Callback object to send heartbeats with.
///
/// **Returns**  
/// The PackageReturnState describing how the call went on success, or a LetError on failure.
async fn complete(
    process: TokioChild,
    // callback: &mut Option<&mut Callback>,
) -> Result<PackageReturnState, LetError> {
    let mut process = process;

    // Handle waiting for the subprocess and doing heartbeats in a neat way, using select
    let status: ExitStatus = process.wait().await.map_err(|err| LetError::PackageRunError { err })?;

    // Try to get stdout and stderr readers
    let mut stdout = process.stdout.ok_or(LetError::ClosedStdout)?;
    let mut stderr = process.stderr.ok_or(LetError::ClosedStderr)?;

    // Consume the readers into the raw text
    let mut stdout_text: Vec<u8> = Vec::with_capacity(DEFAULT_STD_BUFFER_SIZE);
    let _n_stdout = stdout.read_to_end(&mut stdout_text).await.map_err(|err| LetError::StdoutReadError { err })?;

    let mut stderr_text: Vec<u8> = Vec::with_capacity(DEFAULT_STD_BUFFER_SIZE);
    let _n_stderr = stderr.read_to_end(&mut stderr_text).await.map_err(|err| LetError::StderrReadError { err })?;

    // Convert the bytes to text
    let stdout = String::from_utf8_lossy(&stdout_text).to_string();
    let stderr = String::from_utf8_lossy(&stderr_text).to_string();

    // Always print stdout/stderr
    let barrier = "-".repeat(80);
    debug!("Job stdout (unprocessed):\n{barrier}\n{stdout}\n{barrier}\n\n");
    debug!("Job stderr (unprocessed):\n{barrier}\n{stderr}\n{barrier}\n\n");

    // If the process failed, return it does
    if !status.success() {
        // Check if it was killed
        if let Some(signal) = status.signal() {
            return Ok(PackageReturnState::Stopped { signal });
        }

        return Ok(PackageReturnState::Failed { code: status.code().unwrap_or(-1), stdout, stderr });
    }

    // Otherwise, it was a success, so return it as such!
    Ok(PackageReturnState::Finished { stdout })
}

/// Preprocesses stdout by only leaving the stuff that is relevant for the branelet (i.e., only that which is marked as captured by the mode).
///
/// **Arguments**
///  * `stdout`: The stdout from the process, split on lines.
///  * `mode`: The mode how to capture the data.
///
/// **Returns**  
/// The preprocessed stdout.
fn preprocess_stdout(stdout: String, mode: &Option<String>) -> String {
    let mode = mode.clone().unwrap_or_else(|| String::from("complete"));
    match mode.as_str() {
        "complete" => stdout,
        "marked" => stdout
            .lines()
            .skip_while(|line| !line.trim_start().starts_with(MARK_START))
            .skip(1)
            .take_while(|line| !line.trim_start().starts_with(MARK_END))
            .collect::<Vec<_>>()
            .join("\n"),
        "prefixed" => {
            stdout.lines().filter(|line| line.starts_with(PREFIX)).map(|line| line.trim_start_matches(PREFIX)).collect::<Vec<_>>().join("\n")
        },
        _ => panic!("Encountered illegal capture mode '{}'; this should never happen!", mode),
    }
}





/***** DECODE *****/
/// Decodes the given PackageReturnState to a PackageResult (reading the YAML) if it's the Finished state. Simply maps the state to the value otherwise.
///
/// **Arguments**
///  * `result`: The result from the call that we (possibly) want to decode.
///  * `mode`: The capture mode that determines which bit of the output is interesting to us.
///
/// **Returns**  
/// The decoded return state as a PackageResult, or a LetError otherwise.
fn decode(result: PackageReturnState, mode: &Option<String>) -> Result<PackageResult, LetError> {
    // Match on the result
    match result {
        PackageReturnState::Finished { stdout } => {
            // First, preprocess the stdout
            let stdout = preprocess_stdout(stdout, mode);

            // If there is nothing to parse, note a Void
            if !stdout.trim().is_empty() {
                // Simply use serde, our old friend
                let output: HashMap<String, FullValue> = serde_yaml::from_str(&stdout).map_err(|err| LetError::DecodeError { stdout, err })?;

                // Get the only key
                if output.len() > 1 {
                    return Err(LetError::UnsupportedMultipleOutputs { n: output.len() });
                }
                let value = if output.len() == 1 { output.into_iter().next().unwrap().1 } else { FullValue::Void };

                // Done
                Ok(PackageResult::Finished { result: value })
            } else {
                Ok(PackageResult::Finished { result: FullValue::Void })
            }
        },

        PackageReturnState::Failed { code, stdout, stderr } => {
            // Simply map the values
            Ok(PackageResult::Failed { code, stdout, stderr })
        },

        PackageReturnState::Stopped { signal } => {
            // Simply map the value
            Ok(PackageResult::Stopped { signal })
        },
    }
}
