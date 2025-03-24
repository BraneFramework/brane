//  EXEC ECU.rs
//    by Lut99
//
//  Created:
//    20 Sep 2022, 13:55:30
//  Last edited:
//    25 May 2023, 20:43:21
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
use std::process::{Command, Stdio};

use brane_exe::FullValue;
use specifications::container::{Action, ActionCommand, LocalContainerInfo};
use tokio::io::AsyncReadExt as _;
use tokio::process::{Child as TokioChild, Command as TokioCommand};
use tokio::time::{self, Duration};
use tracing::{debug, info};

// use crate::callback::Callback;
use crate::common::{HEARTBEAT_DELAY, Map, PackageResult, PackageReturnState, assert_input};
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
/// **Edited: working with new callback interface + events.**
///
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
    let (container_info, function) = match initialize(&function, &arguments, &working_dir) {
        Ok(results) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.initialized().await { warn!("Could not update driver on Initialized: {}", err); }
            // }

            info!("Reached target 'Initialized'");
            results
        },
        Err(err) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.initialize_failed(format!("{}", &err)).await { warn!("Could not update driver on InitializeFailed: {}", err); }
            // }
            return Err(err);
        },
    };

    // Launch the job
    let (command, process) = match start(&container_info, &function, &arguments, &working_dir) {
        Ok(result) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.started().await { warn!("Could not update driver on Started: {}", err); }
            // }

            info!("Reached target 'Started'");
            result
        },
        Err(err) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.start_failed(format!("{}", &err)).await { warn!("Could not update driver on StartFailed: {}", err); }
            // }
            return Err(err);
        },
    };

    // Wait until the job is completed
    let result = match complete(process).await {
        Ok(result) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.completed().await { warn!("Could not update driver on Completed: {}", err); }
            // }

            info!("Reached target 'Completed'");
            result
        },
        Err(err) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.complete_failed(format!("{}", &err)).await { warn!("Could not update driver on CompleteFailed: {}", err); }
            // }
            return Err(err);
        },
    };

    // Convert the call to a PackageReturn value instead of state
    let result = match decode(result, &command.capture) {
        Ok(result) => result,
        Err(err) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.decode_failed(format!("{}", &err)).await { warn!("Could not update driver on DecodeFailed: {}", err); }
            // }
            return Err(err);
        },
    };
    info!("Reached target 'Decode'");

    // Return the package call result!
    Ok(result)
}





/***** INITIALIZATION *****/
/// **Edited: returning LetErrors + now also doing the steps before the specific working dir initialization.**
///
/// Initializes the environment for the nested package by reading the container.yml and preparing the working directory.
///
/// **Arguments**
///  * `function`: The function name to execute in the package.
///  * `arguments`: The arguments, as a map of argument name / value pairs.
///  * `working_dir`: The wokring directory for this package.
///
/// **Returns**  
///  * On success, a tuple with (in order):
///    * The LocalContainerInfo struct representing the local_container.yml in this package
///    * The function represented as an Action that we should execute
///    * A list of Parmaters describing the function's _output_
///  * On failure:
///    * A LetError describing what went wrong.
fn initialize(function: &str, arguments: &Map<FullValue>, working_dir: &Path) -> Result<(LocalContainerInfo, Action), LetError> {
    debug!("Reading local_container.yml...");
    // Get the container info from the path
    let container_info_path = working_dir.join("local_container.yml");
    let container_info = LocalContainerInfo::from_path(container_info_path.clone())
        .map_err(|source| LetError::LocalContainerInfoError { path: container_info_path, source })?;

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
    let result = command.output().map_err(|source| LetError::WorkdirInitLaunchError { command: format!("{command:?}"), source })?;
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
    let entrypoint_path = entrypoint_path.canonicalize().map_err(|source| LetError::EntrypointPathError { path: entrypoint_path, source })?;

    // Prepare the actual subprocess crate command to execute
    // No idea what is happening here precisely, so disabling it until I run into it missing >:)
    // let command = if entrypoint_path.is_file() {
    //     Exec::cmd(entrypoint_path)
    // } else {
    //     let segments = entrypoint.split_whitespace().collect::<Vec<&str>>();
    //     let entrypoint_path = working_dir.join(&segments[0]).canonicalize()?;

    //     Exec::cmd(entrypoint_path).args(&segments[1..])
    // };
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
    let process = exec_command.spawn().map_err(|source| LetError::PackageLaunchError { command: format!("{exec_command:?}"), source })?;

    // Done, return the process!!
    Ok((command, process))
}

/// **Edited: now returning LetErrors.**
///
/// Creates a map with enviroment variables for the nested package based on the given arguments.
///
/// **Arguments**
///  * `variables`: The arguments to pass to the nested package.
///
/// **Returns**  
/// A new map with the environment on success, or a LetError on failure.
fn construct_envs(variables: &Map<FullValue>) -> Result<Map<String>, LetError> {
    // Simply add the values one-by-one
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
            serde_json::to_string(variable).map_err(|source| LetError::SerializeError { argument: name, data_type: variable.data_type(), source })?,
        );
        // use FullValue::*;
        // match variable {
        //     Boolean(value) => { envs.insert(name, format!("{}", value)); },
        //     Integer(value) => { envs.insert(name, format!("{}", value)); },
        //     Real(value)    => { envs.insert(name, format!("{}", value)); },
        //     String(value)  => { envs.insert(name, value.clone()); },

        //     Array(values) => { envs.insert(name.clone(), match serde_json::to_string(values) {
        //         Ok(value) => value,
        //         Err(err)  => { return Err(LetError::ArraySerializeError{ argument: name, err }); },
        //     }); },
        //     Instance(c_name, values) => { envs.insert(name.clone(), match serde_json::to_string(values) {
        //         Ok(value) => value,
        //         Err(err)  => { return Err(LetError::ClassSerializeError{ argument: name, class: c_name.clone(), err }); }
        //     }); },

        //     // The rest (i.e., Void) is not supported.
        //     _ => return Err(LetError::UnsupportedType{ argument: name.clone(), elem_type: variable.data_type() }),
        // }
    }

    Ok(envs)
}

// /// **Edited: now returning LetErrors + accepting a single basename instead of name + index.**
// ///
// /// Translates a struct to environment variables.
// ///
// /// **Arguments**
// ///  * `base_name`: The base name of the struct environment variable, which is either its name or an array element.
// ///  * `properties`: The struct's properties.
// ///  * `envs`: The resulting dict containing the environment.
// ///
// /// **Returns**
// /// Nothing on success, or a LetError otherwise.
// fn construct_struct_envs(
//     base_name: &str,
//     properties: &Map<Value>,
//     envs: &mut Map<String>,
// ) -> Result<(), LetError> {
//     // Simply add each property under its own name
//     for (key, entry) in properties.iter() {
//         // Make sure the field name doesn't already exist
//         let field_name = format!("{}_{}", base_name, key);
//         if envs.contains_key(&field_name) { return Err(LetError::DuplicateStructArgument{ sname: base_name.to_string(), field: key.clone(), name: field_name }); }

//         // Match on the value type
//         let value = match entry {
//             Value::Array { entries: _, .. } => { return Err(LetError::UnsupportedStructArray{ name: base_name.to_string(), field: key.clone() }) },
//             Value::Boolean(value) => value.to_string(),
//             Value::Integer(value) => value.to_string(),
//             Value::Real(value)    => value.to_string(),
//             Value::Unicode(value) => value.to_string(),
//             Value::Struct { data_type, properties } => match data_type.as_str() {
//                 "Directory" | "File" => {
//                     // Make sure they have a URL field
//                     let value = match properties.get("url") {
//                         Some(value) => value.to_string(),
//                         None        => { return Err(LetError::IllegalNestedURL{ name: base_name.to_string(), field: key.clone() }); }
//                     };
//                     // Construct the nested field name
//                     let nested_field_name = format!("{}_URL", field_name);
//                     if envs.contains_key(&nested_field_name) { return Err(LetError::DuplicateStructArgument{ sname: field_name, field: "URL".to_string(), name: nested_field_name }); }
//                     // Add it!
//                     envs.insert(nested_field_name, value);
//                     continue;
//                 }
//                 _ => { return Err(LetError::UnsupportedNestedStruct{ name: base_name.to_string(), field: key.clone() }); },
//             },
//             _ => { return Err(LetError::UnsupportedStructField{ name: base_name.to_string(), field: key.clone(), elem_type: entry.data_type() }); },
//         };

//         // Add the converted value
//         envs.insert(field_name, value);
//     }

//     // Done!
//     Ok(())
// }





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
    let status = loop {
        // Prepare the timer
        let sleep = time::sleep(Duration::from_millis(HEARTBEAT_DELAY));
        tokio::pin!(sleep);

        // Wait for either the timer or the process
        let status = tokio::select! {
            status = process.wait() => {
                // Process is finished!
                Some(status)
            },
            _ = &mut sleep => {
                // // Timeout occurred; send the heartbeat and continue
                // if let Some(callback) = callback {
                //     if let Err(err) = callback.heartbeat().await { warn!("Could not update driver on Heartbeat: {}", err); }
                //     else { debug!("Sent Heartbeat to driver."); }
                // }

                // Stop without result
                None
            },
        };

        // If we have a result, break from the main loop; otherwise, try again
        if let Some(status) = status {
            break status;
        }
    };

    // Match the status result
    let status = status.map_err(|source| LetError::PackageRunError { source })?;

    // Try to get stdout and stderr readers
    let mut stdout = process.stdout.ok_or_else(|| LetError::ClosedStdout)?;
    let mut stderr = process.stderr.ok_or_else(|| LetError::ClosedStderr)?;
    // Consume the readers into the raw text
    let mut stdout_text: Vec<u8> = Vec::with_capacity(DEFAULT_STD_BUFFER_SIZE);
    let _n_stdout = stdout.read_to_end(&mut stdout_text).await.map_err(|source| LetError::StdoutReadError { source })?;
    let mut stderr_text: Vec<u8> = Vec::with_capacity(DEFAULT_STD_BUFFER_SIZE);
    let _n_stderr = stderr.read_to_end(&mut stderr_text).await.map_err(|source| LetError::StderrReadError { source })?;
    // Convert the bytes to text
    let stdout = String::from_utf8_lossy(&stdout_text).to_string();
    let stderr = String::from_utf8_lossy(&stderr_text).to_string();

    // Always print stdout/stderr
    debug!("Job stdout (unprocessed):\n{}\n{}\n{}\n\n", (0..80).map(|_| '-').collect::<String>(), stdout, (0..80).map(|_| '-').collect::<String>());
    debug!("Job stderr (unprocessed):\n{}\n{}\n{}\n\n", (0..80).map(|_| '-').collect::<String>(), stdout, (0..80).map(|_| '-').collect::<String>());

    // If the process failed, return it does
    if !status.success() {
        // Check if it was killed
        if status.signal().is_some() {
            return Ok(PackageReturnState::Stopped { signal: status.signal().unwrap() });
        }
        return Ok(PackageReturnState::Failed { code: status.code().unwrap_or(-1), stdout, stderr });
    }

    // Otherwise, it was a success, so return it as such!
    Ok(PackageReturnState::Finished { stdout })
}

/// **Edited: returns LetErrors + changed to accept string instead of split stuff.**
///
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

    let mut captured = Vec::new();
    match mode.as_str() {
        "complete" => return stdout,
        "marked" => {
            let mut capture = false;

            for line in stdout.lines() {
                if line.trim_start().starts_with(MARK_START) {
                    capture = true;
                    continue;
                }

                // Stop capturing after observing MARK_END after MARK_START
                if capture && line.trim_start().starts_with(MARK_END) {
                    break;
                }

                if capture {
                    debug!("captured: {}", line);
                    captured.push(line);
                }
            }
        },
        "prefixed" => {
            for line in stdout.lines() {
                if line.starts_with(PREFIX) {
                    let trimmed = line.trim_start_matches(PREFIX);
                    debug!("captured: {}", trimmed);
                    captured.push(trimmed);
                }
            }
        },
        _ => panic!("Encountered illegal capture mode '{}'; this should never happen!", mode),
    }

    captured.join("\n")
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
                let output: HashMap<String, FullValue> = serde_yaml::from_str(&stdout).map_err(|source| LetError::DecodeError { stdout, source })?;

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

// /// **Edited: now returning DecodeErrors.**
// ///
// /// Tries to extract the given parameters with types from the given YAML output from a package call.
// ///
// /// **Arguments**
// ///  * `value`: The YAML output from the package call.
// ///  * `parameters`: The list of function output parameters.
// ///  * `types`: A list of class types that we know of at the time of parsing.
// ///
// /// **Returns**
// /// The parsed outputs, stored by key, on success, or a DecodeError on failure.
// fn unwrap_yaml_hash(
//     value: &Yaml,
//     parameters: &[Parameter],
//     types: &Map<Type>,
// ) -> Result<Map<FullValue>, DecodeError> {
//     // Get the hashmap variant of the YAML data
//     let map = match value.as_hash() {
//         Some(map)  => map,
//         None       => { return Err(DecodeError::NotAHash); }
//     };

//     // Go through the parameters to try to get them all
//     let mut output = Map::<FullValue>::new();
//     for p in parameters {
//         // Try to get this parameter from the map
//         let key = Yaml::from_str(p.name.as_str());
//         let value = &map[&key];

//         // Match the values
//         let value = match value {
//             Yaml::Array(elements) => {
//                 // Get the expected array type as everything before the '[]' in the typename as provided by container.yml
//                 let n = match p.data_type.find('[') {
//                     Some(n) => n,
//                     None    => { return Err(DecodeError::OutputTypeMismatch{ name: p.name.clone(), expected: p.data_type.clone(), got: "Array".to_string() }); }
//                 };
//                 let value_type: String = p.data_type.chars().take(n).collect();

//                 // Unwrap the entry values as the expected type
//                 let mut values = vec![];
//                 for element in elements.iter() {
//                     let variable = unwrap_yaml_value(element, &value_type, &p.name)?;
//                     values.push(variable);
//                 }

//                 // Return the value as an Array
//                 let data_type = p.data_type.to_string();
//                 FullValue::Array { values }
//             }
//             Yaml::Hash(_)  => unwrap_yaml_struct(value, &p.data_type, types, &p.name)?,
//             Yaml::BadValue => { return Err(DecodeError::MissingOutputArgument{ name: p.name.clone() }); }
//             _              => unwrap_yaml_value(value, &p.data_type, &p.name)?,
//         };

//         output.insert(p.name.clone(), value);
//     }

//     // Done!
//     Ok(output)
// }

// /// **Edited: now returning DecodeErrors.**
// ///
// /// Converts a given Yaml Hash value to a Value struct.
// ///
// /// **Arguments**
// ///  * `value`: The YAML value to parse.
// ///  * `data_type`: The data type to parse the value as.
// ///  * `types`: A list of class types that we know of at the time of parsing.
// ///  * `p_name`: The name of the output argument we're currently parsing. Used for writing sensible errors only.
// fn unwrap_yaml_struct(
//     value: &Yaml,
//     data_type: &str,
//     types: &Map<Type>,
//     p_name: &str,
// ) -> Result<FullValue, DecodeError> {
//     // Try to get the class type
//     let class_type = match types.get(data_type) {
//         Some(class_type) => class_type,
//         None             => { return Err(DecodeError::UnknownClassType{ name: p_name.to_string(), class_name: data_type.to_string() }); }
//     };
//     let mut values = Map::<FullValue>::new();

//     // Loop through the properties of this class to parse them all
//     for p in &class_type.properties {
//         // Define the temporary p_name
//         let mut class_p_name = String::from(p_name); class_p_name.push('.'); class_p_name.push_str(&p.name);

//         // Get the property
//         let prop_value = value[p.name.as_str()].clone();
//         if let Yaml::BadValue = prop_value { return Err(DecodeError::MissingStructProperty{ name: p_name.to_string(), class_name: data_type.to_string(), property_name: p.name.clone() }); }
//         let prop = unwrap_yaml_value(&prop_value, &p.data_type, &class_p_name)?;

//         // Insert it into the list
//         values.insert(p.name.to_string(), prop);
//     }

//     // Return the new struct
//     Ok(FullValue::Instance {
//         values,
//         name : class_type.name,
//     })
// }

// /// **Edited: now returning DecodeErrors.**
// ///
// /// Converts a given Yaml value to a Value value.
// ///
// /// **Arguments**
// ///  * `value`: The YAML value to parse.
// ///  * `data_type`: The data type to parse the value as.
// ///  * `p_name`: The name of the output argument we're currently parsing. Used for writing sensible errors only.
// fn unwrap_yaml_value(
//     value: &Yaml,
//     data_type: &str,
//     p_name: &str,
// ) -> Result<FullValue, DecodeError> {
//     debug!("Unwrapping as {}: {:?} ", data_type, value);

//     // Match on the data type
//     let value = match data_type {
//         "boolean" => {
//             match value.as_bool() {
//                 Some(value) => FullValue::Boolean(value),
//                 None        => { return Err(DecodeError::OutputTypeMismatch{ name: p_name.to_string(), expected: data_type.to_string(), got: "Boolean".to_string() }) },
//             }
//         }
//         "File[]" => {
//             // It's an array of files
//             if let Yaml::Array(elements) = value {
//                 // Go through each of the elements, recursing to parse those
//                 let mut entries = vec![];
//                 for element in elements.iter() {
//                     let variable = unwrap_yaml_value(element, "File", p_name)?;
//                     entries.push(variable);
//                 }

//                 // Construct an array with the parsed values
//                 Value::Array {
//                     data_type: data_type.to_string(),
//                     entries,
//                 }
//             } else {
//                 return Err(DecodeError::OutputTypeMismatch{ name: p_name.to_string(), expected: data_type.to_string(), got: "a non-array".to_string() });
//             }
//         }
//         "Directory" | "File" => {
//             // We expected a string URL now
//             let url = match value.as_str() {
//                 Some(value) => Value::Unicode(String::from(value)),
//                 None        => {
//                     // Pimp the expected type a little before returning
//                     let mut expected = String::from(data_type); expected.push_str(" (URL as String)");
//                     return Err(DecodeError::OutputTypeMismatch{ name: p_name.to_string(), expected, got: "a non-string".to_string() });
//                 }
//             };

//             // Create a struct to wrap this property
//             let mut properties: Map<Value> = Default::default();
//             properties.insert(String::from("url"), url);

//             // Return it
//             Value::Struct {
//                 data_type: String::from(data_type),
//                 properties,
//             }
//         }
//         "integer" => {
//             match value.as_i64() {
//                 Some(value) => Value::Integer(value),
//                 None        => { return Err(DecodeError::OutputTypeMismatch{ name: p_name.to_string(), expected: data_type.to_string(), got: "a non-integer".to_string() }); }
//             }
//         }
//         "real" => {
//             match value.as_f64() {
//                 Some(value) => Value::Real(value),
//                 None        => { return Err(DecodeError::OutputTypeMismatch{ name: p_name.to_string(), expected: data_type.to_string(), got: "a non-float".to_string() }); }
//             }
//         }
//         _ => {
//             // Otherwise, just get as a string(?)
//             match value.as_str() {
//                 Some(value) => Value::Unicode(String::from(value)),
//                 None        => { return Err(DecodeError::OutputTypeMismatch{ name: p_name.to_string(), expected: data_type.to_string(), got: "a non-string".to_string() }); }
//             }
//         }
//     };

//     Ok(value)
// }
