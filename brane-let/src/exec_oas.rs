//  EXEC OAS.rs
//    by Lut99
// 
//  Created:
//    20 Sep 2022, 13:57:17
//  Last edited:
//    05 Jan 2023, 12:37:49
//  Auto updated?
//    Yes
// 
//  Description:
//!   Contains code for executing OpenAPI Standard (OAS) packages.
// 

use std::path::{Path, PathBuf};
use std::str::FromStr;

use tokio::time::{self, Duration};

use brane_exe::FullValue;
use brane_oas::OpenAPI;
use specifications::package::{PackageInfo, PackageKind};
use specifications::version::Version;

// use crate::callback::Callback;
use crate::common::{assert_input, HEARTBEAT_DELAY, Map, PackageResult, PackageReturnState};
use crate::errors::LetError;


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
    debug!("Executing '{}' (oas) using arguments:\n{:#?}", function, arguments);

    // Initialize the package
    let oas_document = match initialize(&function, &arguments, &working_dir) {
        Ok(results) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.initialized().await { warn!("Could not update driver on Initialized: {}", err); }
            //     if let Err(err) = callback.started().await { warn!("Could not update driver on Started: {}", err); }
            // }

            info!("Reached target 'Initialized'");
            info!("Reached target 'Started'");
            results
        },
        Err(err) => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.initialize_failed(format!("{}", &err)).await { warn!("Could not update driver on InitializeFailed: {}", err); }
            // }
            return Err(err);
        }
    };

    // Do the API call, sending heartbeat updates while at it
    let result = match complete(&function, &arguments, &oas_document).await {
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
    let result = match decode(result) {
        Ok(result) => result,
        Err(err)   => {
            // if let Some(callback) = callback {
            //     if let Err(err) = callback.decode_failed(format!("{}", &err)).await { warn!("Could not update driver on DecodeFailed: {}", err); }
            // }
            return Err(err);
        }
    };

    // Return the package call result!
    Ok(result)
}





/***** INITIALIZATION *****/
/// **Edited: returning LetErrors + now also doing the steps before the specific working dir initialization.**
/// 
/// Initializes the environment for the nested package by reading the package.yml and preparing the working directory (though that's not needed yet).
/// 
/// **Arguments**
///  * `function`: The function name to execute in the package.
///  * `arguments`: The arguments, as a map of argument name / value pairs.
///  * `working_dir`: The wokring directory for this package.
/// 
/// **Returns**  
///  * On success, a tuple with (in order):
///    * The PackageInfo struct representing the package.yml in this package
///    * The function represented as an Action that we should execute
///  * On failure:
///    * A LetError describing what went wrong.
fn initialize(
    function: &str,
    arguments: &Map<FullValue>,
    working_dir: &Path,
) -> Result<OpenAPI, LetError> {
    // Get the OasDocument from path
    let oas_file = working_dir.join("document.yml");
    let oas_document = match brane_oas::parse_oas_file(&oas_file) {
        Ok(oas_document) => oas_document,
        Err(err) => { return Err(LetError::IllegalOasDocument{ path: oas_file, err }); },
    };

    // Get the package info from the OasDocument
    let package_info = match create_package_info(&oas_document) {
        Ok(package_info) => package_info,
        Err(err)         => { return Err(LetError::PackageInfoError{ err }); }
    };

    // Resolve the function we're supposed to call
    let function_info = match package_info.functions.get(function) {
        Some(function_info) => function_info.clone(),
        None                => { return Err(LetError::UnknownFunction{ function: function.to_string(), package: package_info.name, kind: package_info.kind }) }
    };

    // Make sure the input matches what we expect
    assert_input(&function_info.parameters, arguments, function, &package_info.name, package_info.kind)?;

    // Done!
    Ok(oas_document)
}



/// **Edited: now returning BuildErrors.**
/// 
/// Tries to build a PackageInfo from an OpenAPI document.
/// 
/// **Arguments**
///  * `document`: The OpenAPI document to try and convert.
/// 
/// **Returns**  
/// The newly constructed PackageInfo upon success, or an anyhow::Error otherwise.
fn create_package_info(
    document: &OpenAPI,
) -> Result<PackageInfo, anyhow::Error> {
    // Collect some metadata from the document
    let name = document.info.title.to_lowercase().replace(' ', "-");
    let version = Version::from_str(&document.info.version)?;
    let description = document.info.description.clone().unwrap_or_default();

    // Try to build the functions
    let (functions, types) = brane_oas::build::build_oas_functions(document)?;

    // With the collected info, build and return the new PackageInfo
    Ok(PackageInfo::new(
        name,
        version,
        PackageKind::Oas,
        vec![],
        description,
        false,
        functions,
        types,
    ))
}





/***** WAITING FOR RESULT *****/
/// Waits for the given process to complete, then returns its result.
/// 
/// **Arguments**
///  * `function`: The OpenAPI function to run.
///  * `arguments`: The Arguments to pass to the OpenAPI call.
///  * `oas_doc`: The parsed document with the call to execute.
///  * `callback`: A Callback object to send heartbeats with.
/// 
/// **Returns**  
/// The PackageReturnState describing how the call went on success, or a LetError on failure.
async fn complete(
    function: &str,
    arguments: &Map<FullValue>,
    oas_doc: &OpenAPI,
    // callback: &mut Option<&mut Callback>,
) -> Result<PackageReturnState, LetError> {
    // Handle waiting for the subprocess and doing heartbeats in a neat way, using select
    let result = loop {
        // Prepare the timer
        let sleep = time::sleep(Duration::from_millis(HEARTBEAT_DELAY));
        tokio::pin!(sleep);

        // Wait for either the timer or the process
        let status = loop {
            tokio::select! {
                result = brane_oas::execute(function, arguments, oas_doc) => {
                    // Process is finished!
                    break Some(result);
                },
                _ = &mut sleep => {
                    // // Timeout occurred; send the heartbeat and continue
                    // if let Some(callback) = callback {
                    //     if let Err(err) = callback.heartbeat().await { warn!("Could not update driver on Heartbeat: {}", err); }
                    //     else { debug!("Sent Heartbeat to driver."); }
                    // }

                    // Stop without result
                    break None;
                },
            }
        };

        // If we have a result, break from the main loop; otherwise, try again
        if let Some(status) = status { break status; }
    };

    // Match the status
    match result {
        Ok(stdout) => Ok(PackageReturnState::Finished{ stdout }),
        Err(err)   => Ok(PackageReturnState::Failed{ code: -1, stdout: String::new(), stderr: format!("Could not perform external OpenAPI call: {err}") }),
    }
}





/***** DECODE *****/
/// Decodes the given PackageReturnState to a PackageResult (reading the YAML) if it's the Finished state. Simply maps the state to the value otherwise.
/// 
/// **Arguments**
///  * `result`: The result from the call that we (possibly) want to decode.
/// 
/// **Returns**  
/// The decoded return state as a PackageResult, or a LetError otherwise.
fn decode(result: PackageReturnState) -> Result<PackageResult, LetError> {
    // Match on the result
    match result {
        PackageReturnState::Finished{ stdout } => {
            // First, convert the input to a JSON value
            let stdout_json: serde_json::Value = match serde_json::from_str(&stdout) {
                Ok(stdout_json) => stdout_json,
                Err(err)        => { return Err(LetError::OasDecodeError{ stdout, err }); }
            };
            debug!("Received JSON response:\n{}", serde_json::to_string_pretty(&stdout_json).unwrap_or_else(|_| String::from("<could not serialize>")));
            let output: FullValue = match serde_json::from_value(stdout_json) {
                Ok(output) => output,
                Err(err)   => { return Err(LetError::OasDecodeError{ stdout, err }); }
            };
            debug!("Parsed response:\n{:#?}", output);

            // Done
            Ok(PackageResult::Finished{ result: output })
        },

        PackageReturnState::Failed{ code, stdout, stderr } => {
            // Simply map the values
            Ok(PackageResult::Failed{ code, stdout, stderr })
        },

        PackageReturnState::Stopped{ signal } => {
            // Simply map the value
            Ok(PackageResult::Stopped{ signal })
        },
    }
}

// /// **Edited: Now returning DecodeErrors.**
// /// 
// /// Tries to build the given object or array with proper typing.  
// /// Simply clones the value if it isn't an object or an array.
// /// 
// /// **Arguments**
// ///  * `object`: The object or array (or other) to rebuild.
// ///  * `c_type`: The type we want the object to be.
// ///  * `c_types`: A list of known Class type definitions.
// ///  * `p_name`: The name of the output argument we're currently parsing. Used for writing sensible errors only.
// /// 
// /// **Returns**  
// /// The rebuilt Value on success, or a DecodeError otherwise.
// fn as_type(
//     object: &Value,
//     c_type: &str,
//     c_types: &Map<Type>,
//     p_name: &str,
// ) -> Result<Value, DecodeError> {
//     // Switch on the object type
//     let mut filtered = Map::<Value>::new();
//     match object {
//         Value::Struct { properties, .. } => {
//             // It's a struct, so check if the type exists in the form it is now
//             match c_types.get(c_type) {
//                 Some(c_type) => {
//                     // Rebuild all properties
//                     for p in &c_type.properties {
//                         // Try to get one
//                         let property = match properties.get(&p.name) {
//                             Some(property) => property,
//                             None           => { return Err(DecodeError::MissingStructProperty{ name: p_name.to_string(), class_name: c_type.name.clone(), property_name: p.name.clone() }); }
//                         };

//                         // Rebuild it with a recursive call
//                         let property = as_type(property, &p.data_type, c_types, p_name)?;
//                         filtered.insert(p.name.to_string(), property.clone());
//                     }

//                     // Return the rebuild struct
//                     Ok(Value::Struct {
//                         data_type: c_type.name.clone(),
//                         properties: filtered,
//                     })
//                 },
//                 None => Err(DecodeError::UnknownClassType{ name: p_name.to_string(), class_name: c_type.to_string() }),
//             }
//         }
//         Value::Array { entries: elements, .. } => {
//             // Get the array's base type name
//             let n = match c_type.find('[') {
//                 Some(n) => n,
//                 None    => { return Err(DecodeError::OutputTypeMismatch{ name: p_name.to_string(), expected: c_type.to_string(), got: "Array".to_string() }); }
//             };
//             let element_type: String = c_type.chars().take(n).collect();

//             // Go through each of the elements, recursing to rebuild those
//             let mut entries = vec![];
//             for element in elements.iter() {
//                 let variable = as_type(element, &element_type, c_types, p_name)?;
//                 entries.push(variable);
//             }

//             // Finally, return the rebuild array
//             Ok(Value::Array {
//                 entries,
//                 data_type: c_type.to_string(),
//             })
//         }
//         _ => Ok(object.clone()),
//     }
// }
