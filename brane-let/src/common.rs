//  COMMON.rs
//    by Lut99
//
//  Created:
//    14 Feb 2022, 14:21:21
//  Last edited:
//    22 May 2023, 10:23:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains common definitions across all executions.
//

use brane_ast::DataType;
use brane_exe::FullValue;
use specifications::common::Parameter;
use specifications::package::PackageKind;
use tracing::debug;

use crate::errors::LetError;


/***** CONSTANTS *****/
/// The time between each heartbeat update (in ms)
///
/// Shouldn't be longer than the timeout of heartbeats defined in brane-drv (10 seconds at the time of writing), as brane-drv considers the branelet dead if it didn't send a heartbeat in that time.
pub const HEARTBEAT_DELAY: u64 = 5000;





/***** CUSTOM TYPE DEFINITIONS *****/
/// Defines a shortcut for a map with string keys
pub type Map<T> = std::collections::HashMap<String, T>;





/***** ENUMS *****/
/// Defines the different ways a package can return.
pub enum PackageReturnState {
    /// The package was forcefully stopped by some external force
    Stopped { signal: i32 },
    /// The package failed to execute on its own
    Failed { code: i32, stdout: String, stderr: String },
    /// The package completed successfully
    Finished { stdout: String },
}



/// Defines a slightly higher level version of the PackageReturnState.
pub enum PackageResult {
    /// The package was forcefully stopped by some external force
    Stopped { signal: i32 },
    /// The package failed to execute on its own
    Failed { code: i32, stdout: String, stderr: String },
    /// The package completed successfully
    Finished { result: FullValue },
}




/***** HELPER FUNCTIONS *****/
/// Returns whether this type is allowed for the package's target type.
///
/// # Arguments
/// - `got`: The type we are given to use.
/// - `expected`: The type the package expected.
///
/// # Returns
/// Returns whether they are "the same" or not.
fn assert_type(got: &DataType, expected: &DataType) -> bool {
    match (got, expected) {
        // Specific cases
        (DataType::String, DataType::Data) => true,
        (DataType::String, DataType::IntermediateResult) => true,

        // Recursive cases
        (DataType::Array { elem_type: got }, DataType::Array { elem_type: expected }) => assert_type(got, expected),

        // General cases
        (DataType::Any, _) => true,
        (_, DataType::Any) => true,
        (got, expected) => got == expected,
    }
}





/***** INITIALIZATION *****/
/// **Edited: now returning LetErrors.**
///
/// Tries to confirm that what we're told to put in the function is the same as the function accepts.
///
/// **Arguments**
///  * `parameters`: The list of what the function accepts as parameters as returned by container.yml.
///  * `arguments`: The arguments we got to pass to the function.
///  * `function`: The name of the function we're trying to evaluate (used for debugging purposes).
///  * `package`: The name of the internal package (used for debugging purposes).
///  * `kind`: The kind of the internal package (used for debugging purposes).
///
/// **Returns**  
/// Nothing if the assert went alright, but a LetError describing why it failed on an error.
pub fn assert_input(parameters: &[Parameter], arguments: &Map<FullValue>, function: &str, package: &str, kind: PackageKind) -> Result<(), LetError> {
    debug!("Asserting input arguments");

    // Search through all the allowed parameters
    for p in parameters {
        // Get the expected type, but skip mounts(?)
        let expected_type = DataType::from(p.data_type.as_str());

        // Check if the user specified it
        let argument = match arguments.get(&p.name) {
            Some(argument) => argument,
            None => {
                return Err(LetError::MissingInputArgument {
                    function: function.to_string(),
                    package: package.to_string(),
                    kind,
                    name: p.name.clone(),
                });
            },
        };

        // Check if the type makes sense
        // Note that we make a special case for data & intermediate results, since that will be converted to a type the package is comfortable with
        let actual_type = argument.data_type();
        if !assert_type(&actual_type, &expected_type) {
            return Err(LetError::IncompatibleTypes {
                function: function.to_string(),
                package: package.to_string(),
                kind,
                name: p.name.clone(),
                expected: expected_type,
                got: actual_type,
            });
        }
    }

    // It all is allowed!
    Ok(())
}
