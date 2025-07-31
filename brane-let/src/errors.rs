//  ERRORS.rs
//    by Lut99
//
//  Created:
//    11 Feb 2022, 13:09:23
//  Last edited:
//    14 Nov 2024, 17:23:46
//  Auto updated?
//    Yes
//
//  Description:
//!   Collects errors for the brane-let applications.
//

use std::path::PathBuf;

use specifications::container::LocalContainerInfoError;
use specifications::package::PackageKind;
use specifications::wir::data_type::DataType;


/***** ERRORS *****/
/// Generic, top-level errors for the brane-let application.
#[derive(Debug, thiserror::Error)]
pub enum LetError {
    /// Could not launch the JuiceFS executable
    #[error("Could not run JuiceFS command '{command}'")]
    JuiceFSLaunchError { command: String, source: std::io::Error },
    /// The JuiceFS executable didn't complete successfully
    #[error(
        "JuiceFS command '{command}' returned exit code {code}:\n\nstdout:\n{stdout}\n{bar}\n{bar}\n\nstderr:\n{stderr}\n{bar}\n{bar}\n\n",
        bar = "-".repeat(80)
    )]
    JuiceFSError { command: String, code: i32, stdout: String, stderr: String },

    /// Could not start the proxy redirector in the background
    #[error("Could not start redirector to '{address}' in the background")]
    RedirectorError { address: String, err: String },
    /// Could not decode input arguments with Base64
    #[error("Could not decode input arguments as Base64")]
    ArgumentsBase64Error { source: base64::DecodeError },
    /// Could not decode input arguments as UTF-8
    #[error("Could not decode input arguments as UTF-8")]
    ArgumentsUTF8Error { source: std::string::FromUtf8Error },
    /// Could not decode input arguments with JSON
    #[error("Could not parse input arguments as JSON")]
    ArgumentsJSONError { source: serde_json::Error },

    /// Could not load a ContainerInfo file.
    #[error("Could not load local container information file '{}'", path.display())]
    LocalContainerInfoError { path: PathBuf, source: LocalContainerInfoError },
    /// Could not load a PackageInfo file.
    #[error("Could not parse package information file from Open-API document")]
    PackageInfoError { source: anyhow::Error },
    /// Missing the 'functions' property in the package info YAML
    #[error("Missing property 'functions' in package information file '{}'", path.display())]
    MissingFunctionsProperty { path: PathBuf },
    /// The requested function is not part of the package that this brane-let is responsible for
    #[error("Unknown function '{}' in package '{}' ({})", function, package, kind.pretty())]
    UnknownFunction { function: String, package: String, kind: PackageKind },
    /// We're missing a required parameter in the function
    #[error("Parameter '{}' not specified for function '{}' in package '{}' ({})", name, function, package, kind.pretty())]
    MissingInputArgument { function: String, package: String, kind: PackageKind, name: String },
    /// An argument has an incompatible type
    #[error("Type check failed for parameter '{}' of function '{}' in package '{}' ({}): expected {}, got {}", name, function, package, kind.pretty(), expected, got)]
    IncompatibleTypes { function: String, package: String, kind: PackageKind, name: String, expected: DataType, got: DataType },
    /// Could not start the init.sh workdirectory preparation script
    #[error("Could not run init.sh ('{command}')")]
    WorkdirInitLaunchError { command: String, source: std::io::Error },
    /// The init.sh workdirectory preparation script returned a non-zero exit code
    #[error(
        "init.sh ('{command}') returned exit code {code}:\n\nstdout:\n{stdout}\n{bar}\n{bar}\n\nstderr:\n{stderr}\n{bar}\n{bar}\n\n",
        bar = "-".repeat(80)
    )]
    WorkdirInitError { command: String, code: i32, stdout: String, stderr: String },

    /// Could not canonicalize the entrypoint file's path
    #[error("Could not canonicalize path '{}'", path.display())]
    EntrypointPathError { path: PathBuf, source: std::io::Error },
    /// We encountered two arguments with indistinguishable names
    #[error("Encountered duplicate function argument '{name}'; make sure your names don't conflict in case-insensitive scenarios either")]
    DuplicateArgument { name: String },
    /// We encountered an array element with indistringuishable name from another environment variable
    #[error(
        "Element {elem} of array '{array}' has the same name as environment variable '{name}'; remember that arrays generate new arguments for each \
         element"
    )]
    DuplicateArrayArgument { array: String, elem: usize, name: String },
    /// We encountered a struct field with indistringuishable name from another environment variable
    #[error(
        "Field '{field}' of struct '{sname}' has the same name as environment variable '{name}'; remember that structs generate new arguments for \
         each field"
    )]
    DuplicateStructArgument { sname: String, field: String, name: String },
    /// The user tried to pass an unsuppored type to a function
    #[error("Argument '{argument}' has type '{elem_type}'; this type is not (yet) supported, please use other types")]
    UnsupportedType { argument: String, elem_type: DataType },
    /// The user tried to give us a nested array, but that's unsupported for now.
    #[error("Element {elem} of array is an array; nested arrays are not (yet) supported, please use flat arrays only")]
    UnsupportedNestedArray { elem: usize },
    /// The user tried to give us an array with (for now) unsupported element types.
    #[error("Element {elem} of array has type '{elem_type}'; this type is not (yet) supported in arrays, please use other types")]
    UnsupportedArrayElement { elem: usize, elem_type: String },
    /// The user tried to give us a struct with a nested array.
    #[error(
        "Field '{field}' of struct '{name}' is an array; nested arrays in structs are not (yet) supported, please pass arrays separately as flat \
         arrays"
    )]
    UnsupportedStructArray { name: String, field: String },
    /// The user tried to pass a nested Directory or File argument without 'url' property.
    #[error(
        "Field '{field}' of struct '{name}' is a non-File, non-Directory struct; nested structs are not (yet) supported, please pass structs \
         separately"
    )]
    UnsupportedNestedStruct { name: String, field: String },
    /// The user tried to pass a Struct with a general unsupported type.
    #[error("Field '{field}' of struct '{name}' has type '{elem_type}'; this type is not (yet) supported in structs, please use other types")]
    UnsupportedStructField { name: String, field: String, elem_type: String },
    /// The user tried to pass a nested Directory or File argument without 'url' property.
    #[error("Field '{field}' of struct '{name}' is a Directory or a File struct, but misses the 'URL' field")]
    IllegalNestedURL { name: String, field: String },
    /// We got an error launching the package
    #[error("Could not run nested package call '{command}'")]
    PackageLaunchError { command: String, source: std::io::Error },

    /// The given Open API Standard file does not parse as OAS
    #[error("Could not parse OpenAPI specification '{}'", path.display())]
    IllegalOasDocument { path: PathBuf, source: anyhow::Error },

    /// Somehow, we got an error while waiting for the subprocess
    #[error("Could not get package run status")]
    PackageRunError { source: std::io::Error },
    /// The subprocess' stdout wasn't opened successfully
    #[error("Could not open subprocess stdout")]
    ClosedStdout,
    /// The subprocess' stderr wasn't opened successfully
    #[error("Could not open subprocess stdout")]
    ClosedStderr,
    /// Could not open stdout
    #[error("Could not read from stdout")]
    StdoutReadError { source: std::io::Error },
    /// Could not open stderr
    #[error("Could not read from stderr")]
    StderrReadError { source: std::io::Error },

    /// Something went wrong while decoding the package output as YAML
    #[error("Could not parse package stdout:\n{}", stdout)]
    DecodeError { stdout: String, source: serde_yaml::Error },
    /// Failed to parse the output of an OAS package (which uses JSON instead of YAML cuz OAS)
    #[error("Could not parse package stdout:\n{}", stdout)]
    OasDecodeError { stdout: String, source: serde_json::Error },
    /// Encountered more than one output from the function
    #[error("Function return {n} outputs; this is not (yet) supported, please return only one")]
    UnsupportedMultipleOutputs { n: usize },

    /// Failed to encode the input JSON
    #[error("Failed to serialize argument '{argument}' ({data_type}) to JSON")]
    SerializeError { argument: String, data_type: DataType, source: serde_json::Error },
    /// Could not encode the given array to JSON.
    #[error("Failed to serialize Array in argument '{argument}' to JSON")]
    ArraySerializeError { argument: String, source: serde_json::Error },
    /// Could not encode the given class to JSON.
    #[error("Failed to serialize Class '{class}' in argument '{argument}' to JSON")]
    ClassSerializeError { argument: String, class: String, source: serde_json::Error },
    /// Could not write the resulting value to JSON
    #[error("Could not serialize value '{value}' to JSON")]
    ResultJSONError { value: String, source: serde_json::Error },
}

/// Defines errors that can occur during decoding.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The input was not valid YAML
    #[error("Invalid YAML")]
    InvalidYAML { source: yaml_rust::ScanError },
    /// The input was not valid JSON
    #[error("Invalid JSON")]
    InvalidJSON { source: serde_json::Error },

    /// The input is not a valid Hash, i.e., not a valid object (I think)
    #[error("Top-level YAML is not a valid hash")]
    NotAHash,
    /// Some returned output argument was missing from what the function reported
    #[error("Missing output argument '{name}' in function output")]
    MissingOutputArgument { name: String },
    /// Some returned output argument has an incorrect type
    #[error("Function output '{name}' has type '{got}', but expected type '{expected}'")]
    OutputTypeMismatch { name: String, expected: String, got: String },
    /// A given output has a given class type defined, but we don't know about it
    #[error("Function output '{name}' has object type '{class_name}', but that object type is undefined")]
    UnknownClassType { name: String, class_name: String },

    /// Some output struct did not have all its properties defined.
    #[error("Function output '{name}' has object type '{class_name}', but is missing property '{property_name}'")]
    MissingStructProperty { name: String, class_name: String, property_name: String },
}
