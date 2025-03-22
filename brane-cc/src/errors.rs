//  ERRORS.rs
//    by Lut99
//
//  Created:
//    18 Nov 2022, 14:40:14
//  Last edited:
//    18 Nov 2022, 15:18:47
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines errors for the `brane-cc` crate.
//

use std::path::PathBuf;


/***** LIBRARY *****/
/// Collects errors that relate to offline compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// Failed to open the given input file.
    #[error("Failed to open input file '{}'", path.display())]
    InputOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to read from the input.
    #[error("Failed to read from input '{name}'")]
    InputReadError { name: String, source: std::io::Error },
    /// Failed to fetch the remote package index.
    #[error("Failed to fetch remote package index from '{endpoint}'")]
    RemotePackageIndexError { endpoint: String, source: brane_tsk::api::Error },
    /// Failed to fetch the remote data index.
    #[error("Failed to fetch remote data index from '{endpoint}'")]
    RemoteDataIndexError { endpoint: String, source: brane_tsk::api::Error },
    /// Failed to fetch the local package index.
    #[error("Failed to fetch local package index")]
    LocalPackageIndexError { source: brane_tsk::local::Error },
    /// Failed to fetch the local data index.
    #[error("Failed to fetch local data index")]
    LocalDataIndexError { source: brane_tsk::local::Error },
    /// Failed to serialize workflow.
    #[error("Failed to serialize the compiled workflow")]
    WorkflowSerializeError { source: serde_json::Error },
    /// Failed to create the given output file.
    #[error("Failed to create output file '{}'", path.display())]
    OutputCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to write to the given output file.
    #[error("Failed to write to output '{name}'")]
    OutputWriteError { name: String, source: std::io::Error },

    /// Compilation itself failed.
    #[error("Failed to compile given workflow (see output above)")]
    CompileError { sources: Vec<brane_ast::Error> },
}



/// Defines errors that occur when attempting to parse an IndexLocationParseError.
#[derive(Debug, thiserror::Error)]
#[error("The impossible has happened; an IndexLocationParseError was raised, even though none exist")]
pub struct IndexLocationParseError;
