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

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;


/***** LIBRARY *****/
/// Collects errors that relate to offline compilation.
#[derive(Debug)]
pub enum CompileError {
    /// Failed to open the given input file.
    InputOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read from the input.
    InputReadError{ name: String, err: std::io::Error },
    /// Failed to fetch the remote package index.
    RemotePackageIndexError{ endpoint: String, err: brane_tsk::api::Error },
    /// Failed to fetch the remote data index.
    RemoteDataIndexError{ endpoint: String, err: brane_tsk::api::Error },
    /// Failed to fetch the local package index.
    LocalPackageIndexError{ err: brane_tsk::local::Error },
    /// Failed to fetch the local data index.
    LocalDataIndexError{ err: brane_tsk::local::Error },
    /// Failed to serialize workflow.
    WorkflowSerializeError{ err: serde_json::Error },
    /// Failed to create the given output file.
    OutputCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the given output file.
    OutputWriteError{ name: String, err: std::io::Error },

    /// Compilation itself failed.
    CompileError{ errs: Vec<brane_ast::Error> },
}

impl Display for CompileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::CompileError::*;
        match self {
            InputOpenError{ path, err }              => write!(f, "Failed to open input file '{}': {}", path.display(), err),
            InputReadError{ name, err }              => write!(f, "Failed to read from input '{name}': {err}"),
            RemotePackageIndexError{ endpoint, err } => write!(f, "Failed to fetch remote package index from '{endpoint}': {err}"),
            RemoteDataIndexError{ endpoint, err }    => write!(f, "Failed to fetch remote data index from '{endpoint}': {err}"),
            LocalPackageIndexError{ err }            => write!(f, "Failed to fetch local package index: {err}"),
            LocalDataIndexError{ err }               => write!(f, "Failed to fetch local data index: {err}"),
            WorkflowSerializeError{ err }            => write!(f, "Failed to serialize the compiled workflow: {err}"),
            OutputCreateError{ path, err }           => write!(f, "Failed to create output file '{}': {}", path.display(), err),
            OutputWriteError{ name, err }            => write!(f, "Failed to write to output '{name}': {err}"),

            CompileError{ .. } => write!(f, "Failed to compile given workflow (see output above)"),
        }
    }
}

impl Error for CompileError {}



/// Defines errors that occur when attempting to parse an IndexLocationParseError.
#[derive(Debug)]
pub struct IndexLocationParseError;

impl Display for IndexLocationParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(f, "The impossible has happened; an IndexLocationParseError was raised, even though none exist")
    }
}

impl Error for IndexLocationParseError {}
