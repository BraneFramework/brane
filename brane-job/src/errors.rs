//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    30 Nov 2022, 18:08:54
//  Last edited:
//    30 Nov 2022, 18:13:44
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines any errors that occur in the `brane-job` crate.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;


/***** LIBRARY *****/
/// Defines errors that relate to the ContainerHashes file.
#[derive(Debug)]
pub enum ContainerHashesError {
    /// Failed to read the given hash file.
    ReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the given hash file as the appropriate YAML.
    ParseError{ path: PathBuf, err: serde_yaml::Error },
    /// There was a duplicate hash in there.
    DuplicateHash{ path: PathBuf, hash: String },

    /// Failed to serialize the hash file.
    SerializeError{ err: serde_yaml::Error },
    /// Failed to write to the given file.
    WriteError{ path: PathBuf, err: std::io::Error },
}
impl Display for ContainerHashesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ContainerHashesError::*;
        match self {
            ReadError{ path, err }      => write!(f, "Failed to read hash file '{}': {}", path.display(), err),
            ParseError{ path, err }     => write!(f, "Failed to parse hash file '{}' as YAML: {}", path.display(), err),
            DuplicateHash{ path, hash } => write!(f, "Hash file '{}' contains duplicate hash '{}'", path.display(), hash),

            SerializeError{ err }   => write!(f, "Failed to serialize hash file: {err}"),
            WriteError{ path, err } => write!(f, "Failed to write hash file to '{}': {}", path.display(), err),
        }
    }
}
impl Error for ContainerHashesError {}
