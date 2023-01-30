//  IDENTITY.rs
//    by Lut99
// 
//  Created:
//    26 Jan 2023, 09:33:45
//  Last edited:
//    26 Jan 2023, 13:57:36
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines interfaces and structs relating to a user's identity in an
//!   instance.
// 

use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use enum_debug::EnumDebug;
use serde::{Deserialize, Serialize};

use crate::address::Address;


/***** ERRORS *****/
/// Errors that relate to loading and/or writing an IdentityFile.
#[derive(Debug)]
pub enum IdentityFileError {
    /// The file was not found (which probably implied the user did not login)
    FileNotFound{ path: PathBuf },
    /// Failed to open the given file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read the given file.
    FileReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the contents of the given file.
    FileParseError{ path: PathBuf, err: serde_json::Error },

    /// Failed to serialize the IdentityFile.
    SerializeError{ err: serde_json::Error },
    /// Failed to create a new file.
    FileCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the new file.
    FileWriteError{ path: PathBuf, err: std::io::Error },
}
impl Display for IdentityFileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use IdentityFileError::*;
        match self {
            FileNotFound{ path }        => write!(f, "Login file '{}' not found", path.display()),
            FileOpenError{ path, err }  => write!(f, "Failed to open login file '{}': {}", path.display(), err),
            FileReadError{ path, err }  => write!(f, "Failed to read login file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse login file '{}' as valid JSON: {}", path.display(), err),

            SerializeError{ err }        => write!(f, "Failed to serialize a login file: {}", err),
            FileCreateError{ path, err } => write!(f, "Failed to create a new login file '{}': {}", path.display(), err),
            FileWriteError{ path, err }  => write!(f, "Failed to write to login file '{}': {}", path.display(), err),
        }
    }
}





/***** LIBRARY *****/
/// Defines the possible modes a user can identify themselves.
#[derive(Clone, Debug, Deserialize, EnumDebug, Eq, Hash, PartialEq, Serialize)]
pub enum Identity {
    /// The user identifies themselves using a plain username (no password or whatever).
    Username(String),
    /// The user identifies themselves using an SSL certificate which embeds their name.
    Certificate(PathBuf),
}



/// Defines an IdentityFile, which stores whatever we need to know about an identity in the client.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdentityFile {
    /// The address and port of the API service at the remote host.
    pub api_service : Address,
    /// The address and port of the driver service at the remote host.
    pub drv_service : Address,

    /// The identity with which the user makes themselves known.
    pub identity : Identity,
}

impl IdentityFile {
    /// Constructor for the IdentityFile that reads its contents from the given path.
    /// 
    /// # Arguments
    /// - `path`: The path to read the IdentityFile from.
    /// 
    /// # Returns
    /// A new IdentityFile instance, with its contents loaded from the targeted file.
    /// 
    /// # Errors
    /// This function may error if we failed to load the target file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, IdentityFileError> {
        let path: &Path = path.as_ref();

        // Attempt to open the file
        let mut handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err)   => {
                // Return a full error _or_ not found
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Err(IdentityFileError::FileNotFound { path: path.into() });
                } else {
                    return Err(IdentityFileError::FileOpenError{ path: path.into(), err });
                }
            },
        };

        // Read it to a string
        let mut contents: String = String::new();
        if let Err(err) = handle.read_to_string(&mut contents) { return Err(IdentityFileError::FileReadError { path: path.into(), err }); }

        // Parse it with serde, which is the result
        match serde_json::from_str(&contents) {
            Ok(file) => Ok(file),
            Err(err) => Err(IdentityFileError::FileParseError { path: path.into(), err }),
        }
    }

    /// Writes this IdentityFile to the given path.
    /// 
    /// # Arguments
    /// - `path`: The path to write the IdentityFile to.
    /// 
    /// # Errors
    /// This function errors if we failed to create or write the file, or if we failed to serialize ourselves.
    pub fn to_path(&self, path: impl AsRef<Path>) -> Result<(), IdentityFileError> {
        let path: &Path = path.as_ref();

        // Attempt to serialize ourselves
        let contents: String = match serde_json::to_string_pretty(self) {
            Ok(contents) => contents,
            Err(err)     => { return Err(IdentityFileError::SerializeError{ err }); },
        };

        // Create the target file
        let mut handle: File = match File::create(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(IdentityFileError::FileCreateError { path: path.into(), err }); },
        };

        // Write the contents to it, done is Cees
        match write!(handle, "{}", contents) {
            Ok(_)    => Ok(()),
            Err(err) => Err(IdentityFileError::FileWriteError { path: path.into(), err }),
        }
    }
}
