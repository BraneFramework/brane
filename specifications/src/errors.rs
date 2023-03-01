/* ERRORS.rs
 *   by Lut99
 *
 * Created:
 *   28 Jan 2022, 13:50:37
 * Last edited:
 *   28 Jan 2022, 15:24:46
 * Auto updated?
 *   Yes
 *
 * Description:
 *   Contains common error types that span over multiple packages and/or
 *   modules.
**/

use std::path::PathBuf;


/***** ERROR ENUMS *****/
/// Errors that relate to finding Brane directories
#[derive(Debug)]
pub enum SystemDirectoryError {
    /// Could not find the user local data folder
    UserLocalDataDirNotFound,
    /// Could not find the user config folder
    UserConfigDirNotFound,

    /// Could not find brane's folder in the data folder
    BraneLocalDataDirNotFound{ path: PathBuf },
    /// Could not find brane's folder in the config folder
    BraneConfigDirNotFound{ path: PathBuf },
}

impl std::fmt::Display for SystemDirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemDirectoryError::UserLocalDataDirNotFound => write!(f, "Could not find the user's local data directory for your OS (reported as {})", std::env::consts::OS),
            SystemDirectoryError::UserConfigDirNotFound    => write!(f, "Could not find the user's config directory for your OS (reported as {})", std::env::consts::OS),

            SystemDirectoryError::BraneLocalDataDirNotFound{ path } => write!(f, "Brane data directory '{}' not found", path.display()),
            SystemDirectoryError::BraneConfigDirNotFound{ path }    => write!(f, "Brane config directory '{}' not found", path.display()),
        }
    }
}

impl std::error::Error for SystemDirectoryError {}



/// Errors that relate to encoding or decoding output
#[derive(Debug)]
pub enum EncodeDecodeError {
    /// Could not decode the given string from Base64 binary data
    Base64DecodeError{ err: base64::DecodeError },

    /// Could not decode the given raw binary using UTF-8
    Utf8DecodeError{ err: std::string::FromUtf8Error },

    /// Could not decode the given input as JSON
    JsonDecodeError{ err: serde_json::Error },
}

impl std::fmt::Display for EncodeDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeDecodeError::Base64DecodeError{ err } => write!(f, "Could not decode string input as Base64: {err}"),

            EncodeDecodeError::Utf8DecodeError{ err } => write!(f, "Could not decode binary input as UTF-8: {err}"),

            EncodeDecodeError::JsonDecodeError{ err } => write!(f, "Could not decode string input as JSON: {err}"),
        }
    }
}

impl std::error::Error for EncodeDecodeError {}
