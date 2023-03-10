//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    26 Sep 2022, 15:13:34
//  Last edited:
//    10 Mar 2023, 15:52:21
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the errors that may occur in the `brane-reg` crate.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::net::SocketAddr;
use std::path::PathBuf;


/***** LIBRARY *****/
/// Defines Store-related errors.
#[derive(Debug)]
pub enum StoreError {
    /// Failed to parse from the given reader.
    ReaderParseError{ err: serde_yaml::Error },

    /// Failed to open the store file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the store file.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to read the given directory.
    DirReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to read an entry in the given directory.
    DirReadEntryError{ path: PathBuf, i: usize, err: std::io::Error },
    /// Failed to read the AssetInfo file.
    AssetInfoReadError{ path: PathBuf, err: specifications::data::AssetInfoError },
}

impl Display for StoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use StoreError::*;
        match self {
            ReaderParseError{ err } => write!(f, "Failed to parse the given store reader as YAML: {err}"),

            FileOpenError{ path, err }  => write!(f, "Failed to open store file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse store file '{}' as YAML: {}", path.display(), err),

            DirReadError{ path, err }         => write!(f, "Failed to read directory '{}': {}", path.display(), err),
            DirReadEntryError{ path, i, err } => write!(f, "Failed to read entry {} in directory '{}': {}", i, path.display(), err),
            AssetInfoReadError{ path, err }   => write!(f, "Failed to load asset info file '{}': {}", path.display(), err),
        }
    }
}

impl Error for StoreError {}



/// Errors that relate to the customized serving process of warp.
#[derive(Debug)]
pub enum ServerError {
    /// Failed to create a new TcpListener and bind it to the given address.
    ServerBindError{ address: SocketAddr, err: std::io::Error },
    /// Failed to load the keypair.
    KeypairLoadError{ err: brane_cfg::certs::Error },
    /// Failed to load the certificate root store.
    StoreLoadError{ err: brane_cfg::certs::Error },
    /// Failed to create a new ServerConfig for the TLS setup.
    ServerConfigError{ err: rustls::Error },
}

impl Display for ServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ServerError::*;
        match self {
            ServerBindError{ address, err } => write!(f, "Failed to bind new TCP server to '{address}': {err}"),
            KeypairLoadError{ err }         => write!(f, "Failed to load keypair: {err}"),
            StoreLoadError{ err }           => write!(f, "Failed to load root store: {err}"),
            ServerConfigError{ err }        => write!(f, "Failed to create new TLS server configuration: {err}"),
        }
    }
}

impl Error for ServerError {}



/// Errors that relate to the `/data` path (and nested).
#[derive(Debug)]
pub enum DataError {
    /// Failed to serialize the contents of the store file (i.e., all known datasets)
    StoreSerializeError{ err: serde_json::Error },
    /// Failed to serialize the contents of a single dataset.
    AssetSerializeError{ name: String, err: serde_json::Error },

    /// Failed to create a temporary directory.
    TempDirCreateError{ err: std::io::Error },
    /// Failed to archive the given dataset.
    DataArchiveError{ err: brane_shr::fs::Error },
    /// Failed to re-open the tar file after compressing.
    TarOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read from the tar file.
    TarReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to send chunk of bytes on the body.
    TarSendError{ err: warp::hyper::Error },
    /// The given file was not a file, nor a directory.
    UnknownFileTypeError{ path: PathBuf },
    /// The given data path does not point to a data set, curiously enough.
    MissingData{ name: String, path: PathBuf },
    /// The given result does not point to a data set, curiously enough.
    MissingResult{ name: String, path: PathBuf },
}

impl Display for DataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DataError::*;
        match self {
            StoreSerializeError{ err }       => write!(f, "Failed to serialize known datasets: {err}"),
            AssetSerializeError{ name, err } => write!(f, "Failed to serialize dataset metadata for dataset '{name}': {err}"),

            TempDirCreateError{ err }              => write!(f, "Failed to create a temporary directory: {err}"),
            DataArchiveError{ err }                => write!(f, "Failed to archive data: {err}"),
            TarOpenError{ path, err }              => write!(f, "Failed to re-open tarball file '{}': {}", path.display(), err),
            TarReadError{ path, err }              => write!(f, "Failed to read from tarball file '{}': {}", path.display(), err),
            TarSendError{ err }                    => write!(f, "Failed to send chunk of tarball file as body: {err}"),
            UnknownFileTypeError{ path }           => write!(f, "Dataset file '{}' is neither a file, nor a directory; don't know what to do with it", path.display()),
            MissingData{ name, path }              => write!(f, "The data of dataset '{}' should be at '{}', but doesn't exist", name, path.display()),
            MissingResult{ name, path }            => write!(f, "The data of intermediate result '{}' should be at '{}', but doesn't exist", name, path.display()),
        }
    }
}

impl Error for DataError {}

impl warp::reject::Reject for DataError {}



/// Errors that relate to checker authorization.
#[derive(Debug)]
pub enum AuthorizeError {
    /// The client did not provide us with a certificate.
    ClientNoCert,

    /// Failed to load the policy file.
    PolicyFileError{ err: brane_cfg::policies::Error },
    /// No policy matched this user/data pair.
    NoUserPolicy{ user: String, data: String },
}

impl Display for AuthorizeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AuthorizeError::*;
        match self {
            ClientNoCert => write!(f, "No certificate provided"),

            PolicyFileError{ err }     => write!(f, "Failed to load policy file: {err}"),
            NoUserPolicy{ user, data } => write!(f, "No matching policy rule found for user '{user}' / data '{data}' (did you forget a final AllowAll/DenyAll?)"),
        }
    }
}

impl Error for AuthorizeError {}
