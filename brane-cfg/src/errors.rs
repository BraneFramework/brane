//  ERRORS.rs
//    by Lut99
//
//  Created:
//    04 Oct 2022, 11:09:56
//  Last edited:
//    07 Jun 2023, 16:27:48
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines errors that occur in the `brane-cfg` crate.
//

use std::fmt::Debug;
use std::path::PathBuf;


/***** LIBRARY *****/
/// Errors that relate to certificate loading and such.
#[derive(Debug, thiserror::Error)]
pub enum CertsError {
    /// A given certificate file could not be parsed.
    #[error("Failed to parse given client certificate file")]
    ClientCertParseError { source: x509_parser::nom::Err<x509_parser::error::X509Error> },
    /// A given certificate did not have the `CN`-field specified.
    #[error("Certificate subject field '{subject}' does not specify a CN")]
    ClientCertNoCN { subject: String },

    /// Failed to open a given file.
    #[error("Failed to open {} file '{}'", what, path.display())]
    FileOpenError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Failed to read a given file.
    #[error("Failed to read {} file '{}'", what, path.display())]
    FileReadError { what: &'static str, path: PathBuf, source: std::io::Error },
    /// Encountered unknown item in the given file.
    #[error("Encountered non-certificate, non-key item in {} file '{}'", what, path.display())]
    UnknownItemError { what: &'static str, path: PathBuf },

    /// Failed to parse the certificate file.
    #[error("Failed to parse certificates in '{}'", path.display())]
    CertFileParseError { path: PathBuf, source: std::io::Error },
    /// Failed to parse the key file.
    #[error("Failed to parse keys in '{}'", path.display())]
    KeyFileParseError { path: PathBuf, source: std::io::Error },

    /// The given certificate file was empty.
    #[error("No certificates found in file '{}'", path.display())]
    EmptyCertFile { path: PathBuf },
    /// The given keyfile was empty.
    #[error("No keys found in file '{}'", path.display())]
    EmptyKeyFile { path: PathBuf },
}


/// Errors that relate to a NodeConfig.
#[derive(Debug, thiserror::Error)]
pub enum NodeConfigError {
    /// Failed to open the given config path.
    #[error("Failed to open the node config file '{}'", path.display())]
    FileOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to read from the given config path.
    #[error("Failed to read the ndoe config file '{}'", path.display())]
    FileReadError { path: PathBuf, source: std::io::Error },
    /// Failed to parse the given file.
    #[error("Failed to parse node config file '{}' as YAML", path.display())]
    FileParseError { path: PathBuf, source: serde_yaml::Error },

    /// Failed to open the given config path.
    #[error("Failed to create the node config file '{}'", path.display())]
    FileCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to write to the given config path.
    #[error("Failed to write to the ndoe config file '{}'", path.display())]
    FileWriteError { path: PathBuf, source: std::io::Error },
    /// Failed to serialze the NodeConfig.
    #[error("Failed to serialize node config to YAML")]
    ConfigSerializeError { source: serde_yaml::Error },

    /// Failed to write to the given writer.
    #[error("Failed to write to given writer")]
    WriterWriteError { source: std::io::Error },
}

/// Defines errors that may occur when parsing proxy protocol strings.
#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolParseError {
    /// The protocol (version) is unknown to us.
    #[error("Unknown proxy protocol '{raw}'")]
    UnknownProtocol { raw: String },
}

/// Defines errors that may occur when parsing node kind strings.
#[derive(Debug, thiserror::Error)]
pub enum NodeKindParseError {
    /// The given NodeKind was unknown to us.
    #[error("Unknown node kind '{raw}'")]
    UnknownNodeKind { raw: String },
}
