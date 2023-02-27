//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    04 Oct 2022, 11:09:56
//  Last edited:
//    27 Feb 2023, 15:19:37
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines errors that occur in the `brane-cfg` crate.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;


/***** LIBRARY *****/
/// Errors that relate to certificate loading and such.
#[derive(Debug)]
pub enum CertsError {
    /// A given certificate file could not be parsed.
    ClientCertParseError{ err: x509_parser::nom::Err<x509_parser::error::X509Error> },
    /// A given certificate did not have the `CN`-field specified.
    ClientCertNoCN{ subject: String },

    /// Failed to open a given file.
    FileOpenError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Failed to read a given file.
    FileReadError{ what: &'static str, path: PathBuf, err: std::io::Error },
    /// Encountered unknown item in the given file.
    UnknownItemError{ what: &'static str, path: PathBuf },

    /// Failed to parse the certificate file.
    CertFileParseError{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the key file.
    KeyFileParseError{ path: PathBuf, err: std::io::Error },

    /// The given certificate file was empty.
    EmptyCertFile{ path: PathBuf },
    /// The given keyfile was empty.
    EmptyKeyFile{ path: PathBuf },
}

impl Display for CertsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CertsError::*;
        match self {
            ClientCertParseError{ err } => write!(f, "Failed to parse given client certificate file: {}", err),
            ClientCertNoCN{ subject }   => write!(f, "Certificate subject field '{}' does not specify a CN", subject),

            FileOpenError{ what, path, err } => write!(f, "Failed to open {} file '{}': {}", what, path.display(), err),
            FileReadError{ what, path, err } => write!(f, "Failed to read {} file '{}': {}", what, path.display(), err),
            UnknownItemError{ what, path }   => write!(f, "Encountered non-certificate, non-key item in {} file '{}'", what, path.display()),

            CertFileParseError{ path, err } => write!(f, "Failed to parse certificates in '{}': {}", path.display(), err),
            KeyFileParseError{ path, err }  => write!(f, "Failed to parse keys in '{}': {}", path.display(), err),

            EmptyCertFile{ path }           => write!(f, "No certificates found in file '{}'", path.display()),
            EmptyKeyFile{ path }            => write!(f, "No keys found in file '{}'", path.display()),
        }
    }
}

impl Error for CertsError {}



// Errors that relate to the InfraFile struct.
#[derive(Debug)]
pub enum InfraFileError {
    /// Failed to open the given file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read/parse the given file as YAML.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to write to the given writer.
    WriterWriteError{ err: std::io::Error },
    /// Failed to serialze the NodeConfig.
    ConfigSerializeError{ err: serde_yaml::Error },
}
impl Display for InfraFileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use InfraFileError::*;
        match self {
            FileOpenError{ path, err }  => write!(f, "Failed to open infrastructure file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse infrastructure file '{}' as YAML: {}", path.display(), err),

            WriterWriteError{ err }     => write!(f, "Failed to write to given writer: {}", err),
            ConfigSerializeError{ err } => write!(f, "Failed to serialize infrastructure file to YAML: {}", err),
        }
    }
}
impl Error for InfraFileError {}



/// Errors that relate to the CredsFile struct.
#[derive(Debug)]
pub enum CredsFileError {
    /// Failed to open the given file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read/parse the given file as YAML.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to write to the given writer.
    WriterWriteError{ err: std::io::Error },
    /// Failed to serialze the NodeConfig.
    ConfigSerializeError{ err: serde_yaml::Error },
}
impl Display for CredsFileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CredsFileError::*;
        match self {
            FileOpenError{ path, err }  => write!(f, "Failed to open credentials file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse credentials file '{}' as YAML: {}", path.display(), err),

            WriterWriteError{ err }     => write!(f, "Failed to write to given writer: {}", err),
            ConfigSerializeError{ err } => write!(f, "Failed to serialize credentials file to YAML: {}", err),
        }
    }
}
impl Error for CredsFileError {}



/// Errors that relate to a NodeConfig.
#[derive(Debug)]
pub enum NodeConfigError {
    /// The given NodeKind was unknown to us.
    UnknownNodeKind{ raw: String },

    /// Failed to open the given config path.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read from the given config path.
    FileReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the given file.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to open the given config path.
    FileCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the given config path.
    FileWriteError{ path: PathBuf, err: std::io::Error },
    /// Failed to serialze the NodeConfig.
    ConfigSerializeError{ err: serde_yaml::Error },

    /// Failed to write to the given writer.
    WriterWriteError{ err: std::io::Error },
}
impl Display for NodeConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use NodeConfigError::*;
        match self {
            UnknownNodeKind{ raw } => write!(f, "Unknown node kind '{}'", raw),

            FileOpenError{ path, err }  => write!(f, "Failed to open the node config file '{}': {}", path.display(), err),
            FileReadError{ path, err }  => write!(f, "Failed to read the ndoe config file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse node config file '{}' as YAML: {}", path.display(), err),

            FileCreateError{ path, err } => write!(f, "Failed to create the node config file '{}': {}", path.display(), err),
            FileWriteError{ path, err }  => write!(f, "Failed to write to the ndoe config file '{}': {}", path.display(), err),
            ConfigSerializeError{ err }  => write!(f, "Failed to serialize node config to YAML: {}", err),

            WriterWriteError{ err } => write!(f, "Failed to write to given writer: {}", err),
        }
    }
}
impl Error for NodeConfigError {}

/// Defines errors that may occur when parsing proxy protocol strings.
#[derive(Debug)]
pub enum ProxyProtocolParseError {
    /// The protocol (version) is unknown to us.
    UnknownProtocol{ raw: String },
}
impl Display for ProxyProtocolParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ProxyProtocolParseError::*;
        match self {
            UnknownProtocol{ raw } => write!(f, "Unknown proxy protocol '{}'", raw),
        }
    }
}
impl Error for ProxyProtocolParseError {}



/// Errors that relate to the PolicyFile.
#[derive(Debug)]
pub enum PolicyFileError {
    /// Failed to open & read the file
    FileReadError{ path: PathBuf, err: std::io::Error },
    /// Failed to parse the file as YAML of our specification.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to write to the given writer.
    WriterWriteError{ err: std::io::Error },
    /// Failed to serialze the NodeConfig.
    ConfigSerializeError{ err: serde_yaml::Error },
}
impl Display for PolicyFileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PolicyFileError::*;
        match self {
            FileReadError{ path, err }  => write!(f, "Failed to read file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse file '{}' as YAML: {}", path.display(), err),

            WriterWriteError{ err }     => write!(f, "Failed to write to given writer: {}", err),
            ConfigSerializeError{ err } => write!(f, "Failed to serialize infrastructure file to YAML: {}", err),
        }
    }
}
impl Error for PolicyFileError {}
