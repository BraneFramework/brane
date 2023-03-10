//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    04 Oct 2022, 11:09:56
//  Last edited:
//    10 Mar 2023, 16:07:32
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines errors that occur in the `brane-cfg` crate.
// 

use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
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
            ClientCertParseError{ err } => write!(f, "Failed to parse given client certificate file: {err}"),
            ClientCertNoCN{ subject }   => write!(f, "Certificate subject field '{subject}' does not specify a CN"),

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



/// Errors that relate to a NodeConfig.
#[derive(Debug)]
pub enum NodeConfigError {
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
            FileOpenError{ path, err }  => write!(f, "Failed to open the node config file '{}': {}", path.display(), err),
            FileReadError{ path, err }  => write!(f, "Failed to read the ndoe config file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse node config file '{}' as YAML: {}", path.display(), err),

            FileCreateError{ path, err } => write!(f, "Failed to create the node config file '{}': {}", path.display(), err),
            FileWriteError{ path, err }  => write!(f, "Failed to write to the ndoe config file '{}': {}", path.display(), err),
            ConfigSerializeError{ err }  => write!(f, "Failed to serialize node config to YAML: {err}"),

            WriterWriteError{ err } => write!(f, "Failed to write to given writer: {err}"),
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
            UnknownProtocol{ raw } => write!(f, "Unknown proxy protocol '{raw}'"),
        }
    }
}
impl Error for ProxyProtocolParseError {}

/// Defines errors that may occur when parsing node kind strings.
#[derive(Debug)]
pub enum NodeKindParseError {
    /// The given NodeKind was unknown to us.
    UnknownNodeKind{ raw: String },
}
impl Display for NodeKindParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use NodeKindParseError::*;
        match self {
            UnknownNodeKind{ raw } => write!(f, "Unknown node kind '{raw}'"),
        }
    }
}
impl Error for NodeKindParseError {}



/// Defines general errors for configs.
#[derive(Debug)]
pub enum ConfigError<E: Debug> {
    /// Failed to create the output file.
    OutputCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to open the input file.
    InputOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read the input file.
    InputReadError{ path: PathBuf, err: std::io::Error },

    /// Failed to serialize the config to a string.
    StringSerializeError{ err: E },
    /// Failed to serialize the config to a given writer.
    WriterSerializeError{ err: E },
    /// Failed to serialize the config to a given file.
    FileSerializeError{ path: PathBuf, err: E },

    /// Failed to deserialize a string to the config.
    StringDeserializeError{ err: E },
    /// Failed to deserialize a reader to the config.
    ReaderDeserializeError{ err: E },
    /// Failed to deserialize a file to the config.
    FileDeserializeError{ path: PathBuf, err: E },
}
impl<E: Error> Display for ConfigError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ConfigError::*;
        match self {
            OutputCreateError{ path, err } => write!(f, "Failed to create output file '{}': {}", path.display(), err),
            InputOpenError{ path, err }    => write!(f, "Failed to open input file '{}': {}", path.display(), err),
            InputReadError{ path, err }    => write!(f, "Failed to read input file '{}': {}", path.display(), err),

            StringSerializeError{ err }     => write!(f, "Failed to serialize to string: {err}"),
            WriterSerializeError{ err }     => write!(f, "Failed to serialize to a writer: {err}"),
            FileSerializeError{ path, err } => write!(f, "Failed to serialize to output file '{}': {}", path.display(), err),

            StringDeserializeError{ err }     => write!(f, "Failed to deserialize from string: {err}"),
            ReaderDeserializeError{ err }     => write!(f, "Failed to deserialize from a reader: {err}"),
            FileDeserializeError{ path, err } => write!(f, "Failed to deserialize from input file '{}': {}", path.display(), err),
        }
    }
}
