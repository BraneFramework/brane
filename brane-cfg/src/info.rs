//  INFO.rs
//    by Lut99
//
//  Created:
//    28 Feb 2023, 10:07:36
//  Last edited:
//    14 Jun 2024, 15:12:07
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the general [`Info`]-trait, which is used to abstract over the
//!   various types of disk-stored configuration files.
//

use std::error::Error;
use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use brane_shr::errors::SerdeError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::fs::File as TFile;
use tokio::io::AsyncReadExt as _;


/***** ERRORS *****/
/// Defines general errors for configs.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum InfoError<E: std::error::Error + Send + Sync + 'static> {
    /// Failed to create the output file.
    #[error("Failed to create output file '{}'", path.display())]
    OutputCreateError { path: PathBuf, source: std::io::Error },
    /// Failed to open the input file.
    #[error("Failed to open input file '{}'", path.display())]
    InputOpenError { path: PathBuf, source: std::io::Error },
    /// Failed to read the input file.
    #[error("Failed to read input file '{}'", path.display())]
    InputReadError { path: PathBuf, source: std::io::Error },

    /// Failed to serialize the config to a string.
    #[error("Failed to serialize to string")]
    StringSerializeError { source: E },
    /// Failed to serialize the config to a given writer.
    #[error("Failed to serialize to a writer")]
    WriterSerializeError { source: E },
    /// Failed to serialize the config to a given file.
    #[error("Failed to serialize to output file '{}'", path.display())]
    FileSerializeError { path: PathBuf, source: E },

    #[error("Failed to deserialize from string")]
    #[diagnostic(transparent)]
    StringDeserializeError(#[from] SerdeError<serde_yaml::Error>),
    /// Failed to deserialize a reader to the config.
    #[error("Failed to deserialize from a reader")]
    ReaderDeserializeError { source: E },
    /// Failed to deserialize a file to the config.
    #[error("Failed to deserialize from input file '{}'", path.display())]
    FileDeserializeError { path: PathBuf, source: E },
}





/***** LIBRARY *****/
/// Defines a serializable struct that we typically use for structs that are directly read and written to disk.
#[async_trait]
pub trait Info: Clone + Debug {
    /// The types of errors that may be thrown by the serialization function(s).
    type Error: Error + Send + Sync;


    // Child-provided
    /// Serializes this Config to a string.
    ///
    /// # Arguments
    /// - `pretty`: If true, then it will be serialized using a pretty version of the backend (if available).
    ///
    /// # Returns
    /// A new String that represents this config but serialized.
    ///
    /// # Errors
    /// This function may error if the serialization failed.
    fn to_string(&self, pretty: bool) -> Result<String, InfoError<Self::Error>>;
    /// Serializes this Config to a reader.
    ///
    /// # Arguments
    /// - `writer`: The `Write`r to write the serialized representation to.
    /// - `pretty`: If true, then it will be serialized using a pretty version of the backend (if available).
    ///
    /// # Errors
    /// This function may error if the serialization failed or if we failed to write to the given writer.
    fn to_writer(&self, writer: impl Write, pretty: bool) -> Result<(), InfoError<Self::Error>>;

    /// Deserializes the given string to an instance of ourselves.
    ///
    /// # Arguments
    /// - `raw`: The raw string to deserialize.
    ///
    /// # Returns
    /// A new instance of `Self` with its contents read from the given raw string.
    ///
    /// # Errors
    /// This function may fail if the input string was invalid for this object.
    fn from_string(raw: impl AsRef<str>) -> Result<Self, InfoError<Self::Error>>;
    /// Deserializes the contents of the given reader to an instance of ourselves.
    ///
    /// # Arguments
    /// - `reader`: The `Read`er who's contents to deserialize.
    ///
    /// # Returns
    /// A new instance of `Self` with its contents read from the given reader.
    ///
    /// # Errors
    /// This function may fail if we failed to read from the reader or if its contents were invalid for this object.
    fn from_reader(reader: impl Read) -> Result<Self, InfoError<Self::Error>>;


    // Globally deduced
    /// Serializes this Config to a file at the given path.
    ///
    /// This will always choose a pretty representation of the serialization (if applicable).
    ///
    /// # Arguments
    /// - `path`: The path where to write the file to.
    ///
    /// # Errors
    /// This function may error if the serialization failed or if we failed to create and/or write to the file.
    fn to_path(&self, path: impl AsRef<Path>) -> Result<(), InfoError<Self::Error>> {
        let path: &Path = path.as_ref();

        // Attempt to create the new file
        let handle: File = match File::create(path) {
            Ok(handle) => handle,
            Err(source) => {
                return Err(InfoError::OutputCreateError { path: path.into(), source });
            },
        };

        // Write it using the child function, wrapping the error that may occur
        match self.to_writer(handle, true) {
            Ok(_) => Ok(()),
            Err(InfoError::WriterSerializeError { source }) => Err(InfoError::FileSerializeError { path: path.into(), source }),
            Err(err) => Err(err),
        }
    }

    /// Deserializes this Config from the file at the given path.
    ///
    /// # Arguments
    /// - `path`: The path where to read the file from.
    ///
    /// # Errors
    /// This function may fail if we failed to open/read from the file or if its contents were invalid for this object.
    fn from_path(path: impl AsRef<Path>) -> Result<Self, InfoError<Self::Error>> {
        let path: &Path = path.as_ref();

        // Attempt to open the given file
        let handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(source) => {
                return Err(InfoError::InputOpenError { path: path.into(), source });
            },
        };

        // Write it using the child function, wrapping the error that may occur
        match Self::from_reader(handle) {
            Ok(config) => Ok(config),
            Err(InfoError::ReaderDeserializeError { source }) => Err(InfoError::FileDeserializeError { path: path.into(), source }),
            Err(err) => Err(err),
        }
    }
    /// Deserializes this Config from the file at the given path, with the reading part done asynchronously.
    ///
    /// Note that the parsing path cannot be done asynchronously. Also, note that, because serde does not support asynchronous deserialization, we have to read the entire file in one go.
    ///
    /// # Arguments
    /// - `path`: The path where to read the file from.
    ///
    /// # Errors
    /// This function may fail if we failed to open/read from the file or if its contents were invalid for this object.
    async fn from_path_async(path: impl Send + AsRef<Path>) -> Result<Self, InfoError<Self::Error>> {
        let path: &Path = path.as_ref();

        // Read the file to a string
        let raw: String = {
            // Attempt to open the given file
            let mut handle: TFile = match TFile::open(path).await {
                Ok(handle) => handle,
                Err(source) => {
                    return Err(InfoError::InputOpenError { path: path.into(), source });
                },
            };

            // Read everything to a string
            let mut raw: String = String::new();
            if let Err(source) = handle.read_to_string(&mut raw).await {
                return Err(InfoError::InputReadError { path: path.into(), source });
            }
            raw
        };

        // Write it using the child function, wrapping the error that may occur
        match Self::from_string(raw) {
            Ok(config) => Ok(config),
            Err(InfoError::ReaderDeserializeError { source }) => Err(InfoError::FileDeserializeError { path: path.into(), source }),
            Err(err) => Err(err),
        }
    }
}



/// A marker trait that will let the compiler implement `Config` for this object using the `serde_yaml` backend.
pub trait YamlInfo<'de>: Clone + Debug + Deserialize<'de> + Serialize {}
impl<T: DeserializeOwned + Serialize + for<'de> YamlInfo<'de>> Info for T {
    type Error = serde_yaml::Error;

    fn to_string(&self, _pretty: bool) -> Result<String, InfoError<Self::Error>> {
        match serde_yaml::to_string(self) {
            Ok(raw) => Ok(raw),
            Err(err) => Err(InfoError::StringSerializeError { source: err }),
        }
    }

    fn to_writer(&self, writer: impl Write, _pretty: bool) -> Result<(), InfoError<Self::Error>> {
        match serde_yaml::to_writer(writer, self) {
            Ok(raw) => Ok(raw),
            Err(err) => Err(InfoError::ReaderDeserializeError { source: err }),
        }
    }

    fn from_string(raw: impl AsRef<str>) -> Result<Self, InfoError<Self::Error>> {
        let raw = raw.as_ref();
        match serde_yaml::from_str(raw) {
            Ok(config) => Ok(config),
            Err(err) => {
                // let loc = err.location().unwrap();
                // let offset = SourceOffset::from_location(raw, loc.line(), loc.column());
                //
                // Err(InfoError::StringDeserializeError { source: err, offset, source_code: raw.to_owned() })
                Err(<SerdeError<serde_yaml::Error>>::from_yaml(raw.to_owned(), err).into())
            },
        }
    }

    fn from_reader(reader: impl Read) -> Result<Self, InfoError<Self::Error>> {
        match serde_yaml::from_reader(reader) {
            Ok(config) => Ok(config),
            Err(err) => Err(InfoError::ReaderDeserializeError { source: err }),
        }
    }
}

/// A type alias for the ConfigError for the YamlConfig.
pub type YamlError = InfoError<serde_yaml::Error>;
