//  SPEC.rs
//    by Lut99
// 
//  Created:
//    28 Feb 2023, 10:07:36
//  Last edited:
//    28 Feb 2023, 18:21:46
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines (public) interfaces and structs that serve the interfaces
//!   and structs in `brane-cfg`.
// 

use std::error::Error;
use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

use crate::errors::ConfigError;


/***** LIBRARY *****/
/// Defines a serializable struct that we typically use as configuration for a service.
pub trait Config: Clone + Debug {
    /// The types of errors that may be thrown by the serialization function(s).
    type Error : Error;


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
    fn to_string(&self, pretty: bool) -> Result<String, ConfigError<Self::Error>>;
    /// Serializes this Config to a reader.
    /// 
    /// # Arguments
    /// - `writer`: The `Write`r to write the serialized representation to.
    /// - `pretty`: If true, then it will be serialized using a pretty version of the backend (if available).
    /// 
    /// # Errors
    /// This function may error if the serialization failed or if we failed to write to the given writer.
    fn to_writer(&self, writer: impl Write, pretty: bool) -> Result<(), ConfigError<Self::Error>>;

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
    fn from_string(raw: impl AsRef<str>) -> Result<Self, ConfigError<Self::Error>>;
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
    fn from_reader(reader: impl Read) -> Result<Self, ConfigError<Self::Error>>;


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
    fn to_path(&self, path: impl AsRef<Path>) -> Result<(), ConfigError<Self::Error>> {
        let path: &Path = path.as_ref();

        // Attempt to create the new file
        let handle: File = match File::create(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(ConfigError::OutputCreateError { path: path.into(), err }); },
        };

        // Write it using the child function, wrapping the error that may occur
        match self.to_writer(handle, true) {
            Ok(_)                                         => Ok(()),
            Err(ConfigError::WriterSerializeError{ err }) => Err(ConfigError::FileSerializeError { path: path.into(), err }),
            Err(err)                                      => Err(err),
        }
    }

    /// Deserializes this Config from the file at the given path.
    /// 
    /// # Arguments
    /// - `path`: The path where to read the file from.
    /// 
    /// # Errors
    /// This function may fail if we failed to open/read from the file or if its contents were invalid for this object.
    fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError<Self::Error>> {
        let path: &Path = path.as_ref();

        // Attempt to open the given file
        let handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(ConfigError::InputOpenError { path: path.into(), err }); },
        };

        // Write it using the child function, wrapping the error that may occur
        match Self::from_reader(handle) {
            Ok(config)                                      => Ok(config),
            Err(ConfigError::ReaderDeserializeError{ err }) => Err(ConfigError::FileDeserializeError { path: path.into(), err }),
            Err(err)                                        => Err(err),
        }
    }
}



/// A marker trait that will let the compiler implement `Config` for this object using the `serde_yaml` backend.
pub trait YamlConfig<'de>: Clone + Debug + Deserialize<'de> + Serialize {}
impl<T: DeserializeOwned + Serialize + for<'de> YamlConfig<'de>> Config for T {
    type Error = serde_yaml::Error;


    fn to_string(&self, _pretty: bool) -> Result<String, ConfigError<Self::Error>> {
        match serde_yaml::to_string(self) {
            Ok(raw)  => Ok(raw),
            Err(err) => Err(ConfigError::StringSerializeError { err }),
        }
    }
    fn to_writer(&self, writer: impl Write, _pretty: bool) -> Result<(), ConfigError<Self::Error>> {
        match serde_yaml::to_writer(writer, self) {
            Ok(raw)  => Ok(raw),
            Err(err) => Err(ConfigError::WriterSerializeError { err }),
        }
    }

    fn from_string(raw: impl AsRef<str>) -> Result<Self, ConfigError<Self::Error>> {
        match serde_yaml::from_str(raw.as_ref()) {
            Ok(config) => Ok(config),
            Err(err)   => Err(ConfigError::WriterSerializeError { err }),
        }
    }
    fn from_reader(reader: impl Read) -> Result<Self, ConfigError<Self::Error>> {
        match serde_yaml::from_reader(reader) {
            Ok(config) => Ok(config),
            Err(err)   => Err(ConfigError::WriterSerializeError { err }),
        }
    }
}

/// A type alias for the ConfigError for the YamlConfig.
pub type YamlError = ConfigError<serde_yaml::Error>;
