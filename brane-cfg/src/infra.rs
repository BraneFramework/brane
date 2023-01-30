//  INFRA.rs
//    by Lut99
// 
//  Created:
//    04 Oct 2022, 11:04:33
//  Last edited:
//    26 Jan 2023, 09:56:13
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements a more up-to-date version of the infrastructure document.
// 

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use specifications::address::Address;

pub use crate::errors::InfraFileError as Error;


/***** AUXILLARY *****/
/// Defines a single Location in the InfraFile.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InfraLocation {
    /// Defines a more human-readable name for the location.
    pub name     : String,
    /// The address of the delegate to connect to.
    pub delegate : Address,
    /// The address of the local registry to query for locally available packages, datasets and more.
    pub registry : Address,
}





/***** LIBRARY *****/
/// Defines a "handle" to the document that contains the Brane instance layout.
/// 
/// It is recommended to only load when used, to allow system admins to update the file during runtime.
#[derive(Debug, Deserialize, Serialize)]
pub struct InfraFile {
    /// The map of locations (mapped by ID).
    locations : HashMap<String, InfraLocation>,
}

impl InfraFile {
    /// Constructor for the InfraFile.
    /// 
    /// # Arguments
    /// - `locations`: The map of location IDs to InfraLocations around which to initialize this InfraFile.
    /// 
    /// # Returns
    /// A new InfraFile instance.
    #[inline]
    pub fn new(locations: HashMap<String, InfraLocation>) -> Self {
        Self {
            locations,
        }
    }

    /// Reads the `infra.yml` file at the given path to an InfraFile.
    /// 
    /// # Arguments
    /// - `path`: The path from which to load this file.
    /// 
    /// # Returns
    /// A new InfraFile instance.
    /// 
    /// # Errors
    /// This function fails if we could either not read the file or the file was not valid YAML.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path: &Path = path.as_ref();

        // Open the file
        let handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(Error::FileOpenError { path: path.into(), err }); },  
        };

        // Run it through serde, done
        match serde_yaml::from_reader(handle) {
            Ok(locs) => Ok(locs),
            Err(err) => Err(Error::FileParseError { path: path.into(), err }),
        }
    }

    /// Writes the InfraFile to the given writer.
    /// 
    /// # Arguments
    /// - `writer`: The writer to write the InfraFile to.
    /// 
    /// # Returns
    /// Nothing, but does obviously populate the given writer with its own serialized contents.
    /// 
    /// # Errors
    /// This function errors if we failed to write or failed to serialize ourselves.
    pub fn to_writer(&self, writer: impl Write) -> Result<(), Error> {
        let mut writer = writer;

        // Serialize the config
        let config: String = match serde_yaml::to_string(self) {
            Ok(config) => config,
            Err(err)   => { return Err(Error::ConfigSerializeError{ err }); },
        };

        // Write it
        if let Err(err) = writer.write_all(config.as_bytes()) { return Err(Error::WriterWriteError{ err }); }

        // Done
        Ok(())
    }



    /// Returns the metadata for the location with the given name.
    /// 
    /// # Arguments
    /// - `name`: The name of the location to retrieve.
    /// 
    /// # Returns
    /// The InfraLocation of the location that was referenced by the name, or else `None` if it didn't exist.
    #[inline]
    pub fn get(&self, name: impl AsRef<str>) -> Option<&InfraLocation> {
        self.locations.get(name.as_ref())
    }



    /// Returns an iterator-by-reference over the internal map.
    #[inline]
    pub fn iter(&self) -> std::collections::hash_map::Iter<String, InfraLocation> { self.into_iter() }

    /// Returns a muteable iterator-by-reference over the internal map.
    #[inline]
    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<String, InfraLocation> { self.into_iter() }

}

impl IntoIterator for InfraFile {
    type Item     = (String, InfraLocation);
    type IntoIter = std::collections::hash_map::IntoIter<String, InfraLocation>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.locations.into_iter()
    }
}
impl<'a> IntoIterator for &'a InfraFile {
    type Item     = (&'a String, &'a InfraLocation);
    type IntoIter = std::collections::hash_map::Iter<'a, String, InfraLocation>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.locations.iter()
    }
}
impl<'a> IntoIterator for &'a mut InfraFile {
    type Item     = (&'a String, &'a mut InfraLocation);
    type IntoIter = std::collections::hash_map::IterMut<'a, String, InfraLocation>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.locations.iter_mut()
    }
}
