//  INFRA.rs
//    by Lut99
//
//  Created:
//    04 Oct 2022, 11:04:33
//  Last edited:
//    31 Jan 2024, 15:53:29
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a more up-to-date version of the infrastructure document.
//

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use specifications::address::Address;

pub use crate::info::YamlError as Error;
use crate::info::YamlInfo;


/***** AUXILLARY *****/
/// Defines a single Location in the InfraFile.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InfraLocation {
    /// Defines a more human-readable name for the location.
    pub name:     String,
    /// The address of the delegate to connect to.
    pub delegate: Address,
    /// The address of the local registry to query for locally available packages, datasets and more.
    pub registry: Address,
}





/***** LIBRARY *****/
/// Defines a "handle" to the document that contains the Brane instance layout.
///
/// It is recommended to only load when used, to allow system admins to update the file during runtime.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InfraFile {
    /// The map of locations (mapped by ID).
    locations: HashMap<String, InfraLocation>,
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
    pub fn new(locations: HashMap<String, InfraLocation>) -> Self { Self { locations } }

    /// Returns the metadata for the location with the given name.
    ///
    /// # Arguments
    /// - `name`: The name of the location to retrieve.
    ///
    /// # Returns
    /// The InfraLocation of the location that was referenced by the name, or else `None` if it didn't exist.
    #[inline]
    pub fn get(&self, name: impl AsRef<str>) -> Option<&InfraLocation> { self.locations.get(name.as_ref()) }

    /// Returns an iterator-by-reference over the internal map.
    #[inline]
    pub fn iter(&self) -> std::collections::hash_map::Iter<String, InfraLocation> { self.into_iter() }

    /// Returns a muteable iterator-by-reference over the internal map.
    #[inline]
    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<String, InfraLocation> { self.into_iter() }

    /// Returns the number of locations in this file.
    #[inline]
    pub fn len(&self) -> usize { self.locations.len() }

    #[inline]
    pub fn is_empty(&self) -> bool { self.locations.len() == 0 }
}
impl YamlInfo<'_> for InfraFile {}

impl IntoIterator for InfraFile {
    type IntoIter = std::collections::hash_map::IntoIter<String, InfraLocation>;
    type Item = (String, InfraLocation);

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.locations.into_iter() }
}
impl<'a> IntoIterator for &'a InfraFile {
    type IntoIter = std::collections::hash_map::Iter<'a, String, InfraLocation>;
    type Item = (&'a String, &'a InfraLocation);

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.locations.iter() }
}
impl<'a> IntoIterator for &'a mut InfraFile {
    type IntoIter = std::collections::hash_map::IterMut<'a, String, InfraLocation>;
    type Item = (&'a String, &'a mut InfraLocation);

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.locations.iter_mut() }
}
