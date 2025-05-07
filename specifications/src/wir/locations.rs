//  LOCATIONS.rs
//    by Lut99
//
//  Created:
//    07 Sep 2022, 10:48:30
//  Last edited:
//    14 Nov 2024, 16:02:37
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines a few enums that help analysing location restrictions on a
//!   node.
//

use serde::{Deserialize, Serialize};


/***** LIBRARY *****/
/// Defines a single location to run.
pub type Location = String;



/// Contains location restrictions for a certain node.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Locations {
    /// All locations are allowed.
    All,
    /// If not all, then the following locations are allowed as a whitelist.
    Restricted(Vec<Location>),
}

impl Locations {
    /// Returns the restrictive list of locations if this Locations is, in fact, restrictive.
    ///
    /// # Returns
    /// A slice that to the whitelist of locations.
    ///
    /// # Panics
    /// This function panics if the Locations was not `Locations::Restricted`. Use `Locations::is_restrictive` to query beforehand.
    #[inline]
    pub fn restricted(&self) -> &[Location] {
        if let Self::Restricted(locs) = self {
            locs
        } else {
            panic!("Cannot unwrap Locations::{self:?} as restricted");
        }
    }

    /// Returns whether this Locations is an open-to-all kinda thing.
    #[inline]
    pub fn is_all(&self) -> bool { matches!(self, Self::All) }

    /// Returns whether this Locations is a restrictive list.
    #[inline]
    pub fn is_restrictive(&self) -> bool { matches!(self, Self::Restricted(_)) }
}
