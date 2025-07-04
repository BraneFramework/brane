//  MERGE STRATEGY.rs
//    by Lut99
//
//  Created:
//    14 Nov 2024, 16:07:58
//  Last edited:
//    14 Nov 2024, 16:08:25
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the [`MergeStrategy`], which defines how the results of
//!   parallel statements are combined into one.
//

use serde::{Deserialize, Serialize};


/***** LIBRARY *****/
/// Defines merge strategies for the parallel statements.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
pub enum MergeStrategy {
    /// Take the value that arrived first. The statement will already return as soon as this statement is in, not the rest.
    First,
    /// Take the value that arrived first. The statement will still block until all values returned.
    FirstBlocking,
    /// Take the value that arrived last.
    Last,

    /// Add all the resulting values together. This means that they must all be numeric.
    Sum,
    /// Multiple all the resulting values together. This means that they must all be numeric.
    Product,

    /// Take the largest value. Use on booleans to get an 'OR'-effect (i.e., it returns true iff there is at least one true).
    Max,
    /// Take the smallest value. Use on booleans to get an 'AND'-effect (i.e., it returns false iff there is at least one false).
    Min,

    /// Returns all values as an Array.
    All,

    /// No merge strategy needed
    None,
}

impl From<&str> for MergeStrategy {
    #[inline]
    fn from(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "first" => Self::First,
            "first*" => Self::FirstBlocking,
            "last" => Self::Last,

            "+" | "sum" => Self::Sum,
            "*" | "product" => Self::Product,

            "max" => Self::Max,
            "min" => Self::Min,

            "all" => Self::All,

            _ => Self::None,
        }
    }
}
