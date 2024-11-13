//  REGISTERING.rs
//    by Lut99
//
//  Created:
//    15 Jan 2024, 14:32:30
//  Last edited:
//    07 Feb 2024, 13:49:33
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines networks structs for communicating with the (local)
//!   registry.
//

use serde::{Deserialize, Serialize};
use serde_json::Value;


/***** LIBRARY *****/
/// Defines the input in the body of a request to download an asset.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DownloadAssetRequest {
    /// The use-case for which we're checking (determines which API registry to use).
    pub use_case: String,

    /// The workflow that we're checking.
    ///
    /// Note that we leave it open, as this would require importing `brane-ast` (and that would be a cycling dependency).
    pub workflow: Value,

    /// The task within the workflow that acts as the context in which the download occurs. If omitted, then it should be interpreted as the data being accessed to download the final result of the workflow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<(Option<u64>, u64)>,
}



/// Defines the input for a request to check if a data transfer is allowed to happen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckTransferRequest {
    /// The use-case for which we're checking (determines which API registry to use).
    pub use_case: String,
    /// The workflow that we're checking.
    ///
    /// Note that we leave it open, as this would require importing `brane-ast` (and that would be a cycling dependency).
    pub workflow: Value,
    /// The task within the workflow that acts as the context in which the download occurs. If omitted, then it should be interpreted as the data being accessed to download the final result of the workflow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task:     Option<(Option<u64>, u64)>,
}

/// Defines the output for a request to check if a data transfer is allowed to happen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckTransferReply {
    /// The verdict of the checker; `true` means OK, `false` means deny.
    pub verdict: bool,
    /// If `verdict` is false, this \*may\* contain reasons why a the transfer was denied.
    #[serde(default = "Vec::new", skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}
