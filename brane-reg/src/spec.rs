//  SPEC.rs
//    by Lut99
//
//  Created:
//    06 Nov 2022, 17:05:19
//  Last edited:
//    02 May 2025, 13:32:53
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains (public) interfaces and structs for the `brane-reg` crate.
//

use std::path::PathBuf;


/***** LIBRARY *****/
/// Defines the context for all of the warp paths.
#[derive(Clone, Debug)]
pub struct Context {
    /// The path to the node config file.
    pub node_config_path: PathBuf,
    /// The deliberation token used to commune with the checker.
    pub delib_token:      String,
}
