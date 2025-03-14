//  SPEC.rs
//    by Lut99
//
//  Created:
//    17 Oct 2022, 15:16:04
//  Last edited:
//    28 Nov 2022, 17:15:19
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines (public) interfaces and structs for the `brane-api` crate.
//

use std::path::PathBuf;
use std::sync::Arc;

use brane_prx::client::ProxyClient;
use scylla::client::session::Session;


/***** LIBRARY *****/
/// Defines the context of all the path calls.
#[derive(Clone)]
pub struct Context {
    /// Points to the `node.yml` file we use in warp functions.
    pub node_config_path: PathBuf,
    /// Points to the Scylla database where we store package information.
    pub scylla: Arc<Session>,
    /// The proxy client through which we send our requests.
    pub proxy: Arc<ProxyClient>,
}
