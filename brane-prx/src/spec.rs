//  SPEC.rs
//    by Lut99
// 
//  Created:
//    23 Nov 2022, 11:02:54
//  Last edited:
//    27 Feb 2023, 15:28:45
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines (public) interfaces and structs used in the `brane-prx`
//!   crate.
// 

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use brane_cfg::node::ProxyConfig;

use crate::ports::PortAllocator;


/***** LIBRARY *****/
/// Defines the Context to all warp calls.
#[derive(Debug)]
pub struct Context {
    /// Specifies the node config file.
    pub node_config_path : PathBuf,

    /// The address to proxy to if at all.
    pub proxy  : Option<ProxyConfig>,
    /// Specificies ports we're already serving on.
    pub opened : Mutex<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>>,
    /// Specificies available path ports.
    pub ports  : Mutex<PortAllocator>,
}



/// Defines the body for new path requests.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewPathRequest {
    /// The address to connect to.
    pub address : String,

    /// If given, uses TLS with the given options.
    pub tls : Option<NewPathRequestTlsOptions>,
}

/// Defines the body for TLS options.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct NewPathRequestTlsOptions {
    /// The location for which we use TLS. Effectively this means a root certificate to use.
    pub location        : String,
    /// Whether to load a client certficate or not.
    pub use_client_auth : bool,
}
