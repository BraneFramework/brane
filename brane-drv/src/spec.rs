//  SPEC.rs
//    by Lut99
// 
//  Created:
//    28 Nov 2022, 16:08:36
//  Last edited:
//    09 Jan 2023, 13:41:25
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines (public) interfaces and structs for the `brane-drv` crate.
// 

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc::Sender;
use tonic::Status;

use brane_exe::spec::CustomGlobalState;
use brane_prx::client::ProxyClient;
use brane_tsk::spec::AppId;
use specifications::driving::ExecuteReply;


/***** LIBRARY *****/
/// The global state for the RemoteVm.
#[derive(Clone, Debug)]
pub struct GlobalState {
    /// The path to the configuration for this node's environment. For us, contains the path to the infra.yml and (optional) secrets.yml files.
    pub node_config_path : PathBuf,
    /// The application identifier for this session.
    pub app_id           : AppId,
    /// The (shared) proxy client we use to communicate, well, through proxies.
    pub proxy            : Arc<ProxyClient>,

    /// The workflow for this session, which will be updated when a new one is received.
    pub workflow : Option<String>,

    /// The callback for the client to receive prints and other status updates on (such as the final result).
    /// 
    /// Note that this value is updated for every new connection the client makes.
    pub tx : Option<Arc<Sender<Result<ExecuteReply, Status>>>>,
}
impl CustomGlobalState for GlobalState {}

/// The local state for the RemoteVm is unused.
pub type LocalState = ();
