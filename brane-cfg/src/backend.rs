//  BACKEND.rs
//    by Lut99
//
//  Created:
//    18 Oct 2022, 13:50:11
//  Last edited:
//    23 May 2023, 15:22:15
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the credentials and a file that describes them for the job
//!   service to connect with its backend.
//

use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use specifications::address::Address;
use specifications::package::Capability;

pub use crate::info::YamlError as Error;
use crate::info::YamlInfo;


/***** AUXILLARY *****/
/// Defines the possible credentials we may encounter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Credentials {
    // Job node acting as a node
    /// Defines that this job node connects to the "backend" by simply spinning up the local Docker daemon.
    Local {
        /// If given, uses a non-default path to connect to the Docker daemon.
        path:    Option<PathBuf>,
        /// If given, uses a non-default client version to connect with the Docker daemon.
        version: Option<(usize, usize)>,
    },

    // Job node acting as a scheduler
    /// Defines that this job node connects to one node by use of SSH. This effectively allows the centralized Brane manager to orchestrate over nodes instead of clusters.
    Ssh {
        /// The address of the machine to connect to. Should include any ports if needed.
        address: Address,
        /// The path to the key file to connect with.
        key:     PathBuf,
    },

    // Job node acting as a cluster connector
    /// Defines that this job node connects to a backend Slurm cluster.
    Slurm {/* TBD */},
    /// Defines that this job node connects to a backend Kubernetes cluster.
    Kubernetes {
        /// The address of the Docker registry that we push container images to.
        registry_address: Address,
        /// The path to the Kubernetes config file to connect with.
        config: PathBuf,
    },
}





/***** LIBRARY *****/
/// Defines a file that describes how a job service may connect to its backend.
///
/// Note that this struct is designed to act as a "handle"; i.e., keep it only around when using it but otherwise refer to it only by path.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackendFile {
    /// The capabilities advertised by this domain.
    pub capabilities: Option<HashSet<Capability>>,
    /// Can be specified to disable container hash checking.
    pub hash_containers: Option<bool>,
    /// The method of connecting
    pub method: Credentials,
}

impl BackendFile {
    /// Returns whether the user wants hash containers to be hashed, generating a default value if they didn't specify it.
    ///
    /// # Returns
    /// Whether container hash security should be enabled (true) or not (false).
    #[inline]
    pub fn hash_containers(&self) -> bool { self.hash_containers.unwrap_or(true) }
}
impl YamlInfo<'_> for BackendFile {}
