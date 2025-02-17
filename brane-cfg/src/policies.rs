//  POLICIES.rs
//    by Lut99
//
//  Created:
//    01 Dec 2022, 09:20:32
//  Last edited:
//    27 Mar 2023, 11:45:02
//  Auto updated?
//    Yes
//
//  Description:
//!   Temporary config file that is used to read simple policies until we
//!   have eFLINT
//

use enum_debug::EnumDebug;
use serde::{Deserialize, Serialize};

pub use crate::info::YamlError as Error;
use crate::info::YamlInfo;


/***** LIBRARY *****/
/// Defines the toplevel policy file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyFile {
    /// The users to allow
    pub users:      Vec<UserPolicy>,
    /// The containers to allow
    pub containers: Vec<ContainerPolicy>,
}
impl YamlInfo<'_> for PolicyFile {}



/// Defines the possible policies for users.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(rename_all = "snake_case", tag = "policy")]
pub enum UserPolicy {
    /// Allows everyone to do anything.
    AllowAll,
    /// Denies everyone anything.
    DenyAll,

    /// Allows this user to do anything.
    AllowUserAll {
        /// The name/ID of the user as found in their certificate
        #[serde(alias = "user")]
        name: String,
    },
    /// Denies this user anything.
    DenyUserAll {
        /// The name/ID of the user as found in their certificate.
        #[serde(alias = "user")]
        name: String,
    },

    /// Allows this user to do anything on a limited set of datasets.
    Allow {
        /// The name/ID of the user as found in their certificate.
        #[serde(alias = "user")]
        name: String,
        /// The dataset to allow the operations for.
        data: String,
    },
    /// Deny this user to do thing on a limited set of datasets.
    Deny {
        /// The name/ID of the user as found on their certificate.
        #[serde(alias = "user")]
        name: String,
        /// The dataset for which to deny them.
        data: String,
    },
}

/// Defines the possible policies for containers.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(rename_all = "snake_case", tag = "policy")]
pub enum ContainerPolicy {
    /// Allow all containers.
    AllowAll,
    /// Deny all containers.
    DenyAll,

    /// Allows a specific container.
    Allow {
        /// An optional name to identify the container in the logs
        name: Option<String>,
        /// The hash of the container to allow.
        hash: String,
    },
    /// Deny a specific container.
    Deny {
        /// An optional name to identify the container in the logs
        name: Option<String>,
        /// The hash of the container to allow.
        hash: String,
    },
}
