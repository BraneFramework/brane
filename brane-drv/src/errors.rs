//  ERRORS.rs
//    by Lut99
//
//  Created:
//    01 Feb 2022, 16:13:53
//  Last edited:
//    08 Feb 2024, 16:49:47
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains errors used within the brane-drv package only.
//

use std::path::PathBuf;

/***** ERRORS *****/
/// Defines errors that relate to the RemoteVm.
#[derive(Debug, thiserror::Error)]
pub enum RemoteVmError {
    /// Failed to plan a workflow.
    #[error("Failed to plan workflow")]
    PlanError { source: brane_tsk::errors::PlanError },
    /// Failed to run a workflow.
    #[error("Failed to execute workflow (drv)")]
    ExecError { source: brane_exe::Error },

    /// The given node config was not for this type of node.
    #[error("Illegal node config kind in node config '{}'; expected Central, got {}", path.display(), got)]
    IllegalNodeConfig { path: PathBuf, got: String },
    /// Failed to load the given infra file.
    #[error("Failed to load infra file '{}'", path.display())]
    InfraFileLoad { path: PathBuf, source: brane_cfg::info::YamlError },
    /// Failed to load the given node config file.
    #[error("Failed to load node config file '{}'", path.display())]
    NodeConfigLoad { path: PathBuf, source: brane_cfg::info::YamlError },
}
