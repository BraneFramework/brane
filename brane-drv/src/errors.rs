//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    01 Feb 2022, 16:13:53
//  Last edited:
//    23 Dec 2022, 13:43:18
//  Auto updated?
//    Yes
// 
//  Description:
//!   Contains errors used within the brane-drv package only.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};


/***** ERRORS *****/
/// Defines errors that relate to the RemoteVm.
#[derive(Debug)]
pub enum RemoteVmError {
    /// Failed to plan a workflow.
    PlanError{ err: brane_tsk::errors::PlanError },
    /// Failed to run a workflow.
    ExecError{ err: brane_exe::Error },
}

impl Display for RemoteVmError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use RemoteVmError::*;
        match self {
            PlanError{ err } => write!(f, "Failed to plan workflow: {err}"),
            ExecError{ err } => write!(f, "Failed to execute workflow: {err}"),
        }
    }
}

impl Error for RemoteVmError {}
