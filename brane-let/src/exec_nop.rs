//  EXEC NOP.rs
//    by Lut99
//
//  Created:
//    14 Feb 2022, 16:37:17
//  Last edited:
//    22 May 2023, 10:24:20
//  Auto updated?
//    Yes
//
//  Description:
//!   "Executes" the no-operation command in brane-let. Does nothing,
//!   except
//

use brane_exe::FullValue;
use tracing::{debug, info};

// use crate::callback::Callback;
use crate::common::PackageResult;
use crate::errors::LetError;


/***** ENTRYPOINT *****/
/// Handles athe No-Op, and thus does no meaningful work (except for sending as many callbacks as needed).
///
/// **Arguments**
///  * `callback`: The callback object we use to keep in touch with the driver.
///
/// **Returns**  
/// The return state of the package call on success, or a LetError otherwise.
pub async fn handle(// callback: &mut Option<&mut Callback>,
) -> Result<PackageResult, LetError> {
    debug!("Executing No-Operation (nop) without arguments");

    // Send the 'Initialize' callback
    // if let Some(callback) = callback {
    //     if let Err(err) = callback.initialized().await { warn!("Could not update driver on Initialized: {}", err); }
    // }
    info!("Reached target 'Initialized'");

    // Send the 'Started' callback
    // if let Some(callback) = callback {
    //     if let Err(err) = callback.started().await { warn!("Could not update driver on Started: {}", err); }
    // }
    info!("Reached target 'Started'");

    // Send the 'Completed' callback
    // if let Some(callback) = callback {
    //     if let Err(err) = callback.completed().await { warn!("Could not update driver on Completed: {}", err); }
    // }
    info!("Reached target 'Completed'");

    // Done, return the empty result
    Ok(PackageResult::Finished { result: FullValue::Void })
}
