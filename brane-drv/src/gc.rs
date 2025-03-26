//  GC.rs
//    by Lut99
//
//  Created:
//    12 Jul 2023, 16:31:40
//  Last edited:
//    13 Jul 2023, 10:26:03
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a small function that can be used as a "garbage
//!   collector" for `brane-drv` sessions.
//

use std::sync::Weak;
use std::time::{Duration, Instant};

use brane_tsk::spec::AppId;
use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::vm::InstanceVm;


/***** CONSTANTS *****/
/// The timeout between garbage collector polls.
const GC_POLL_TIMEOUT: u64 = 3600;

/// The timeout for sessions.
const SESSION_TIMEOUT: u64 = 24 * 3600;





/***** LIBRARY *****/
/// Can be run as a `tokio` background task to periodically clean the list of active sessions.
///
/// Is really quite cancellation-safe.
///
/// # Arguments
/// - `sessions`: The [`DashMap`] of weak sessions. Note that, to avoid memory leaks because its destructor would not be run when this task is cancelled, we assume a [`Weak`] reference.
///
/// # Returns
/// Never, unless the referred `sessions` is free'd.
pub async fn sessions(sessions: Weak<DashMap<AppId, (InstanceVm, Instant)>>) {
    // Loop indefinitely
    debug!("Starting sessions garbage collector");
    loop {
        // Wait indefinitely (like an hour or so)
        tokio::time::sleep(Duration::from_secs(GC_POLL_TIMEOUT)).await;
        debug!("Running sessions garbage collector");

        // Attempt to get the sessions
        // (We assume this gap is small enough not to run into serious memory leaks)
        if let Some(sessions) = sessions.upgrade() {
            // Remove the required things
            sessions.retain(|k, v| {
                // Only keep those with recent enough usage
                if v.1.elapsed() < Duration::from_secs(SESSION_TIMEOUT) {
                    true
                } else {
                    info!(
                        "Removing session '{}' because it has not been used for {} seconds (last use {} seconds ago)",
                        k,
                        SESSION_TIMEOUT,
                        v.1.elapsed().as_secs()
                    );
                    false
                }
            });
        } else {
            warn!("Garbage collector attempted to run after `sessions` has been deallocated; quitting garbage collector");
            break;
        }
    }
}
