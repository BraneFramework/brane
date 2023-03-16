//  VERIFY.rs
//    by Lut99
// 
//  Created:
//    17 Oct 2022, 16:11:00
//  Last edited:
//    16 Mar 2023, 16:55:41
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements functions for various verification tasks.
// 

use std::path::Path;

use brane_cfg::spec::Config as _;
use brane_cfg::infra::InfraFile;

pub use crate::errors::VerifyError as Error;


/***** LIBRARY *****/
/// Verifies the configuration (i.e., `infra.yml` and `secrets.`yml`) files.
/// 
/// # Arguments
/// - `infra`: Path to the infrastructure file to validate.
/// 
/// # Errors
/// This function errors if we failed to verify them.
pub fn config(infra: impl AsRef<Path>) -> Result<(), Error> {
    // Verify the infra file, which will validate the secrets file
    match InfraFile::from_path(infra.as_ref()) {
        Ok(_)    => Ok(()),
        Err(err) => Err(Error::ConfigFailed{ err }),
    }
}
