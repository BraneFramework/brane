//  LIB.rs
//    by Lut99
// 
//  Created:
//    30 Sep 2022, 16:21:24
//  Last edited:
//    22 May 2023, 13:14:13
//  Auto updated?
//    Yes
// 
//  Description:
//!   The `brane-shr` crate defines common functions and other tools used
//!   throughout the framework. This crate differs from the
//!   `specifications` crate in that it does not aim to standerdize
//!   things, but rather just provide a common implementation.
// 

// Declare some modules
pub mod errors;
pub mod formatters;
pub mod fs;
pub mod jobs;
pub mod kafka;
pub mod utilities;
