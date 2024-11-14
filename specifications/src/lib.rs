//  LIB.rs
//    by Lut99
//
//  Created:
//    07 Jun 2023, 16:22:04
//  Last edited:
//    14 Nov 2024, 16:09:37
//  Auto updated?
//    Yes
//
//  Description:
//!   The `specifications` crate defines not just public interfaces and
//!   structs, but parts of the specification that are "extra-Rust"; e.g.,
//!   things that relate to command-line parameters, file layouts, network
//!   messages, etc.
//

// Declare submodules
pub mod address;
pub mod arch;
pub mod checking;
pub mod common;
pub mod container;
pub mod data;
pub mod driving;
pub mod errors;
pub mod os;
pub mod package;
pub mod pc;
pub mod planning;
pub mod policy;
pub mod profiling;
pub mod registering;
pub mod version;
pub mod wir;
pub mod working;
