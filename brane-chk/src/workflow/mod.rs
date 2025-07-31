//  MOD.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:39:23
//  Last edited:
//    29 Apr 2025, 23:36:22
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains code for compiling the Brane WIR to the policy reasoner's
//!   version of a workflow.
//

// Declare submodules
pub mod compile;
pub mod eflint;
pub mod preprocess;
#[cfg(test)]
mod tests;
mod utils;

// Decide what to put in this namespace
pub use compile::compile;
pub use eflint::{WorkflowToEflint, eflint_fmt};
