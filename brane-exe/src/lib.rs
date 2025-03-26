//  LIB.rs
//    by Lut99
//
//  Created:
//    09 Sep 2022, 11:54:53
//  Last edited:
//    16 Jan 2024, 15:15:43
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines an executor for (unplanned) Workflow graphs.
//

// Define some modules
pub mod errors;
pub mod spec;
// pub mod vtable;
pub mod dummy;
pub mod frame_stack;
pub mod pc;
pub mod stack;
pub mod thread;
pub mod value;
// pub mod varreg;
pub mod vm;

// Pull some stuff into the crate namespace
pub use errors::VmError as Error;
pub use spec::RunState;
pub use thread::Thread;
pub use value::{FullValue, Value};
pub use vm::Vm;


// A few useful macros
/// Macro that conditionally logs nodes that are being run.
#[cfg(feature = "print_exec_path")]
macro_rules! dbg_node {
    ($($arg:tt)+) => {
        { tracing::debug!($($arg)+); }
    };
}
/// Macro that conditionally logs nodes that are being run.
#[cfg(not(feature = "print_exec_path"))]
macro_rules! dbg_node {
    ($($arg:tt)+) => {};
}
pub(crate) use dbg_node;
