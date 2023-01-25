//  LIB.rs
//    by Lut99
// 
//  Created:
//    09 Sep 2022, 11:54:53
//  Last edited:
//    19 Jan 2023, 15:46:52
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines an executor for (unplanned) Workflow graphs.
// 

// Define some modules
pub mod errors;
pub mod spec;
pub mod vtable;
pub mod value;
pub mod stack;
pub mod varreg;
pub mod frame_stack;
pub mod thread;
pub mod vm;
pub mod dummy;

// Pull some stuff into the crate namespace
pub use errors::VmError as Error;
pub use spec::RunState;
pub use value::{FullValue, Value};
pub use thread::Thread;
pub use vm::Vm;


// A few useful macros
/// Macro that conditionally logs nodes that are being run.
#[cfg(feature = "print_exec_path")]
macro_rules! dbg_node {
    ($($arg:tt)+) => {
        { log::debug!($($arg)+); }
    };
}
/// Macro that conditionally logs nodes that are being run.
#[cfg(not(feature = "print_exec_path"))]
macro_rules! dbg_node {
    ($($arg:tt)+) => {};
}
pub(crate) use dbg_node;
