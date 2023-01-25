//  LIB.rs
//    by Lut99
// 
//  Created:
//    24 Oct 2022, 15:26:59
//  Last edited:
//    09 Jan 2023, 13:05:21
//  Auto updated?
//    Yes
// 
//  Description:
//!   The `brane-tsk` library picks up where `brane-exe` left off, and
//!   provides various tools and base code for VMs building on top of it to
//!   start executing workflows.
// 

// Declare modules
pub mod errors;
pub mod spec;
pub mod tools;
pub mod docker;
pub mod local;
pub mod api;

// // The grpc module is a bit special
// #[allow(clippy::all)]
// pub mod grpc {
//     tonic::include_proto!("driver");
//     tonic::include_proto!("job");

//     pub use driver_service_client::DriverServiceClient;
//     pub use driver_service_server::{DriverService, DriverServiceServer};
//     pub use job_service_client::JobServiceClient;
//     pub use job_service_server::{JobService, JobServiceServer};
// }
