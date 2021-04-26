#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;


pub mod handler;

pub mod grpc {
    tonic::include_proto!("driver");

    pub use driver_service_client::DriverServiceClient;
    pub use driver_service_server::DriverService;
    pub use driver_service_server::DriverServiceServer;
}
