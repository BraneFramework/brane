//  DRIVING.rs
//    by Lut99
//
//  Created:
//    06 Jan 2023, 14:43:35
//  Last edited:
//    02 May 2025, 14:18:22
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the prost messages for interacting with the driver.
//

use std::error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::sync::Arc;

pub use DriverServiceError as Error;
use async_trait::async_trait;
use futures::Stream;
use prost::Message;
use tonic::body::Body;
use tonic::client::Grpc as GrpcClient;
use tonic::codec::{ProstCodec, Streaming};
use tonic::codegen::{self, BoxFuture, Context, Poll, Service, StdError, http};
use tonic::server::{Grpc as GrpcServer, NamedService, ServerStreamingService, UnaryService};
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Response, Status};


/***** ERRORS *****/
/// Defines the errors occuring in the [`DriverServiceClient`] or [`DriverServiceServer`].
#[derive(Debug)]
pub enum DriverServiceError {
    /// Failed to create an endpoint with the given address.
    EndpointError { address: String, err: tonic::transport::Error },
    /// Failed to connect to the given address.
    ConnectError { address: String, err: tonic::transport::Error },
}
impl Display for DriverServiceError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DriverServiceError::*;
        match self {
            EndpointError { address, err } => write!(f, "Failed to create a new Endpoint from '{address}': {err}"),
            ConnectError { address, err } => write!(f, "Failed to connect to gRPC endpoint '{address}': {err}"),
        }
    }
}
impl error::Error for DriverServiceError {}





/***** MESSAGES *****/
/// Request for creating a new session.
#[derive(Clone, Message)]
pub struct CreateSessionRequest {}

/// The reply sent by the driver when a new session has been created.
#[derive(Clone, Message)]
pub struct CreateSessionReply {
    /// The resulting UUID of the session.
    #[prost(tag = "1", required, string)]
    pub uuid: String,
}



/// Request for checking the given workflow only.
#[derive(Clone, Message)]
pub struct CheckRequest {
    /// The workflow to check
    #[prost(tag = "1", required, string)]
    pub workflow: String,
}

/// Reply to the [`CheckRequest`].
#[derive(Clone, Message)]
pub struct CheckReply {
    /// If all checkers agreed with it across all questions.
    #[prost(tag = "1", required, bool)]
    pub verdict: bool,
    /// Which checker was the first to deny (if any).
    #[prost(tag = "2", optional, string)]
    pub who:     Option<String>,
    /// The reasons for the first checker to deny, if any (and the checker wants to share).
    #[prost(tag = "3", repeated, string)]
    pub reasons: Vec<String>,

    /// If any, contains profile results of the driver.
    #[prost(tag = "4", optional, string)]
    pub profile: Option<String>,
}



/// Request for executing the given workflow.
#[derive(Clone, Message)]
pub struct ExecuteRequest {
    /// The session in which to execute the workflow.
    #[prost(tag = "1", required, string)]
    pub uuid:  String,
    /// The input to the request, i.e., the workflow.
    #[prost(tag = "2", required, string)]
    pub input: String,
}

/// The reply sent by the driver when a workflow has been executed.
#[derive(Clone, Message)]
pub struct ExecuteReply {
    /// Whether to close the communication after this or nay.
    #[prost(tag = "1", required, bool)]
    pub close: bool,

    /// If given, then the driver has some debug information to show to the user.
    #[prost(tag = "2", optional, string)]
    pub debug:  Option<String>,
    /// If given, then the driver has stdout to write to the user.
    #[prost(tag = "3", optional, string)]
    pub stdout: Option<String>,
    /// If given, then the driver has stderr to write to the user.
    #[prost(tag = "4", optional, string)]
    pub stderr: Option<String>,
    /// If given, then the workflow has returned a value to use (a tuple of a `FullValue` and an optional `ProgramCounter` encoded as JSON).
    #[prost(tag = "5", optional, string)]
    pub value:  Option<String>,
}





/***** SERVICES *****/
/// The `DriverServiceClient` can connect to a remote server implementing the [`DriverService`] protocol.
#[derive(Debug, Clone)]
pub struct DriverServiceClient {
    /// The client with which we actually do everything
    client: GrpcClient<Channel>,
}

impl DriverServiceClient {
    /// Attempts to connect to the remote endpoint.
    ///
    /// # Arguments
    /// - `address`: The address of the remote endpoint to connect to.
    ///
    /// # Returns
    /// A new `DriverServiceClient` instance that is connected to the remove endpoint.
    ///
    /// # Errors
    /// This function errors if the connection could not be established for whatever reason.
    pub async fn connect(address: impl Into<String>) -> Result<Self, Error> {
        let address: String = address.into();

        // Attempt to make the connection
        let conn: Channel = match Endpoint::new(address.clone()) {
            Ok(endpoint) => match endpoint.connect().await {
                Ok(conn) => conn,
                Err(err) => {
                    return Err(Error::ConnectError { address, err });
                },
            },
            Err(err) => {
                return Err(Error::EndpointError { address, err });
            },
        };

        // Store it internally
        Ok(Self { client: GrpcClient::new(conn) })
    }

    /// Send a [`CreateSessionRequest`] to the connected endpoint.
    ///
    /// # Arguments
    /// - `request`: The [`CreateSessionRequest`] to send to the endpoint.
    ///
    /// # Returns
    /// The [`CreateSessionReply`] the endpoint returns.
    ///
    /// # Errors
    /// This function errors if either we failed to send the request or the endpoint itself failed to process it.
    pub async fn create_session(&mut self, request: impl tonic::IntoRequest<CreateSessionRequest>) -> Result<Response<CreateSessionReply>, Status> {
        // Assert the client is ready to get the party started
        if let Err(err) = self.client.ready().await {
            return Err(Status::new(Code::Unknown, format!("Service was not ready: {err}")));
        }

        // Set the default stuff
        let codec: ProstCodec<_, _> = ProstCodec::default();
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/driver.DriverService/CreateSession");
        self.client.unary(request.into_request(), path, codec).await
    }

    /// Send a request to validate a workflow to the connected endpoint.
    ///
    /// # Arguments
    /// - `request`: The [`CheckRequest`] to send to the endpoint.
    ///
    /// # Returns
    /// A [`CheckReply`] the endpoint returns.
    ///
    /// # Errors
    /// This function errors if either we failed to send the request or the endpoint itself failed to process it.
    pub async fn check(&mut self, request: impl tonic::IntoRequest<CheckRequest>) -> Result<Response<CheckReply>, Status> {
        // Assert the client is ready to get the party started
        if let Err(err) = self.client.ready().await {
            return Err(Status::new(Code::Unknown, format!("Service was not ready: {err}")));
        }

        // Set the default stuff
        let codec: ProstCodec<_, _> = ProstCodec::default();
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/driver.DriverService/Check");
        self.client.unary(request.into_request(), path, codec).await
    }

    /// Send an [`ExecuteRequest`] to the connected endpoint.
    ///
    /// # Arguments
    /// - `request`: The [`ExecuteRequest`] to send to the endpoint.
    ///
    /// # Returns
    /// The [`ExecuteReply`] the endpoint returns.
    ///
    /// # Errors
    /// This function errors if either we failed to send the request or the endpoint itself failed to process it.
    pub async fn execute(&mut self, request: impl tonic::IntoRequest<ExecuteRequest>) -> Result<Response<Streaming<ExecuteReply>>, Status> {
        // Assert the client is ready to get the party started
        if let Err(err) = self.client.ready().await {
            return Err(Status::new(Code::Unknown, format!("Service was not ready: {err}")));
        }

        // Set the default stuff
        let codec: ProstCodec<_, _> = ProstCodec::default();
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/driver.DriverService/Execute");
        self.client.server_streaming(request.into_request(), path, codec).await
    }
}



/// The DriverService, which is a trait for easily writing a service for the driver communication protocol.
///
/// Implementation based on the auto-generated version from tonic.
#[async_trait]
pub trait DriverService: 'static + Send + Sync {
    /// The response type for stream returned by `DriverService::execute()`.
    type ExecuteStream: 'static + Send + Stream<Item = Result<ExecuteReply, Status>>;



    /// Handle for when a CreateSessionRequest comes in.
    ///
    /// # Arguments
    /// - `request`: The (`tonic::Request`-wrapped) CreateSessionRequest containing the relevant details.
    ///
    /// # Returns
    /// A CreateSessionReply for this request, wrapped in a `tonic::Response`.
    ///
    /// # Errors
    /// This function may error (i.e., send back a `tonic::Status`) whenever it fails.
    async fn create_session(&self, request: Request<CreateSessionRequest>) -> Result<Response<CreateSessionReply>, Status>;

    /// Handle for when a [`CheckRequest`] comes in.
    ///
    /// # Arguments
    /// - `request`: The ([`tonic::Request`]-wrapped) [`CheckRequest`] containing the relevant details.
    ///
    /// # Returns
    /// A [`CheckReply`] for this request, wrapped in a [`tonic::Response`].
    ///
    /// # Errors
    /// This function may error (i.e., send back a [`tonic::Status`]) whenever it fails.
    async fn check(&self, request: Request<CheckRequest>) -> Result<Response<CheckReply>, Status>;

    /// Handle for when an ExecuteRequest comes in.
    ///
    /// # Arguments
    /// - `request`: The (`tonic::Request`-wrapped) ExecuteRequest containing the relevant details.
    ///
    /// # Returns
    /// A stream of ExecuteReply messages, updating the client and eventually sending back the workflow result.
    ///
    /// # Errors
    /// This function may error (i.e., send back a `tonic::Status`) whenever it fails.
    async fn execute(&self, request: Request<ExecuteRequest>) -> Result<Response<Self::ExecuteStream>, Status>;
}

/// The `DriverServiceServer` hosts the server part of the [`DriverService`] protocol.
#[derive(Debug)]
pub struct DriverServiceServer<T> {
    /// The service that we host.
    service: Arc<T>,
}

impl<T> DriverServiceServer<T> {
    /// Constructor for the `DriverServiceServer`.
    ///
    /// # Arguments
    /// - `service`: The [`Service`] to serve.
    ///
    /// # Returns
    /// A new `DriverServiceServer` instance.
    #[inline]
    pub fn new(service: T) -> Self { Self { service: Arc::new(service) } }
}

impl<T: DriverService, B> Service<http::Request<B>> for DriverServiceServer<T>
where
    T: DriverService,
    B: 'static + Send + codegen::Body,
    B::Error: 'static + Send + Into<StdError>,
{
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;
    type Response = http::Response<Body>;

    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        match req.uri().path() {
            // Incoming CreateSessionRequest
            "/driver.DriverService/CreateSession" => {
                /// Helper struct for the given [`DriverService`] that focusses specifically on this request.
                struct CreateSessionSvc<T>(Arc<T>);
                impl<T: DriverService> UnaryService<CreateSessionRequest> for CreateSessionSvc<T> {
                    type Future = BoxFuture<Response<Self::Response>, Status>;
                    type Response = CreateSessionReply;

                    fn call(&mut self, req: Request<CreateSessionRequest>) -> Self::Future {
                        // Return the service function as the future to run
                        let service = self.0.clone();
                        let fut = async move { (*service).create_session(req).await };
                        Box::pin(fut)
                    }
                }

                // Create a future that creates the service
                let service = self.service.clone();
                Box::pin(async move {
                    let method: CreateSessionSvc<T> = CreateSessionSvc(service);
                    let codec: ProstCodec<_, _> = ProstCodec::default();
                    let mut grpc: GrpcServer<ProstCodec<_, _>> = GrpcServer::new(codec);
                    Ok(grpc.unary(method, req).await)
                })
            },

            // Incoming CheckRequest
            "/driver.DriverService/Check" => {
                /// Helper struct for the given [`DriverService`] that focusses specifically on this request.
                struct CheckSvc<T>(Arc<T>);
                impl<T: DriverService> UnaryService<CheckRequest> for CheckSvc<T> {
                    type Future = BoxFuture<Response<Self::Response>, Status>;
                    type Response = CheckReply;

                    fn call(&mut self, req: Request<CheckRequest>) -> Self::Future {
                        // Return the service function as the future to run
                        let service = self.0.clone();
                        let fut = async move { (*service).check(req).await };
                        Box::pin(fut)
                    }
                }

                // Create a future that creates the service
                let service = self.service.clone();
                Box::pin(async move {
                    let method: CheckSvc<T> = CheckSvc(service);
                    let codec: ProstCodec<_, _> = ProstCodec::default();
                    let mut grpc: GrpcServer<ProstCodec<_, _>> = GrpcServer::new(codec);
                    Ok(grpc.unary(method, req).await)
                })
            },

            // Incoming ExecuteRequest
            "/driver.DriverService/Execute" => {
                /// Helper struct for the given [`DriverService`] that focusses specifically on this request.
                struct ExecuteSvc<T>(Arc<T>);
                impl<T: DriverService> ServerStreamingService<ExecuteRequest> for ExecuteSvc<T> {
                    type Future = BoxFuture<Response<Self::ResponseStream>, Status>;
                    type Response = ExecuteReply;
                    type ResponseStream = T::ExecuteStream;

                    fn call(&mut self, req: Request<ExecuteRequest>) -> Self::Future {
                        // Return the service function as the future to run
                        let service = self.0.clone();
                        let fut = async move { (*service).execute(req).await };
                        Box::pin(fut)
                    }
                }

                // Create a future that creates the service
                let service = self.service.clone();
                Box::pin(async move {
                    let method: ExecuteSvc<T> = ExecuteSvc(service);
                    let codec: ProstCodec<_, _> = ProstCodec::default();
                    let mut grpc: GrpcServer<ProstCodec<_, _>> = GrpcServer::new(codec);
                    Ok(grpc.server_streaming(method, req).await)
                })
            },

            // Other (boring) request types
            _ => {
                // Return a future that simply does ¯\_(ツ)_/¯
                Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(Body::empty())
                        .unwrap())
                })
            },
        }
    }
}

impl<T: Clone> Clone for DriverServiceServer<T> {
    #[inline]
    fn clone(&self) -> Self { Self { service: self.service.clone() } }
}
impl<T: DriverService> NamedService for DriverServiceServer<T> {
    const NAME: &'static str = "driver.DriverService";
}
