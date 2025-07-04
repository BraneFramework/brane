//  WORKING.rs
//    by Lut99
//
//  Created:
//    06 Jan 2023, 15:01:17
//  Last edited:
//    02 May 2025, 15:07:33
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains prost messages for interacting with the job service /
//!   worker.
//

use std::convert::TryFrom;
use std::error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::sync::Arc;

pub use JobServiceError as Error;
use async_trait::async_trait;
use futures::Stream;
use policy_reasoner::spec::reasons::ManyReason;
use prost::{Enumeration, Message, Oneof};
use tonic::body::Body;
use tonic::client::Grpc as GrpcClient;
use tonic::codec::{ProstCodec, Streaming};
use tonic::codegen::{self, BoxFuture, Context, Poll, Service, StdError, http};
use tonic::server::{Grpc as GrpcServer, NamedService, ServerStreamingService, UnaryService};
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Response, Status};

use crate::checking::deliberation::{CheckResponse, CheckTaskRequest, CheckWorkflowRequest, Prost};


/***** ERRORS *****/
/// Defines the errors occurring when juggling [`PreprocessKind`]s.
#[derive(Debug)]
pub enum PreprocessKindConvertError {
    /// The given [`PreprocessKind`] did not have a successfully parsed `dataname`-field.
    NoDataName,
}
impl Display for PreprocessKindConvertError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PreprocessKindConvertError::*;
        match self {
            NoDataName => write!(f, "Missing 'dataname' in given gRPC version of PreprocessKind"),
        }
    }
}
impl error::Error for PreprocessKindConvertError {}

/// Defines the errors occuring in the [`JobServiceClient`] or [`JobServiceServer`].
#[derive(Debug)]
pub enum JobServiceError {
    /// Failed to create an endpoint with the given address.
    EndpointError { address: String, err: tonic::transport::Error },
    /// Failed to connect to the given address.
    ConnectError { address: String, err: tonic::transport::Error },
}
impl Display for JobServiceError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use JobServiceError::*;
        match self {
            EndpointError { address, err } => write!(f, "Failed to create a new Endpoint from '{address}': {err}"),
            ConnectError { address, err } => write!(f, "Failed to connect to gRPC endpoint '{address}': {err}"),
        }
    }
}
impl error::Error for JobServiceError {}





/***** AUXILLARY MESSAGES *****/
// /// Auxillary enum that defines the possible kinds of datasets.
// #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
// #[repr(i32)]
// pub enum DataKind {
//     /// A full-fledged, persistent dataset.
//     Data               = 0,
//     /// An intermediate result that will not outlive the scope of the workflow.
//     IntermediateResult = 1,
// }

// /// Auxillary message for carrying a dataset with its associated name.
// #[derive(Clone, Message)]
// pub struct DataName {
//     /// The name of the dataset.
//     #[prost(tag = "1", required, string)]
//     pub name : String,
//     /// The kind of the dataset (i.e., Data or IntermediateResult).
//     #[prost(tag = "2", required, enumeration = "DataKind")]
//     pub kind : i32,
// }

/// Auxillary message for carrying a data kind with its associated name.
#[derive(Clone, Oneof)]
pub enum DataName {
    /// The piece of data is a dataset.
    #[prost(tag = "2", string)]
    Data(String),
    /// The piece of data is an intermediate result.
    #[prost(tag = "3", string)]
    IntermediateResult(String),
}

impl From<crate::data::DataName> for DataName {
    #[inline]
    fn from(value: crate::data::DataName) -> Self {
        match value {
            crate::data::DataName::Data(name) => DataName::Data(name),
            crate::data::DataName::IntermediateResult(name) => DataName::IntermediateResult(name),
        }
    }
}
impl From<DataName> for crate::data::DataName {
    #[inline]
    fn from(value: DataName) -> Self {
        match value {
            DataName::Data(name) => Self::Data(name),
            DataName::IntermediateResult(name) => Self::IntermediateResult(name),
        }
    }
}



/// Auxillary message that implements the fields for a `TransferRegistryTar` [`PreprocessKind`].
#[derive(Clone, Message)]
pub struct TransferRegistryTar {
    /// The location where the address is from.
    #[prost(tag = "1", required, string)]
    pub location: String,
    /// The name of the dataset that we aim to retrieve.
    #[prost(tags = "2,3", oneof = "DataName")]
    pub dataname: Option<DataName>,
}

/// Auxillary enum that defines the possible kinds of datasets.
#[derive(Clone, Oneof)]
pub enum PreprocessKind {
    /// We want to transfer it as a tar.gz from a local registry.
    #[prost(tag = "1", message)]
    TransferRegistryTar(TransferRegistryTar),
}
impl From<crate::data::PreprocessKind> for PreprocessKind {
    #[inline]
    fn from(value: crate::data::PreprocessKind) -> Self {
        match value {
            crate::data::PreprocessKind::TransferRegistryTar { location, dataname } => {
                Self::TransferRegistryTar(TransferRegistryTar { location, dataname: Some(dataname.into()) })
            },
        }
    }
}
impl TryFrom<PreprocessKind> for crate::data::PreprocessKind {
    type Error = PreprocessKindConvertError;

    #[inline]
    fn try_from(value: PreprocessKind) -> Result<Self, Self::Error> {
        match value {
            PreprocessKind::TransferRegistryTar(TransferRegistryTar { location, dataname }) => match dataname {
                Some(dataname) => Ok(crate::data::PreprocessKind::TransferRegistryTar { location, dataname: dataname.into() }),
                None => Err(PreprocessKindConvertError::NoDataName),
            },
        }
    }
}



/// Auxillary enum that defines the possible states a task can have.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum TaskStatus {
    // Meta events
    /// No status yet / unknown
    Unknown = 0,

    // Job events
    /// The job has been received by the job node.
    Received = 1,

    // Checker events
    /// The job has been authorized by the job's checker(s).
    Authorized = 2,
    /// The job has been denied by the job's checker(s).
    Denied = 3,
    /// Authorization has failed. If seen, the `value` field is also populated with the error message.
    AuthorizationFailed = 4,

    // Creation events
    /// The job container has been created.
    Created = 5,
    /// We failed to create the job container. If seen, the `value` field is also populated with the error message.
    CreationFailed = 6,

    // Initialization events
    /// The branelet has been booted (first event it sends).
    Ready = 7,
    /// The branelet node has been initialized; now only to spawn the job itself.
    Initialized = 8,
    /// We failed to initialize branelet. If seen, the `value` field is also populated with the error message.
    InitializationFailed = 9,
    /// The actual subcall executeable / script has started
    Started = 10,
    /// The subprocess executable did not want to start (calling it failed) If seen, the `value` field is also populated with the error message.
    StartingFailed = 11,

    // Progress events
    /// Occassional message to let the user know the container is alive and running.
    Heartbeat = 12,
    /// The package call went successfully from the branelet's side.
    Completed = 13,
    /// The package call went wrong from the branelet's side. If seen, the `value` field is also populated with the error message.
    CompletionFailed = 14,

    // Finish events
    /// The container has exited with a zero status code and return a value. If seen, then the `value` field is populated with the JSON-encoded `FullValue` returned.
    Finished = 15,
    /// The container was interrupted by the Job node
    Stopped = 16,
    /// brane-let could not decode the output from the package call. If seen, the `value` field is also populated with the error message.
    DecodingFailed = 17,
    /// The container has exited with a non-zero status code.  If seen, the `value` field is populated with a JSON-encoded triplet of the error code, the container's stdout and the container's stderr.
    Failed = 18,
}





/***** MESSAGES *****/
/// Request for preprocessing a given dataset.
#[derive(Clone, Message)]
pub struct PreprocessRequest {
    /// Some identifier relating to the worker which use-case (registry) is being used.
    #[prost(tag = "1", required, string)]
    pub use_case: String,

    // /// The dataset's name (and kind)
    // #[prost(tags = "2,3", oneof = "DataName")]
    // pub data: Option<DataName>,
    /// The type of preprocessing that will need to happen.
    // #[prost(tags = "2", oneof = "PreprocessKind")]
    // pub kind: Option<PreprocessKind>,
    #[prost(tag = "2", required, message)]
    pub kind: TransferRegistryTar,

    /// The workflow provided as context of the data transfer.
    #[prost(tag = "3", required, string)]
    pub workflow: String,
    /// The function in which we do the call.
    #[prost(tag = "4", message)]
    pub pc: Option<ProgramCounter>,
}

/// Defines two numbers that make up a program counter.
#[derive(Clone, Message)]
pub struct ProgramCounter {
    /// The function ID of the PC.
    #[prost(tag = "1", required, uint64)]
    pub func_id:  u64,
    /// The edge index of the PC.
    #[prost(tag = "2", required, uint64)]
    pub edge_idx: u64,
}

/// The reply sent by the worker when the preprocessing of a dataset has been done.
#[derive(Clone, Message)]
pub struct PreprocessReply {
    /// The method of accessing this dataset from now on.
    #[prost(tag = "1", required, string)]
    pub access: String,
}



/// Request for executing a task on some domain.
#[derive(Clone, Message)]
pub struct ExecuteRequest {
    /// Some identifier relating to the worker which use-case (registry) is being used.
    #[prost(tag = "1", required, string)]
    pub use_case: String,

    /// The workflow of which the task to execute is a part.
    #[prost(tag = "2", required, string)]
    pub workflow: String,
    /// The function & edge in which we do the call.
    #[prost(tag = "3", required, message)]
    pub call_pc:  ProgramCounter,
    /// The index of the task to execute in the workflow's task table.
    #[prost(tag = "4", required, uint64)]
    pub task_def: u64,

    /// The input (i.e., datasets/intermediate results) that are used in this call. It is a map encoded as JSON.
    #[prost(tag = "5", required, string)]
    pub input:  String,
    /// The intermediat result returned by this call, if any.
    #[prost(tag = "6", optional, string)]
    pub result: Option<String>,
    /// The arguments to run the request with. Given as a JSON-encoded map of names to `FullValues`.
    #[prost(tag = "7", required, string)]
    pub args:   String,
}

/// The reply sent by the worker while a task has executing.
#[derive(Clone, Message)]
pub struct ExecuteReply {
    /// The current status of the task. May also indicate a failure status.
    #[prost(tag = "1", required, enumeration = "TaskStatus")]
    pub status: i32,
    /// An optional value that may be carried along with some of the statusses. See the `TaskStatus` enum for more information.
    #[prost(tag = "2", optional, string)]
    pub value:  Option<String>,
}



/// Request for committing a result to a full dataset.
#[derive(Clone, Message)]
pub struct CommitRequest {
    /// The name of the intermediate result to commit.
    #[prost(tag = "1", string)]
    pub result_name: String,
    /// The name that the result should have once it is committed.
    #[prost(tag = "2", string)]
    pub data_name:   String,
}

/// The reply sent by the worker when the comittation was successfull.
#[derive(Clone, Message)]
pub struct CommitReply {}





/***** SERVICES *****/
/// The `JobServiceClient` can connect to a remote server implementing the `DriverService` protocol.
#[derive(Debug, Clone)]
pub struct JobServiceClient {
    /// The client with which we actually do everything
    client: GrpcClient<Channel>,
}

impl JobServiceClient {
    /// Attempts to connect to the remote endpoint.
    ///
    /// # Arguments
    /// - `address`: The address of the remote endpoint to connect to.
    ///
    /// # Returns
    /// A new `JobServiceClient` instance that is connected to the remove endpoint.
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

    /// Send a request to validate a workflow to the connected endpoint.
    ///
    /// # Arguments
    /// - `request`: The [`CheckWorkflowRequest`] to send to the endpoint.
    ///
    /// # Returns
    /// The [`CheckResponse`] the endpoint returns.
    ///
    /// # Errors
    /// This function errors if either we failed to send the request or the endpoint itself failed to process it.
    pub async fn check_workflow(
        &mut self,
        request: impl tonic::IntoRequest<Prost<CheckWorkflowRequest>>,
    ) -> Result<Response<Prost<CheckResponse<ManyReason<String>>>>, Status> {
        // Assert the client is ready to get the party started
        if let Err(err) = self.client.ready().await {
            return Err(Status::new(Code::Unknown, format!("Service was not ready: {err}")));
        }

        // Set the default stuff
        let codec: ProstCodec<_, _> = ProstCodec::default();
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/job.JobService/CheckWorkflow");
        self.client.unary(request.into_request(), path, codec).await
    }

    /// Send a request to validate a task in a workflow to the connected endpoint.
    ///
    /// # Arguments
    /// - `request`: The [`CheckTaskRequest`] to send to the endpoint.
    ///
    /// # Returns
    /// The [`CheckResponse`] the endpoint returns.
    ///
    /// # Errors
    /// This function errors if either we failed to send the request or the endpoint itself failed to process it.
    pub async fn check_task(
        &mut self,
        request: impl tonic::IntoRequest<Prost<CheckTaskRequest>>,
    ) -> Result<Response<Prost<CheckResponse<ManyReason<String>>>>, Status> {
        // Assert the client is ready to get the party started
        if let Err(err) = self.client.ready().await {
            return Err(Status::new(Code::Unknown, format!("Service was not ready: {err}")));
        }

        // Set the default stuff
        let codec: ProstCodec<_, _> = ProstCodec::default();
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/job.JobService/CheckTask");
        self.client.unary(request.into_request(), path, codec).await
    }

    /// Send a [`PreprocessRequest`] to the connected endpoint.
    ///
    /// # Arguments
    /// - `request`: The [`PreprocessRequest`] to send to the endpoint.
    ///
    /// # Returns
    /// The [`PreprocessReply`] the endpoint returns.
    ///
    /// # Errors
    /// This function errors if either we failed to send the request or the endpoint itself failed to process it.
    pub async fn preprocess(&mut self, request: impl tonic::IntoRequest<PreprocessRequest>) -> Result<Response<PreprocessReply>, Status> {
        // Assert the client is ready to get the party started
        if let Err(err) = self.client.ready().await {
            return Err(Status::new(Code::Unknown, format!("Service was not ready: {err}")));
        }

        // Set the default stuff
        let codec: ProstCodec<_, _> = ProstCodec::default();
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/job.JobService/Preprocess");
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
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/job.JobService/Execute");
        self.client.server_streaming(request.into_request(), path, codec).await
    }

    /// Send a [`CommitRequest`] to the connected endpoint.
    ///
    /// # Arguments
    /// - `request`: The [`CommitRequest`] to send to the endpoint.
    ///
    /// # Returns
    /// The [`CommitReply`] the endpoint returns.
    ///
    /// # Errors
    /// This function errors if either we failed to send the request or the endpoint itself failed to process it.
    pub async fn commit(&mut self, request: impl tonic::IntoRequest<CommitRequest>) -> Result<Response<CommitReply>, Status> {
        // Assert the client is ready to get the party started
        if let Err(err) = self.client.ready().await {
            return Err(Status::new(Code::Unknown, format!("Service was not ready: {err}")));
        }

        // Set the default stuff
        let codec: ProstCodec<_, _> = ProstCodec::default();
        let path: http::uri::PathAndQuery = http::uri::PathAndQuery::from_static("/job.JobService/Commit");
        self.client.unary(request.into_request(), path, codec).await
    }
}



/// The JobService is a trait for easily writing a service for the driver communication protocol.
///
/// Implementation based on the auto-generated version from tonic.
#[async_trait]
pub trait JobService: 'static + Send + Sync {
    /// The response type for stream returned by `JobService::execute()`.
    type ExecuteStream: 'static + Send + Stream<Item = Result<ExecuteReply, Status>>;



    /// Handle for when a [`CheckWorkflowRequest`] comes in.
    ///
    /// # Arguments
    /// - `request`: The ([`tonic::Request`]-wrapped) [`CheckWorkflowRequest`] containing the relevant details.
    ///
    /// # Returns
    /// A [`CheckResponse`] for this request, wrapped in a [`tonic::Response`].
    ///
    /// # Errors
    /// This function may error (i.e., send back a `tonic::Status`) whenever it fails.
    async fn check_workflow(
        &self,
        request: Request<Prost<CheckWorkflowRequest>>,
    ) -> Result<Response<Prost<CheckResponse<ManyReason<String>>>>, Status>;

    /// Handle for when a [`CheckTaskRequest`] comes in.
    ///
    /// # Arguments
    /// - `request`: The ([`tonic::Request`]-wrapped) [`CheckTaskRequest`] containing the relevant details.
    ///
    /// # Returns
    /// A [`CheckResponse`] for this request, wrapped in a [`tonic::Response`].
    ///
    /// # Errors
    /// This function may error (i.e., send back a `tonic::Status`) whenever it fails.
    async fn check_task(&self, request: Request<Prost<CheckTaskRequest>>) -> Result<Response<Prost<CheckResponse<ManyReason<String>>>>, Status>;

    /// Handle for when a PreprocessRequest comes in.
    ///
    /// # Arguments
    /// - `request`: The (`tonic::Request`-wrapped) PreprocessRequest containing the relevant details.
    ///
    /// # Returns
    /// A PreprocessReply for this request, wrapped in a `tonic::Response`.
    ///
    /// # Errors
    /// This function may error (i.e., send back a `tonic::Status`) whenever it fails.
    async fn preprocess(&self, request: Request<PreprocessRequest>) -> Result<Response<PreprocessReply>, Status>;

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

    /// Handle for when a CommitRequest comes in.
    ///
    /// # Arguments
    /// - `request`: The (`tonic::Request`-wrapped) CommitRequest containing the relevant details.
    ///
    /// # Returns
    /// A CommitReply for this request, wrapped in a `tonic::Response`.
    ///
    /// # Errors
    /// This function may error (i.e., send back a `tonic::Status`) whenever it fails.
    async fn commit(&self, request: Request<CommitRequest>) -> Result<Response<CommitReply>, Status>;
}

/// The `JobServiceServer` hosts the server part of the [`JobService`] protocol.
#[derive(Clone, Debug)]
pub struct JobServiceServer<T> {
    /// The service that we host.
    service: Arc<T>,
}

impl<T> JobServiceServer<T> {
    /// Constructor for the `JobServiceServer`.
    ///
    /// # Arguments
    /// - `service`: The Service to serve.
    ///
    /// # Returns
    /// A new `JobServiceServer` instance.
    #[inline]
    pub fn new(service: T) -> Self { Self { service: Arc::new(service) } }
}

impl<T, B> Service<http::Request<B>> for JobServiceServer<T>
where
    T: JobService,
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
            // Incoming CheckRequest
            "/job.JobService/CheckWorkflow" => {
                /// Helper struct for the given [`JobService`] that focusses specifically on this request.
                struct CheckWorkflowSvc<T>(Arc<T>);
                impl<T: JobService> UnaryService<Prost<CheckWorkflowRequest>> for CheckWorkflowSvc<T> {
                    type Future = BoxFuture<Response<Self::Response>, Status>;
                    type Response = Prost<CheckResponse<ManyReason<String>>>;

                    fn call(&mut self, req: Request<Prost<CheckWorkflowRequest>>) -> Self::Future {
                        // Return the service function as the future to run
                        let service = self.0.clone();
                        let fut = async move { (*service).check_workflow(req).await };
                        Box::pin(fut)
                    }
                }

                // Create a future that creates the service
                let service = self.service.clone();
                Box::pin(async move {
                    let method: CheckWorkflowSvc<T> = CheckWorkflowSvc(service);
                    let codec: ProstCodec<_, _> = ProstCodec::default();
                    let mut grpc: GrpcServer<ProstCodec<_, _>> = GrpcServer::new(codec);
                    Ok(grpc.unary(method, req).await)
                })
            },

            // Incoming CheckRequest
            "/job.JobService/CheckTask" => {
                /// Helper struct for the given [`JobService`] that focusses specifically on this request.
                struct CheckTaskSvc<T>(Arc<T>);
                impl<T: JobService> UnaryService<Prost<CheckTaskRequest>> for CheckTaskSvc<T> {
                    type Future = BoxFuture<Response<Self::Response>, Status>;
                    type Response = Prost<CheckResponse<ManyReason<String>>>;

                    fn call(&mut self, req: Request<Prost<CheckTaskRequest>>) -> Self::Future {
                        // Return the service function as the future to run
                        let service = self.0.clone();
                        let fut = async move { (*service).check_task(req).await };
                        Box::pin(fut)
                    }
                }

                // Create a future that creates the service
                let service = self.service.clone();
                Box::pin(async move {
                    let method: CheckTaskSvc<T> = CheckTaskSvc(service);
                    let codec: ProstCodec<_, _> = ProstCodec::default();
                    let mut grpc: GrpcServer<ProstCodec<_, _>> = GrpcServer::new(codec);
                    Ok(grpc.unary(method, req).await)
                })
            },

            // Incoming PreprocessRequest
            "/job.JobService/Preprocess" => {
                /// Helper struct for the given [`JobService`] that focusses specifically on this request.
                struct PreprocessSvc<T>(Arc<T>);
                impl<T: JobService> UnaryService<PreprocessRequest> for PreprocessSvc<T> {
                    type Future = BoxFuture<Response<Self::Response>, Status>;
                    type Response = PreprocessReply;

                    fn call(&mut self, req: Request<PreprocessRequest>) -> Self::Future {
                        // Return the service function as the future to run
                        let service = self.0.clone();
                        let fut = async move { (*service).preprocess(req).await };
                        Box::pin(fut)
                    }
                }

                // Create a future that creates the service
                let service = self.service.clone();
                Box::pin(async move {
                    let method: PreprocessSvc<T> = PreprocessSvc(service);
                    let codec: ProstCodec<_, _> = ProstCodec::default();
                    let mut grpc: GrpcServer<ProstCodec<_, _>> = GrpcServer::new(codec);
                    Ok(grpc.unary(method, req).await)
                })
            },

            // Incoming ExecuteRequest
            "/job.JobService/Execute" => {
                /// Helper struct for the given `DriverService` that focusses specifically on this request.
                struct ExecuteSvc<T>(Arc<T>);
                impl<T: JobService> ServerStreamingService<ExecuteRequest> for ExecuteSvc<T> {
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

            // Incoming CommitRequest
            "/job.JobService/Commit" => {
                /// Helper struct for the given [`JobService`] that focusses specifically on this request.
                struct CommitSvc<T>(Arc<T>);
                impl<T: JobService> UnaryService<CommitRequest> for CommitSvc<T> {
                    type Future = BoxFuture<Response<Self::Response>, Status>;
                    type Response = CommitReply;

                    fn call(&mut self, req: Request<CommitRequest>) -> Self::Future {
                        // Return the service function as the future to run
                        let service = self.0.clone();
                        let fut = async move { (*service).commit(req).await };
                        Box::pin(fut)
                    }
                }

                // Create a future that creates the service
                let service = self.service.clone();
                Box::pin(async move {
                    let method: CommitSvc<T> = CommitSvc(service);
                    let codec: ProstCodec<_, _> = ProstCodec::default();
                    let mut grpc: GrpcServer<ProstCodec<_, _>> = GrpcServer::new(codec);
                    Ok(grpc.unary(method, req).await)
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
impl<T: JobService> NamedService for JobServiceServer<T> {
    const NAME: &'static str = "job.JobService";
}
