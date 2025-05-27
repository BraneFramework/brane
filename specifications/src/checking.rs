//  CHECKING.rs
//    by Lut99
//
//  Created:
//    07 Feb 2024, 11:54:14
//  Last edited:
//    02 May 2025, 15:01:38
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines interface structs & constants necessary for communication
//!   with the `policy-reasoner`.
//


/***** APIS *****/
/// Defines the interface to the policy store API.
pub mod store {
    use policy_reasoner::reasoners::eflint_haskell::EFlintHaskellReasonerContext;
    // Re-export everything from the axum server
    pub use policy_store::servers::axum::spec::*;
    use reqwest::Method;
    use serde::{Deserialize, Serialize};


    /// Define the additional reasoner context endpoint
    pub const GET_CONTEXT_PATH: EndpointPath = EndpointPath { method: Method::GET, path: "/v2/context" };


    /// Defines the response of getting the reasoner context.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct GetContextResponse {
        /// The context as returned by the reasoner
        pub context: EFlintHaskellReasonerWithInterfaceContext,
    }

    /// Defines the context for the eFLINT reasoner.
    pub type EFlintHaskellReasonerWithInterfaceContext = EFlintHaskellReasonerContext;
}





/// Defines the interface to the policy deliberation API.
pub mod deliberation {
    use std::error::Error;
    use std::fmt::{Display, Formatter, Result as FResult};

    use policy_reasoner::spec::reasonerconn::ReasonerResponse;
    use policy_reasoner::spec::reasons::ManyReason;
    use policy_store::servers::axum::spec::EndpointPath;
    use prost::bytes::{Buf, BufMut};
    use prost::encoding::{DecodeContext, WireType};
    use prost::{DecodeError, Message};
    use reqwest::Method;
    use serde::{Deserialize, Serialize};

    use crate::pc::ProgramCounter;
    use crate::wir::Workflow;


    /***** CONSTANTS *****/
    /// Defines the API path to check if a workflow as a whole is permitted to be executed.
    pub const CHECK_WORKFLOW_PATH: EndpointPath = EndpointPath { method: Method::GET, path: "/v2/workflow" };
    /// Defines the API path to check if a task in a workflow is permitted to be executed.
    pub const CHECK_TASK_PATH: EndpointPath = EndpointPath { method: Method::GET, path: "/v2/task" };
    /// Defines the API path to check if a dataset in a workflow is permitted to be transferred.
    pub const CHECK_TRANSFER_PATH: EndpointPath = EndpointPath { method: Method::GET, path: "/v2/transfer" };





    /***** ERRORS *****/
    /// Failed to decode one of the requests.
    #[derive(Debug)]
    pub enum RequestDecodeError {
        /// Failed to decode the workflow in the request.
        Workflow { err: serde_json::Error },
        /// Failed to decode the task in the request.
        Task { err: serde_json::Error },
    }
    impl Display for RequestDecodeError {
        #[inline]
        fn fmt(&self, f: &mut Formatter) -> FResult {
            match self {
                Self::Workflow { .. } => write!(f, "Failed to parse workflow in message"),
                Self::Task { .. } => write!(f, "Failed to parse task in message"),
            }
        }
    }
    impl Error for RequestDecodeError {
        #[inline]
        fn source(&self) -> Option<&(dyn 'static + Error)> {
            match self {
                Self::Workflow { err } => Some(err),
                Self::Task { err } => Some(err),
            }
        }
    }





    /***** AUXILLARY *****/
    /// Defines a wrapper around some other struct such that we can wrap one of its fields as a serde
    /// JSON implementation.
    #[derive(Clone, Debug)]
    pub struct Prost<R> {
        /// The actual request
        request: R,
        /// The string buffer we use for parsing.
        buffers: Vec<String>,
    }





    /***** API BODIES *****/
    /// Defines the request to send to the workflow validation endpoint.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct CheckWorkflowRequest {
        /// The usecase that refers to the API to consult for state.
        pub usecase:  String,
        /// The workflow we're parsing.
        pub workflow: Workflow,
    }

    // Prost impl for the CheckWorkflowRequest
    impl Default for Prost<CheckWorkflowRequest> {
        #[inline]
        fn default() -> Self {
            Self { request: CheckWorkflowRequest { usecase: String::new(), workflow: Workflow::default() }, buffers: vec![String::new()] }
        }
    }
    impl Prost<CheckWorkflowRequest> {
        /// Constructor for the Prost that creates it from an existing request.
        ///
        /// When encoding something, this is needed to properly encode it.
        ///
        /// # Arguments
        /// - `request`: The `R`equest to be encoded.
        ///
        /// # Returns
        /// A new Prost, ready to be encoded.
        pub fn new(request: CheckWorkflowRequest) -> Self {
            // Serialize the workflow first
            let wf: String = match serde_json::to_string(&request.workflow) {
                Ok(wf) => wf,
                Err(err) => panic!("Failed to serialize given workflow: {err}"),
            };

            // OK, return self
            Self { request, buffers: vec![wf] }
        }

        /// Retrieves the internal request.
        ///
        /// Note that this may fail, as the embedded workflow won't be parsed up until this moment.
        ///
        /// # Returns
        /// A new [`CheckWorkflowRequest`] that is ready to use.
        ///
        /// # Errors
        /// This function fails if we failed to parse the internal workflow.
        pub fn into_inner(mut self) -> Result<CheckWorkflowRequest, RequestDecodeError> {
            self.request.workflow = serde_json::from_str(&self.buffers[0]).map_err(|err| RequestDecodeError::Workflow { err })?;
            Ok(self.request)
        }
    }
    impl Message for Prost<CheckWorkflowRequest> {
        fn encode_raw(&self, buf: &mut impl BufMut)
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            if !self.request.usecase.is_empty() {
                ::prost::encoding::string::encode(1u32, &self.request.usecase, buf);
            }
            if !self.buffers[0].is_empty() {
                ::prost::encoding::string::encode(2u32, &self.buffers[0], buf);
            }
        }

        fn merge_field(&mut self, tag: u32, wire_type: WireType, buf: &mut impl Buf, ctx: DecodeContext) -> Result<(), DecodeError>
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            const STRUCT_NAME: &str = "CheckWorkflowRequest";
            match tag {
                1u32 => ::prost::encoding::string::merge(wire_type, &mut self.request.usecase, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "usecase");
                    error
                }),
                2u32 => ::prost::encoding::string::merge(wire_type, &mut self.buffers[0], buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "workflow");
                    error
                }),
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }

        fn encoded_len(&self) -> usize {
            // This is copied from the auto-generated prost code but only for the fields in question
            let mut len: usize = 0;
            if !self.request.usecase.is_empty() {
                len += ::prost::encoding::string::encoded_len(1u32, &self.request.usecase);
            }
            if !self.buffers[0].is_empty() {
                len += ::prost::encoding::string::encoded_len(2u32, &self.buffers[0])
            }
            len
        }

        fn clear(&mut self) {
            // This is copied from the auto-generated prost code but only for the fields in question
            self.request.usecase.clear();
            self.buffers[0].clear();
        }
    }



    /// Defines the request to send to the task validation endpoint.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct CheckTaskRequest {
        /// The usecase that refers to the API to consult for state.
        pub usecase:  String,
        /// The workflow we're parsing.
        pub workflow: Workflow,
        /// The task in the workflow that we want to check specifically.
        pub task:     ProgramCounter,
    }

    // Prost impl for the CheckWorkflowRequest
    impl Default for Prost<CheckTaskRequest> {
        #[inline]
        fn default() -> Self {
            Self {
                request: CheckTaskRequest { usecase: String::new(), workflow: Workflow::default(), task: ProgramCounter::default() },
                buffers: vec![String::new(), String::new()],
            }
        }
    }
    impl Prost<CheckTaskRequest> {
        /// Constructor for the Prost that creates it from an existing request.
        ///
        /// When encoding something, this is needed to properly encode it.
        ///
        /// # Arguments
        /// - `request`: The `R`equest to be encoded.
        ///
        /// # Returns
        /// A new Prost, ready to be encoded.
        pub fn new(request: CheckTaskRequest) -> Self {
            // Serialize the workflow & PC first
            let wf: String = match serde_json::to_string(&request.workflow) {
                Ok(wf) => wf,
                Err(err) => panic!("Failed to serialize given workflow: {err}"),
            };
            let pc: String = match serde_json::to_string(&request.task) {
                Ok(pc) => pc,
                Err(err) => panic!("Failed to serialize given program counter: {err}"),
            };

            // OK, return self
            Self { request, buffers: vec![wf, pc] }
        }

        /// Retrieves the internal request.
        ///
        /// Note that this may fail, as the embedded workflow won't be parsed up until this moment.
        ///
        /// # Returns
        /// A new [`CheckTaskRequest`] that is ready to use.
        ///
        /// # Errors
        /// This function fails if we failed to parse the internal workflow.
        pub fn into_inner(mut self) -> Result<CheckTaskRequest, RequestDecodeError> {
            self.request.workflow = serde_json::from_str(&self.buffers[0]).map_err(|err| RequestDecodeError::Workflow { err })?;
            self.request.task = serde_json::from_str(&self.buffers[1]).map_err(|err| RequestDecodeError::Task { err })?;
            Ok(self.request)
        }
    }
    impl Message for Prost<CheckTaskRequest> {
        fn encode_raw(&self, buf: &mut impl BufMut)
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            if !self.request.usecase.is_empty() {
                ::prost::encoding::string::encode(1u32, &self.request.usecase, buf);
            }
            if !self.buffers[0].is_empty() {
                ::prost::encoding::string::encode(2u32, &self.buffers[0], buf);
            }
            if !self.buffers[1].is_empty() {
                ::prost::encoding::string::encode(3u32, &self.buffers[1], buf);
            }
        }

        fn merge_field(&mut self, tag: u32, wire_type: WireType, buf: &mut impl Buf, ctx: DecodeContext) -> Result<(), DecodeError>
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            const STRUCT_NAME: &str = "CheckTaskRequest";
            match tag {
                1u32 => ::prost::encoding::string::merge(wire_type, &mut self.request.usecase, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "usecase");
                    error
                }),
                2u32 => ::prost::encoding::string::merge(wire_type, &mut self.buffers[0], buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "workflow");
                    error
                }),
                3u32 => ::prost::encoding::string::merge(wire_type, &mut self.buffers[1], buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "task");
                    error
                }),
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }

        fn encoded_len(&self) -> usize {
            // This is copied from the auto-generated prost code but only for the fields in question
            let mut len: usize = 0;
            if !self.request.usecase.is_empty() {
                len += ::prost::encoding::string::encoded_len(1u32, &self.request.usecase);
            }
            if !self.buffers[0].is_empty() {
                len += ::prost::encoding::string::encoded_len(2u32, &self.buffers[0]);
            }
            if !self.buffers[1].is_empty() {
                len += ::prost::encoding::string::encoded_len(3u32, &self.buffers[1]);
            }
            len
        }

        fn clear(&mut self) {
            // This is copied from the auto-generated prost code but only for the fields in question
            self.request.usecase.clear();
            self.buffers[0].clear();
            self.buffers[1].clear();
        }
    }



    /// Defines the request to send to the transfer validation endpoint.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct CheckTransferRequest {
        /// The usecase that refers to the API to consult for state.
        pub usecase:  String,
        /// The workflow we're parsing.
        pub workflow: Workflow,
        /// The task in the workflow that we want to check specifically.
        pub task:     Option<ProgramCounter>,
        /// The input in the task that we want to check specifically.
        pub input:    String,
    }

    // Prost impl for the CheckWorkflowRequest
    impl Default for Prost<CheckTransferRequest> {
        #[inline]
        fn default() -> Self {
            Self {
                request: CheckTransferRequest {
                    usecase:  String::new(),
                    workflow: Workflow::default(),
                    task:     Some(ProgramCounter::default()),
                    input:    String::new(),
                },
                buffers: vec![String::new(), String::new()],
            }
        }
    }
    impl Prost<CheckTransferRequest> {
        /// Constructor for the Prost that creates it from an existing request.
        ///
        /// When encoding something, this is needed to properly encode it.
        ///
        /// # Arguments
        /// - `request`: The `R`equest to be encoded.
        ///
        /// # Returns
        /// A new Prost, ready to be encoded.
        pub fn new(request: CheckTransferRequest) -> Self {
            // Serialize the workflow & PC first
            let wf: String = match serde_json::to_string(&request.workflow) {
                Ok(wf) => wf,
                Err(err) => panic!("Failed to serialize given workflow: {err}"),
            };
            let pc: String = match serde_json::to_string(&request.task) {
                Ok(pc) => pc,
                Err(err) => panic!("Failed to serialize given program counter: {err}"),
            };

            // OK, return self
            Self { request, buffers: vec![wf, pc] }
        }

        /// Retrieves the internal request.
        ///
        /// Note that this may fail, as the embedded workflow won't be parsed up until this moment.
        ///
        /// # Returns
        /// A new [`CheckTransferRequest`] that is ready to use.
        ///
        /// # Errors
        /// This function fails if we failed to parse the internal workflow.
        pub fn into_inner(mut self) -> Result<CheckTransferRequest, RequestDecodeError> {
            self.request.workflow = serde_json::from_str(&self.buffers[0]).map_err(|err| RequestDecodeError::Workflow { err })?;
            self.request.task = serde_json::from_str(&self.buffers[1]).map_err(|err| RequestDecodeError::Task { err })?;
            Ok(self.request)
        }
    }
    impl Message for Prost<CheckTransferRequest> {
        fn encode_raw(&self, buf: &mut impl BufMut)
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            if !self.request.usecase.is_empty() {
                ::prost::encoding::string::encode(1u32, &self.request.usecase, buf);
            }
            if !self.buffers[0].is_empty() {
                ::prost::encoding::string::encode(2u32, &self.buffers[0], buf);
            }
            if !self.buffers[1].is_empty() {
                ::prost::encoding::string::encode(3u32, &self.buffers[1], buf);
            }
            if !self.request.input.is_empty() {
                ::prost::encoding::string::encode(4u32, &self.request.input, buf);
            }
        }

        fn merge_field(&mut self, tag: u32, wire_type: WireType, buf: &mut impl Buf, ctx: DecodeContext) -> Result<(), DecodeError>
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            const STRUCT_NAME: &str = "CheckTaskRequest";
            match tag {
                1u32 => ::prost::encoding::string::merge(wire_type, &mut self.request.usecase, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "usecase");
                    error
                }),
                2u32 => ::prost::encoding::string::merge(wire_type, &mut self.buffers[0], buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "workflow");
                    error
                }),
                3u32 => ::prost::encoding::string::merge(wire_type, &mut self.buffers[1], buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "task");
                    error
                }),
                4u32 => ::prost::encoding::string::merge(wire_type, &mut self.request.input, buf, ctx).map_err(|mut error| {
                    error.push(STRUCT_NAME, "input");
                    error
                }),
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }

        fn encoded_len(&self) -> usize {
            // This is copied from the auto-generated prost code but only for the fields in question
            let mut len: usize = 0;
            if !self.request.usecase.is_empty() {
                len += ::prost::encoding::string::encoded_len(1u32, &self.request.usecase);
            }
            if !self.buffers[0].is_empty() {
                len += ::prost::encoding::string::encoded_len(2u32, &self.buffers[0]);
            }
            if !self.buffers[1].is_empty() {
                len += ::prost::encoding::string::encoded_len(3u32, &self.buffers[1]);
            }
            if !self.request.input.is_empty() {
                len += ::prost::encoding::string::encoded_len(1u32, &self.request.input);
            }
            len
        }

        fn clear(&mut self) {
            // This is copied from the auto-generated prost code but only for the fields in question
            self.request.usecase.clear();
            self.buffers[0].clear();
            self.buffers[1].clear();
            self.request.input.clear();
        }
    }



    /// Defines the result of the three checking endpoints.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct CheckResponse<R> {
        /// The result
        pub verdict: ReasonerResponse<R>,
    }

    // Prost impl for the CheckResponse
    impl Default for Prost<CheckResponse<ManyReason<String>>> {
        #[inline]
        fn default() -> Self { Self { request: CheckResponse { verdict: ReasonerResponse::Success }, buffers: vec!["1".into()] } }
    }
    impl Prost<CheckResponse<ManyReason<String>>> {
        /// Constructor for the Prost that creates it from an existing request.
        ///
        /// When encoding something, this is needed to properly encode it.
        ///
        /// # Arguments
        /// - `request`: The `R`equest to be encoded.
        ///
        /// # Returns
        /// A new Prost, ready to be encoded.
        pub fn new(request: CheckResponse<ManyReason<String>>) -> Self {
            // Build the buffers accordingly
            let mut buffers = Vec::with_capacity(1 + if let ReasonerResponse::Violated(reasons) = &request.verdict { reasons.len() } else { 0 });
            buffers.push(if matches!(request.verdict, ReasonerResponse::Success) { "1".to_string() } else { "0".to_string() });
            if let ReasonerResponse::Violated(reasons) = request.verdict {
                for reason in reasons.into_iter() {
                    buffers.push(reason);
                }
            }

            // OK, return self
            Self { request: CheckResponse { verdict: ReasonerResponse::Success }, buffers }
        }

        /// Retrieves the internal request.
        ///
        /// Note that this may fail, as the embedded workflow won't be parsed up until this moment.
        ///
        /// # Returns
        /// A new [`CheckResponse`] that is ready to use.
        ///
        /// # Errors
        /// This function fails if we failed to parse the internal workflow.
        pub fn into_inner(mut self) -> CheckResponse<ManyReason<String>> {
            if self.buffers[0] == "1" {
                CheckResponse { verdict: ReasonerResponse::Success }
            } else {
                CheckResponse { verdict: ReasonerResponse::Violated(self.buffers.drain(1..).collect()) }
            }
        }
    }
    impl Message for Prost<CheckResponse<ManyReason<String>>> {
        fn encode_raw(&self, buf: &mut impl BufMut)
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            ::prost::encoding::bool::encode(1u32, &(self.buffers[0] == "1"), buf);
            ::prost::encoding::string::encode_repeated(2u32, &self.buffers[1..], buf);
        }

        fn merge_field(&mut self, tag: u32, wire_type: WireType, buf: &mut impl Buf, ctx: DecodeContext) -> Result<(), DecodeError>
        where
            Self: Sized,
        {
            // This is copied from the auto-generated prost code but only for the fields in question
            const STRUCT_NAME: &str = "CheckResponse";
            match tag {
                1u32 => {
                    let mut value = self.buffers[0] == "1";
                    ::prost::encoding::bool::merge(wire_type, &mut value, buf, ctx).map_err(|mut error| {
                        error.push(STRUCT_NAME, "success");
                        error
                    })?;
                    if value {
                        self.buffers[0] = "1".into();
                    } else {
                        self.buffers[0] = "0".into();
                    }
                    Ok(())
                },
                2u32 => {
                    let mut buffers: Vec<String> = self.buffers.drain(1..).collect();
                    ::prost::encoding::string::merge_repeated(wire_type, &mut buffers, buf, ctx).map_err(|mut error| {
                        error.push(STRUCT_NAME, "reasons");
                        error
                    })?;
                    self.buffers.extend(buffers);
                    Ok(())
                },
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }

        fn encoded_len(&self) -> usize {
            // This is copied from the auto-generated prost code but only for the fields in question
            let mut len: usize = 0;
            if !self.buffers[0].is_empty() {
                len += ::prost::encoding::string::encoded_len(1u32, &self.buffers[0]);
            }
            len += ::prost::encoding::string::encoded_len_repeated(2u32, &self.buffers[1..]);
            len
        }

        fn clear(&mut self) {
            // This is copied from the auto-generated prost code but only for the fields in question
            self.buffers[0].clear();
            self.buffers.truncate(1);
        }
    }
}
