use anyhow::Result;
use brane_clb::grpc::{CallbackKind, CallbackRequest, CallbackServiceClient};
// use brane_job::interface::FailureResult;
use libc::{strsignal, c_int, c_char};
use tracing::debug;
use std::error::Error;
use std::ffi::CStr;
use std::fmt::{Display, Formatter, Result as FResult};
use std::sync::atomic::{AtomicI32, Ordering};
use tonic::transport::Channel;


/***** CONSTANTS *****/
/// The default name of a signal in case strsignal fails.
const UNKNOWN_SIGNAL_NAME: &str = "UNKNOWN";





/***** ERRORS *****/
/// Collects all Callback-related errors
#[derive(Debug)]
pub enum CallbackError {
    /// Could not connect to the remote callback server
    ConnectError{ address: String, err: tonic::transport::Error },
    /// Could not send a callback
    SendError{ kind: String, err: tonic::Status },

    /// Could not serialize a given struct of code, stdout & stderr
    FailureSerializeError{ err: serde_json::Error },
}

impl Display for CallbackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            CallbackError::ConnectError{ address, err } => write!(f, "Could not connect to remote gRPC callback server at '{}': {}", address, err),
            CallbackError::SendError{ kind, err }       => write!(f, "Could not send {} callback:  status {}", kind, err),

            CallbackError::FailureSerializeError{ err } => write!(f, "Could not serialize output from failed job: {}", err),
        }
    }
}

impl Error for CallbackError {}





/***** CALLBACK *****/
/// An instance that represents a connection to a remote callback node.
pub struct Callback {
    application_id: String,
    location_id: String,
    job_id: String,
    event_counter: AtomicI32,
    client: CallbackServiceClient<Channel>,
}

impl Callback {
    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Constructor for the Callback.
    /// 
    /// **Arguments**
    ///  * `application_id`: The ID of the application that this branelet is working for.
    ///  * `location_id`: The ID of the location where we are currently running.
    ///  * `job_id`: The ID of the job that we're executing.
    ///  * `callback_to`: The address where this instance will report callbacks to.
    /// 
    /// **Returns**  
    /// The new Callback instance on success, or a CallbackError on failure.
    pub async fn new<S: Into<String>>(
        application_id: S,
        location_id: S,
        job_id: S,
        callback_to: S,
    ) -> Result<Self, CallbackError> {
        // Conver the string-like callback_to to a string
        let callback_to = callback_to.into();

        // Create the gRPC channel
        debug!("Setting up a callback channel to: {}.", callback_to);
        let client = match CallbackServiceClient::connect(callback_to.to_string()).await {
            Ok(client) => client,
            Err(err)   => { return Err(CallbackError::ConnectError{ address: callback_to, err }); }
        };

        // Create the instance
        Ok(Callback {
            application_id: application_id.into(),
            location_id: location_id.into(),
            job_id: job_id.into(),
            event_counter: AtomicI32::new(1),
            client,
        })
    }

    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Performs a callback call to the remote callback.
    /// 
    /// **Arguments**
    ///  * `kind`: The kind of the callback as a number of any sort.
    ///  * `payload`: Optional payload to send along with the callback.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    async fn call(
        &mut self,
        kind: CallbackKind,
        payload: Option<Vec<u8>>,
    ) -> Result<(), CallbackError> {
        // Get this message's order ID
        let order = self.event_counter.fetch_add(1, Ordering::Release);

        // Create the request
        let request = CallbackRequest {
            application: self.application_id.clone(),
            location: self.location_id.clone(),
            job: self.job_id.clone(),
            kind: kind.into(),
            order,
            payload: payload.unwrap_or_default(),
        };

        // Send the client on its way
        debug!("Reached target: {:?}", kind);
        match self.client.callback(request).await {
            Ok(_)    => Ok(()),
            Err(err) => Err(CallbackError::SendError{ kind: format!("{:?}", kind), err }),
        }
    }

    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Sends a Ready callback to the remote callback node.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn ready(&mut self) -> Result<(), CallbackError> {
        self.call(CallbackKind::Ready, None).await
    }

    /// Sends an InitializeFail callback to the remote callback node.
    /// 
    /// **Arguments**
    ///  * `err`: String description of why we failed to intialize.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.\
    #[inline]
    pub async fn initialize_failed(&mut self, err: String) -> Result<(), CallbackError> {
        self.call(CallbackKind::InitializeFailed, Some(err.as_bytes().to_vec())).await
    }
    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Sends an Initialized callback to the remote callback node.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn initialized(&mut self) -> Result<(), CallbackError> {
        self.call(CallbackKind::Initialized, None).await
    }

    /// Sends an StartFailed callback to the remote callback node.
    /// 
    /// **Arguments**
    ///  * `err`: String description of why we failed to start.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.\
    #[inline]
    pub async fn start_failed(&mut self, err: String) -> Result<(), CallbackError> {
        self.call(CallbackKind::StartFailed, Some(err.as_bytes().to_vec())).await
    }
    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Sends a Started callback to the remote callback node.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn started(&mut self) -> Result<(), CallbackError> {
        self.call(CallbackKind::Started, None).await
    }

    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Sends a Heartbeat callback to the remote callback node.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn heartbeat(&mut self) -> Result<(), CallbackError> {
        self.call(CallbackKind::Heartbeat, None).await
    }
    /// Sends a CompleteFailed callback to the remote callback node.
    /// 
    /// **Arguments**
    ///  * `err`: The reason why waiting for the package to finish failed.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn complete_failed(&mut self, err: String) -> Result<(), CallbackError> {
        self.call(CallbackKind::CompleteFailed, Some(err.as_bytes().to_vec())).await
    }
    /// Sends a Completed callback to the remote callback node.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn completed(&mut self) -> Result<(), CallbackError> {
        self.call(CallbackKind::Completed, None).await
    }

    /// Sends a DecodeFailed to te remote callback node.
    /// 
    /// **Arguments**
    ///  * `err`: The reason why decoding the package output failed.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn decode_failed(&mut self, err: String) -> Result<(), CallbackError> {
        self.call(CallbackKind::DecodeFailed, Some(err.as_bytes().to_vec())).await
    }
    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Sends a Stopped callback to the remote callback node.
    /// 
    /// **Arguments**
    ///  * `signal`: The signal with which the package was stopped.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn stopped(&mut self, signal: i32) -> Result<(), CallbackError> {
        // Try to map the signal to a name
        let signal_name: String;
        unsafe {
            // Call strsignal to get the name
            let raw_signal_name: *mut c_char = strsignal(signal as c_int);
            if raw_signal_name.is_null() { signal_name = String::from(UNKNOWN_SIGNAL_NAME); }
            else {
                // Try to translate it to a string
                let c_signal_name = CStr::from_ptr(raw_signal_name);
                signal_name = match c_signal_name.to_str() {
                    Ok(signal_name) => String::from(signal_name),
                    Err(_)          => String::from(UNKNOWN_SIGNAL_NAME),
                };
            }
        }

        // Write the string version of the signal
        self.call(CallbackKind::Stopped, Some(signal_name.as_bytes().to_vec())).await
    }
    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Sends a Failed callback to the remote callback node.
    /// 
    /// **Arguments**
    ///  * `code`: The return code of the job executable.
    ///  * `stdout`: The output of the job executable.
    ///  * `stderr`: The error-side output of the job executable.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    pub async fn failed(&mut self, code: i32, stdout: String, stderr: String) -> Result<(), CallbackError> {
        // Encode the strings as the JSON intermediate representation
        let payload_text = match serde_json::to_string(&(code, stdout, stderr)) {
            Ok(payload_text) => payload_text,
            Err(err)         => { return Err(CallbackError::FailureSerializeError{ err }); }
        };
        let payload = payload_text.as_bytes().to_vec();

        // Perform the call
        self.call(CallbackKind::Failed, Some(payload)).await
    }
    /// **Edited: now returning CallbackErrors.**
    /// 
    /// Sends a Finished callback to the remote callback node.
    /// 
    /// **Arguments**
    ///  * `raw_result`: The raw results as a string to send back to the calling Driver.
    /// 
    /// **Returns**  
    /// Nothing when the call was sent successfully, or a CallbackError otherwise.
    #[inline]
    pub async fn finished(&mut self, raw_result: String) -> Result<(), CallbackError> {
        self.call(CallbackKind::Finished, Some(raw_result.as_bytes().to_vec())).await
    }
}
