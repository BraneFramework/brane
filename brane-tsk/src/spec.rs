//  SPEC.rs
//    by Lut99
//
//  Created:
//    24 Oct 2022, 16:42:17
//  Last edited:
//    14 Nov 2024, 17:23:56
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines (public) interfaces and structs for the `brane-tsk` crate.
//

use std::fmt::{Display, Formatter, Result as FResult};
use std::str::FromStr;

use brane_exe::FullValue;
use log::warn;
use specifications::wir::Workflow;
use specifications::working::TaskStatus;
use uuid::Uuid;

use crate::errors::{ExecuteError, IdError, PlanError};


/***** HELPER MACROS *****/
/// Defines a helper macro that checks if the string is actually None before returning the value.
macro_rules! return_status {
    (JobStatus:: $status:ident, $str:ident) => {{
        if !$str.is_none() {
            warn!("Given string is not None (but it isn't used)");
        }
        Ok(JobStatus::$status)
    }};
}

/// Defines a helper macro that takes a string for a JobStatus before returning it.
macro_rules! return_status_str {
    (JobStatus:: $status:ident, $str:ident) => {{ if let Some(s) = $str { Ok(JobStatus::$status(s)) } else { Err(ExecuteError::StatusEmptyStringError { status: TaskStatus::$status }) } }};
}

/// Defines a helper macro that parses a value for a JobStatus before returning it.
macro_rules! return_status_val {
    (JobStatus:: $status:ident, $str:ident) => {{
        if let Some(s) = $str {
            match serde_json::from_str(&s) {
                Ok(val) => Ok(JobStatus::$status(val)),
                Err(source) => Err(ExecuteError::StatusValueParseError { status: TaskStatus::$status, raw: s, source }),
            }
        } else {
            Err(ExecuteError::StatusEmptyStringError { status: TaskStatus::$status })
        }
    }};
}

/// Defines a helper macro that parses a code, stdout, stderr triplet for a JobStatus before returning it.
macro_rules! return_status_failed {
    (JobStatus:: $status:ident, $str:ident) => {{
        if let Some(s) = $str {
            match serde_json::from_str::<(i32, String, String)>(&s) {
                Ok((code, stdout, stderr)) => Ok(JobStatus::$status(code, stdout, stderr)),
                Err(source) => Err(ExecuteError::StatusTripletParseError { status: TaskStatus::$status, raw: s, source }),
            }
        } else {
            Err(ExecuteError::StatusEmptyStringError { status: TaskStatus::$status })
        }
    }};
}





/***** LIBRARY *****/
/// Special constant that marks it needs to be run on the local machine.
pub const LOCALHOST: &str = "localhost";



/// Defines an application identifier, which is used to identify... applications... (wow)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AppId(Uuid);

impl AppId {
    /// Generate a new AppId.
    ///
    /// # Returns
    /// A new instance of a AppId that is practically unique.
    pub fn generate() -> Self { Self(Uuid::new_v4()) }
}

impl From<&AppId> for AppId {
    #[inline]
    fn from(value: &AppId) -> Self { value.clone() }
}
impl AsRef<AppId> for AppId {
    #[inline]
    fn as_ref(&self) -> &AppId { self }
}

impl From<AppId> for String {
    #[inline]
    fn from(value: AppId) -> Self { Self::from(&value) }
}
impl From<&AppId> for String {
    #[inline]
    fn from(value: &AppId) -> Self { value.0.to_string() }
}
impl Display for AppId {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", self.0) }
}

impl FromStr for AppId {
    type Err = IdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match Uuid::from_str(value) {
            Ok(uuid) => Ok(Self(uuid)),
            Err(source) => Err(IdError::ParseError { what: "AppId", raw: value.into(), source }),
        }
    }
}



/// Defines a unique identifier used to distinguish individual task submissions within a coherent workflow.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TaskId(Uuid);

impl TaskId {
    /// Generate a new AppId.
    ///
    /// # Returns
    /// A new instance of a AppId that is practically unique.
    pub fn generate() -> Self { Self(Uuid::new_v4()) }
}

impl From<&TaskId> for TaskId {
    #[inline]
    fn from(value: &TaskId) -> Self { value.clone() }
}
impl AsRef<TaskId> for TaskId {
    #[inline]
    fn as_ref(&self) -> &TaskId { self }
}

impl From<TaskId> for String {
    #[inline]
    fn from(value: TaskId) -> Self { Self::from(&value) }
}
impl From<&TaskId> for String {
    #[inline]
    fn from(value: &TaskId) -> Self { value.0.to_string() }
}
impl Display for TaskId {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", self.0) }
}

impl FromStr for TaskId {
    type Err = IdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match Uuid::from_str(value) {
            Ok(uuid) => Ok(Self(uuid)),
            Err(source) => Err(IdError::ParseError { what: "TaskId", raw: value.into(), source }),
        }
    }
}



/// Defines a common interface for planners. This is mostly for software engineering reasons, and not really due to the need to have them interchangeable.
#[async_trait::async_trait]
pub trait Planner {
    /// Plans the given workflow by:
    /// - resolving every `at` at every Node to have a location that makes sense for this instance; and
    /// - populating the matching RuntimeDataIndex, that hosts information on accessing both datasets and intermediate results.
    ///
    /// # Arguments
    /// - `workflow`: The workflow to plan.
    ///
    /// # Returns
    /// A tuple of same workflow, but now with planned nodes, and the new RuntimeDataIndex.
    async fn plan(&self, workflow: Workflow) -> Result<Workflow, PlanError>;
}



/// Defines the possible states a job can have.
#[derive(Clone, Debug)]
pub enum JobStatus {
    // Meta events
    /// No status yet / unknown
    Unknown,

    // Job events
    /// The job has been received by the job node.
    Received,

    // Checker events
    /// The job has been authorized by the job's checker(s).
    Authorized,
    /// The job has been denied by the job's checker(s).
    Denied,
    /// Authorization has failed.
    AuthorizationFailed(String),

    // Creation events
    /// The job container has been created.
    Created,
    /// We failed to create the job container.
    CreationFailed(String),

    // Initialization events
    /// The branelet has been booted (first event it sends).
    Ready,
    /// The branelet node has been initialized; now only to spawn the job itself.
    Initialized,
    /// We failed to initialize branelet.
    InitializationFailed(String),
    /// The actual subcall executeable / script has started
    Started,
    /// The subprocess executable did not want to start (calling it failed)
    StartingFailed(String),

    // Progress events
    /// Occassional message to let the user know the container is alive and running
    Heartbeat,
    /// The package call went successfully from the branelet's side
    Completed,
    /// The package call went wrong from the branelet's side
    CompletionFailed(String),

    // Finish events
    /// The container has exited with a zero status code (and returned the given value, which may be Void)
    Finished(FullValue),
    /// The container was interrupted by the Job node
    Stopped,
    /// brane-let could not decode the output from the package call
    DecodingFailed(String),
    /// The container has exited with a non-zero status code
    Failed(i32, String, String),
}

impl JobStatus {
    /// Attempts to parse the given status & value into a JobStatus.
    ///
    /// # Arguments
    /// - `status`: The ExecuteState that provides the wire status.
    /// - `value`: The optional String value that we will parse to values or errors.
    ///
    /// # Returns
    /// A new JobStatus instance.
    ///
    /// # Errors
    /// This function errors if we failed to parse the string, or it was None when we expected Some.
    pub fn from_status(status: TaskStatus, value: Option<String>) -> Result<Self, ExecuteError> {
        // Match on the status
        use TaskStatus::*;
        match status {
            Unknown => {
                return_status!(JobStatus::Unknown, value)
            },

            Received => {
                return_status!(JobStatus::Received, value)
            },

            Authorized => {
                return_status!(JobStatus::Authorized, value)
            },
            Denied => {
                return_status!(JobStatus::Denied, value)
            },
            AuthorizationFailed => {
                return_status_str!(JobStatus::AuthorizationFailed, value)
            },

            Created => {
                return_status!(JobStatus::Created, value)
            },
            CreationFailed => {
                return_status_str!(JobStatus::CreationFailed, value)
            },

            Ready => {
                return_status!(JobStatus::Ready, value)
            },
            Initialized => {
                return_status!(JobStatus::Initialized, value)
            },
            InitializationFailed => {
                return_status_str!(JobStatus::InitializationFailed, value)
            },
            Started => {
                return_status!(JobStatus::Started, value)
            },
            StartingFailed => {
                return_status_str!(JobStatus::StartingFailed, value)
            },

            Heartbeat => {
                return_status!(JobStatus::Heartbeat, value)
            },
            Completed => {
                return_status!(JobStatus::Completed, value)
            },
            CompletionFailed => {
                return_status_str!(JobStatus::CompletionFailed, value)
            },

            Finished => {
                return_status_val!(JobStatus::Finished, value)
            },
            Stopped => {
                return_status!(JobStatus::Stopped, value)
            },
            DecodingFailed => {
                return_status_str!(JobStatus::DecodingFailed, value)
            },
            Failed => {
                return_status_failed!(JobStatus::Failed, value)
            },
        }
    }

    /// Returns whether this status is a heartbeat.
    #[inline]
    pub fn is_heartbeat(&self) -> bool { matches!(self, Self::Heartbeat) }

    /// Converts the JobStatus into some 'progress index', which is a number that can be used to determine if some JobStatus logically should be send after another.
    ///
    /// # Returns
    /// A number representing the progress index. If it's higher than that of another JobStatus, this indicates its part of a later 'step' in the process.
    pub fn progress_index(&self) -> u32 {
        use JobStatus::*;
        match self {
            Unknown => 0,

            Received => 1,

            Authorized => 2,
            Denied => 2,
            AuthorizationFailed(_) => 2,

            Created => 3,
            CreationFailed(_) => 3,

            Ready => 4,
            Initialized => 5,
            InitializationFailed(_) => 5,
            Started => 6,
            StartingFailed(_) => 6,

            Heartbeat => 7,
            Completed => 8,
            CompletionFailed(_) => 8,

            DecodingFailed(_) => 9,
            Finished(_) => 10,
            Stopped => 10,
            Failed(_, _, _) => 10,
        }
    }
}

impl PartialEq for JobStatus {
    fn eq(&self, other: &Self) -> bool { TaskStatus::from(self) as i32 == TaskStatus::from(other) as i32 }
}

impl From<JobStatus> for TaskStatus {
    fn from(value: JobStatus) -> Self { Self::from(&value) }
}
impl From<&JobStatus> for TaskStatus {
    fn from(value: &JobStatus) -> Self {
        use JobStatus::*;
        match value {
            Unknown => Self::Unknown,

            Received => Self::Received,

            Authorized => Self::Authorized,
            Denied => Self::Denied,
            AuthorizationFailed(_) => Self::AuthorizationFailed,

            Created => Self::Created,
            CreationFailed(_) => Self::CreationFailed,

            Ready => Self::Ready,
            Initialized => Self::Initialized,
            InitializationFailed(_) => Self::InitializationFailed,
            Started => Self::Started,
            StartingFailed(_) => Self::StartingFailed,

            Heartbeat => Self::Heartbeat,
            Completed => Self::Completed,
            CompletionFailed(_) => Self::CompletionFailed,

            Finished(_) => Self::Finished,
            Stopped => Self::Stopped,
            DecodingFailed(_) => Self::DecodingFailed,
            Failed(_, _, _) => Self::Failed,
        }
    }
}

impl From<JobStatus> for (TaskStatus, Option<String>) {
    fn from(value: JobStatus) -> Self { Self::from(&value) }
}
impl From<&JobStatus> for (TaskStatus, Option<String>) {
    fn from(value: &JobStatus) -> Self {
        use JobStatus::*;
        match value {
            Unknown => (TaskStatus::Unknown, None),

            Received => (TaskStatus::Received, None),

            Authorized => (TaskStatus::Authorized, None),
            Denied => (TaskStatus::Denied, None),
            AuthorizationFailed(err) => (TaskStatus::AuthorizationFailed, Some(err.clone())),

            Created => (TaskStatus::Created, None),
            CreationFailed(err) => (TaskStatus::CreationFailed, Some(err.clone())),

            Ready => (TaskStatus::Ready, None),
            Initialized => (TaskStatus::Initialized, None),
            InitializationFailed(err) => (TaskStatus::InitializationFailed, Some(err.clone())),
            Started => (TaskStatus::Started, None),
            StartingFailed(err) => (TaskStatus::StartingFailed, Some(err.clone())),

            Heartbeat => (TaskStatus::Heartbeat, None),
            Completed => (TaskStatus::Completed, None),
            CompletionFailed(err) => (TaskStatus::CompletionFailed, Some(err.clone())),

            Finished(val) => (TaskStatus::Finished, Some(serde_json::to_string(&val).unwrap())),
            Stopped => (TaskStatus::Stopped, None),
            DecodingFailed(err) => (TaskStatus::DecodingFailed, Some(err.clone())),
            Failed(code, stdout, stderr) => (TaskStatus::Failed, Some(serde_json::to_string(&(code, stdout, stderr)).unwrap())),
        }
    }
}
