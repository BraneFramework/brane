//  JOBS.rs
//    by Lut99
//
//  Created:
//    14 Nov 2022, 09:50:29
//  Last edited:
//    14 Nov 2022, 09:50:30
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements some public interfaces & definitions for working with
//!   jobs.
//


/// Lists the possible states that a job can have from the brane-drv perspective.
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum JobStatus {
    // Meta states
    /// Meta state for undefined states
    Unknown,

    // Creation states
    /// We successfully created a container for the call
    Created,
    /// We could not create the container to run the call.
    ///
    /// **Carries**
    ///  * `err`: A string describing why we failed to launch a job.
    CreateFailed { err: String },

    // Initialization states
    /// The container is ready with setting up the branelet executable (first opportunity for branelet to send events)
    Ready,
    /// The container has initialized its working directory
    Initialized,
    /// Something went wrong while setting up the working directory
    ///
    /// **Carries**
    ///  * `err`: A string describing why we failed to intialize a job.
    InitializeFailed { err: String },

    // Progress states
    /// The actual subcall executeable / script has started
    Started,
    /// The subprocess executable did not want to start (calling it failed)
    ///
    /// **Carries**
    ///  * `err`: A string describing why we failed to start a job.
    StartFailed { err: String },
    /// The subcall executable has finished without errors - at least, from the branelet's side, that is
    Completed,
    /// The subcall executable has finished with errors on the branelet side
    ///
    /// **Carries**
    ///  * `err`: A string describing why we failed to complete a job.
    CompleteFailed { err: String },

    // Finish states
    /// The container has exited with a zero status code
    ///
    /// **Carries**
    ///  * `res`: A JSON-formatted string (hopefully) containing the value of the finished job.
    Finished { res: String },
    /// The container has exited with a non-zero status code
    ///
    /// **Carries**
    ///  * `res`: A JSON-formatted string (hopefully) containing a code/stdout/stderr triplet of results of the failed job.
    Failed { res: String },
    /// The container was interrupted by the Job node
    Stopped { signal: String },
    /// We could not decode the output from the package
    ///
    /// **Carries**
    ///  * `err`: A string describing why we failed to decode the job output.
    DecodeFailed { err: String },
}

impl JobStatus {
    /// Converts any of the states to a numeric number representing their ordering.  
    /// The earlier the state in a job's lifecycle, the lower the number.
    ///
    /// **Returns**  
    /// The ordering as an unsigned integer.
    pub fn order(&self) -> u32 {
        match self {
            JobStatus::Unknown => 0,
            JobStatus::Created => 1,
            JobStatus::CreateFailed { .. } => 1,
            JobStatus::Ready => 2,
            JobStatus::Initialized => 3,
            JobStatus::InitializeFailed { .. } => 3,
            JobStatus::Started => 4,
            JobStatus::StartFailed { .. } => 4,
            JobStatus::Completed => 5,
            JobStatus::CompleteFailed { .. } => 5,
            JobStatus::Finished { .. } => 6,
            JobStatus::Failed { .. } => 6,
            JobStatus::Stopped { .. } => 6,
            JobStatus::DecodeFailed { .. } => 6,
        }
    }

    /// Returns whether the this state is equal to or has surpassed the given state in terms of ordering.  
    /// In case they are equal, also requires the specific variants to be the same (not just the ordering).
    ///
    /// **Arguments**
    ///  * `target`: The target state to check if the job has reached.
    ///
    /// **Returns**  
    /// True if this state's ordering is equal to or higher than the target's ordering.
    #[inline]
    pub fn reached(&self, target: &JobStatus) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(target) || self.order() > target.order()
    }
}

impl PartialEq<&JobStatus> for JobStatus {
    fn eq(&self, other: &&JobStatus) -> bool { self == *other }
}
