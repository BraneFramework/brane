//  STATERESOLVER.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:09:36
//  Last edited:
//    02 May 2025, 14:59:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the Brane-specific state resolver.
//

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use brane_cfg::node::WorkerUsecase;
use policy_reasoner::spec::auditlogger::{AuditLogger, SessionedAuditLogger};
use policy_reasoner::spec::stateresolver::StateResolver;
use policy_reasoner::workflow::visitor::Visitor;
use policy_reasoner::workflow::{Elem, ElemCall, Workflow};
use policy_store::databases::sqlite::{SQLiteConnection, SQLiteDatabase};
use policy_store::spec::databaseconn::{DatabaseConnection as _, DatabaseConnector as _};
use policy_store::spec::metadata::User;
use reqwest::StatusCode;
use specifications::address::Address;
use specifications::version::Version;
use thiserror::Error;
use tracing::{debug, instrument, warn};

use crate::question::Question;
use crate::workflow::compile;


/***** CONSTANTS *****/
const BLOCK_SEPARATOR: &str = "--------------------------------------------------------------------------------";

/***** STATICS *****/
/// The user used to represent ourselves in the backend.
static DATABASE_USER: LazyLock<User> = LazyLock::new(|| User { id: "brane".into(), name: "Brane".into() });

/// The special policy that is used when the database doesn't mention any active.
static DENY_ALL_POLICY: &str = "Invariant contradiction When False.";





/***** ERRORS *****/
#[derive(Debug, Error)]
pub enum Error {
    /// The active version in the backend was not suitable for our reasoner.
    #[error("Active version {version} is not compatible with reasoner (policy is for {got:?}, but expected for {expected:?})")]
    DatabaseActiveVersionMismatch { version: u64, got: String, expected: String },
    /// Failed to connect to the backend database.
    #[error("Failed to connect to the backend database as user 'brane'")]
    DatabaseConnect { source: policy_store::databases::sqlite::DatabaseError },
    /// Failed to get the active version from the backend database.
    #[error("Failed to get the active version from the backend database")]
    DatabaseGetActiveVersion { source: policy_store::databases::sqlite::ConnectionError },
    /// Failed to get the active version from the backend database.
    #[error("Failed to get the contents of active version {version} from the backend database")]
    DatabaseGetActiveVersionContent { version: u64, source: policy_store::databases::sqlite::ConnectionError },
    /// Failed to get the metadata of the active version from the backend database.
    #[error("Failed to get the metadata of active version {version} from the backend database")]
    DatabaseGetActiveVersionMetadata { version: u64, source: policy_store::databases::sqlite::ConnectionError },
    /// The active version reported was not found.
    #[error("Inconsistent database version: version {version} was reported as the active version, but that version is not found")]
    DatabaseInconsistentActive { version: u64 },
    /// Found too many calls with the same ID.
    #[error("Given call ID {call:?} occurs multiple times in workflow {workflow:?}")]
    DuplicateCallId { workflow: String, call: String },
    /// Found too many inputs in the given call with the same ID.
    #[error("Given input ID {input:?} occurs multiple times in the input to call {call:?} in workflow {workflow:?}")]
    DuplicateInputId { workflow: String, call: String, input: String },
    /// Found an illegal version string in a task string.
    #[error("Illegal version identifier {version:?} in task {task:?} in call {call:?} in workflow {workflow:?}")]
    IllegalVersionFormat { workflow: String, call: String, task: String, version: String, source: specifications::version::ParseError },
    /// Failed to get the package index from the remote registry.
    #[error("Failed to get package index from the central registry at {addr:?}")]
    PackageIndex { addr: String, source: brane_tsk::api::Error },
    /// Failed to send a request to the central registry.
    #[error("Failed to send a request to the central registry at {addr:?} to retrieve {what}")]
    Request { what: &'static str, addr: String, source: reqwest::Error },
    /// The server responded with a non-200 OK exit code.
    #[error(
        "Central registry at '{addr}' returned {} ({}) when trying to retrieve {what}{}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("???"),
        raw.as_ref().map(|raw| format!("\n\nRaw response:\n{BLOCK_SEPARATOR}\n{raw}\n{BLOCK_SEPARATOR}\n")).unwrap_or_default()
    )]
    RequestFailure { what: &'static str, addr: String, status: StatusCode, raw: Option<String> },
    /// Failed to resolve the data index with the remote Brane API registry.
    #[error("Failed to resolve data with remote Brane registry at {addr:?}")]
    ResolveData { addr: Address, source: brane_tsk::api::Error },
    /// Failed to resolve the workflow submitted with the request.
    #[error("Failed to resolve workflow '{id}'")]
    ResolveWorkflow { id: String, source: crate::workflow::compile::Error },
    /// Failed to deserialize the response of the server.
    #[error("Failed to deserialize responses of central registry at {addr:?} as {what}")]
    ResponseDeserialize { what: &'static str, addr: String, source: serde_json::Error },
    /// Failed to download the response of the server.
    #[error("Failed to download a {what} response from the central registry at {addr:?}")]
    ResponseDownload { what: &'static str, addr: String, source: reqwest::Error },
    /// A given call ID was not found.
    #[error("No call {call:?} exists in workflow {workflow:?}")]
    UnknownCall { workflow: String, call: String },
    /// The function called on a package in a call was unknown to that package.
    #[error("Unknown function {function:?} in package {package:?} ({version}) in call {call:?} in workflow {workflow:?}")]
    UnknownFunction { workflow: String, call: String, package: String, version: Version, function: String },
    /// Some input to a task was unknown to us.
    #[error("Unknown input {input:?} to call {call:?} in workflow {workflow:?}")]
    UnknownInput { workflow: String, call: String, input: String },
    /// A given input ID was not found in the input to a call.
    #[error("No input {input:?} exists as input to call {call:?} in workflow {workflow:?}")]
    UnknownInputToCall { workflow: String, call: String, input: String },
    /// The planned user that contibutes an input to a task was unknown to us.
    #[error("Unknown user {user:?} providing input {input:?} to call {call:?} in workflow {workflow:?}")]
    UnknownInputUser { workflow: String, call: String, input: String, user: String },
    /// The user that owns a tag was unknown to us.
    #[error("Unknown user {user:?} owning tag {tag:?} of call {call:?} in workflow {workflow:?}")]
    UnknownOwnerUser { workflow: String, call: String, tag: String, user: String },
    /// The package extracted from a call was unknown to us.
    #[error("Unknown package {package:?} ({version}) in call {call:?} in workflow {workflow:?}")]
    UnknownPackage { workflow: String, call: String, package: String, version: Version },
    /// The planned user of a task was unknown to us.
    #[error("Unknown planned user {user:?} in call {call:?} in workflow {workflow:?}")]
    UnknownPlannedUser { workflow: String, call: String, user: String },
    /// A package in a task did not have the brane format.
    #[error("Task {task:?} in call {call:?} in workflow {workflow:?} does not have the Brane format (\"PACKAGE[VERSION]::FUNCTION\")")]
    UnknownTaskFormat { workflow: String, call: String, task: String },
    /// The usecase submitted with the request was unknown.
    #[error("Unkown usecase '{usecase}'")]
    UnknownUsecase { usecase: String },
    /// The workflow user was not found.
    #[error("Unknown workflow user {user:?} in workflow {workflow:?}")]
    UnknownWorkflowUser { workflow: String, user: String },
    /// The planned user "contributing" an output was not the planned user of the task.
    #[error(
        "User {output_user:?} providing output {output:?} to call {call:?} in workflow {workflow:?} is not the user planned to do that task \
         ({planned_user:?})"
    )]
    UnplannedOutputUser { workflow: String, call: String, output: String, planned_user: Option<String>, output_user: Option<String> },
}

impl From<&Error> for StatusCode {
    fn from(value: &Error) -> Self {
        use Error::*;
        match value {
            DatabaseActiveVersionMismatch { .. }
            | DatabaseConnect { .. }
            | DatabaseGetActiveVersion { .. }
            | DatabaseGetActiveVersionContent { .. }
            | DatabaseGetActiveVersionMetadata { .. }
            | DatabaseInconsistentActive { .. }
            | PackageIndex { .. }
            | Request { .. }
            | RequestFailure { .. }
            | ResolveData { .. }
            | ResponseDeserialize { .. }
            | ResponseDownload { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            DuplicateCallId { .. }
            | DuplicateInputId { .. }
            | IllegalVersionFormat { .. }
            | ResolveWorkflow { .. }
            | UnknownCall { .. }
            | UnknownFunction { .. }
            | UnknownInput { .. }
            | UnknownInputToCall { .. }
            | UnknownInputUser { .. }
            | UnknownOwnerUser { .. }
            | UnknownPackage { .. }
            | UnknownPlannedUser { .. }
            | UnknownTaskFormat { .. }
            | UnknownWorkflowUser { .. }
            | UnplannedOutputUser { .. } => StatusCode::BAD_REQUEST,
            UnknownUsecase { .. } => StatusCode::NOT_FOUND,
        }
    }
}





/***** HELPER FUNCTIONS *****/
/// Interacts with the database to get the currently active policy.
///
/// # Arguments
/// - `base_policy_hash`: A hash of the base policy that we use to ensure that the active policy is still applicable.
/// - `db`: The [`SQLiteDatabase`] connector that we use to talk to the database.
/// - `res`: Appends the active policy to this list. If there is somehow a disabled policy, the
///   policy is completely overwritten.
///
/// # Errors
/// This function errors if we failed to interact with the database, or if no policy was currently active.
async fn get_active_policy(base_policy_hash: &str, db: &SQLiteDatabase<String>, res: &mut String) -> Result<(), Error> {
    // Time to fetch a connection
    debug!("Connecting to backend database...");
    let mut conn: SQLiteConnection<String> = db.connect(&DATABASE_USER).await.map_err(|source| Error::DatabaseConnect { source })?;

    // Get the active policy
    debug!("Retrieving active policy...");
    let Some(version) = conn.get_active_version().await.map_err(|source| Error::DatabaseGetActiveVersion { source })? else {
        warn!("No active policy set in database; assuming builtin VIOLATION policy");
        *res = DENY_ALL_POLICY.into();
        return Ok(());
    };

    debug!("Fetching active policy {version} metadata...");
    let Some(md) = conn.get_version_metadata(version).await.map_err(|source| Error::DatabaseGetActiveVersionMetadata { version, source })? else {
        return Err(Error::DatabaseInconsistentActive { version });
    };

    let expected_language = format!("eflint-haskell-{base_policy_hash}");
    if md.attached.language != expected_language {
        return Err(Error::DatabaseActiveVersionMismatch { version, got: md.attached.language, expected: expected_language });
    }

    debug!("Fetching active policy {version}...");
    match conn.get_version_content(version).await.map_err(|source| Error::DatabaseGetActiveVersionContent { version, source })? {
        Some(version) => {
            res.push_str(&version);
            Ok(())
        },
        None => Err(Error::DatabaseInconsistentActive { version }),
    }
}





/***** VISITORS *****/
/// Asserts that the given task occurs exactly once in the workflow.
#[derive(Debug)]
struct CallFinder<'w> {
    /// The workflow ID (for debugging)
    wf_id: &'w str,
    /// The task to find.
    call:  &'w str,
    /// Whether we already found it or not.
    found: bool,
}
impl<'w> CallFinder<'w> {
    /// Constructor for the CallFinder.
    ///
    /// # Arguments
    /// - `wf_id`: The ID of the workflow we're asserting.
    /// - `call`: The ID of the call to find.
    ///
    /// # Returns
    /// A new instance of Self, ready to sniff out the call!
    #[inline]
    fn new(wf_id: &'w str, call: &'w str) -> Self { Self { wf_id, call, found: false } }
}
impl<'w> Visitor<'w> for CallFinder<'w> {
    type Error = Error;

    #[inline]
    fn visit_call(&mut self, elem: &'w ElemCall) -> Result<Option<&'w Elem>, Self::Error> {
        // Check if it's the one
        if self.call == elem.id {
            if !self.found {
                self.found = true;
            } else {
                return Err(Error::DuplicateCallId { workflow: self.wf_id.into(), call: elem.id.clone() });
            }
        }

        // OK, continue
        Ok(Some(&elem.next))
    }
}

/// Asserts that the given task occurs exactly once in the workflow and that it has exactly one
/// input with the given name.
#[derive(Debug)]
struct CallInputFinder<'w> {
    /// The workflow ID (for debugging)
    wf_id: &'w str,
    /// The task to find.
    call: &'w str,
    /// The input to find.
    input: &'w str,
    /// Whether we already found the call it or not.
    found_call: bool,
}
impl<'w> CallInputFinder<'w> {
    /// Constructor for the CallInputFinder.
    ///
    /// # Arguments
    /// - `wf_id`: The ID of the workflow we're asserting.
    /// - `call`: The ID of the call to find.
    /// - `input`: The ID of the input to the given call to find.
    ///
    /// # Returns
    /// A new instance of Self, ready to scooby the input to call.
    #[inline]
    fn new(wf_id: &'w str, call: &'w str, input: &'w str) -> Self { Self { wf_id, call, input, found_call: false } }
}
impl<'w> Visitor<'w> for CallInputFinder<'w> {
    type Error = Error;

    #[inline]
    fn visit_call(&mut self, elem: &'w ElemCall) -> Result<Option<&'w Elem>, Self::Error> {
        // Check if it's the one
        if self.call == elem.id {
            // It is, so mark it (or complain we've seen it before)
            if self.found_call {
                return Err(Error::DuplicateCallId { workflow: self.wf_id.into(), call: elem.id.clone() });
            }
            self.found_call = true;

            // Also verify the input exists in this call
            let mut found_input: bool = false;
            for i in &elem.input {
                if self.input == i.id {
                    if found_input {
                        return Err(Error::DuplicateInputId { workflow: self.wf_id.into(), call: elem.id.clone(), input: i.id.clone() });
                    }
                    found_input = true;
                }
            }
            if !found_input {
                return Err(Error::UnknownInputToCall { workflow: self.wf_id.into(), call: elem.id.clone(), input: self.input.into() });
            }
        }

        // OK, continue
        Ok(Some(&elem.next))
    }
}





/***** AUXILLARY *****/
/// Defines the input to the [`StateResolver`]` that will be resolved to concrete info for the reasoner.
#[derive(Clone)]
pub struct Input {
    // Policy-related
    /// The database connector we use to connect to t' pool.
    pub store: Arc<SQLiteDatabase<String>>,

    // Workflow-related
    /// The usecase that determines the central registry to use.
    pub usecase:  String,
    /// The workflow to further resolve.
    pub workflow: specifications::wir::Workflow,
    /// Question-specific input.
    pub input:    QuestionInput,
}

/// Defines question-specific input to the [`StateResolver`] that will be resolved to concrete info for the reasoner.
#[derive(Clone, Debug)]
pub enum QuestionInput {
    ValidateWorkflow,
    ExecuteTask { task: String },
    TransferInput { task: String, input: String },
    TransferResult { result: String },
}





/***** LIBRARY *****/
/// Resolves state for the reasoner in the Brane registry.
#[derive(Clone, Debug)]
pub struct BraneStateResolver {
    /// The use-cases that we use to map use-case ID to Brane central registry.
    pub usecases: HashMap<String, WorkerUsecase>,
    /// The hash of the base policy to ensure validity of active policy with.
    pub base_policy_hash: String,
}
impl BraneStateResolver {
    /// Constructor for the BraneStateResolver.
    ///
    /// # Arguments
    /// - `usecases`: A map of usecase identifiers to information about where we find the
    ///   appropriate central registry for that usecase.
    /// - `base_policy_hash`: The hash of the base policy to ensure validity of active policy with.
    ///
    /// # Returns
    /// A new StateResolver, ready to resolve state.
    #[inline]
    pub fn new(usecases: impl IntoIterator<Item = (String, WorkerUsecase)>, hash: &[u8; 32]) -> Self {
        Self { usecases: usecases.into_iter().collect(), base_policy_hash: base16ct::lower::encode_string(hash) }
    }
}
impl StateResolver for BraneStateResolver {
    type Error = Error;
    type Resolved = (String, Question);
    type State = Input;

    #[instrument(level="info", skip_all, fields(reference = %logger.reference(), usecase = state.usecase, workflow = state.workflow.id))]
    async fn resolve<'a, L>(&'a self, state: Self::State, logger: &'a SessionedAuditLogger<L>) -> Result<Self::Resolved, Self::Error>
    where
        L: Sync + AuditLogger,
    {
        // First, resolve the policy by calling the store
        let mut policy: String = String::new();
        get_active_policy(&self.base_policy_hash, &state.store, &mut policy).await?;


        // Then resolve the workflow and create the appropriate question
        debug!("Compiling input workflow...");
        let id: String = state.workflow.id.clone();
        let wf: Workflow = compile(state.workflow).map_err(|source| Error::ResolveWorkflow { id, source })?;

        // FIXME: Verify whether all things in the workflow exist

        // Now check some question-specific input...
        match state.input {
            QuestionInput::ValidateWorkflow => Ok((policy, Question::ValidateWorkflow { workflow: wf })),
            QuestionInput::ExecuteTask { task } => {
                let mut finder = CallFinder::new(&wf.id, &task);
                wf.visit(&mut finder)?;
                if !finder.found {
                    return Err(Error::UnknownCall { workflow: wf.id.clone(), call: task });
                }
                Ok((policy, Question::ExecuteTask { workflow: wf, task }))
            },
            QuestionInput::TransferInput { task, input } => {
                let mut finder = CallInputFinder::new(&wf.id, &task, &input);
                wf.visit(&mut finder)?;
                if !finder.found_call {
                    return Err(Error::UnknownCall { workflow: wf.id.clone(), call: task });
                }
                Ok((policy, Question::TransferInput { workflow: wf, task, input }))
            },
            QuestionInput::TransferResult { result } => Ok((policy, Question::TransferResult { workflow: wf, result })),
        }
    }
}
