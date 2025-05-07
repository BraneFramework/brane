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

// use std::collections::{HashMap, HashSet};
use std::collections::HashMap;
use std::future::Future;
// use std::str::FromStr as _;
use std::sync::{Arc, LazyLock};

use brane_cfg::node::WorkerUsecase;
use policy_reasoner::spec::auditlogger::{AuditLogger, SessionedAuditLogger};
use policy_reasoner::spec::stateresolver::StateResolver;
use policy_reasoner::workflow::visitor::Visitor;
use policy_reasoner::workflow::{Elem, ElemCall, Workflow};
use policy_store::databases::sqlite::{SQLiteConnection, SQLiteDatabase};
use policy_store::spec::authresolver::HttpError;
use policy_store::spec::databaseconn::{DatabaseConnection as _, DatabaseConnector as _};
use policy_store::spec::metadata::{Metadata, User};
// use reqwest::{Response, StatusCode};
use reqwest::StatusCode;
// use serde::de::DeserializeOwned;
use specifications::address::Address;
// use specifications::data::DataInfo;
// use specifications::package::PackageIndex;
use specifications::version::Version;
use thiserror::Error;
use tracing::{Level, debug, span, warn};

use crate::question::Question;
use crate::workflow::compile;


/***** STATICS *****/
/// The user used to represent ourselves in the backend.
static DATABASE_USER: LazyLock<User> = LazyLock::new(|| User { id: "brane".into(), name: "Brane".into() });

/// The special policy that is used when the database doesn't mention any active.
static DENY_ALL_POLICY: &'static str = "Invariant contradiction When False.";





/***** ERRORS *****/
#[derive(Debug, Error)]
pub enum Error {
    /// The active version in the backend was not suitable for our reasoner.
    #[error("Active version {version} is not compatible with reasoner (policy is for {got:?}, but expected for {expected:?})")]
    DatabaseActiveVersionMismatch { version: u64, got: String, expected: String },
    /// Failed to connect to the backend database.
    #[error("Failed to connect to the backend database as user 'brane'")]
    DatabaseConnect {
        #[source]
        err: policy_store::databases::sqlite::DatabaseError,
    },
    /// Failed to get the active version from the backend database.
    #[error("Failed to get the active version from the backend database")]
    DatabaseGetActiveVersion {
        #[source]
        err: policy_store::databases::sqlite::ConnectionError,
    },
    /// Failed to get the active version from the backend database.
    #[error("Failed to get the contents of active version {version} from the backend database")]
    DatabaseGetActiveVersionContent {
        version: u64,
        #[source]
        err:     policy_store::databases::sqlite::ConnectionError,
    },
    /// Failed to get the metadata of the active version from the backend database.
    #[error("Failed to get the metadata of active version {version} from the backend database")]
    DatabaseGetActiveVersionMetadata {
        version: u64,
        #[source]
        err:     policy_store::databases::sqlite::ConnectionError,
    },
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
    IllegalVersionFormat {
        workflow: String,
        call:     String,
        task:     String,
        version:  String,
        #[source]
        err:      specifications::version::ParseError,
    },
    /// Failed to get the package index from the remote registry.
    #[error("Failed to get package index from the central registry at {addr:?}")]
    PackageIndex { addr: String, err: brane_tsk::api::Error },
    /// Failed to send a request to the central registry.
    #[error("Failed to send a request to the central registry at {addr:?} to retrieve {what}")]
    Request {
        what: &'static str,
        addr: String,
        #[source]
        err:  reqwest::Error,
    },
    /// The server responded with a non-200 OK exit code.
    #[error("Central registry at '{addr}' returned {} ({}) when trying to retrieve {what}{}", status.as_u16(), status.canonical_reason().unwrap_or("???"), if let Some(raw) = raw { format!("\n\nRaw response:\n{}\n{}\n{}\n", (0..80).map(|_| '-').collect::<String>(), raw, (0..80).map(|_| '-').collect::<String>()) } else { String::new() })]
    RequestFailure { what: &'static str, addr: String, status: StatusCode, raw: Option<String> },
    /// Failed to resolve the data index with the remote Brane API registry.
    #[error("Failed to resolve data with remote Brane registry at {addr:?}")]
    ResolveData {
        addr: Address,
        #[source]
        err:  brane_tsk::api::Error,
    },
    /// Failed to resolve the workflow submitted with the request.
    #[error("Failed to resolve workflow '{id}'")]
    ResolveWorkflow {
        id:  String,
        #[source]
        err: crate::workflow::compile::Error,
    },
    /// Failed to deserialize the response of the server.
    #[error("Failed to deserialize respones of central registry at {addr:?} as {what}")]
    ResponseDeserialize {
        what: &'static str,
        addr: String,
        #[source]
        err:  serde_json::Error,
    },
    /// Failed to download the response of the server.
    #[error("Failed to download a {what} response from the central registry at {addr:?}")]
    ResponseDownload {
        what: &'static str,
        addr: String,
        #[source]
        err:  reqwest::Error,
    },
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
impl HttpError for Error {
    #[inline]
    fn status_code(&self) -> StatusCode {
        use Error::*;
        match self {
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
// /// Sends a GET-request and tries to deserialize the response.
// ///
// /// # Generic arguments
// /// - `R`: The [`Deserialize`]able object to expect in the response.
// ///
// /// # Arguments
// /// - `url`: The path to send a request to.
// ///
// /// # Returns
// /// A parsed `R` if the server replied with 200 OK.
// ///
// /// # Errors
// /// This function errors if we failed to send the request, receive the response or if the server did not 200 OK.
// async fn send_request<R: DeserializeOwned>(url: &str) -> Result<R, Error> {
//     // Send the request out
//     let res: Response = match reqwest::get(url.to_string()).await {
//         Ok(res) => res,
//         Err(err) => return Err(Error::Request { what: std::any::type_name::<R>(), addr: url.into(), err }),
//     };
//     // Check if the response makes sense
//     if !res.status().is_success() {
//         return Err(Error::RequestFailure {
//             what:   std::any::type_name::<R>(),
//             addr:   url.into(),
//             status: res.status(),
//             raw:    res.text().await.ok(),
//         });
//     }

//     // Now attempt to deserialize the response
//     let raw: String = match res.text().await {
//         Ok(raw) => raw,
//         Err(err) => return Err(Error::ResponseDownload { what: std::any::type_name::<R>(), addr: url.into(), err }),
//     };
//     let res: R = match serde_json::from_str(&raw) {
//         Ok(res) => res,
//         Err(err) => return Err(Error::ResponseDeserialize { what: std::any::type_name::<R>(), addr: url.into(), err }),
//     };

//     // Done
//     Ok(res)
// }

/// Checks if all users, datasets, packages etc exist in the given workflow.
///
/// # Arguments
/// - `wf`: The [`Workflow`] who's context to verify.
/// - `usecase`: The usecase identifier to resolve.
/// - `usecases`: The map of usescases to resolve the `usecase` to a registry address with.
///
/// # Returns
/// A [`DataIndex`] that contains the known data in the system.
///
/// # Errors
/// This function may error if the `usecase` is unknown, or if the remote registry does not reply (correctly).
async fn assert_workflow_context(_wf: &Workflow, usecase: &str, usecases: &HashMap<String, WorkerUsecase>) -> Result<(), Error> {
    // Resolve the usecase to an address to query
    debug!("Resolving usecase {usecase:?} to registry address...");
    let _api: &Address = match usecases.get(usecase) {
        Some(usecase) => &usecase.api,
        None => return Err(Error::UnknownUsecase { usecase: usecase.into() }),
    };


    // // TODO: Finish this
    // // Cannot really do it for now, since, unfortunately, we do not know all users (i.e., no idea
    // // about scientists). Some kind of user database is, clearly, essential.

    // // // Send the request to the Brane API registry to get the current state of the datasets
    // // let users: String = format!("http://{api}/infra/registries");
    // // debug!("Retrieving list of users from registry at {users:?}...");
    // // let users: HashSet<String> = send_request::<HashMap<String, Address>>(&users).await?.into_keys().collect();

    // // // Check if the users are all found in the system
    // // debug!("Asserting all users in workflow {:?} exist...", wf.id);
    // // if let Some(user) = &wf.user {
    // //     if !users.contains(&user.id) {
    // //         return Err(Error::UnknownWorkflowUser { workflow: wf.id.clone(), user: user.id.clone() });
    // //     }
    // // }
    // // wf.visit(AssertUserExistance::new(&wf.id, &users))?;


    // // Check if all the packages mentioned exist in the system
    // let graphql: String = format!("http://{api}/graphql");
    // debug!("Retrieving list of packages from registry at {graphql:?}...");
    // let packages: PackageIndex = match brane_tsk::api::get_package_index(&graphql).await {
    //     Ok(index) => index,
    //     Err(err) => return Err(Error::PackageIndex { addr: graphql, err }),
    // };

    // debug!("Asserting all packages in workflow {:?} exist...", wf.id);
    // wf.visit(AssertPackageExistance::new(&wf.id, &packages))?;


    // // Check if all the datasets mentioned exist in the system
    // let datasets: String = format!("http://{api}/data/info");
    // debug!("Retrieving list of datasets from registry at {datasets:?}...");
    // let datasets: HashSet<String> = send_request::<HashMap<String, DataInfo>>(&datasets).await?.into_keys().collect();

    // debug!("Asserting all input datasets in workflow {:?} exist...", wf.id);
    // wf.visit(AssertDataExistance::new(&wf.id, datasets))?;


    // Done!
    Ok(())
}

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
    let mut conn: SQLiteConnection<String> = match db.connect(&*DATABASE_USER).await {
        Ok(conn) => conn,
        Err(err) => return Err(Error::DatabaseConnect { err }),
    };

    // Get the active policy
    debug!("Retrieving active policy...");
    let version: u64 = match conn.get_active_version().await {
        Ok(Some(pol)) => pol,
        Ok(None) => {
            warn!("No active policy set in database; assuming builtin VIOLATION policy");
            *res = DENY_ALL_POLICY.into();
            return Ok(());
        },
        Err(err) => return Err(Error::DatabaseGetActiveVersion { err }),
    };

    debug!("Fetching active policy {version} metadata...");
    let md: Metadata = match conn.get_version_metadata(version).await {
        Ok(Some(md)) => md,
        Ok(None) => return Err(Error::DatabaseInconsistentActive { version }),
        Err(err) => return Err(Error::DatabaseGetActiveVersionMetadata { version, err }),
    };
    if md.attached.language.len() < 15
        || &md.attached.language.as_bytes()[..15] != b"eflint-haskell-"
        || &md.attached.language.as_bytes()[15..] != base_policy_hash.as_bytes()
    {
        return Err(Error::DatabaseActiveVersionMismatch {
            version,
            got: md.attached.language,
            expected: format!("eflint-haskell-{base_policy_hash}"),
        });
    }

    debug!("Fetching active policy {version}...");
    match conn.get_version_content(version).await {
        Ok(Some(version)) => {
            res.push_str(&version);
            Ok(())
        },
        Ok(None) => Err(Error::DatabaseInconsistentActive { version }),
        Err(err) => Err(Error::DatabaseGetActiveVersionContent { version, err }),
    }
}





/***** VISITORS *****/
// /// Checks whether all users mentioned in a workflow exist.
// #[derive(Debug)]
// struct AssertUserExistance<'w> {
//     /// The workflow ID (for debugging)
//     wf_id: &'w str,
//     /// The users that exist.
//     users: &'w HashSet<String>,
// }
// impl<'w> AssertUserExistance<'w> {
//     /// Constructor for the AssertUserExistance.
//     ///
//     /// # Arguments
//     /// - `wf_id`: The ID of the workflow we're asserting.
//     /// - `users`: The users that exist. Any users occuring in the workflow but not in this list
//     ///   will be reported.
//     ///
//     /// # Returns
//     /// A new instance of Self, ready to kick ass and assert user existances (and there's no users
//     /// to check).
//     #[inline]
//     fn new(wf_id: &'w str, users: &'w HashSet<String>) -> Self { Self { wf_id, users } }
// }
// impl<'w> Visitor<'w> for AssertUserExistance<'w> {
//     type Error = Error;

//     #[inline]
//     fn visit_call(&mut self, elem: &'w policy_reasoner::workflow::ElemCall) -> Result<Option<&'w Elem>, Self::Error> {
//         // Check if all users contributing input are known
//         for i in &elem.input {
//             if let Some(from) = &i.from {
//                 if !self.users.contains(&from.id) {
//                     return Err(Error::UnknownInputUser {
//                         workflow: self.wf_id.into(),
//                         call:     elem.id.clone(),
//                         input:    i.id.clone(),
//                         user:     from.id.clone(),
//                     });
//                 }
//             }
//         }
//         // Assert that only the planned user generates output
//         for o in &elem.output {
//             if elem.at != o.from {
//                 return Err(Error::UnplannedOutputUser {
//                     workflow: self.wf_id.into(),
//                     call: elem.id.clone(),
//                     output: o.id.clone(),
//                     planned_user: elem.at.as_ref().map(|e| e.id.clone()),
//                     output_user: o.from.as_ref().map(|e| e.id.clone()),
//                 });
//             }
//         }

//         // Check if the planned user is known
//         if let Some(user) = &elem.at {
//             if !self.users.contains(&user.id) {
//                 return Err(Error::UnknownPlannedUser { workflow: self.wf_id.into(), call: elem.id.clone(), user: user.id.clone() });
//             }
//         }

//         // Finally, check if all metadata users are known
//         for m in &elem.metadata {
//             if let Some((owner, _)) = &m.signature {
//                 if !self.users.contains(&owner.id) {
//                     return Err(Error::UnknownOwnerUser {
//                         workflow: self.wf_id.into(),
//                         call:     elem.id.clone(),
//                         tag:      m.tag.clone(),
//                         user:     owner.id.clone(),
//                     });
//                 }
//             }
//         }

//         // OK, continue
//         Ok(Some(&elem.next))
//     }
// }

// /// Checks whether all packages mentioned in a workflow exist.
// #[derive(Debug)]
// struct AssertPackageExistance<'w> {
//     /// The workflow ID (for debugging)
//     wf_id: &'w str,
//     /// The users that exist.
//     index: &'w PackageIndex,
// }
// impl<'w> AssertPackageExistance<'w> {
//     /// Constructor for the AssertPackageExistance.
//     ///
//     /// # Arguments
//     /// - `wf_id`: The ID of the workflow we're asserting.
//     /// - `index`: The [`PackageIndex`] listing which packages exist. Any packages occuring in the
//     ///   workflow but not in this list will be reported.
//     ///
//     /// # Returns
//     /// A new instance of Self, ready to check the existance of those rowdy packages.
//     #[inline]
//     fn new(wf_id: &'w str, index: &'w PackageIndex) -> Self { Self { wf_id, index } }
// }
// impl<'w> Visitor<'w> for AssertPackageExistance<'w> {
//     type Error = Error;

//     #[inline]
//     fn visit_call(&mut self, elem: &'w ElemCall) -> Result<Option<&'w Elem>, Self::Error> {
//         // Check if the package mentioned matches the Brane structure
//         let (package, version, function): (&str, &str, &str) = if let Some(l) = elem.task.find('[') {
//             if let Some(r) = elem.task[l + 1..].find(']') {
//                 if let Some(dot) = elem.task[l + 1 + r + 1..].find("::") {
//                     (&elem.task[..l], &elem.task[l + 1..l + 1 + r], &elem.task[l + 1 + r + 1 + dot + 2..])
//                 } else {
//                     return Err(Error::UnknownTaskFormat { workflow: self.wf_id.into(), call: elem.id.clone(), task: elem.task.clone() });
//                 }
//             } else {
//                 return Err(Error::UnknownTaskFormat { workflow: self.wf_id.into(), call: elem.id.clone(), task: elem.task.clone() });
//             }
//         } else {
//             return Err(Error::UnknownTaskFormat { workflow: self.wf_id.into(), call: elem.id.clone(), task: elem.task.clone() });
//         };

//         // See if we can parse the version
//         let version: Version = match Version::from_str(version) {
//             Ok(ver) => ver,
//             Err(err) => {
//                 return Err(Error::IllegalVersionFormat {
//                     workflow: self.wf_id.into(),
//                     call: elem.id.clone(),
//                     task: elem.task.clone(),
//                     version: version.into(),
//                     err,
//                 });
//             },
//         };

//         // OK, now check the package index
//         if let Some(info) = self.index.get(package, Some(&version)) {
//             if info.functions.get(function).is_none() {
//                 return Err(Error::UnknownFunction {
//                     workflow: self.wf_id.into(),
//                     call: elem.id.clone(),
//                     package: package.into(),
//                     version,
//                     function: function.into(),
//                 });
//             }
//         } else {
//             return Err(Error::UnknownPackage { workflow: self.wf_id.into(), call: elem.id.clone(), package: package.into(), version });
//         }

//         // OK, continue
//         Ok(Some(&elem.next))
//     }
// }

// /// Checks whether all datasets mentioned in a workflow exist.
// #[derive(Debug)]
// struct AssertDataExistance<'w> {
//     /// The workflow ID (for debugging)
//     wf_id:    &'w str,
//     /// The datasets that exist.
//     datasets: HashSet<String>,
// }
// impl<'w> AssertDataExistance<'w> {
//     /// Constructor for the AssertDataExistance.
//     ///
//     /// # Arguments
//     /// - `wf_id`: The ID of the workflow we're asserting.
//     /// - `datasets`: The list of datasets that we already know exist. Taken by ownership to also
//     ///   register temporary outputs as we find them.
//     ///
//     /// # Returns
//     /// A new instance of Self, ready to assert the heck out of datasets.
//     #[inline]
//     fn new(wf_id: &'w str, datasets: HashSet<String>) -> Self { Self { wf_id, datasets } }
// }
// impl<'w> Visitor<'w> for AssertDataExistance<'w> {
//     type Error = Error;

//     #[inline]
//     fn visit_call(&mut self, elem: &'w ElemCall) -> Result<Option<&'w Elem>, Self::Error> {
//         // First, check if the inputs exist
//         for i in &elem.input {
//             if !self.datasets.contains(&i.id) {
//                 return Err(Error::UnknownInput { workflow: self.wf_id.into(), call: elem.id.clone(), input: i.id.clone() });
//             }
//         }
//         // Then register any produced outputs
//         for o in &elem.output {
//             self.datasets.insert(o.id.clone());
//         }

//         // OK, continue
//         Ok(Some(&elem.next))
//     }
// }

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
            if !self.found_call {
                self.found_call = true;
            } else {
                return Err(Error::DuplicateCallId { workflow: self.wf_id.into(), call: elem.id.clone() });
            }

            // Also verify the input exists in this call
            let mut found_input: bool = false;
            for i in &elem.input {
                if self.input == i.id {
                    if !found_input {
                        found_input = true;
                    } else {
                        return Err(Error::DuplicateInputId { workflow: self.wf_id.into(), call: elem.id.clone(), input: i.id.clone() });
                    }
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

    fn resolve<'a, L>(
        &'a self,
        state: Self::State,
        logger: &'a SessionedAuditLogger<L>,
    ) -> impl 'a + Send + Future<Output = Result<Self::Resolved, Self::Error>>
    where
        L: Sync + AuditLogger,
    {
        async move {
            let _span = span!(
                Level::INFO,
                "BraneStateResolver::resolve",
                reference = logger.reference(),
                usecase = state.usecase,
                workflow = state.workflow.id
            );


            // First, resolve the policy by calling the store
            let mut policy: String = String::new();
            get_active_policy(&self.base_policy_hash, &state.store, &mut policy).await?;


            // Then resolve the workflow and create the appropriate question
            debug!("Compiling input workflow...");
            let id: String = state.workflow.id.clone();
            let wf: Workflow = match compile(state.workflow) {
                Ok(wf) => wf,
                Err(err) => return Err(Error::ResolveWorkflow { id, err }),
            };

            // Verify whether all things in the workflow exist
            assert_workflow_context(&wf, &state.usecase, &self.usecases).await?;

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
}
