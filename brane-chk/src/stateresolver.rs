//  STATERESOLVER.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:09:36
//  Last edited:
//    18 Oct 2024, 14:10:29
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the Brane-specific state resolver.
//

use std::collections::{HashMap, HashSet};

use brane_cfg::node::WorkerUsecase;
use brane_tsk::api::get_data_index;
use policy_reasoner::spec::stateresolver::StateResolver;
use policy_reasoner::workflow::Workflow;
use policy_reasoner::workflow::visitor::Visitor;
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use specifications::address::Address;
use specifications::data::DataIndex;
use thiserror::Error;
use tracing::{Level, debug, span};

use crate::state::State;
use crate::workflow::compile;


/***** ERRORS *****/
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to send a request to the central registry.
    #[error("Failed to send a request to the central registry at '{addr}' to retrieve {what}")]
    Request {
        what: &'static str,
        addr: Address,
        #[source]
        err:  reqwest::Error,
    },
    /// The server responded with a non-200 OK exit code.
    #[error("Central registry at '{addr}' returned {} ({}) when trying to retrieve {what}{}", status.as_u16(), status.canonical_reason().unwrap_or("???"), if let Some(raw) = raw { format!("\n\nRaw response:\n{}\n{}\n{}\n", (0..80).map(|_| '-').collect::<String>(), raw, (0..80).map(|_| '-').collect::<String>()) } else { String::new() })]
    RequestFailure { what: &'static str, addr: Address, status: StatusCode, raw: Option<String> },
    /// Failed to resolve the data index with the remote Brane API registry.
    #[error("Failed to resolve data with remote Brane registry at '{addr}'")]
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
    #[error("Failed to deserialize respones of central registry at '{addr}' as {what}")]
    ResponseDeserialize {
        what: &'static str,
        addr: Address,
        #[source]
        err:  serde_json::Error,
    },
    /// Failed to download the response of the server.
    #[error("Failed to download a {what} response from the central registry at '{addr}'")]
    ResponseDownload {
        what: &'static str,
        addr: Address,
        #[source]
        err:  reqwest::Error,
    },
    /// The planned user of a task was unknown to us.
    #[error("Unknown planned user {user:?} in call {call:?} in workflow {workflow:?}")]
    UnknownPlannedUser { workflow: String, call: String, user: String },
    /// The usecase submitted with the request was unknown.
    #[error("Unkown usecase '{usecase}'")]
    UnknownUsecase { usecase: String },
    /// The workflow user was not found.
    #[error("Unknown workflow user {user:?} in workflow {workflow:?}")]
    UnknownWorkflowUser { workflow: String, user: String },
}





/***** HELPER FUNCTIONS *****/
/// Sends a GET-request and tries to deserialize the response.
///
/// # Generic arguments
/// - `R`: The [`Deserialize`]able object to expect in the response.
///
/// # Arguments
/// - `url`: The path to send a request to.
///
/// # Returns
/// A parsed `R` if the server replied with 200 OK.
///
/// # Errors
/// This function errors if we failed to send the request, receive the response or if the server did not 200 OK.
async fn send_request<R: DeserializeOwned>(url: &Address) -> Result<R, Error> {
    // Send the request out
    let res: Response = match reqwest::get(url.to_string()).await {
        Ok(res) => res,
        Err(err) => return Err(Error::Request { what: std::any::type_name::<R>(), addr: url.clone(), err }),
    };
    // Check if the response makes sense
    if !res.status().is_success() {
        return Err(Error::RequestFailure {
            what:   std::any::type_name::<R>(),
            addr:   url.clone(),
            status: res.status(),
            raw:    res.text().await.ok(),
        });
    }

    // Now attempt to deserialize the response
    let raw: String = match res.text().await {
        Ok(raw) => raw,
        Err(err) => return Err(Error::ResponseDownload { what: std::any::type_name::<R>(), addr: url.clone(), err }),
    };
    let res: R = match serde_json::from_str(&raw) {
        Ok(res) => res,
        Err(err) => return Err(Error::ResponseDeserialize { what: std::any::type_name::<R>(), addr: url.clone(), err }),
    };

    // Done
    Ok(res)
}

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
async fn assert_workflow_context(wf: &Workflow, usecase: &str, usecases: &HashMap<String, WorkerUsecase>) -> Result<(), Error> {
    // Resolve the usecase to an address to query
    debug!("Resolving usecase {usecase:?} to registry address...");
    let api: &Address = match usecases.get(usecase) {
        Some(usecase) => &usecase.api,
        None => return Err(Error::UnknownUsecase { usecase: usecase.into() }),
    };

    // Send the request to the Brane API registry to get the current state of the datasets
    debug!("Retrieving list of users from registry at '{api}'...");
    let users: HashSet<String> = send_request::<HashMap<String, Address>>(api).await?.into_keys().collect();

    // Check if the users are all found in the system
    if !users.contains(&wf.user.id) {
        return Err(Error::UnknownWorkflowUser { workflow: wf.id.clone(), user: wf.user.id.clone() });
    }

    // let dindex: DataIndex = get_data_index(api.to_string()).await.map_err(|err| Error::ResolveData { addr: api.clone(), err })?;

    // Done!
    Ok(())
}





/***** VISITORS *****/
/// Checks whether all users mentioned in a workflow exist.
#[derive(Debug)]
pub struct AssertUserExistance<'w> {
    /// The workflow ID (for debugging)
    pub wf_id: &'w str,
    /// The users that exist.
    pub users: HashSet<String>,
}
impl<'w> Visitor<'w> for AssertUserExistance<'w> {
    type Error = Error;

    #[inline]
    fn visit_call(&mut self, elem: &'w policy_reasoner::workflow::ElemCall) -> Result<(), Self::Error> {
        // Check if the planned user is known
        if let Some(user) = &elem.at {
            if !self.users.contains(&user.id) {
                return Err(Error::UnknownPlannedUser { workflow: self.wf_id.into(), call: elem.id.clone(), user: user.id.clone() });
            }
        }
        todo!()
    }
}





/***** AUXILLARY *****/
/// Defines the input to the [`StateResolver`]` that will be resolved to concrete info for the reasoner.
#[derive(Clone, Debug)]
pub struct Input {
    /// The usecase that determines the central registry to use.
    pub usecase:  String,
    /// The workflow to further resolve.
    pub workflow: brane_ast::Workflow,
}





/***** LIBRARY *****/
/// Resolves state for the reasoner in the Brane registry.
#[derive(Clone, Debug)]
pub struct BraneStateResolver {
    /// The use-cases that we use to map use-case ID to Brane central registry.
    pub usecases: HashMap<String, WorkerUsecase>,
}
impl BraneStateResolver {}
impl StateResolver for BraneStateResolver {
    type Error = Error;
    type Resolved = State;
    type State = Input;

    fn resolve<L>(
        &self,
        state: Self::State,
        logger: &policy_reasoner::spec::auditlogger::SessionedAuditLogger<L>,
    ) -> impl std::future::Future<Output = Result<Self::Resolved, Self::Error>>
    where
        L: policy_reasoner::spec::AuditLogger,
    {
        async move {
            let _span = span!(
                Level::INFO,
                "BraneStateResolver::resolve",
                reference = logger.reference(),
                usecase = state.usecase,
                workflow = state.workflow.id
            );

            // Then resolve the workflow
            debug!("Compiling input workflow...");
            let id: String = state.workflow.id.clone();
            let wf: Workflow = match compile(state.workflow) {
                Ok(wf) => wf,
                Err(err) => return Err(Error::ResolveWorkflow { id, err }),
            };

            // Verify whether all things in the workflow exist
            assert_workflow_context(&wf, &state.usecase, &self.usecases).await?;

            // Done
            todo!()
        }
    }
}
