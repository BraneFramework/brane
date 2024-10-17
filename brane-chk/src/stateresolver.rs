//  STATERESOLVER.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:09:36
//  Last edited:
//    17 Oct 2024, 16:38:46
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the Brane-specific state resolver.
//

use std::collections::HashMap;

use brane_cfg::node::WorkerUsecase;
use brane_tsk::api::get_data_index;
use policy_reasoner::spec::stateresolver::StateResolver;
use specifications::address::Address;
use specifications::data::DataIndex;
use thiserror::Error;
use tracing::{Level, debug, span};

use crate::state::State;


/***** ERRORS *****/
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to resolve the data index with the remote Brane API registry.
    #[error("Failed to resolve data with remote Brane registry at '{addr}'")]
    ResolveData { addr: Address, err: brane_tsk::api::Error },
    /// The usecase submitted with the request was unknown.
    #[error("Unkown usecase '{usecase}'")]
    UnknownUsecase { usecase: String },
}





/***** HELPER FUNCTIONS *****/
/// Resolves a usecase identifier to a set of datasets.
///
/// # Arguments
/// - `usecase`: The usecase identifier to resolve.
/// - `usecases`: The map of usescases to resolve the `usecase` to a registry address with.
///
/// # Returns
/// A [`DataIndex`] that contains the known data in the system.
///
/// # Errors
/// This function may error if the `usecase` is unknown, or if the remote registry does not reply (correctly).
async fn resolve_usecase(usecase: &str, usecases: &HashMap<String, WorkerUsecase>) -> Result<DataIndex, Error> {
    // Resolve the usecase to an address to query
    debug!("Resolving usecase {usecase:?} to registry address...");
    let api: &Address = match usecases.get(usecase) {
        Some(usecase) => &usecase.api,
        None => return Err(Error::UnknownUsecase { usecase: usecase.into() }),
    };

    // Send the request to the Brane API registry to get the current state of the datasets
    debug!("Retrieving data index from registry at '{api}'...");
    let dindex: DataIndex = get_data_index(api.to_string()).await.map_err(|err| Error::ResolveData { addr: api.clone(), err })?;
    Ok(dindex)
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

            // Resolve the usecase first
            resolve_usecase(&state.usecase, &self.usecases).await?;

            // Done
            todo!()
        }
    }
}
