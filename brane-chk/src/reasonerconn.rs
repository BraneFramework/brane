//  REASONERCONN.rs
//    by Lut99
//
//  Created:
//    02 Dec 2024, 15:35:46
//  Last edited:
//    01 May 2025, 15:30:10
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines a wrapper around an [`EFlintHaskellReasonerConnector`] that
//!   includes a particular policy interface.
//

use std::path::PathBuf;

use policy_reasoner::reasoners::eflint_haskell::reasons::{PrefixedHandler, ReasonHandler};
use policy_reasoner::reasoners::eflint_haskell::{EFlintHaskellReasonerConnector, Error};
use policy_reasoner::spec::auditlogger::SessionedAuditLogger;
use policy_reasoner::spec::reasonerconn::ReasonerResponse;
use policy_reasoner::spec::{AuditLogger, ReasonerConnector};
use specifications::checking::store::EFlintHaskellReasonerWithInterfaceContext;
use tracing::instrument;

use crate::question::Question;


/***** LIBRARY *****/
/// Wrapper of a [`EFlintHaskellReasonerConnector`] that includes a bit of default interface policy.
#[derive(Clone, Debug)]
pub struct EFlintHaskellReasonerConnectorWithInterface {
    /// The actual reasoner.
    pub reasoner: EFlintHaskellReasonerConnector<PrefixedHandler<'static>, String, Question>,
}
impl EFlintHaskellReasonerConnectorWithInterface {
    /// Constructor for the EFlintHaskellReasonerConnectorWithInterface.
    ///
    /// This constructor logs asynchronously.
    ///
    /// # Arguments
    /// - `cmd`: The command with which to execute the backend `eflint-repl` binary.
    /// - `base_policy_path`: A path to an eFLINT file containing the base policy to load.
    /// - `handler`: The [`ReasonHandler`] that determines how errors from the reasoners are propagated to the user.
    /// - `logger`: A logger to write this reasoner's context to.
    ///
    /// # Returns
    /// A new instance of Self, ready for reasoning.
    ///
    /// # Errors
    /// This function may error if it failed to log to the given `logger`.
    ///
    /// # Panics
    /// This function uses the embedded, compiled eFLINT base code (see the `policy`-directory in
    /// its manifest directory). Building the reasoner will trigger the first load, if any,
    /// and this may panic if the input is somehow ill-formed.
    #[inline]
    pub async fn new_async<'l, L: AuditLogger>(
        cmd: impl 'l + IntoIterator<Item = String>,
        base_policy_path: impl 'l + Into<PathBuf>,
        handler: PrefixedHandler<'static>,
        logger: &'l L,
    ) -> Result<Self, Error> {
        Ok(Self { reasoner: EFlintHaskellReasonerConnector::new_async(cmd, base_policy_path, handler, logger).await? })
    }
}
impl ReasonerConnector for EFlintHaskellReasonerConnectorWithInterface {
    type Context = EFlintHaskellReasonerWithInterfaceContext;
    type Error = Error;
    type Question = Question;
    type Reason = <PrefixedHandler<'static> as ReasonHandler>::Reason;
    type State = String;

    fn context(&self) -> Self::Context { self.reasoner.context() }

    #[instrument(skip_all, fields(reference = logger.reference()))]
    async fn consult<'a, L>(
        &'a self,
        mut state: Self::State,
        question: Self::Question,
        logger: &'a SessionedAuditLogger<L>,
    ) -> Result<ReasonerResponse<Self::Reason>, Self::Error>
    where
        L: Sync + AuditLogger,
    {
        // Then run the normal one
        state.push('\n');
        self.reasoner.consult(state, question, logger).await
    }
}
