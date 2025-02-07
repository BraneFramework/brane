//  REASONERCONN.rs
//    by Lut99
//
//  Created:
//    02 Dec 2024, 15:35:46
//  Last edited:
//    07 Feb 2025, 16:32:28
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines a wrapper around an [`EFlintJsonReasonerConnector`] that
//!   includes a particular policy interface.
//

use std::fmt::Display;
use std::future::Future;
use std::sync::LazyLock;

use eflint_json::spec::{Phrase, Request};
use policy_reasoner::reasoners::eflint_json::reasons::{EFlintPrefixedReasonHandler, ReasonHandler};
use policy_reasoner::reasoners::eflint_json::spec::EFlintable;
use policy_reasoner::reasoners::eflint_json::{EFlintJsonReasonerConnector, EFlintJsonReasonerContext, Error};
use policy_reasoner::spec::auditlogger::SessionedAuditLogger;
use policy_reasoner::spec::reasonerconn::ReasonerResponse;
use policy_reasoner::spec::{AuditLogger, ReasonerConnector};
use specifications::checking::store::EFlintJsonReasonerWithInterfaceContext;
use tracing::{Instrument as _, Level, span};

use crate::question::Question;


/***** GLOBALS *****/
/// The base policy that it preprended to any given policy.
static BASE_POLICY: LazyLock<Vec<Phrase>> = LazyLock::new(|| {
    serde_json::from_str::<Request>(include_str!(env!("BASE_DEFS_EFLINT_JSON")))
        .unwrap_or_else(|err| panic!("Failed to deserialize base policy: {err}"))
        .into_phrases()
        .phrases
});





/***** LIBRARY *****/
/// Wrapper of a [`EFlintJsonReasonerConnector`] that includes a bit of default interface policy.
#[derive(Clone, Debug)]
pub struct EFlintJsonReasonerConnectorWithInterface {
    /// The actual reasoner.
    pub reasoner: EFlintJsonReasonerConnector<EFlintPrefixedReasonHandler, Vec<Phrase>, Question>,
}
impl EFlintJsonReasonerConnectorWithInterface {
    /// Constructor for the EFlintJsonReasonerConnectorWithInterface.
    ///
    /// This constructor logs asynchronously.
    ///
    /// # Arguments
    /// - `addr`: The address of the remote reasoner that we will connect to.
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
    pub fn new_async<'l, L: AuditLogger>(
        addr: impl 'l + Display,
        handler: EFlintPrefixedReasonHandler,
        logger: &'l L,
    ) -> impl 'l
    + Future<
        Output = Result<
            Self,
            Error<<EFlintPrefixedReasonHandler as ReasonHandler>::Error, <Vec<Phrase> as EFlintable>::Error, <Question as EFlintable>::Error>,
        >,
    > {
        async move {
            // Trigger loading the embedded file to be sure it's already properly deserialized
            LazyLock::force(&BASE_POLICY);

            // Create the normal one
            let reasoner: EFlintJsonReasonerConnector<EFlintPrefixedReasonHandler, Vec<Phrase>, Question> =
                EFlintJsonReasonerConnector::new_async(format!("http://{addr}"), handler, logger).await?;

            // OK, done
            Ok(Self { reasoner })
        }
    }
}
impl ReasonerConnector for EFlintJsonReasonerConnectorWithInterface {
    type Context = EFlintJsonReasonerWithInterfaceContext;
    type Error = Error<<EFlintPrefixedReasonHandler as ReasonHandler>::Error, <Vec<Phrase> as EFlintable>::Error, <Question as EFlintable>::Error>;
    type Question = Question;
    type Reason = <EFlintPrefixedReasonHandler as ReasonHandler>::Reason;
    type State = Vec<Phrase>;

    fn context(&self) -> Self::Context {
        EFlintJsonReasonerWithInterfaceContext { context: EFlintJsonReasonerContext::default(), hash: env!("BASE_DEFS_EFLINT_JSON_HASH").into() }
    }

    fn consult<'a, L>(
        &'a self,
        state: Self::State,
        question: Self::Question,
        logger: &'a SessionedAuditLogger<L>,
    ) -> impl 'a + Send + Future<Output = Result<ReasonerResponse<Self::Reason>, Self::Error>>
    where
        L: Sync + AuditLogger,
    {
        async move {
            // Prefix the base policy
            let mut policy = BASE_POLICY.clone();
            policy.extend(state);

            // Then run the normal one
            self.reasoner.consult(policy, question, logger).await
        }
        .instrument(span!(Level::INFO, "EFlintJsonReasonerConnectorWithInterface::consult", reference = logger.reference()))
    }
}
