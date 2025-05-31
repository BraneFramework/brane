//  REASONER.rs
//    by Lut99
//
//  Created:
//    02 Dec 2024, 14:00:06
//  Last edited:
//    29 Apr 2025, 23:33:56
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements an API for getting non-"public" (deliberation)
//!   information that is beyond the store API.
//

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Extension, Router};
use error_trace::{ErrorTrace as _, Trace};
use hyper::StatusCode;
use policy_reasoner::spec::ReasonerConnector;
use policy_store::servers::axum::AxumServer;
use policy_store::spec::AuthResolver;
use policy_store::spec::metadata::User;
use specifications::checking::store::{EFlintHaskellReasonerWithInterfaceContext, GetContextResponse};
use thiserror::Error;
use tracing::{debug, error, instrument};


/***** ERRORS *****/
/// Defines the errors originating in the reasoner API.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create the KID resolver")]
    KidResolver { source: policy_store::auth::jwk::keyresolver::kid::ServerError },
    #[error("Failed to bind server on address '{addr}'")]
    ListenerBind { addr: SocketAddr, source: std::io::Error },
}





/***** LIBRARY *****/
/// Handler for `GET /v2/context` (i.e., retrieving reasoner context).
///
/// Out:
/// - 200 OK with a [`GetContextResponse`] detailling the relevant reasoner information; or
/// - 500 INTERNAL SERVER ERROR with a message what went wrong.
#[instrument(skip_all, fields(user = auth.id))]
pub async fn get_context<R>(State(this): State<Arc<R>>, Extension(auth): Extension<User>) -> (StatusCode, String)
where
    R: Send + Sync + ReasonerConnector<Context = EFlintHaskellReasonerWithInterfaceContext>,
{
    // Generate the context
    let res: GetContextResponse = GetContextResponse { context: this.context() };

    // Serialize and send back
    match serde_json::to_string(&res) {
        Ok(res) => (StatusCode::OK, res),
        Err(err) => {
            let err = Trace::from_source("Failed to serialize context", err);
            error!("{}", err.trace());
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        },
    }
}

/// Given a [`Router`], injects the [`get_context()`]-path into it.
///
/// # Arguments
/// - `server`: The already existing [`AxumServer`] that is also the state to give to the
///   auth function.
/// - `reasoner`: Some [`ReasonerConnector`] that can provide us with the context to provide.
/// - `router`: A [`Router`] to inject with the path.
///
/// # Returns
/// A new [`Router`] that is the same but with the new path in it.
#[instrument(skip_all)]
pub fn inject_reasoner_api<A, D, R>(server: Arc<AxumServer<A, D>>, reasoner: Arc<R>, router: Router<()>) -> Router<()>
where
    A: 'static + Send + Sync + AuthResolver,
    A::Context: 'static + Send + Sync + Clone,
    A::ClientError: 'static,
    A::ServerError: 'static,
    D: 'static + Send + Sync,
    R: 'static + Send + Sync + ReasonerConnector<Context = EFlintHaskellReasonerWithInterfaceContext>,
{
    // First, define the axum paths
    debug!("Injecting additional axum paths...");
    let get_context: Router = Router::new()
        .route("/context", get(get_context::<R>))
        .layer(axum::middleware::from_fn_with_state(server, policy_store::servers::axum::AxumServer::check))
        .with_state(reasoner.clone());
    router.nest("/v2/", get_context)
}
