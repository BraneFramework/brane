//  SERVER.rs
//    by Lut99
//
//  Created:
//    28 Oct 2024, 20:44:52
//  Last edited:
//    02 May 2025, 15:01:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the webserver for the deliberation API.
//

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::on;
use axum::{Extension, Router};
use brane_shr::errors::confidentiality::HttpError;
use error_trace::trace;
use futures::StreamExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use policy_reasoner::spec::auditlogger::SessionedAuditLogger;
use policy_reasoner::spec::{AuditLogger, ReasonerConnector, StateResolver};
use policy_store::auth::jwk::JwkResolver;
use policy_store::auth::jwk::keyresolver::KidResolver;
use policy_store::databases::sqlite::SQLiteDatabase;
use policy_store::spec::AuthResolver as _;
use policy_store::spec::authresolver::HttpError as _;
use policy_store::spec::metadata::User;
use rand::Rng;
use rand::distr::Alphanumeric;
use serde::Serialize;
use serde::de::DeserializeOwned;
use specifications::checking::deliberation::{
    CHECK_TASK_PATH, CHECK_TRANSFER_PATH, CHECK_WORKFLOW_PATH, CheckResponse, CheckTaskRequest, CheckTransferRequest, CheckWorkflowRequest,
};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tower_service::Service as _;
use tracing::{Span, debug, error, info, instrument};

use crate::stateresolver::{Input, QuestionInput};
use crate::workflow::compile::pc_to_id;


/***** CONSTANTS *****/
/// The initiator claim that must be given in the input header token.
pub const INITIATOR_CLAIM: &str = "username";
const BLOCK_SEPARATOR: &str = "--------------------------------------------------------------------------------";





/***** ERRORS *****/
/// Defines errors originating from the bowels of the [`Deliberation`].
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create the KID resolver")]
    KidResolver { source: policy_store::auth::jwk::keyresolver::kid::ServerError },
    #[error("Failed to bind server on address '{addr}'")]
    ListenerBind { addr: SocketAddr, source: std::io::Error },
}




/***** HELPER FUNCTIONS *****/
/// Turns the given [`Request`] into a deserialized object.
///
/// This is done instead of using the [`Json`](axum::extract::Json) extractor because we want to
/// log the raw inputs upon failure.
///
/// # Generics
/// - `T`: The thing to deserialize to.
///
/// # Arguments
/// - `request`: The [`Request`] to download and turn into JSON.
///
/// # Returns
/// A parsed `T`.
///
/// # Errors
/// This function errors if we failed to download the request body, or it was not valid JSON.
async fn download_request<T: DeserializeOwned>(request: Request) -> Result<T, HttpError> {
    // Download the entire request first
    let mut req: Vec<u8> = Vec::new();
    let mut request = request.into_body().into_data_stream();
    while let Some(next) = request.next().await {
        // Unwrap the chunk
        let next =
            next.map_err(|source| HttpError::new("Failed to download request body".into(), Box::new(source), StatusCode::INTERNAL_SERVER_ERROR))?;

        // Append it
        req.extend(next);
    }

    // Deserialize the request contents
    serde_json::from_slice(&req).map_err(|source| {
        let msg: String = format!(
            "{}Raw body:\n{BLOCK_SEPARATOR}\n{}\n{BLOCK_SEPARATOR}\n",
            trace!(("Failed to deserialize request body"), source),
            String::from_utf8_lossy(&req)
        );

        HttpError::new(msg, Box::new(source), StatusCode::BAD_REQUEST)
    })
}





/***** LIBRARY *****/
pub struct Reference(pub Arc<str>);

impl Reference {
    /// Creates a reference from its inner type, you probably want to use [`Self::create()`]
    /// instead
    pub fn new(reference: impl Into<Arc<str>>) -> Self { Self(reference.into()) }

    /// Create a reference using a auth_id
    pub fn create(auth_id: &str) -> Self {
        const RANDOM_LEN: usize = 8;
        const SEPARATOR_LEN: usize = 1;

        let capacity = auth_id.len() + SEPARATOR_LEN + RANDOM_LEN;
        let mut reference = String::with_capacity(capacity);

        reference.push_str(auth_id);
        reference.push('-');
        reference.extend(rand::rng().sample_iter(Alphanumeric).take(RANDOM_LEN).map(char::from));

        debug_assert_eq!(reference.len(), capacity, "Unexpected string length");

        Self::new(reference.into_boxed_str())
    }

    pub fn as_str(&self) -> &str { &self.0 }
}


/// Defines a Brane-compliant deliberation API server.
pub struct Deliberation<S, P, L> {
    /// The address on which to bind the server.
    addr:     SocketAddr,
    /// The auth resolver for resolving auth.
    auth:     JwkResolver<KidResolver>,
    /// The store for accessing the backend database.
    store:    Arc<SQLiteDatabase<String>>,
    /// The state resolver for resolving state.
    resolver: S,
    /// The reasoner connector for connecting to reasoners.
    reasoner: Arc<P>,
    /// The logger for logging!
    logger:   L,
}
impl<S, P, L> Deliberation<S, P, L> {
    /// Constructor for the Deliberation.
    ///
    /// # Arguments
    /// - `addr`: The address on which to listen once [`serve()`](Deliberation::serve())ing.
    /// - `keystore_path`: The path to the keystore file that maps KIDs to the key used for
    ///   encrypting/decrypting login JWTs.
    /// - `store`: A shared ownership of the [`SQLiteDatabase`] that we use for accessing policies.
    /// - `resolver`: The [`StateResolver`] used to resolve the state in the given requests.
    /// - `reasoner`: The [`ReasonerConnector`] used to interact with the backend reasoner.
    /// - `logger`: The [`AuditLogger`] that will log what the reasoner is doing.
    ///
    /// # Returns
    /// A new Deliberation, ready to handle requests or something.
    #[inline]
    pub fn new(
        addr: impl Into<SocketAddr>,
        keystore_path: impl AsRef<Path>,
        store: Arc<SQLiteDatabase<String>>,
        resolver: S,
        reasoner: Arc<P>,
        logger: L,
    ) -> Result<Self, Error> {
        // Attempt to create the KidResolver
        let kid = KidResolver::new(keystore_path).map_err(|source| Error::KidResolver { source })?;

        // If that worked, get kicking
        Ok(Self { addr: addr.into(), auth: JwkResolver::new(INITIATOR_CLAIM, kid), store, resolver, reasoner, logger })
    }
}

// Paths
impl<S, P, L> Deliberation<S, P, L>
where
    S: 'static + Send + Sync + StateResolver<State = Input, Resolved = (P::State, P::Question)>,
    for<'e> &'e S::Error: Into<StatusCode>,
    S::Error: std::error::Error,
    P: 'static + Send + Sync + ReasonerConnector,
    P::Reason: Serialize,
    L: Send + Sync + AuditLogger,
{
    /// Helper function for handling all three endpoints after the question has been decided.
    ///
    /// # Arguments
    /// - `this`: `self` but in an [`Arc`].
    /// - `reference`: The reference for which this request is being done.
    /// - `input`: The [`Input`] that will be resolved to the reasoner input.
    ///
    /// # Returns
    /// The status code of the response and a message to attach to it.
    async fn check(this: Arc<Self>, reference: &str, input: Input) -> Result<Response, HttpError> {
        // Build the state, then resolve it
        let (state, question): (P::State, P::Question) =
            this.resolver.resolve(input, &SessionedAuditLogger::new(reference, &this.logger)).await.map_err(|source| {
                let status_code = (&source).into();
                HttpError::new("Failed to resolve input to the reasoner".into(), Box::new(source), status_code)
            })?;

        // With that in order, hit the reasoner
        let res = this
            .reasoner
            .consult(state, question, &SessionedAuditLogger::new(reference, &this.logger))
            .await
            .map_err(|source| HttpError::from_error(Box::new(source), StatusCode::INTERNAL_SERVER_ERROR).expose())?;

        // Serialize the response
        let res: String = serde_json::to_string(&CheckResponse { verdict: res })
            .map_err(|source| HttpError::new("Failed to serialize reasoner response".into(), Box::new(source), StatusCode::INTERNAL_SERVER_ERROR))?;

        // OK
        Ok((StatusCode::OK, res).into_response())
    }

    /// Authorization middle layer for the Deliberation.
    ///
    /// This will read the `Authorization` header in the incoming request for a token that
    /// identifies the user. The request will be interrupted if the token is missing, invalid or
    /// not (properly) signed.
    #[instrument(level="info", skip_all, fields(client = %client))]
    async fn authorize(
        State(context): State<Arc<Self>>,
        ConnectInfo(client): ConnectInfo<SocketAddr>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, HttpError> {
        let user: User = context
            .auth
            .authorize(request.headers())
            .await
            .map_err(|source| HttpError::new("Failed to authorize incoming request".into(), Box::new(source), StatusCode::INTERNAL_SERVER_ERROR))?
            .map_err(|source| {
                let status_code = source.status_code();
                HttpError::new("Failed to authorize incoming request".into(), Box::new(source), status_code).expose()
            })?;

        // If we found a context, then inject it in the request as an extension; then continue
        request.extensions_mut().insert(user);
        Ok(next.run(request).await)
    }

    /// Handler for `GET /v2/workflow` (i.e., checking a whole workflow).
    ///
    /// In:
    /// - [`CheckWorkflowRequest`].
    ///
    /// Out:
    /// - 200 OK with an [`CheckResponse`] detailling the verdict of the reasoner;
    /// - 400 BAD REQUEST with the reason why we failed to parse the request;
    /// - 404 NOT FOUND if the given use-case was unknown; or
    /// - 500 INTERNAL SERVER ERROR with a message what went wrong.
    #[instrument(skip_all, fields(user = auth.id, reference))]
    async fn check_workflow(State(this): State<Arc<Self>>, Extension(auth): Extension<User>, request: Request) -> Result<Response, HttpError> {
        let reference = Reference::create(&auth.id);
        Span::current().record("reference", reference.as_str());

        // Get the request
        let req: CheckWorkflowRequest = download_request(request).await?;

        // Decide the input
        let input = Input { store: this.store.clone(), usecase: req.usecase, workflow: req.workflow, input: QuestionInput::ValidateWorkflow };

        // Continue with the agnostic function for maintainability
        Self::check(this, reference.as_str(), input).await
    }

    /// Handler for `GET /v2/task` (i.e., checking a task in a workflow).
    ///
    /// In:
    /// - [`CheckTaskRequest`].
    ///
    /// Out:
    /// - 200 OK with an [`CheckResponse`] detailling the verdict of the reasoner;
    /// - 404 BAD REQUEST with the reason why we failed to parse the request; or
    /// - 500 INTERNAL SERVER ERROR with a message what went wrong.
    #[instrument(skip_all, fields(user = auth.id, reference))]
    async fn check_task(State(this): State<Arc<Self>>, Extension(auth): Extension<User>, request: Request) -> Result<Response, HttpError> {
        let reference = Reference::create(&auth.id);
        Span::current().record("reference", reference.as_str());

        // Get the request
        let req: CheckTaskRequest = download_request(request).await?;

        // Decide the input
        let task_id: String = pc_to_id(&req.workflow, req.task);
        let input = Input {
            store:    this.store.clone(),
            usecase:  req.usecase,
            workflow: req.workflow,
            input:    QuestionInput::ExecuteTask { task: task_id },
        };

        // Continue with the agnostic function for maintainability
        Self::check(this, reference.as_str(), input).await
    }

    /// Handler for `GET /v2/transfer` (i.e., checking a transfer for a task in a workflow).
    ///
    /// In:
    /// - [`CheckTransferRequest`].
    ///
    /// Out:
    /// - 200 OK with an [`CheckResponse`] detailling the verdict of the reasoner;
    /// - 404 BAD REQUEST with the reason why we failed to parse the request; or
    /// - 500 INTERNAL SERVER ERROR with a message what went wrong.
    #[instrument(skip_all, fields(user = auth.id, reference))]
    async fn check_transfer(State(this): State<Arc<Self>>, Extension(auth): Extension<User>, request: Request) -> Result<Response, HttpError> {
        let reference = Reference::create(&auth.id);
        Span::current().record("reference", reference.as_str());

        // Get the request
        let req: CheckTransferRequest = download_request(request).await?;

        let input = if let Some(task) = req.task {
            let task_id: String = pc_to_id(&req.workflow, task);
            QuestionInput::TransferInput { task: task_id, input: req.input }
        } else {
            QuestionInput::TransferResult { result: req.input }
        };

        // Decide the input
        let input = Input { store: this.store.clone(), usecase: req.usecase, workflow: req.workflow, input };

        // Continue with the agnostic function for maintainability
        Self::check(this, reference.as_str(), input).await
    }
}

// Serve
impl<S, P, L> Deliberation<S, P, L>
where
    S: 'static + Send + Sync + StateResolver<State = Input, Resolved = (P::State, P::Question)>,
    for<'e> &'e S::Error: Into<StatusCode>,
    S::Error: std::error::Error,
    P: 'static + Send + Sync + ReasonerConnector,
    P::Reason: Serialize,
    L: 'static + Send + Sync + AuditLogger,
{
    /// Runs this server.
    ///
    /// This will hijack the current codeflow and keep serving the server until the end of the
    /// universe! ...or until the server quits.
    ///
    /// In case of the latter, the thread just returns.
    ///
    /// # Errors
    /// This function may error if the server failed to listen of if a fatal server errors comes
    /// along as it serves. However, client-side errors should not trigger errors at this level.
    #[instrument(skip_all)]
    pub async fn serve(self) -> Result<(), Error> {
        let this: Arc<Self> = Arc::new(self);

        // First, define the axum paths
        debug!("Building axum paths...");
        let check_workflow: Router = Router::new()
            .route(CHECK_WORKFLOW_PATH.path, on(CHECK_WORKFLOW_PATH.method.try_into().unwrap(), Self::check_workflow))
            .layer(axum::middleware::from_fn_with_state(this.clone(), Self::authorize))
            .with_state(this.clone());
        let check_task: Router = Router::new()
            .route(CHECK_TASK_PATH.path, on(CHECK_TASK_PATH.method.try_into().unwrap(), Self::check_task))
            .layer(axum::middleware::from_fn_with_state(this.clone(), Self::authorize))
            .with_state(this.clone());
        let check_transfer: Router = Router::new()
            .route(CHECK_TRANSFER_PATH.path, on(CHECK_TRANSFER_PATH.method.try_into().unwrap(), Self::check_transfer))
            .layer(axum::middleware::from_fn_with_state(this.clone(), Self::authorize))
            .with_state(this.clone());
        let router: IntoMakeServiceWithConnectInfo<Router, SocketAddr> =
            Router::new().nest("/", check_workflow).nest("/", check_task).nest("/", check_transfer).into_make_service_with_connect_info();

        // Bind the TCP Listener
        debug!("Binding server on '{}'...", this.addr);
        let listener = TcpListener::bind(this.addr).await.map_err(|source| Error::ListenerBind { addr: this.addr, source })?;

        // Accept new connections!
        info!("Initialization OK, awaiting connections...");
        loop {
            // Accept a new connection
            let (socket, remote_addr): (TcpStream, SocketAddr) = match listener.accept().await {
                Ok(res) => res,
                Err(err) => {
                    error!("{}", trace!(("Failed to accept incoming connection"), err));
                    continue;
                },
            };

            // Move the rest to a separate task
            let router: IntoMakeServiceWithConnectInfo<_, _> = router.clone();
            tokio::spawn(async move { Self::handle(remote_addr, socket, router).await });
        }
    }

    /// Handle a single connection the serve function
    #[instrument(skip_all, fields(remote_addr = %remote_addr))]
    async fn handle(remote_addr: SocketAddr, socket: TcpStream, router: IntoMakeServiceWithConnectInfo<Router, SocketAddr>) {
        debug!("Handling incoming connection from '{remote_addr}'");

        // Build  the service
        let service = hyper::service::service_fn(|request: Request<Incoming>| {
            // Sadly, we must `move` again because this service could be called multiple times (at least according to the typesystem)
            let mut router = router.clone();
            async move {
                // SAFETY: We can call `unwrap()` because the call returns an infallible.
                router.call(remote_addr).await.unwrap().call(request).await
            }
        });

        // Create a service that handles this for us
        let socket: TokioIo<_> = TokioIo::new(socket);
        if let Err(err) = HyperBuilder::new(TokioExecutor::new()).serve_connection_with_upgrades(socket, service).await {
            error!("{}", trace!(("Failed to serve incoming connection"), *err));
        }
    }
}
