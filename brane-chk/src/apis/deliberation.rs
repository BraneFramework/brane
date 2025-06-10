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

use axum::body::Bytes;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::on;
use axum::{Extension, Json, Router};
use brane_shr::errors::SerdeError;
use brane_shr::errors::confidentiality::{Confidentiality, HttpError};
use error_trace::trace;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use miette::Report;
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





/***** ERRORS *****/
/// Defines errors originating from the bowels of the [`Deliberation`].
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create the KID resolver")]
    KidResolver { source: policy_store::auth::jwk::keyresolver::kid::ServerError },
    #[error("Failed to bind server on address '{addr}'")]
    ListenerBind { addr: SocketAddr, source: std::io::Error },
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
    S::Error: std::error::Error + Send + Sync,
    P: 'static + Send + Sync + ReasonerConnector,
    P::Error: Send + Sync + 'static,
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
    async fn check(this: Arc<Self>, reference: &str, input: Input) -> Result<Json<CheckResponse<<P as ReasonerConnector>::Reason>>, HttpError> {
        // Build the state, then resolve it
        let (state, question): (P::State, P::Question) =
            this.resolver.resolve(input, &SessionedAuditLogger::new(reference, &this.logger)).await.map_err(|source| {
                let status_code = (&source).into();
                let report = Report::from_err(source).wrap_err("Failed to resolve input to the reasoner");
                HttpError::new_from_report(Confidentiality::OnlyMessage, report, status_code)
            })?;

        // With that in order, hit the reasoner
        let res = this
            .reasoner
            .consult(state, question, &SessionedAuditLogger::new(reference, &this.logger))
            .await
            .map_err(|source| HttpError::new_from_error(Confidentiality::Public, Box::new(source), StatusCode::INTERNAL_SERVER_ERROR).expose())?;

        Ok(Json(CheckResponse { verdict: res }))
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
            .map_err(|source| {
                HttpError::new_from_report(
                    Confidentiality::OnlyMessage,
                    Report::from_err(source).wrap_err("Failed to authorize incoming request"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?
            .map_err(|source| {
                let status_code = source.status_code();
                HttpError::new_from_report(
                    Confidentiality::OnlyMessage,
                    Report::new(source).wrap_err("Failed to authorize incoming request"),
                    status_code,
                )
                .expose()
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
    async fn check_workflow(
        State(this): State<Arc<Self>>,
        Extension(auth): Extension<User>,
        MietteJson(request): MietteJson<CheckWorkflowRequest>,
    ) -> Result<Json<CheckResponse<<P as ReasonerConnector>::Reason>>, HttpError> {
        let reference = Reference::create(&auth.id);
        Span::current().record("reference", reference.as_str());

        // Decide the input
        let input =
            Input { store: this.store.clone(), usecase: request.usecase, workflow: request.workflow, input: QuestionInput::ValidateWorkflow };

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
    async fn check_task(
        State(this): State<Arc<Self>>,
        Extension(auth): Extension<User>,
        MietteJson(request): MietteJson<CheckTaskRequest>,
    ) -> Result<Json<CheckResponse<<P as ReasonerConnector>::Reason>>, HttpError> {
        let reference = Reference::create(&auth.id);
        Span::current().record("reference", reference.as_str());

        // Decide the input
        let task_id: String = pc_to_id(&request.workflow, request.task);
        let input = Input {
            store:    this.store.clone(),
            usecase:  request.usecase,
            workflow: request.workflow,
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
    async fn check_transfer(
        State(this): State<Arc<Self>>,
        Extension(auth): Extension<User>,
        MietteJson(request): MietteJson<CheckTransferRequest>,
    ) -> Result<Json<CheckResponse<<P as ReasonerConnector>::Reason>>, HttpError> {
        let reference = Reference::create(&auth.id);
        Span::current().record("reference", reference.as_str());

        let input = if let Some(task) = request.task {
            let task_id: String = pc_to_id(&request.workflow, task);
            QuestionInput::TransferInput { task: task_id, input: request.input }
        } else {
            QuestionInput::TransferResult { result: request.input }
        };

        // Decide the input
        let input = Input { store: this.store.clone(), usecase: request.usecase, workflow: request.workflow, input };

        // Continue with the agnostic function for maintainability
        Self::check(this, reference.as_str(), input).await
    }
}

// Serve
impl<S, P, L> Deliberation<S, P, L>
where
    S: 'static + Send + Sync + StateResolver<State = Input, Resolved = (P::State, P::Question)>,
    for<'e> &'e S::Error: Into<StatusCode>,
    S::Error: std::error::Error + Send + Sync + 'static,
    P: 'static + Send + Sync + ReasonerConnector,
    P::Error: Send + Sync + 'static,
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
        let router: IntoMakeServiceWithConnectInfo<Router, SocketAddr> = Router::new()
            .route(CHECK_WORKFLOW_PATH.path, on(CHECK_WORKFLOW_PATH.method.try_into().unwrap(), Self::check_workflow))
            .route(CHECK_TASK_PATH.path, on(CHECK_TASK_PATH.method.try_into().unwrap(), Self::check_task))
            .route(CHECK_TRANSFER_PATH.path, on(CHECK_TRANSFER_PATH.method.try_into().unwrap(), Self::check_transfer))
            .with_state(this.clone())
            .layer(axum::middleware::from_fn_with_state(this.clone(), Self::authorize))
            .into_make_service_with_connect_info();

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


use axum::body::Body;
use axum::extract::FromRequest;

pub struct MietteJson<T>(pub T);

impl<S, T> FromRequest<S, Body> for MietteJson<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request(req: axum::extract::Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        // let (parts, body) = req.into_parts();
        let bytes = Bytes::from_request(req, state).await.unwrap();

        // FIXME: Check if body is empty

        let value = serde_json::from_slice(&bytes).map_err(|err| {
            let diag = Box::new(SerdeError::from_json(String::from_utf8(bytes.to_vec()).unwrap(), err));
            HttpError::new_from_diagnostic(Confidentiality::Public, diag, StatusCode::BAD_REQUEST)
        })?;

        Ok(MietteJson(value))
    }
}
