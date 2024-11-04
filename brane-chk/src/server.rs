//  SERVER.rs
//    by Lut99
//
//  Created:
//    28 Oct 2024, 20:44:52
//  Last edited:
//    04 Nov 2024, 16:49:06
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the webserver for the deliberation API.
//

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use brane_ast::Workflow;
use eflint_json::spec::Phrase;
use error_trace::{ErrorTrace as _, trace};
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
use policy_store::spec::authresolver::HttpError;
use policy_store::spec::metadata::User;
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tower_service::Service as _;
use tracing::field::Empty;
use tracing::{Level, debug, error, info, span};

use crate::stateresolver::{Input, QuestionInput};


/***** CONSTANTS *****/
/// The initiator claim that must be given in the input header token.
pub const INITIATOR_CLAIM: &'static str = "username";





/***** ERRORS *****/
/// Simple wrapper for erroring and freezing the result.
#[derive(Debug, Error)]
enum TempError<E> {
    #[error("Failed to authorize incoming request")]
    AuthorizeFailed {
        #[source]
        err: E,
    },
    #[error("Failed to resolve reasoner input")]
    ResolveFailed {
        #[source]
        err: E,
    },
}
impl<E: 'static + HttpError> HttpError for TempError<E> {
    #[inline]
    fn status_code(&self) -> StatusCode {
        match self {
            Self::AuthorizeFailed { err } | Self::ResolveFailed { err } => err.status_code(),
        }
    }
}



/// Defines errors originating from the bowels of the [`Server`].
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to create the KID resolver.
    #[error("Failed to create the KID resolver")]
    KidResolver { err: policy_store::auth::jwk::keyresolver::kid::ServerError },
    /// Failed to bind on the given address.
    #[error("Failed to bind server on address '{addr}'")]
    ListenerBind {
        addr: SocketAddr,
        #[source]
        err:  std::io::Error,
    },
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
async fn download_request<T: DeserializeOwned>(request: Request) -> Result<T, (StatusCode, String)> {
    // Download the entire request first
    let mut req: Vec<u8> = Vec::new();
    let mut request = request.into_body().into_data_stream();
    while let Some(next) = request.next().await {
        // Unwrap the chunk
        let next: Bytes = match next {
            Ok(next) => next,
            Err(err) => {
                let msg: &'static str = "Failed to download request body";
                error!("{}", trace!(("{msg}"), err));
                return Err((StatusCode::INTERNAL_SERVER_ERROR, msg.into()));
            },
        };

        // Append it
        req.extend(next);
    }

    // Deserialize the request contents
    match serde_json::from_slice(&req) {
        Ok(req) => Ok(req),
        Err(err) => {
            let error: String = format!(
                "{}Raw body:\n{}\n{}\n{}\n",
                trace!(("Failed to deserialize request body"), err),
                (0..80).map(|_| '-').collect::<String>(),
                String::from_utf8_lossy(&req),
                (0..80).map(|_| '-').collect::<String>()
            );
            info!("{error}");
            Err((StatusCode::BAD_REQUEST, error))
        },
    }
}





/***** SPECIFICATIONS *****/
/// Defines the request to send to the [`Server::check_workflow()`] endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckWorkflowRequest {
    /// The usecase that refers to the API to consult for state.
    pub usecase:  String,
    /// The workflow we're parsing.
    pub workflow: Workflow,
}





/***** LIBRARY *****/
/// Defines a Brane-compliant Checker API server.
pub struct Server<S, P, L> {
    /// The address on which to bind the server.
    addr:     SocketAddr,
    /// The auth resolver for resolving auth.
    auth:     JwkResolver<KidResolver>,
    /// The store for accessing the backend database.
    store:    Arc<SQLiteDatabase<Vec<Phrase>>>,
    /// The state resolver for resolving state.
    resolver: S,
    /// The reasoner connector for connecting to reasoners.
    reasoner: P,
    /// The logger for logging!
    logger:   L,
}
impl<S, P, L> Server<S, P, L> {
    /// Constructor for the Server.
    ///
    /// # Arguments
    /// - `addr`: The address on which to listen once [`serve()`](Server::serve())ing.
    /// - `keystore_path`: The path to the keystore file that maps KIDs to the key used for
    ///   encrypting/decrypting login JWTs.
    /// - `store`: A shared ownership of the [`SQLiteDatabase`] that we use for accessing policies.
    /// - `resolver`: The [`StateResolver`] used to resolve the state in the given requests.
    /// - `reasoner`: The [`ReasonerConnector`] used to interact with the backend reasoner.
    /// - `logger`: The [`AuditLogger`] that will log what the reasoner is doing.
    ///
    /// # Returns
    /// A new Server, ready to handle requests or something.
    #[inline]
    pub fn new(
        addr: impl Into<SocketAddr>,
        keystore_path: impl AsRef<Path>,
        store: Arc<SQLiteDatabase<Vec<Phrase>>>,
        resolver: S,
        reasoner: P,
        logger: L,
    ) -> Result<Self, Error> {
        // Attempt to create the KidResolver
        let kid = match KidResolver::new(keystore_path) {
            Ok(res) => res,
            Err(err) => return Err(Error::KidResolver { err }),
        };

        // If that worked, get kicking
        Ok(Self { addr: addr.into(), auth: JwkResolver::new(INITIATOR_CLAIM, kid), store, resolver, reasoner, logger })
    }
}

// Paths
impl<S, P, L> Server<S, P, L>
where
    S: 'static + Send + Sync + StateResolver<State = Input, Resolved = (P::State, P::Question)>,
    S::Error: HttpError,
    P: 'static + Send + Sync + ReasonerConnector,
    L: 'static + Send + Sync + AuditLogger,
{
    /// Authorization middle layer for the Server.
    ///
    /// This will read the `Authorization` header in the incoming request for a token that
    /// identifies the user. The request will be interrupted if the token is missing, invalid or
    /// not (properly) signed.
    async fn authorize(State(context): State<Arc<Self>>, ConnectInfo(client): ConnectInfo<SocketAddr>, mut request: Request, next: Next) -> Response {
        let _span = span!(Level::INFO, "Server::authorize", client = client.to_string());

        // Do the auth thingy
        let user: User = match context.auth.authorize(request.headers()).await {
            Ok(Ok(user)) => user,
            Ok(Err(err)) => {
                let err = TempError::AuthorizeFailed { err };
                info!("{}", err.trace());
                let mut res =
                    Response::new(Body::from(serde_json::to_string(&err.freeze()).unwrap_or_else(|err| panic!("Failed to serialize Trace: {err}"))));
                *res.status_mut() = err.status_code();
                return res;
            },
            Err(err) => {
                let err = TempError::AuthorizeFailed { err };
                error!("{}", err.trace());
                let mut res = Response::new(Body::from(err.to_string()));
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return res;
            },
        };

        // If we found a context, then inject it in the request as an extension; then continue
        request.extensions_mut().insert(user);
        next.run(request).await
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
    fn check_workflow(
        State(this): State<Arc<Self>>,
        Extension(auth): Extension<User>,
        request: Request,
    ) -> impl 'static + Send + Future<Output = (StatusCode, String)> {
        async move {
            let reference: String =
                format!("{}-{}", auth.id, rand::thread_rng().sample_iter(Alphanumeric).take(8).map(char::from).collect::<String>());
            let _span = span!(Level::INFO, "Server::check_workflow", user = auth.id, reference = reference);

            // Get the request
            let req: CheckWorkflowRequest = match download_request(request).await {
                Ok(req) => req,
                Err(res) => return res,
            };

            // Build the state, then resolve it
            let input: Input =
                Input { store: this.store.clone(), usecase: req.usecase, workflow: req.workflow, input: QuestionInput::ValidateWorkflow };
            let (state, question): (P::State, P::Question) =
                match this.resolver.resolve(input, &SessionedAuditLogger::new(&reference, this.logger)).await {
                    Ok(state) => state,
                    Err(err) => {
                        let err = TempError::ResolveFailed { err };
                        error!("{}", err.trace());
                        return (err.status_code(), err.to_string());
                    },
                };

            // With that in order, hit the reasoner
            match this.reasoner.consult(state, question, &mut SessionedAuditLogger::new(&reference, &mut this.logger)).await {
                Ok(res) => todo!(),
                Err(err) => {
                    // let err = TempError::ReasonerFailed { err };
                    // error!("{}", err.trace());
                    // (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
                    todo!()
                },
            }
        }
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
    fn check_task(
        State(this): State<Arc<Self>>,
        Extension(auth): Extension<User>,
        request: Request,
    ) -> impl 'static + Send + Future<Output = (StatusCode, String)> {
        async move { todo!() }
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
    fn check_transfer(
        State(this): State<Arc<Self>>,
        Extension(auth): Extension<User>,
        request: Request,
    ) -> impl 'static + Send + Future<Output = (StatusCode, String)> {
        async move { todo!() }
    }
}

// Serve
impl<S, P, L> Server<S, P, L>
where
    S: 'static + Send + Sync + StateResolver<State = Input, Resolved = (P::State, P::Question)>,
    S::Error: HttpError,
    P: 'static + Send + Sync + ReasonerConnector,
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
    pub async fn serve(self) -> impl Future<Output = Result<(), Error>> {
        let this: Arc<Self> = Arc::new(self);
        async move {
            let span = span!(Level::INFO, "Server::serve", state = "starting", client = Empty);

            // First, define the axum paths
            debug!("Building axum paths...");
            let check_workflow: Router = Router::new()
                .route("/workflow", get(Self::check_workflow))
                .layer(axum::middleware::from_fn_with_state(this.clone(), Self::authorize))
                .with_state(this.clone());
            let check_task: Router = Router::new()
                .route("/task", get(Self::check_task))
                .layer(axum::middleware::from_fn_with_state(this.clone(), Self::authorize))
                .with_state(this.clone());
            let check_transfer: Router = Router::new()
                .route("/transfer", get(Self::check_transfer))
                .layer(axum::middleware::from_fn_with_state(this.clone(), Self::authorize))
                .with_state(this.clone());
            let router: IntoMakeServiceWithConnectInfo<Router, SocketAddr> = Router::new()
                .nest("/v2/", check_workflow)
                .nest("/v2/", check_task)
                .nest("/v2/", check_transfer)
                .into_make_service_with_connect_info();

            // Bind the TCP Listener
            debug!("Binding server on '{}'...", this.addr);
            let listener: TcpListener = match TcpListener::bind(this.addr).await {
                Ok(listener) => listener,
                Err(err) => return Err(Error::ListenerBind { addr: this.addr, err }),
            };

            // Accept new connections!
            info!("Initialization OK, awaiting connections...");
            span.record("state", "running");
            loop {
                // Accept a new connection
                let (socket, remote_addr): (TcpStream, SocketAddr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(err) => {
                        error!("{}", trace!(("Failed to accept incoming connection"), err));
                        continue;
                    },
                };
                span.record("client", remote_addr.to_string());

                // Move the rest to a separate task
                let router: IntoMakeServiceWithConnectInfo<_, _> = router.clone();
                tokio::spawn(async move {
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
                });
            }
        }
    }
}
