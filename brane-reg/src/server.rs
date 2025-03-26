//  SERVER.rs
//    by Lut99
//
//  Created:
//    01 Nov 2022, 11:15:17
//  Last edited:
//    16 Jan 2024, 17:29:27
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains code pertaining to the actual server itself. This mostly
//!   deals with TLS & SSL so that we can identify clients based on
//!   certificates used.
//!
//!   Most of the logic in this module is taken from:
//!   <https://gist.github.com/darwindarak/9b18e49d0d5b384dd332d2c8d9e785fe>
//

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use brane_cfg::certs::{load_certstore, load_keypair};
use error_trace::trace;
use rustls::server::{AllowAnyAnonymousOrAuthenticatedClient, ServerConfig, ServerConnection};
use rustls::{Certificate, PrivateKey, RootCertStore};
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};
use warp::hyper::server::conn::Http;
use warp::hyper::service::{self, Service};
use warp::{Filter, Reply};

pub use crate::errors::ServerError as Error;


/***** LIBRARY *****/
/// Function that serves a warp server, but now by providing additional information about the authenticated client.
///
/// # Arguments
/// - `server_cert`: Path to the server's certificate file.
/// - `server_key`: Path to the server's keyfile.
/// - `ca_cert`: Path to the file that contains the root certificate by which all clients must have been signed.
/// - `filter`: The warp filter to serve.
/// - `address`: The address to serve on.
///
/// # Returns
/// Nothing - and by that we mean it typically doesn't really return until the warp server is stopped for some reason.
///
/// # Errors
/// This function errors if we failed to serve properly.
pub async fn serve_with_auth<F, E>(
    server_cert: impl AsRef<Path>,
    server_key: impl AsRef<Path>,
    ca_cert: impl AsRef<Path>,
    filter: F,
    address: SocketAddr,
) -> Result<(), Error>
where
    F: 'static + Send + Sync + Clone + Filter<Extract = E, Error = warp::Rejection>,
    E: Reply,
{
    // Load the TLS config first
    debug!("Loading cryptography...");
    let tls_config: Arc<ServerConfig> = {
        // Load server key pair
        let (certs, key): (Certificate, PrivateKey) = load_keypair(server_cert, server_key).map_err(|source| Error::KeypairLoadError { source })?;

        // Load the client certs
        let client_roots: RootCertStore = load_certstore(ca_cert).map_err(|source| Error::StoreLoadError { source })?;

        // Finally, create the config itself
        match ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(AllowAnyAnonymousOrAuthenticatedClient::new(client_roots)))
            .with_single_cert(vec![certs], key)
        {
            Ok(config) => Arc::new(config),
            Err(source) => {
                return Err(Error::ServerConfigError { source });
            },
        }
    };

    // Start a TCP listener
    debug!("Starting TCP server on '{}'...", address);
    let server: TcpListener = TcpListener::bind(&address).await.map_err(|source| Error::ServerBindError { address, source })?;

    // Start a TLS acceptor.
    let acceptor: TlsAcceptor = TlsAcceptor::from(tls_config);

    // Register a SIGTERM handler to be Docker-friendly
    let mut handler: Signal = match signal(SignalKind::terminate()) {
        Ok(handler) => handler,
        Err(err) => {
            error!("{}", trace!(("Failed to register SIGTERM signal handler"), err));
            warn!("Service will NOT shutdown gracefully on SIGTERM");
            loop {
                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
            }
        },
    };



    // Enter the game loop; we await new connections
    info!("Ready for connections...");
    loop {
        // Select between address or signal
        tokio::select! {
            incoming = server.accept() => {
                // Find if a result occurred
                let (socket, client_addr) = match incoming {
                    Ok(res) => res,
                    Err(err) => {
                        error!("{}", trace!(("Failed to accept incoming connection"), err));
                        continue;
                    },
                };

                // Re-interpret that as an TLS connection
                let stream: TlsStream<tokio::net::TcpStream> = match acceptor.accept(socket).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        error!("{}", trace!(("Failed to accept incoming connection from '{}' with TLS", client_addr), err));
                        continue;
                    },
                };

                // We handle the rest of the request as an asynchronous spawn
                let filter: F = filter.clone();
                tokio::spawn(async move {
                    // Get the client TLS certificate
                    let (_, session): (_, &ServerConnection) = stream.get_ref();
                    let client_cert: Option<Certificate> =
                        session.peer_certificates().map(|certs| if !certs.is_empty() { Some(certs[0].clone()) } else { None }).unwrap_or(None);
                    debug!("Client provided certificate? {}", if client_cert.is_some() { "yes" } else { "no" });

                    // We now do a bit warp magic: we turn the filter into a service (cool!) but do so in a wrapped service so we can inject the certificate as an extension
                    let mut svc = warp::service(filter);
                    let service = service::service_fn(move |mut req| {
                        // Inject the certificate, if any
                        // Note: sadly, we clone client_cert twice, but we have little choice...
                        req.extensions_mut().insert(client_cert.clone());

                        // Now we call the service
                        svc.call(req)
                    });

                    // Now we run that service to serve the request
                    if let Err(err) = Http::new().serve_connection(stream, service).await {
                        error!("{}", trace!(("Failed to handle incoming request"), err));
                    }
                });

                // Done, we can await the next request
            },

            _ = handler.recv() => {
                info!("Received SIGTERM, shutting down gracefully...");
                break Ok(());
            },
        }
    }
}
