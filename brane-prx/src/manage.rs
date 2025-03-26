//  MANAGE.rs
//    by Lut99
//
//  Created:
//    23 Nov 2022, 11:07:05
//  Last edited:
//    12 Jan 2024, 10:43:44
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines warp-paths that relate to management of the proxy service.
//

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, MutexGuard};

use specifications::address::Address;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};
use warp::http::StatusCode;
use warp::hyper::body::Bytes;
use warp::hyper::{Body, Response};
use warp::{Rejection, Reply};

use crate::errors::RedirectError;
use crate::ports::PortAllocator;
use crate::redirect::path_server_factory;
use crate::spec::{Context, NewPathRequest, NewPathRequestTlsOptions};


/***** HELPER MACROS *****/
/// "Casts" the given StatusCode to an empty response.
macro_rules! response {
    (StatusCode:: $status:ident) => {
        Response::builder().status(StatusCode::$status).body(Body::empty()).unwrap()
    };
}

/// "Casts" the given StatusCode to an empty response.
macro_rules! reject {
    ($msg:expr) => {{
        #[derive(Debug)]
        struct InternalError;
        impl Display for InternalError {
            fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "An internal error has occurred.") }
        }
        impl Error for InternalError {}
        impl warp::reject::Reject for InternalError {}

        // Return that
        warp::reject::custom(InternalError)
    }};
}





/***** LIBRARY *****/
/// Creates a new path outgoing from the proxy service.
///
/// This will allocate a new port that an internal service can connect to. Any traffic that then occurs on this port is forwarded and trafficked back to the specified domain.
///
/// # Arguments
/// - `body`: The body of the given request, which we will attempt to parse as JSON.
/// - `context`: The Context struct that contains things we might need.
///
/// # Returns
/// A reponse with the following codes:
/// - `200 OK` if the new path was successfully created. In the body, there is the (serialized) port number of the path to store.
/// - `400 BAD REQUEST` if the given request body was not parseable as the desired JSON.
/// - `507 INSUFFICIENT STORAGE` if the server is out of port ranges to allocate.
///
/// # Errors
/// This function errors if we failed to start a new task that listens for the given port. If so, a `500 INTERNAL ERROR` is returned.
pub async fn new_outgoing_path(body: Bytes, context: Arc<Context>) -> Result<impl Reply, Rejection> {
    info!("Handling POST on '/outgoing/new' (i.e., create new outgoing proxy path)...");

    // Start by parsing the incoming body
    debug!("Parsing incoming body...");
    let body: NewPathRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(source) => {
            error!("Failed to parse incoming request body as JSON: {}", source);
            return Ok(response!(StatusCode::BAD_REQUEST));
        },
    };

    // If the port already exists, shortcut here
    {
        let opened: MutexGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = context.opened.lock().unwrap();
        if let Some(port) = opened.get(&(body.address.clone(), body.tls.clone())) {
            debug!("A path to '{}' with the same TLS options already exists", body.address);
            debug!("OK, returning port {} to client", port);
            return Ok(Response::new(Body::from(port.to_string())));
        }
    }

    // Attempt to find a free port in the allocator
    debug!("Finding available port...");
    let port: u16 = {
        let mut lock: MutexGuard<PortAllocator> = context.ports.lock().unwrap();
        match lock.allocate() {
            Some(port) => port,
            None => {
                error!("No more ports left in range");
                return Ok(response!(StatusCode::INSUFFICIENT_STORAGE));
            },
        }
    };
    debug!("Allocating on: {}", port);

    // Create the future with those settings
    debug!("Launching service...");
    let address: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port).into();
    let server = match path_server_factory(&context, address, body.address.clone(), body.tls.clone()).await {
        Ok(server) => server,
        Err(source) => {
            error!("Failed to create the path server: {}", source);
            return Err(reject!("An internal server error has occurred."));
        },
    };
    // Spawn it as a separate task
    tokio::spawn(server);

    // Note it down as working
    {
        let mut opened: MutexGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = context.opened.lock().unwrap();
        opened.insert((body.address, body.tls), port);
    }

    // Done, return the port
    debug!("OK, returning port {} to client", port);
    Ok(Response::new(Body::from(port.to_string())))
}



/// Creates a new path incoming to the proxy service.
///
/// This will allocate a new static port that an internal service can connect to. Any traffic that then occurs on this port is forwarded and trafficked back to the specified, (probably) internal address.
///
/// # Arguments
/// - `port`: The port to allocate the new service on. Cannot be in the allocated range.
/// - `address`: The address of the remote server to forward traffic to.
/// - `context`: The Context struct that contains things we might need.
///
/// # Errors
/// This function will error if we setup the new tunnel server for some reason; typically, this will be if the port is already in use.
pub async fn new_incoming_path(port: u16, address: Address, context: Arc<Context>) -> Result<(), RedirectError> {
    debug!("Creating new incoming path on port {} to '{}'...", port, address);

    // Sanity check: crash if the port is within the target range
    if context.proxy.outgoing_range.contains(&port) {
        return Err(RedirectError::PortInOutgoingRange { port, range: context.proxy.outgoing_range.clone() });
    }

    // Attempt to start listening on that port
    let socket_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port).into();
    debug!("Creating listener on '{}'", socket_addr);
    let listener: TcpListener =
        TcpListener::bind(socket_addr).await.map_err(|source| RedirectError::ListenerCreateError { address: socket_addr, source })?;

    // Wrap that in a tokio future that does all of our work
    tokio::spawn(async move {
        info!("Initialized inbound listener '>{}' to '{}'", port, address);
        loop {
            // Wait for the next connection
            debug!(">{}->{}: Ready for new connection", port, address);
            let (mut iconn, client_addr): (TcpStream, SocketAddr) = match listener.accept().await {
                Ok(res) => res,
                Err(source) => {
                    error!(">{}->{}: Failed to accept incoming connection: {}", port, address, source);
                    continue;
                },
            };
            debug!(">{}->{}: Got new connection from '{}'", port, address, client_addr);

            // Now we establish a new connection to the internal host
            let addr: String = format!("{}:{}", address.domain(), address.port());
            debug!("Connecting to '{}'...", addr);
            let mut oconn: TcpStream = match TcpStream::connect(&addr).await {
                Ok(oconn) => oconn,
                Err(source) => {
                    error!(">{}->{}: Failed to connect to internal '{}': {}", port, address, addr, source);
                    continue;
                },
            };

            // For the remainder of this session, simply copy the TCP stream both ways
            debug!(">{}->{}: Bidirectional link started", port, address);
            if let Err(err) = tokio::io::copy_bidirectional(&mut iconn, &mut oconn).await {
                error!(">{}->{}: Bidirectional link failed: {}", port, address, err);
                continue;
            }
            debug!(">{}->{}: Bidirectional link completed", port, address);
        }
    });

    // Done
    Ok(())
}
