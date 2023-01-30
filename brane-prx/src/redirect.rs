//  REDIRECT.rs
//    by Lut99
// 
//  Created:
//    23 Nov 2022, 11:26:46
//  Last edited:
//    26 Jan 2023, 09:57:26
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements handlers for the proxy paths.
// 

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use log::{debug, error, info};
use never_say_never::Never;
use rustls::{Certificate, ConfigBuilder, PrivateKey, RootCertStore, ServerName};
use rustls::client::ClientConfig;
use socksx::Socks6Client;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Url;

use brane_cfg::certs::{load_certstore, load_identity};
use brane_cfg::node::NodeConfig;
use specifications::address::Address;

pub use crate::errors::RedirectError as Error;
use crate::spec::{Context, NewPathRequestTlsOptions};


/***** AUXILLARY STRUCTS *****/
/// Wrapper around both a Socks6Client and a normal "client" to serve proxied or not.
pub enum RemoteClient {
    /// A normal client without any proxying (which for us is just the address).
    Direct,
    /// A Socks6Client that does the heavy work for us.
    Proxied(Socks6Client, Address),
}

impl RemoteClient {
    /// Establish a new connection with the remote host.
    /// 
    /// # Arguments
    /// - `address`: The address to connect to.
    /// 
    /// # Returns
    /// A TcpStream that represents the connetion.
    async fn connect(&self, address: impl AsRef<str>) -> Result<TcpStream, Error> {
        let address: &str = address.as_ref();

        use RemoteClient::*;
        match self {
            Direct => match TcpStream::connect(address).await {
                Ok(conn) => Ok(conn),
                Err(err) => Err(Error::TcpStreamConnectError{ address: address.into(), err }),
            },

            Proxied(client, proxy) => match client.connect(address.to_string(), None, None).await {
                Ok((conn, addr)) => { debug!("{:?}", addr); Ok(conn) },
                Err(err)         => Err(Error::Socks6ConnectError{ address: address.into(), proxy: proxy.clone(), err }),
            },
        }
    }
}





/***** LIBRARY *****/
/// Initializes a path server with the given port and address.
/// 
/// # Arguments
/// - `context`: The context that is used for the server.
/// - `socket_addr`: The SocketAddress on which to serve.
/// - `remote_addr`: The address to redirect the traffic to.
/// - `tls`: If given, adds TLS encryption to the remote host with the given address.
/// 
/// # Returns
/// A Future implementing the path server.
/// 
/// # Errors
/// This function errors if we failed to bind a TCP server on the given port.
pub async fn path_server_factory(context: &Arc<Context>, socket_addr: SocketAddr, remote_addr: String, tls: Option<NewPathRequestTlsOptions>) -> Result<impl Future<Output = Never>, Error> {
    // Parse the address to discover the hostname
    let remote_addr: Url = match Url::from_str(&remote_addr) {
        Ok(url)  => url,
        Err(err) => { return Err(Error::IllegalUrl{ raw: remote_addr, err }); },
    };
    let hostname: &str = match remote_addr.domain() {
        Some(hostname) => hostname,
        None           => { return Err(Error::NoDomainName { raw: remote_addr.to_string() }); },
    };

    // Parse the given domain as a hostname first, if required by TLS
    let tls: Option<(ServerName, NewPathRequestTlsOptions)> = if let Some(tls) = tls {
        match ServerName::try_from(hostname) {
            Ok(name) => {
                // Assert it's actually a DNS name, since rustls no like IPs
                if !matches!(name, ServerName::DnsName(_)) { return Err(Error::TlsWithNonHostnameError{ kind: hostname.into() }); }
                Some((name, tls))
            },
            Err(err) => { return Err(Error::IllegalServerName{ raw: hostname.into(), err }); },
        }
    } else {
        None
    };

    // Attempt to open the TCP server
    let listener: TcpListener = match TcpListener::bind(socket_addr).await {
        Ok(listener) => listener,
        Err(err)     => { return Err(Error::ListenerCreateError{ address: socket_addr, err }); },
    };

    // Now match on what to do
    if let Some(proxy_addr) = &context.proxy {
        // Attempt to open the socks client
        let client: Socks6Client = match Socks6Client::new(proxy_addr.to_string(), None).await {
            Ok(client) => client,
            Err(err)   => { return Err(Error::SocksCreateError{ address: proxy_addr.clone(), err }); },
        };

        // If that was successfull, return the future
        Ok(path_server(context.node_config_path.clone(), listener, RemoteClient::Proxied(client, proxy_addr.clone()), socket_addr, remote_addr, tls))

    } else {
        // Otherwise, just pass the address as 'to-be-connected'
        Ok(path_server(context.node_config_path.clone(), listener, RemoteClient::Direct, socket_addr, remote_addr, tls))
    }
}



/// Serves the proxying service on the given path, to the given address.
/// 
/// # Arguments
/// - `node_config_path`: Path to the `node.yml` file where we pull the certificates location from.
/// - `listener`: The TcpListener with which we serve.
/// - `client`: The proxied SOCKS6-client / unproxied TcpClient to connect to remote hosts with.
/// - `socket_addr`: The SocketAddress on which to serve.
/// - `address`: The address to redirect the traffic to.
/// - `tls`: If given, adds TLS encryption to the remote host with the given address.
/// 
/// # Returns
/// Never, ideally.
/// 
/// # Errors
/// This function does not error directly, but instead write errors to stderr (using the `log` crate) and then returns.
pub async fn path_server(node_config_path: PathBuf, listener: TcpListener, client: RemoteClient, socket_addr: SocketAddr, address: Url, tls: Option<(ServerName, NewPathRequestTlsOptions)>) -> Never {
    info!("Initiated new path ':{}' to '{}'", socket_addr, address);
    loop {
        // Wait for the next connection
        debug!(":{}->{}: Ready for new connection", socket_addr.port(), address); 
        let (mut iconn, client_addr): (TcpStream, SocketAddr) = match listener.accept().await {
            Ok(res)  => res,
            Err(err) => {
                error!(":{}->{}: Failed to accept incoming request: {}", socket_addr.port(), address, err);
                continue;
            }
        };
        debug!(":{}->{}: Got new connection from '{}'", socket_addr.port(), address, client_addr);

        // Now we establish a new connection to the remote host
        let addr: String = format!("{}:{}", address.domain().unwrap(), address.port().unwrap());
        debug!("Connecting to '{}'...", addr);
        let mut oconn: TcpStream = match client.connect(&addr).await {
            Ok(oconn) => oconn,
            Err(err)  => {
                error!(":{}->{}: Failed to connect to remote '{}': {}", socket_addr.port(), address, addr, err);
                continue;
            },
        };

        // Now switch on whether we're using TLS or not.
        if let Some((domain, tls)) = &tls {
            // Use TLS
            debug!(":{}->{}: Setting up TLS for location '{}'...", socket_addr.port(), address, tls.location);

            // Load the node config file
            let node_config: NodeConfig = match NodeConfig::from_path(&node_config_path) {
                Ok(config) => config,
                Err(err)   => {
                    error!(":{}->{}: Failed to load NodeConfig file: {}", socket_addr.port(), address, err);
                    std::process::exit(1);
                },
            };

            // Load the root CA certificate file
            let ca_path: PathBuf = node_config.paths.certs.join(&tls.location).join("ca.pem");
            let ca: RootCertStore = match load_certstore(&ca_path) {
                Ok(store) => store,
                Err(err)  => {
                    error!(":{}->{}: Failed to load root certificate '{}' for location '{}': {}", socket_addr.port(), address, ca_path.display(), tls.location, err);
                    continue;
                }
            };

            // If any, also load the client file
            let client: Option<(PathBuf, Vec<Certificate>, PrivateKey)> = if tls.use_client_auth {
                debug!(":{}->{}: Adding client certificate...", socket_addr.port(), address);
                let client_path: PathBuf = node_config.paths.certs.join(&tls.location).join("client-id.pem");
                match load_identity(&client_path) {
                    Ok((certs, key)) => Some((client_path, certs, key)),
                    Err(err)         => {
                        error!(":{}->{}: Failed to load client identity file '{}' for location '{}': {}", socket_addr.port(), address, client_path.display(), tls.location, err);
                        continue;
                    },
                }
            } else {
                None
            };

            // Create a ClientConfig with that
            let config: ConfigBuilder<_, _> = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(ca);
            let config: ClientConfig = if let Some((path, certs, key)) = client {
                match config.with_single_cert(certs, key) {
                    Ok(config) => config,
                    Err(err)   => {
                        error!(":{}->{}: Failed to build client config from '{}' and '{}': {}", socket_addr.port(), address, ca_path.display(), path.display(), err);
                        continue;
                    },
                }
            } else {
                config.with_no_client_auth()
            };

            // We can now wrap the outgoing stream in a TLS client stream.
            debug!(":{}->{}: Negotiating TLS...", socket_addr.port(), address);
            let connector: TlsConnector = TlsConnector::from(Arc::new(config));
            let mut oconn: TlsStream<TcpStream> = match connector.connect(domain.clone(), oconn).await {
                Ok(oconn) => oconn,
                Err(err)  => {
                    error!(":{}->{}: Failed to start a TLS connection with '{}': {}", socket_addr.port(), address, addr, err);
                    continue;
                },
            };

            // For the remainder of this session, simply copy the TCP stream both ways
            debug!(":{}->{}: Bidirectional link started", socket_addr.port(), address);
            if let Err(err) = tokio::io::copy_bidirectional(&mut iconn, &mut oconn).await {
                error!(":{}->{}: Bidirectional link failed: {}", socket_addr.port(), address, err);
                continue;
            }
            debug!(":{}->{}: Bidirectional link completed", socket_addr.port(), address);

        } else {
            // Simple TCP

            // For the remainder of this session, simply copy the TCP stream both ways
            debug!(":{}->{}: Bidirectional link started", socket_addr.port(), address);
            if let Err(err) = tokio::io::copy_bidirectional(&mut iconn, &mut oconn).await {
                error!(":{}->{}: Bidirectional link failed: {}", socket_addr.port(), address, err);
                continue;
            }
            debug!(":{}->{}: Bidirectional link completed", socket_addr.port(), address);
        }
    }
}
