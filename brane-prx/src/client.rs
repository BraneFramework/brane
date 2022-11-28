//  CLIENT.rs
//    by Lut99
// 
//  Created:
//    25 Nov 2022, 15:09:17
//  Last edited:
//    28 Nov 2022, 18:01:17
//  Auto updated?
//    Yes
// 
//  Description:
//!   Provides client code for the `brane-prx` service. In particular,
//!   offers functionality for generating new paths.
// 

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use log::{debug, info};
use reqwest::{Client, Response, Request};
use url::Url;

use brane_cfg::node::Address;

pub use crate::errors::ClientError as Error;
use crate::spec::{NewPathRequest, NewPathRequestTlsOptions};


/***** HELPER FUNCTIONS *****/
/// Declares a new path in the proxy services.
/// 
/// # Arguments
/// - `endpoint`: The proxy service to connect to (hostname + address).
/// - `remote_address`: The remote address to connect to through the proxy.
/// - `tls`: If given, whether to use TLS and for what location.
/// 
/// # Returns
/// The port of the new path that is created.
/// 
/// # Errors
/// This function errors if we failed to create the port for whatever reason.
async fn create_path(endpoint: &Url, remote: impl Into<String>, tls: &Option<NewPathRequestTlsOptions>) -> Result<u16, Error> {
    let remote : String   = remote.into();
    debug!("Creating path to '{}' on proxy service '{}'...", remote, endpoint);

    // Prepare the request
    let request: NewPathRequest = NewPathRequest {
        address : remote.clone(),
        tls     : tls.clone(),
    };

    // Send it with reqwest
    let address : String = format!("{}paths/new", endpoint);
    let client  : Client = Client::new();
    let req: Request = match client.post(&address).json(&request).build() {
        Ok(req)  => req,
        Err(err) => { return Err(Error::RequestBuildError{ address, err }); },
    };
    debug!("Sending request '{}'...", req.url());
    let res: Response = match client.execute(req).await {
        Ok(res)  => res,
        Err(err) => { return Err(Error::RequestError { address, err }); },
    };
    if !res.status().is_success() { return Err(Error::RequestFailure { address, code: res.status(), err: res.text().await.ok() }); }

    // Extract the port
    let port: String = match res.text().await {
        Ok(port) => port,
        Err(err) => { return Err(Error::RequestTextError{ address, err }); },
    };
    let port: u16 = match u16::from_str(&port) {
        Ok(port) => port,
        Err(err) => { return Err(Error::RequestPortParseError{ address, raw: port, err }); },
    };

    // Done
    Ok(port)
}





/***** LIBRARY *****/
/// Defines a ProxyClient, which remembers the paths stored and seamlessly translates between them.
#[derive(Debug)]
pub struct ProxyClient {
    /// The remote address of the endpoint.
    endpoint : Url,

    /// The map of remote addresses / paths that we have already used.
    paths : RwLock<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>>,
}

impl ProxyClient {
    /// Constructor for the ProxyClient.
    /// 
    /// Note that no connection is made yet; this is done lazily.
    /// 
    /// # Arguments
    /// - `endpoint`: The remote proxy endpoint to connect to.
    /// 
    /// # Returns
    /// A new ProxyClient instance.
    pub fn new(endpoint: impl AsRef<Address>) -> Self {
        let endpoint: &Address = endpoint.as_ref();

        // Parse the address as an endpoint
        let endpoint: Url = Url::from_str(&endpoint.to_string()).unwrap_or_else(|err| panic!("Cannot parse given address '{}' as a URL: {}", endpoint, err));
        if endpoint.domain().is_none() { panic!("Given address '{}' does not have a domain", endpoint); }

        // Return us
        Self {
            endpoint,

            paths : RwLock::new(HashMap::new()),
        }
    }



    /// Sends a GET-request to the given address/path.
    /// 
    /// # Arguments
    /// - `address`: The address to send the request to.
    /// - `tls`: The TLS settings of the remote proxy to use for this request.
    /// 
    /// # Returns
    /// The result of the request, as a `Result<reqwest::Response, reqwest::Error>`.
    /// 
    /// # Errors
    /// This function errors if we fail to reserve any new paths if necessary.
    pub async fn get(&self, address: impl AsRef<str>, tls: Option<NewPathRequestTlsOptions>) -> Result<Result<Response, reqwest::Error>, Error> {
        let address: &str = address.as_ref();

        // Create a client
        let client: Client = Client::new();

        // Create a new GET-request with that client
        let request: Request = match client.get(address).build() {
            Ok(request) => request,
            Err(err)    => { return Err(Error::RequestBuildError { address: address.into(), err }); },
        };

        // Pass it onto `ProxyClient::execute()`
        self.execute(client, request, tls).await
    }

    /// Sends the given `reqwest` request to the given address/path using the given client.
    /// 
    /// # Arguments
    /// - `client`: The client to perform the actual request itself.
    /// - `request`: The request to send. Already carries the address to which we send it.
    /// - `tls`: The TLS settings to use for this request.
    /// 
    /// # Returns
    /// The result of the request, as a `Result<reqwest::Response, reqwest::Error>`.
    /// 
    /// # Errors
    /// This function errors if we fail to reserve any new paths if necessary.
    pub async fn execute(&self, client: Client, request: impl Into<Request>, tls: Option<NewPathRequestTlsOptions>) -> Result<Result<Response, reqwest::Error>, Error> {
        let mut request : Request = request.into();
        info!("Sending HTTP request to '{}' through proxy service at '{}'", request.url(), self.endpoint);

        // Assert it has the appropriate fields
        let url: &Url = request.url_mut();
        if url.domain().is_none() { panic!("URL {} does not have a domain defined", url); }
        if url.port().is_none() { panic!("URL {} does not have a port defined", url); }

        // Check if we already have a path for this
        let remote: String = format!("{}://{}:{}", url.scheme(), url.domain().unwrap(), url.port().unwrap());
        let port: Option<u16> = {
            let lock: RwLockReadGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.read().unwrap();
            lock.get(&(remote.clone(), tls.clone())).cloned()
        };

        // If not, request one
        let port: u16 = match port {
            Some(port) => port,
            None       => {
                // Create the path
                let port: u16 = create_path(&self.endpoint, &remote, &tls).await?;

                // Store it in the internal map for next time
                let mut lock: RwLockWriteGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.write().unwrap();
                lock.insert((remote.clone(), tls.clone()), port);

                // And return the port
                port
            },
        };

        // Inject the new address into the request
        let url: Url = url.clone();
        if let Err(err) = request.url_mut().set_host(Some(self.endpoint.domain().unwrap())) { return Err(Error::UrlHostUpdateError{ url: request.url().clone(), host: self.endpoint.domain().unwrap().into(), err }); }
        if let Err(_)   = request.url_mut().set_port(Some(port)) { return Err(Error::UrlPortUpdateError{ url: request.url().clone(), port }); }

        // We can now perform the request
        debug!("Performing request to '{}' (secretly '{}')...", request.url(), url);
        Ok(match client.execute(request).await {
            Ok(res)  => Ok(res),
            Err(err) => {
                // If it fails, remove the mapping so we are forced to ask a new one next time
                let mut lock: RwLockWriteGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.write().unwrap();
                lock.remove(&(remote, tls));
                Err(err)
            },
        })
    }
}
