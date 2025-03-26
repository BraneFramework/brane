//  CLIENT.rs
//    by Lut99
//
//  Created:
//    25 Nov 2022, 15:09:17
//  Last edited:
//    15 Jan 2024, 15:16:14
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

use reqwest::{Client, Request, Response};
use serde::Serialize;
use specifications::address::Address;
use specifications::package::PackageIndex;
use specifications::working::{Error as JobServiceError, JobServiceClient};
use tracing::{debug, info};
use url::Url;

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
    let remote: String = remote.into();
    debug!("Creating path to '{}' on proxy service '{}'...", remote, endpoint);

    // Prepare the request
    let request: NewPathRequest = NewPathRequest { address: remote.clone(), tls: tls.clone() };

    // Send it with reqwest
    let address: String = format!("{endpoint}outgoing/new");
    let client: Client = Client::new();
    let req: Request =
        client.post(&address).json(&request).build().map_err(|source| Error::RequestBuildError { address: address.clone(), source })?;
    debug!("Sending request '{}'...", req.url());
    let res: Response = client.execute(req).await.map_err(|source| Error::RequestError { address: address.clone(), source })?;
    if !res.status().is_success() {
        return Err(Error::RequestFailure { address, code: res.status(), err: res.text().await.ok() });
    }

    // Extract the port
    let port: String = res.text().await.map_err(|source| Error::RequestTextError { address: address.clone(), source })?;
    let port: u16 = u16::from_str(&port).map_err(|source| Error::RequestPortParseError { address: address.clone(), raw: port, source })?;

    // Done
    Ok(port)
}





/***** LIBRARY *****/
/// Defines a ProxyClient, which remembers the paths stored and seamlessly translates between them.
#[derive(Debug)]
pub struct ProxyClient {
    /// The remote address of the endpoint.
    endpoint: Url,

    /// The map of remote addresses / paths that we have already used.
    paths: RwLock<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>>,
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
        let endpoint: Url =
            Url::from_str(&endpoint.to_string()).unwrap_or_else(|err| panic!("Cannot parse given address '{endpoint}' as a URL: {err}"));
        if endpoint.domain().is_none() {
            panic!("Given address '{endpoint}' does not have a domain");
        }

        // Return us
        Self { endpoint, paths: RwLock::new(HashMap::new()) }
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
        let request: Request = client.get(address).build().map_err(|source| Error::RequestBuildError { address: address.into(), source })?;

        // Pass it onto `ProxyClient::execute()`
        self.execute(client, request, tls).await
    }

    /// Sends a GET-request with a JSON body to the given address/path.
    ///
    /// # Arguments
    /// - `address`: The address to send the request to.
    /// - `tls`: The TLS settings of the remote proxy to use for this request.
    /// - `body`: A [`Serialize`]able body to send along.
    ///
    /// # Returns
    /// The result of the request, as a `Result<reqwest::Response, reqwest::Error>`.
    ///
    /// # Errors
    /// This function errors if we fail to reserve any new paths if necessary.
    pub async fn get_with_body(
        &self,
        address: impl AsRef<str>,
        tls: Option<NewPathRequestTlsOptions>,
        body: &(impl ?Sized + Serialize),
    ) -> Result<Result<Response, reqwest::Error>, Error> {
        let address: &str = address.as_ref();

        // Create a client
        let client: Client = Client::new();

        // Create a new GET-request with that client
        let request: Request =
            client.get(address).json(body).build().map_err(|source| Error::RequestBuildError { address: address.into(), source })?;

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
    pub async fn execute(
        &self,
        client: Client,
        request: impl Into<Request>,
        tls: Option<NewPathRequestTlsOptions>,
    ) -> Result<Result<Response, reqwest::Error>, Error> {
        let mut request: Request = request.into();
        info!("Sending HTTP request to '{}' through proxy service at '{}'", request.url(), self.endpoint);

        // Assert it has the appropriate fields
        let url: &Url = request.url_mut();
        if url.domain().is_none() {
            panic!("URL {url} does not have a domain defined");
        }
        if url.port().is_none() {
            panic!("URL {url} does not have a port defined");
        }

        // Check if we already have a path for this
        let remote: String = format!("{}://{}:{}", url.scheme(), url.domain().unwrap(), url.port().unwrap());
        let port: Option<u16> = {
            let lock: RwLockReadGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.read().unwrap();
            lock.get(&(remote.clone(), tls.clone())).cloned()
        };

        // If not, request one
        let port: u16 = match port {
            Some(port) => port,
            None => {
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
        if url.scheme() == "https" {
            // Replace with http, since the proxy will take care of TLS
            if request.url_mut().set_scheme("http").is_err() {
                return Err(Error::UrlSchemeUpdateError { url: request.url().clone(), scheme: "http".into() });
            }
        }
        request.url_mut().set_host(Some(self.endpoint.domain().unwrap())).map_err(|source| Error::UrlHostUpdateError {
            url: request.url().clone(),
            host: self.endpoint.domain().unwrap().into(),
            source,
        })?;
        if request.url_mut().set_port(Some(port)).is_err() {
            return Err(Error::UrlPortUpdateError { url: request.url().clone(), port });
        }

        // We can now perform the request
        debug!("Performing request to '{}' (secretly '{}')...", url, request.url());
        Ok(client.execute(request).await.inspect_err(|_source| {
            // If it fails, remove the mapping so we are forced to ask a new one next time
            let mut lock: RwLockWriteGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.write().unwrap();
            lock.remove(&(remote, tls));
        }))
    }

    /// Requests the package index from the `brane-api` service at the given endpoint.
    ///
    /// # Arguments
    /// - `address`: The endpoint (including path) to fetch the package index from.
    ///
    /// # Returns
    /// The result of the request, as a `Result<PackageIndex, brane_tsk::api::Error>`.
    ///
    /// # Errors
    /// This function errors if we fail to reserve any new paths if necessary.
    pub async fn get_package_index(&self, address: impl AsRef<str>) -> Result<Result<PackageIndex, brane_tsk::api::Error>, Error> {
        let address: &str = address.as_ref();

        // Parse the address as a URL
        let mut address: Url = Url::from_str(address).map_err(|source| Error::IllegalUrl { raw: address.into(), source })?;
        // Assert it has the appropriate fields
        if address.domain().is_none() {
            panic!("URL {address} does not have a domain defined");
        }
        if address.port().is_none() {
            panic!("URL {address} does not have a port defined");
        }

        // Check if we already have a path for this
        let remote: String = format!("{}://{}:{}", address.scheme(), address.domain().unwrap(), address.port().unwrap());
        let port: Option<u16> = {
            let lock: RwLockReadGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.read().unwrap();
            lock.get(&(remote.clone(), None)).cloned()
        };

        // If not, request one
        let port: u16 = match port {
            Some(port) => port,
            None => {
                // Create the path
                let port: u16 = create_path(&self.endpoint, &remote, &None).await?;

                // Store it in the internal map for next time
                let mut lock: RwLockWriteGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.write().unwrap();
                lock.insert((remote.clone(), None), port);

                // And return the port
                port
            },
        };

        // Inject the new target in the URL
        let original: Url = address.clone();
        address.set_host(Some(self.endpoint.domain().unwrap())).map_err(|source| Error::UrlHostUpdateError {
            url: address.clone(),
            host: self.endpoint.domain().unwrap().into(),
            source,
        })?;

        if address.set_port(Some(port)).is_err() {
            return Err(Error::UrlPortUpdateError { url: address, port });
        }

        // Run the normal function
        debug!("Performing request to '{}' (secretly '{}')...", original, address);
        Ok(brane_tsk::api::get_package_index(address).await.inspect_err(|_source| {
            // If it fails, remove the mapping so we are forced to ask a new one next time
            let mut lock: RwLockWriteGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.write().unwrap();
            lock.remove(&(remote, None));
        }))
    }

    /// Connects to the given `brane-job` service using gRPC.
    ///
    /// This effectively creates a JobServiceClient, but through the proxy node.
    ///
    /// # Arguments
    /// - `address`: The address of the remote to connect to.
    ///
    /// # Returns
    /// The result of the connection, as a `Result<JobServiceClient, tonic::transport::Error>`.
    ///
    /// # Errors
    /// This function errors if we fail to reserve any new paths if necessary.
    pub async fn connect_to_job(&self, address: impl AsRef<str>) -> Result<Result<JobServiceClient, JobServiceError>, Error> {
        let address: &str = address.as_ref();

        // Parse the address as a URL
        let mut address: Url = Url::from_str(address).map_err(|source| Error::IllegalUrl { raw: address.into(), source })?;

        // Assert it has the appropriate fields
        if address.domain().is_none() {
            panic!("URL {address} does not have a domain defined");
        }
        if address.port().is_none() {
            panic!("URL {address} does not have a port defined");
        }

        // Check if we already have a path for this
        let remote: String = format!("{}://{}:{}", address.scheme(), address.domain().unwrap(), address.port().unwrap());
        let port: Option<u16> = {
            let lock: RwLockReadGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.read().unwrap();
            lock.get(&(remote.clone(), None)).cloned()
        };

        // If not, request one
        let port: u16 = match port {
            Some(port) => port,
            None => {
                // Create the path
                let port: u16 = create_path(&self.endpoint, &remote, &None).await?;

                // Store it in the internal map for next time
                let mut lock: RwLockWriteGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.write().unwrap();
                lock.insert((remote.clone(), None), port);

                // And return the port
                port
            },
        };

        // Inject the new target in the URL
        let original: Url = address.clone();
        address.set_host(Some(self.endpoint.domain().unwrap())).map_err(|source| Error::UrlHostUpdateError {
            url: address.clone(),
            host: self.endpoint.domain().unwrap().into(),
            source,
        })?;

        if address.set_port(Some(port)).is_err() {
            return Err(Error::UrlPortUpdateError { url: address, port });
        }

        // We can now perform the request
        debug!("Connecting to '{}' (secretly '{}')...", original, address);
        Ok(JobServiceClient::connect(address.to_string()).await.inspect_err(|_source| {
            // If it fails, remove the mapping so we are forced to ask a new one next time
            let mut lock: RwLockWriteGuard<HashMap<(String, Option<NewPathRequestTlsOptions>), u16>> = self.paths.write().unwrap();
            lock.remove(&(remote, None));
        }))
    }
}
