//  CACHES.rs
//    by Lut99
//
//  Created:
//    31 Jan 2024, 11:45:19
//  Last edited:
//    31 Jan 2024, 14:24:26
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements caches that reduce the need to request everything all the
//!   time.
//

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::time::{Duration, Instant};

use brane_ast::locations::Location;
use brane_shr::formatters::BlockFormatter;
use log::debug;
use num_traits::AsPrimitive;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use reqwest::{Response, StatusCode};
use specifications::address::Address;


/***** CONSTANTS *****/
/// The default timeout (in seconds) of entries in the [`DomainRegistryCache`].
pub const DEFAULT_DOMAIN_REGISTRY_CACHE_TIMEOUT: u64 = 6 * 3600;





/***** ERRORS *****/
/// Defines errors originating in the [`DomainRegistryCache`].
#[derive(Debug)]
pub enum DomainRegistryCacheError {
    /// Failed to send a request to the given URL.
    RequestSend { kind: &'static str, url: String, err: reqwest::Error },
    /// Failed to download the body of the given response.
    ResponseDownload { url: String, err: reqwest::Error },
    /// The response was not an OK
    ResponseFailure { url: String, code: StatusCode, response: Option<String> },
    /// Failed to parse the response of the API.
    ResponseParse { url: String, raw: String, err: serde_json::Error },
    /// The given location identifier was not known to this registry.
    UnknownLocation { addr: Address, loc: Location },
}
impl Display for DomainRegistryCacheError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DomainRegistryCacheError::*;
        match self {
            RequestSend { kind, url, .. } => write!(f, "Failed to send {kind}-request to '{url}'"),
            ResponseDownload { url, .. } => write!(f, "Failed to download body of response from '{url}'"),
            ResponseFailure { url, code, response } => write!(
                f,
                "Request to '{}' failed with {} ({}){}",
                url,
                code.as_u16(),
                code.canonical_reason().unwrap_or("???"),
                if let Some(response) = response { format!("\n\nResponse:\n{}\n", BlockFormatter::new(response)) } else { String::new() }
            ),
            ResponseParse { url, raw, .. } => {
                write!(f, "Failed to parse response from '{}' as valid JSON\n\nResponse:\n{}\n", url, BlockFormatter::new(raw))
            },
            UnknownLocation { addr, loc } => write!(f, "Unknown location '{loc}' to registry '{addr}'"),
        }
    }
}
impl Error for DomainRegistryCacheError {
    fn source(&self) -> Option<&(dyn 'static + Error)> {
        use DomainRegistryCacheError::*;
        match self {
            RequestSend { err, .. } => Some(err),
            ResponseDownload { err, .. } => Some(err),
            ResponseFailure { .. } => None,
            ResponseParse { err, .. } => Some(err),
            UnknownLocation { .. } => None,
        }
    }
}





/***** LIBRARY *****/
/// A cache for storing the local registry address of a particular domain.
#[derive(Debug)]
pub struct DomainRegistryCache {
    /// The timeout to that determines after how long entries in the map become stale.
    timeout: u64,
    /// The API address to consult if we don't know one.
    api:     Address,
    /// The mappings of Location identifiers to addresses.
    data:    RwLock<HashMap<Location, (Address, Instant)>>,
}
impl DomainRegistryCache {
    /// Constructor for the DomainRegistryCache that uses the default timeout.
    ///
    /// See [`DEFAULT_DOMAIN_REGISTRY_CACHE_TIMEOUT`] to find what the current default is.
    ///
    /// # Arguments
    /// - `api_address`: The address of a remote centralized `brane-api` registry that knows an up-to-date mapping of locations to local registries.
    ///
    /// # Returns
    /// A new DomainRegistryCache instance.
    #[inline]
    pub fn new(api_address: impl Into<Address>) -> Self {
        Self { timeout: DEFAULT_DOMAIN_REGISTRY_CACHE_TIMEOUT, api: api_address.into(), data: RwLock::new(HashMap::with_capacity(16)) }
    }

    /// Constructor for the DomainRegistryCache.
    ///
    /// # Arguments
    /// - `timeout`: A timeout (in seconds) that determines after how long entries in the cache become stale.
    /// - `api_address`: The address of a remote centralized `brane-api` registry that knows an up-to-date mapping of locations to local registries.
    ///
    /// # Returns
    /// A new DomainRegistryCache instance.
    #[inline]
    pub fn with_timeout(timeout: impl AsPrimitive<u64>, api_address: impl Into<Address>) -> Self {
        Self { timeout: timeout.as_(), api: api_address.into(), data: RwLock::new(HashMap::with_capacity(16)) }
    }

    /// Resolves a given location identifier to an address.
    ///
    /// If we know the mapping already (and it isn't stale), then the in-memory cached address is returned.
    ///
    /// Else, a query is made to the API address that is given in this type's constructor.
    ///
    /// # Arguments
    /// - `location`: The [`Location`] ID to search for.
    ///
    /// # Returns
    /// A reference to the address of the location.
    ///
    /// # Errors
    /// This function may error if we had to retrieve the address from the remote registry but failed.
    pub async fn get(&'_ self, location: &'_ Location) -> Result<Address, DomainRegistryCacheError> {
        debug!("Resolving location '{}' in registry '{}'", location, self.api);

        // Attempt to read the cache
        {
            let lock: RwLockReadGuard<HashMap<String, (Address, Instant)>> = self.data.read();
            if let Some((addr, cached)) = lock.get(location) {
                if cached.elapsed() < Duration::from_secs(self.timeout) {
                    debug!("Found valid cached entry for '{location}', returning address '{addr}'");
                    return Ok(addr.clone());
                }
                debug!("Found expired cached entry for '{location}', fetching new address...");
            } else {
                debug!("No cached entry for '{location}' found, fetching new address...");
            }
        }

        // We didn't found a valid entry, so make a request for a new one
        let url: String = format!("{}/infra/registries", self.api);
        debug!("Sending GET-request to '{url}'...");
        let res: Response = match reqwest::get(&url).await {
            Ok(res) => res,
            Err(err) => return Err(DomainRegistryCacheError::RequestSend { kind: "GET", url, err }),
        };
        if !res.status().is_success() {
            return Err(DomainRegistryCacheError::ResponseFailure { url, code: res.status(), response: res.text().await.ok() });
        }

        // Parse the response
        debug!("Parsing response from registry...");
        let res: String = match res.text().await {
            Ok(res) => res,
            Err(err) => return Err(DomainRegistryCacheError::ResponseDownload { url, err }),
        };
        let res: HashMap<String, Address> = match serde_json::from_str(&res) {
            Ok(res) => res,
            Err(err) => return Err(DomainRegistryCacheError::ResponseParse { url, raw: res, err }),
        };
        debug!("Registry listed '{}' locations", res.len());

        // Alright store all mappings internally
        let now: Instant = Instant::now();
        let mut lock: RwLockWriteGuard<HashMap<String, (Address, Instant)>> = self.data.write();
        lock.extend(res.into_iter().map(|(name, addr)| (name, (addr, now))));

        // Try to find it now
        match lock.get(location) {
            Some((addr, _)) => {
                debug!("Returning newly cached address '{addr}'");
                Ok(addr.clone())
            },
            None => Err(DomainRegistryCacheError::UnknownLocation { addr: self.api.clone(), loc: location.clone() }),
        }
    }
}
