//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    23 Nov 2022, 11:43:56
//  Last edited:
//    26 Jan 2023, 09:57:16
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the errors that may occur in the `brane-prx` crate.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::net::SocketAddr;

use reqwest::StatusCode;
use url::Url;

use specifications::address::Address;


/***** LIBRARY *****/
/// Defines errors that relate to redirection.
#[derive(Debug)]
pub enum RedirectError {
    /// No domain name given in the given URL
    NoDomainName{ raw: String },
    /// The given URL is not a valid URL
    IllegalUrl{ raw: String, err: url::ParseError },
    /// Asked to do TLS with an IP
    TlsWithNonHostnameError{ kind: String },
    /// The given hostname was illegal
    IllegalServerName{ raw: String, err: rustls::client::InvalidDnsNameError },
    /// Failed to create a new tcp listener.
    ListenerCreateError{ address: SocketAddr, err: std::io::Error },
    /// Failed to create a new socks client.
    SocksCreateError{ address: Address, err: anyhow::Error },

    /// Failed to connect using a regular ol' TcpStream.
    TcpStreamConnectError{ address: String, err: std::io::Error },
    /// Failed to connect using a SOCKS6 client.
    Socks6ConnectError{ address: String, proxy: Address, err: anyhow::Error },
}
impl Display for RedirectError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use RedirectError::*;
        match self {
            NoDomainName{ raw }                 => write!(f, "No domain name found in '{}'", raw),
            IllegalUrl{ raw, err }              => write!(f, "Failed to parse '{}' as a valid URL: {}", raw, err),
            TlsWithNonHostnameError{ kind }     => write!(f, "Got a request for TLS but with a non-hostname {} address provided", kind),
            IllegalServerName{ raw, err }       => write!(f, "Cannot parse '{}' as a valid server name: {}", raw, err),
            ListenerCreateError{ address, err } => write!(f, "Failed to create new TCP listener on '{}': {}", address, err),
            SocksCreateError{ address, err }    => write!(f, "Failed to create new SOCKS6 client to '{}': {}", address, err),

            TcpStreamConnectError{ address, err }     => write!(f, "Failed to connect to '{}': {}", address, err),
            Socks6ConnectError{ address, proxy, err } => write!(f, "Failed to connect to '{}' through proxy '{}': {}", address, proxy, err),
        }
    }
}
impl Error for RedirectError {}



/// Defines errors for clients of the proxy.
#[derive(Debug)]
pub enum ClientError {
    /// The given URL was not a URL
    IllegalUrl{ raw: String, err: url::ParseError },
    /// Failed to update the given URL with a new scheme.
    UrlSchemeUpdateError{ url: Url, scheme: String },
    /// Failed to update the given URL with a new host.
    UrlHostUpdateError{ url: Url, host: String, err: url::ParseError },
    /// Failed to update the given URL with a new port.
    UrlPortUpdateError{ url: Url, port: u16 },

    /// Failed to build a request.
    RequestBuildError{ address: String, err: reqwest::Error },
    /// Failed to send a request on its way.
    RequestError{ address: String, err: reqwest::Error },
    /// The request failed with a non-success status code.
    RequestFailure{ address: String, code: StatusCode, err: Option<String> },
    /// Failed to get the body of a response as some text.
    RequestTextError{ address: String, err: reqwest::Error },
    /// Failed to parse the response's body as a port number.
    RequestPortParseError{ address: String, raw: String, err: std::num::ParseIntError },
}
impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ClientError::*;
        match self {
            IllegalUrl{ raw, err }               => write!(f, "'{}' is not a valid URL: {}", raw, err),
            UrlSchemeUpdateError{ url, scheme }  => write!(f, "Failed to update '{}' with new scheme '{}'", url, scheme),
            UrlHostUpdateError{ url, host, err } => write!(f, "Failed to update '{}' with new host '{}': {}", url, host, err),
            UrlPortUpdateError{ url, port }      => write!(f, "Failed to update '{}' with new port '{}'", url, port),

            RequestBuildError{ address, err }          => write!(f, "Failed to build a request to '{}': {}", address, err),
            RequestError{ address, err }               => write!(f, "Failed to send request to '{}': {}", address, err),
            RequestFailure{ address, code, err }       => write!(f, "Request to '{}' failed with status code {} ({}){}", address, code.as_u16(), code.canonical_reason().unwrap_or("??"), if let Some(err) = err { format!(": {}", err) } else { String::new() }),
            RequestTextError{ address, err }           => write!(f, "Failed to get body of response from '{}' as plain text: {}", address, err),
            RequestPortParseError{ address, raw, err } => write!(f, "Failed to parse '{}' received from '{}' as a port number: {}", raw, address, err),
        }
    }
}
impl Error for ClientError {}
