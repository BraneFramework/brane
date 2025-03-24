//  ADDRESS.rs
//    by Lut99
// 
//  Created:
//    26 Jan 2023, 09:41:51
//  Last edited:
//    27 Jun 2023, 16:48:45
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the Address struct, which does something similar to the Url
//!   struct in the `url` crate, except that it's much more lenient
//!   towards defining URL schemes or not. Moreover, it does not contain
//!   any paths.
// 

use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use enum_debug::EnumDebug;
use tracing::debug;
use serde::{Deserialize, Serialize};
use serde::ser::Serializer;
use serde::de::{self, Deserializer, Visitor};
use url::Url;


/***** ERRORS *****/
/// Errors that relate to parsing [`Address`]es.
#[derive(Debug)]
pub enum AddressParseError {
    /// Missing the colon separator (':') in the address.
    MissingColon{ raw: String },
    /// Invalid port number.
    IllegalPortNumber{ raw: String, err: std::num::ParseIntError },
}
impl Display for AddressParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AddressParseError::*;
        match self {
            MissingColon{ raw }           => write!(f, "Missing address/port separator ':' in '{raw}' (did you forget to define a port?)"),
            IllegalPortNumber{ raw, err } => write!(f, "Illegal port number '{raw}': {err}"),
        }
    }
}
impl Error for AddressParseError {}

/// Errors that relate to parsing [`Address`]es from [`Url`]s.
#[derive(Debug)]
pub enum AddressFromUrlError {
    /// The given URL did not have a port defined.
    NoPort { url: Url },
    /// Failed to remove the port from the given URL.
    RemovePort { url: Url },
}
impl Display for AddressFromUrlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AddressFromUrlError::*;
        match self {
            NoPort { url }     => write!(f, "No port defined in URL '{url}'"),
            RemovePort { url } => write!(f, "Failed to remove port from URL '{url}'"),
        }
    }
}
impl Error for AddressFromUrlError {}





/***** LIBRARY *****/
/// Defines a more lenient alternative to a SocketAddr that also accepts hostnames.
#[derive(Clone, Debug, EnumDebug)]
pub enum Address {
    /// It's an Ipv4 address.
    Ipv4(Ipv4Addr, u16),
    /// It's an Ipv6 address.
    Ipv6(Ipv6Addr, u16),
    /// It's a hostname.
    Hostname(String, u16),
}

impl Address {
    /// Constructor for the Address that initializes it for the given IPv4 address.
    /// 
    /// # Arguments
    /// - `b1`: The first byte of the IPv4 address.
    /// - `b2`: The second byte of the IPv4 address.
    /// - `b3`: The third byte of the IPv4 address.
    /// - `b4`: The fourth byte of the IPv4 address.
    /// - `port`: The port for this address.
    /// 
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn ipv4(b1: u8, b2: u8, b3: u8, b4: u8, port: u16) -> Self {
        Self::Ipv4(Ipv4Addr::new(b1, b2, b3, b4), port)
    }
    /// Constructor for the Address that initializes it for the given IPv4 address.
    /// 
    /// # Arguments
    /// - `ipv4`: The already constructed IPv4 address to use.
    /// - `port`: The port for this address.
    /// 
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn from_ipv4(ipv4: impl Into<Ipv4Addr>, port: u16) -> Self {
        Self::Ipv4(ipv4.into(), port)
    }

    /// Constructor for the Address that initializes it for the given IPv6 address.
    /// 
    /// # Arguments
    /// - `b1`: The first pair of bytes of the IPv6 address.
    /// - `b2`: The second pair of bytes of the IPv6 address.
    /// - `b3`: The third pair of bytes of the IPv6 address.
    /// - `b4`: The fourth pair of bytes of the IPv6 address.
    /// - `b5`: The fifth pair of bytes of the IPv6 address.
    /// - `b6`: The sixth pair of bytes of the IPv6 address.
    /// - `b7`: The seventh pair of bytes of the IPv6 address.
    /// - `b8`: The eight pair of bytes of the IPv6 address.
    /// - `port`: The port for this address.
    /// 
    /// # Returns
    /// A new Address instance.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn ipv6(b1: u16, b2: u16, b3: u16, b4: u16, b5: u16, b6: u16, b7: u16, b8: u16, port: u16) -> Self {
        Self::Ipv6(Ipv6Addr::new(b1, b2, b3, b4, b5, b6, b7, b8), port)
    }
    /// Constructor for the Address that initializes it for the given IPv6 address.
    /// 
    /// # Arguments
    /// - `ipv6`: The already constructed IPv6 address to use.
    /// - `port`: The port for this address.
    /// 
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn from_ipv6(ipv6: impl Into<Ipv6Addr>, port: u16) -> Self {
        Self::Ipv6(ipv6.into(), port)
    }

    /// Constructor for the Address that initializes it for the given hostname.
    /// 
    /// # Arguments
    /// - `hostname`: The hostname for this Address.
    /// - `port`: The port for this address.
    /// 
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn hostname(hostname: impl Into<String>, port: u16) -> Self {
        Self::Hostname(hostname.into(), port)
    }



    /// Returns the domain-part, as a (serialized) string version.
    /// 
    /// # Returns
    /// A `Cow<str>` that either contains a reference to the already String hostname, or else a newly created string that is the serialized version of an IP.
    #[inline]
    pub fn domain(&self) -> Cow<'_, str> {
        use Address::*;
        match self {
            Ipv4(addr, _)     => format!("{addr}").into(),
            Ipv6(addr, _)     => format!("{addr}").into(),
            Hostname(addr, _) => addr.into(),
        }
    }

    /// Returns the port-part, as a number.
    /// 
    /// # Returns
    /// A `u16` that is the port.
    #[inline]
    pub fn port(&self) -> u16 {
        use Address::*;
        match self {
            Ipv4(_, port)     => *port,
            Ipv6(_, port)     => *port,
            Hostname(_, port) => *port,
        }
    }

    /// Returns the port-part as a mutable number.
    /// 
    /// # Returns
    /// A mutable reference to the `u16` that is the port.
    #[inline]
    pub fn port_mut(&mut self) -> &mut u16 {
        use Address::*;
        match self {
            Ipv4(_, port)     => port,
            Ipv6(_, port)     => port,
            Hostname(_, port) => port,
        }
    }



    /// Returns if this Address is an `Address::Hostname`.
    /// 
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_hostname(&self) -> bool { matches!(self, Self::Hostname(_, _)) }

    /// Returns if this Address is an `Address::Ipv4` or `Address::Ipv6`.
    /// 
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_ip(&self) -> bool { self.is_ipv4() || self.is_ipv6() }

    /// Returns if this Address is an `Address::Ipv4`.
    /// 
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_ipv4(&self) -> bool { matches!(self, Self::Ipv4(_, _)) }

    /// Returns if this Address is an `Address::Ipv6`.
    /// 
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_ipv6(&self) -> bool { matches!(self, Self::Ipv6(_, _)) }



    /// Returns a formatter that deterministically and parseably serializes the Address.
    #[inline]
    pub fn serialize(&self) -> impl '_ + Display { self }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Address::*;
        match self {
            Ipv4(addr, port)     => write!(f, "{addr}:{port}"),
            Ipv6(addr, port)     => write!(f, "{addr}:{port}"),
            Hostname(addr, port) => write!(f, "{addr}:{port}"),
        }
    }
}

impl Serialize for Address {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self.serialize()))
    }
}
impl<'de> Deserialize<'de> for Address {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Defines the visitor for the Address
        struct AddressVisitor;
        impl<'de> Visitor<'de> for AddressVisitor {
            type Value = Address;

            #[inline]
            fn expecting(&self, f: &mut Formatter<'_>) -> FResult {
                write!(f, "an address:port pair")
            }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Attempt to serialize the incoming string
                match Address::from_str(v) {
                    Ok(address) => Ok(address),
                    Err(err)    => Err(E::custom(err)),
                }
            }
        }

        // Call the visitor
        deserializer.deserialize_str(AddressVisitor)
    }
}
impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt to find the colon first
        let colon_pos: usize = match s.rfind(':') {
            Some(pos) => pos,
            None      => { return Err(AddressParseError::MissingColon{ raw: s.into() }); },
        };

        // Split it on that
        let (address, port): (&str, &str) = (&s[..colon_pos], &s[colon_pos + 1..]);

        // Parse the port
        let port: u16 = match u16::from_str(port) {
            Ok(port) => port,
            Err(err) => { return Err(AddressParseError::IllegalPortNumber{ raw: port.into(), err }); },
        };
 
        // Resolve the address to a new instance of ourselves
        match IpAddr::from_str(address) {
            Ok(address) => match address {
                IpAddr::V4(ip) => Ok(Self::Ipv4(ip, port)),
                IpAddr::V6(ip) => Ok(Self::Ipv6(ip, port)),
            },
            Err(err) => {
                debug!("Parsing '{}' as a hostname, but might be an invalid IP address (parser feedback: {})", address, err);
                Ok(Self::Hostname(address.into(), port))
            }
        }
    }
}

impl TryFrom<Url> for Address {
    type Error = AddressFromUrlError;

    #[inline]
    fn try_from(mut value: Url) -> Result<Self, Self::Error> {
        // Extract the port from the URL
        let port: u16 = match value.port() {
            Some(port) => port,
            None       => { return Err(AddressFromUrlError::NoPort { url: value }); },
        };

        // Get the rest without port
        if value.set_port(None).is_err() { return Err(AddressFromUrlError::RemovePort { url: value }); };
        let host: String = value.to_string();

        // Done
        Ok(Self::Hostname(host, port))
    }
}
impl TryFrom<&Url> for Address {
    type Error = AddressFromUrlError;

    #[inline]
    fn try_from(value: &Url) -> Result<Self, Self::Error> { Self::try_from(value.clone()) }
}
impl TryFrom<&mut Url> for Address {
    type Error = AddressFromUrlError;

    #[inline]
    fn try_from(value: &mut Url) -> Result<Self, Self::Error> { Self::try_from(value.clone()) }
}

impl AsRef<Address> for Address {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&Address> for Address {
    #[inline]
    fn from(value: &Address) -> Self { value.clone() }
}
impl From<&mut Address> for Address {
    #[inline]
    fn from(value: &mut Address) -> Self { value.clone() }
}
