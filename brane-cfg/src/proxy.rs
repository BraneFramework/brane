//  PROXY.rs
//    by Lut99
//
//  Created:
//    09 Mar 2023, 15:15:47
//  Last edited:
//    16 Mar 2023, 15:39:53
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the configuration file for additional incoming proxy rules.
//

use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FResult};
use std::ops::RangeInclusive;
use std::str::FromStr;

use enum_debug::EnumDebug;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use specifications::address::Address;

use crate::errors::ProxyProtocolParseError;
pub use crate::info::YamlError as Error;
use crate::info::YamlInfo;


/***** AUXILLARY *****/
/// Defines the supported proxy protocols (versions).
#[derive(Clone, Copy, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum ProxyProtocol {
    /// Version 5
    Socks5,
    /// Version 6
    Socks6,
}
impl Display for ProxyProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ProxyProtocol::*;
        match self {
            Socks5 => write!(f, "SOCKS5"),
            Socks6 => write!(f, "SOCKS6"),
        }
    }
}
impl FromStr for ProxyProtocol {
    type Err = ProxyProtocolParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "socks5" => Ok(Self::Socks5),
            "socks6" => Ok(Self::Socks6),
            _ => Err(ProxyProtocolParseError::UnknownProtocol { raw: s.into() }),
        }
    }
}
impl Serialize for ProxyProtocol {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for ProxyProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Visitor for the ProxyProtocol.
        struct ProxyProtocolVisitor;
        impl Visitor<'_> for ProxyProtocolVisitor {
            type Value = ProxyProtocol;

            fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "a proxy protocol identifier") }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match ProxyProtocol::from_str(v) {
                    Ok(prot) => Ok(prot),
                    Err(err) => Err(E::custom(err)),
                }
            }
        }

        // Call the visitor
        deserializer.deserialize_str(ProxyProtocolVisitor)
    }
}





/***** LIBRARY *****/
/// Defines the file that can be used to define additional proxy rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Defines the range of outgoing ports we may assign to services.
    pub outgoing_range: RangeInclusive<u16>,
    /// Defines a list of forwarding ports for outside incoming connections. Maps incoming port to outgoing address.
    ///
    /// Note: these will also have to be opened in Docker, obviously, but `branectl` can do this for you.
    #[serde(default = "HashMap::new")]
    pub incoming: HashMap<u16, Address>,

    /// Whether we have to forward our traffic through some external proxy.
    pub forward: Option<ForwardConfig>,
}
impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            outgoing_range: 4200..=4299,
            incoming: HashMap::new(),

            forward: None,
        }
    }
}
impl YamlInfo<'_> for ProxyConfig {}



/// Defines how the forwarding looks like.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForwardConfig {
    /// The address of the proxy to proxy itself.
    pub address:  Address,
    /// The protocol that we use to communicate to the proxy.
    pub protocol: ProxyProtocol,
}
