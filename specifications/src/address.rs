//  ADDRESS.rs
//    by Lut99
//
//  Created:
//    26 Jan 2023, 09:41:51
//  Last edited:
//    29 Apr 2025, 13:57:21
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
use std::fmt::{Display, Formatter, Result as FResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use enum_debug::EnumDebug;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use thiserror::Error;


/***** ERRORS *****/
/// Errors that relate to parsing [`Host`]s.
#[derive(Debug, Error)]
pub enum HostParseError {
    /// No input was given.
    #[error("No host given")]
    NoInput,
    /// The input contained an illegal character for a hostname.
    #[error("Found illegal character {c:?} in host {raw:?} (only a-z, A-Z, 0-9 and '-' are accepted)")]
    IllegalChar { c: char, raw: String },
}

/// Errors that relate to parsing [`Address`]es.
#[derive(Debug, Error)]
pub enum AddressParseError {
    /// Failed to correctly parse the hostname.
    #[error("Failed to parse {raw:?} as a hostname")]
    IllegalHost { raw: String, source: HostParseError },
    /// Failed to correctly parse the port.
    #[error("Failed to parse {raw:?} as a port number")]
    IllegalPort { raw: String, source: std::num::ParseIntError },
    /// There wasn't a colon in the input.
    #[error("No colon found in input {raw:?}")]
    MissingColon { raw: String },
    /// A given [`AddressOpt`] was missing a port.
    #[error("Address {addr} has no port defined")]
    MissingPort { addr: AddressOpt },
    /// No input was given.
    #[error("No address given")]
    NoInput,
}





/***** LIBRARY *****/
/// Defines the possible types of hostnames.
///
/// # Generics
/// - `'a`: The lifetime of the source text from which this host is parsed. It refers to it
///   internally through a [copy-on-write](Cow) pointer, so if it holds by ownership, this lifetime
///   can be `'static`.
#[derive(Clone, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum Host {
    /// It's an IPv4 address.
    IPv4(Ipv4Addr),
    /// It's an IPv6 address.
    IPv6(Ipv6Addr),
    /// It's a hostname.
    Name(String),
}
// Constructors
impl Host {
    /// Constructor for the Host that initializes it for the given IPv4 address.
    ///
    /// # Arguments
    /// - `b1`: The first byte of the IP address.
    /// - `b2`: The second byte of the IP address.
    /// - `b3`: The third byte of the IP address.
    /// - `b4`: The fourth byte of the IP address.
    ///
    /// # Returns
    /// A new Host that is referred to by IPv4.
    #[inline]
    pub const fn new_ipv4(b1: u8, b2: u8, b3: u8, b4: u8) -> Self { Self::IPv4(Ipv4Addr::new(b1, b2, b3, b4)) }

    /// Constructor for the Host that initializes it for the given hostname.
    ///
    /// # Arguments
    /// - `name`: The string name by which the host is known.
    ///
    /// # Returns
    /// A new Host that is referred to by DNS name.
    #[inline]
    pub fn new_name(name: impl Into<String>) -> Self { Self::Name(name.into()) }
}
// Accessessors
impl Host {
    /// Checks whether this Host is an IP address ([IPv4](Host::IPv4) or [IPv6](Host::IPv6)).
    ///
    /// # Returns
    /// True if it is, or false if it isn't.
    #[inline]
    pub const fn is_ip(&self) -> bool { matches!(self, Self::IPv4(_) | Self::IPv6(_)) }

    /// Checks whether this Host is an [IPv4 address](Host::IPv4).
    ///
    /// # Returns
    /// True if it is, or false if it isn't.
    #[inline]
    pub const fn is_ipv4(&self) -> bool { matches!(self, Self::IPv4(_)) }

    /// Checks whether this Host is an [IPv6 address](Host::IPv6).
    ///
    /// # Returns
    /// True if it is, or false if it isn't.
    #[inline]
    pub const fn is_ipv6(&self) -> bool { matches!(self, Self::IPv6(_)) }

    /// Checks whether this Host is a [hostname](Host::Name).
    ///
    /// # Returns
    /// True if it is, or false if it isn't.
    #[inline]
    pub const fn is_name(&self) -> bool { matches!(self, Self::Name(_)) }

    /// Assumes self is an [IPv4 address](Host::IPv4) and provides read-only access to it.
    ///
    /// # Returns
    /// A reference to the internal [`Ipv4Addr`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT an [IPv4 address](Host::IPv4).
    #[inline]
    #[track_caller]
    pub fn ipv4(&self) -> &Ipv4Addr { if let Self::IPv4(addr) = self { addr } else { panic!("Cannot unwrap {:?} as an Host::IPv4", self.variant()) } }

    /// Assumes self is an [IPv6 address](Host::IPv6) and provides read-only access to it.
    ///
    /// # Returns
    /// A reference to the internal [`Ipv6Addr`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT an [IPv6 address](Host::IPv6).
    #[inline]
    #[track_caller]
    pub fn ipv6(&self) -> &Ipv6Addr { if let Self::IPv6(addr) = self { addr } else { panic!("Cannot unwrap {:?} as an Host::IPv6", self.variant()) } }

    /// Assumes self is a [hostname](Host::Name) and provides read-only access to it.
    ///
    /// # Returns
    /// A reference to the internal [`str`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT a [hostname](Host::Name).
    #[inline]
    #[track_caller]
    pub fn name(&self) -> &str {
        if let Self::Name(name) = self { name.as_ref() } else { panic!("Cannot unwrap {:?} as an Host::Name", self.variant()) }
    }

    /// Assumes self is an [IPv4 address](Host::IPv4) and provides mutable access to it.
    ///
    /// # Returns
    /// A mutable reference to the internal [`Ipv4Addr`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT an [IPv4 address](Host::IPv4).
    #[inline]
    #[track_caller]
    pub fn ipv4_mut(&mut self) -> &mut Ipv4Addr {
        if let Self::IPv4(addr) = self { addr } else { panic!("Cannot unwrap {:?} as an Host::IPv4", self.variant()) }
    }

    /// Assumes self is an [IPv6 address](Host::IPv6) and provides mutable access to it.
    ///
    /// # Returns
    /// A mutable reference to the internal [`Ipv6Addr`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT an [IPv6 address](Host::IPv6).
    #[inline]
    #[track_caller]
    pub fn ipv6_mut(&mut self) -> &mut Ipv6Addr {
        if let Self::IPv6(addr) = self { addr } else { panic!("Cannot unwrap {:?} as an Host::IPv6", self.variant()) }
    }

    /// Assumes self is a [hostname](Host::Name) and provides mutable access to it.
    ///
    /// Note that the name may be stored by read-only reference to the source text. If so, calling
    /// this function will force a clone of the inner text to allow it to become mutable.
    ///
    /// # Returns
    /// A mutable reference to the internal [`str`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT a [hostname](Host::Name).
    #[inline]
    #[track_caller]
    pub fn name_mut(&mut self) -> &mut String {
        if let Self::Name(name) = self { name } else { panic!("Cannot unwrap {:?} as an Host::Name", self.variant()) }
    }

    /// Assumes self is an [IPv4 address](Host::IPv4) and returns the inner address.
    ///
    /// # Returns
    /// The internal [`Ipv4Addr`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT an [IPv4 address](Host::IPv4).
    #[inline]
    #[track_caller]
    pub fn into_ipv4(self) -> Ipv4Addr {
        if let Self::IPv4(addr) = self { addr } else { panic!("Cannot unwrap {:?} as an Host::IPv4", self.variant()) }
    }

    /// Assumes self is an [IPv6 address](Host::IPv6) and returns the inner address.
    ///
    /// # Returns
    /// The internal [`Ipv6Addr`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT an [IPv6 address](Host::IPv6).
    #[inline]
    #[track_caller]
    pub fn into_ipv6(self) -> Ipv6Addr {
        if let Self::IPv6(addr) = self { addr } else { panic!("Cannot unwrap {:?} as an Host::IPv6", self.variant()) }
    }

    /// Assumes self is a [hostname](Host::Name) and returns the inner name.
    ///
    /// # Returns
    /// The internal [`str`].
    ///
    /// # Panics
    /// This function panics if self is actually NOT a [hostname](Host::Name).
    #[inline]
    #[track_caller]
    pub fn into_name(self) -> String {
        if let Self::Name(name) = self { name } else { panic!("Cannot unwrap {:?} as an Host::Name", self.variant()) }
    }
}
// Formatting
impl Display for Host {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::IPv4(addr) => addr.fmt(f),
            Self::IPv6(addr) => addr.fmt(f),
            Self::Name(name) => name.fmt(f),
        }
    }
}
// De/Serialization
impl<'de> Deserialize<'de> for Host {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Visitor for the `Host`.
        pub struct HostVisitor;
        impl Visitor<'_> for HostVisitor {
            type Value = Host;

            #[inline]
            fn expecting(&self, f: &mut Formatter) -> FResult { write!(f, "an IP address or a hostname") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match Host::from_str(v) {
                    Ok(host) => Ok(host),
                    Err(err) => Err(E::custom(err)),
                }
            }
        }

        // Call it
        deserializer.deserialize_string(HostVisitor)
    }
}
impl Serialize for Host {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
impl FromStr for Host {
    type Err = HostParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match IpAddr::from_str(s) {
            Ok(IpAddr::V4(addr)) => Ok(Self::IPv4(addr)),
            Ok(IpAddr::V6(addr)) => Ok(Self::IPv6(addr)),
            Err(_) => {
                // Assert there is *something*
                if s.is_empty() {
                    return Err(HostParseError::NoInput);
                }

                // Assert it's only good
                if let Some(c) = s.chars().find(|&c| !(c.is_ascii_alphanumeric() || c == '-' || c == '.')) {
                    return Err(HostParseError::IllegalChar { c, raw: s.into() });
                }

                // OK, it's good
                Ok(Self::Name(s.into()))
            },
        }
    }
}
// Conversion
impl From<IpAddr> for Host {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => Self::from(addr),
            IpAddr::V6(addr) => Self::from(addr),
        }
    }
}
impl From<Ipv4Addr> for Host {
    #[inline]
    fn from(value: Ipv4Addr) -> Self { Self::IPv4(value) }
}
impl From<Ipv6Addr> for Host {
    #[inline]
    fn from(value: Ipv6Addr) -> Self { Self::IPv6(value) }
}
impl<'a> From<&'a str> for Host {
    #[inline]
    fn from(value: &'a str) -> Self { Self::Name(value.into()) }
}
impl From<String> for Host {
    #[inline]
    fn from(value: String) -> Self { Self::Name(value) }
}



/// Defines a more lenient alternative to a [`SocketAddr`](std::net::SocketAddr) that also accepts
/// hostnames.
///
/// # Generics
/// - `'a`: The lifetime of the source text from which this address is parsed. It refers to it
///   internally through a [copy-on-write](Cow) pointer, so if it holds by ownership, this lifetime
///   can be `'static`.
#[derive(Clone, Debug)]
pub struct Address {
    /// The host-part of the address.
    pub host: Host,
    /// The port-part of the address.
    pub port: u16,
}
// Constructors
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
    pub fn ipv4(b1: u8, b2: u8, b3: u8, b4: u8, port: u16) -> Self { Self { host: Host::new_ipv4(b1, b2, b3, b4), port } }

    /// Constructor for the Address that initializes it for the given IPv4 address.
    ///
    /// # Arguments
    /// - `ipv4`: The already constructed IPv4 address to use.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn from_ipv4(ipv4: impl Into<Ipv4Addr>, port: u16) -> Self { Self { host: Host::IPv4(ipv4.into()), port } }

    /// Constructor for the Address that initializes it for the given IPv6 address.
    ///
    /// # Arguments
    /// - `ipv6`: The already constructed IPv6 address to use.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn from_ipv6(ipv6: impl Into<Ipv6Addr>, port: u16) -> Self { Self { host: Host::IPv6(ipv6.into()), port } }

    /// Constructor for the Address that initializes it for the given hostname.
    ///
    /// # Arguments
    /// - `hostname`: The hostname for this Address.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn hostname(hostname: impl Into<String>, port: u16) -> Self { Self { host: Host::new_name(hostname), port } }
}
// Accessors
impl Address {
    /// Returns the domain-part, as a (serialized) string version.
    ///
    /// # Returns
    /// A `Cow<str>` that either contains a reference to the already String hostname, or else a newly created string that is the serialized version of an IP.
    #[inline]
    pub fn domain(&self) -> Cow<'_, str> {
        match &self.host {
            Host::IPv4(addr) => Cow::Owned(addr.to_string()),
            Host::IPv6(addr) => Cow::Owned(addr.to_string()),
            Host::Name(name) => Cow::Borrowed(name),
        }
    }

    /// Returns if this Address is an `Address::Hostname`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_hostname(&self) -> bool { self.host.is_name() }

    /// Returns if this Address is an `Address::Ipv4` or `Address::Ipv6`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_ip(&self) -> bool { self.host.is_ip() }

    /// Returns if this Address is an `Address::Ipv4`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_ipv4(&self) -> bool { self.host.is_ipv4() }

    /// Returns if this Address is an `Address::Ipv6`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_ipv6(&self) -> bool { self.host.is_ipv6() }
}
// Formatting
impl Address {
    /// Returns a formatter that deterministically and parseably serializes the Address.
    #[inline]
    pub const fn serialize(&self) -> impl '_ + Display { self }
}
impl Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}:{}", self.host, self.port) }
}
// De/Serialization
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
        impl Visitor<'_> for AddressVisitor {
            type Value = Address;

            #[inline]
            fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "an address:port pair") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Address::from_str(v).map_err(E::custom)
            }
        }

        // Call the visitor
        deserializer.deserialize_str(AddressVisitor)
    }
}
impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Assert there is *something*
        if s.is_empty() {
            return Err(AddressParseError::NoInput);
        }

        // Check the split
        let (host, port): (&str, &str) = if let Some(pos) = s.find(':') {
            (&s[..pos], &s[pos + 1..])
        } else {
            return Err(AddressParseError::MissingColon { raw: s.into() });
        };

        // Parse the host
        let host: Host = Host::from_str(host).map_err(|source| AddressParseError::IllegalHost { raw: host.into(), source })?;
        let port: u16 = u16::from_str(port).map_err(|source| AddressParseError::IllegalPort { raw: port.into(), source })?;

        // OK
        Ok(Self { host, port })
    }
}
// Conversion
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
impl TryFrom<AddressOpt> for Address {
    type Error = AddressParseError;

    #[inline]
    fn try_from(value: AddressOpt) -> Result<Self, Self::Error> {
        match value.port {
            Some(port) => Ok(Self { host: value.host, port }),
            None => Err(AddressParseError::MissingPort { addr: value }),
        }
    }
}

/// Alternative to an [`Address`] that has an optional port part.
#[derive(Clone, Debug)]
pub struct AddressOpt {
    /// The host-part of the address.
    pub host: Host,
    /// The port-part of the address.
    pub port: Option<u16>,
}
// Constructors
impl AddressOpt {
    /// Constructor for the Address that initializes it for the given IPv4 address.
    ///
    /// # Arguments
    /// - `b1`: The first byte of the IPv4 address.
    /// - `b2`: The second byte of the IPv4 address.
    /// - `b3`: The third byte of the IPv4 address.
    /// - `b4`: The fourth byte of the IPv4 address.
    /// - `port`: The port for this address, if any.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[inline]
    pub fn ipv4(b1: u8, b2: u8, b3: u8, b4: u8, port: Option<u16>) -> Self { Self { host: Host::new_ipv4(b1, b2, b3, b4), port } }

    /// Constructor for the AddressOpt that initializes it for the given IPv4 address.
    ///
    /// # Arguments
    /// - `ipv4`: The already constructed IPv4 address to use.
    /// - `port`: The port for this address, if any.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[inline]
    pub fn from_ipv4(ipv4: impl Into<Ipv4Addr>, port: Option<u16>) -> Self { Self { host: Host::IPv4(ipv4.into()), port } }

    /// Constructor for the AddressOpt that initializes it for the given IPv6 address.
    ///
    /// # Arguments
    /// - `ipv6`: The already constructed IPv6 address to use.
    /// - `port`: The port for this address, if any.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[inline]
    pub fn from_ipv6(ipv6: impl Into<Ipv6Addr>, port: Option<u16>) -> Self { Self { host: Host::IPv6(ipv6.into()), port } }

    /// Constructor for the AddressOpt that initializes it for the given hostname.
    ///
    /// # Arguments
    /// - `hostname`: The hostname for this Address.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[inline]
    pub fn hostname(hostname: impl Into<String>, port: Option<u16>) -> Self { Self { host: Host::new_name(hostname), port } }
}
// Accessors
impl AddressOpt {
    /// Returns the domain-part, as a (serialized) string version.
    ///
    /// # Returns
    /// A `Cow<str>` that either contains a reference to the already String hostname, or else a newly created string that is the serialized version of an IP.
    #[inline]
    pub fn domain(&self) -> Cow<'_, str> {
        match &self.host {
            Host::IPv4(addr) => Cow::Owned(addr.to_string()),
            Host::IPv6(addr) => Cow::Owned(addr.to_string()),
            Host::Name(name) => Cow::Borrowed(name),
        }
    }

    /// Returns if this AddressOpt is an `AddressOpt::Hostname`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_hostname(&self) -> bool { self.host.is_name() }

    /// Returns if this AddressOpt is an `AddressOpt::Ipv4` or `AddressOpt::Ipv6`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_ip(&self) -> bool { self.host.is_ip() }

    /// Returns if this AddressOpt is an `AddressOpt::Ipv4`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_ipv4(&self) -> bool { self.host.is_ipv4() }

    /// Returns if this AddressOpt is an `AddressOpt::Ipv6`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub const fn is_ipv6(&self) -> bool { self.host.is_ipv6() }
}
// Formatting
impl AddressOpt {
    /// Returns a formatter that deterministically and parseably serializes the AddressOpt.
    #[inline]
    pub fn serialize(&self) -> impl '_ + Display { self }
}
impl Display for AddressOpt {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        if let Some(port) = self.port { write!(f, "{}:{}", self.host, port) } else { write!(f, "{}", self.host) }
    }
}
// De/Serialization
impl Serialize for AddressOpt {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self.serialize()))
    }
}
impl<'de> Deserialize<'de> for AddressOpt {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Defines the visitor for the AddressOpt
        struct AddressOptVisitor;
        impl Visitor<'_> for AddressOptVisitor {
            type Value = AddressOpt;

            #[inline]
            fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "an address:port pair") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Attempt to serialize the incoming string
                AddressOpt::from_str(v).map_err(E::custom)
            }
        }

        // Call the visitor
        deserializer.deserialize_str(AddressOptVisitor)
    }
}
impl FromStr for AddressOpt {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Assert there is *something*
        if s.is_empty() {
            return Err(AddressParseError::NoInput);
        }

        // Check the split
        let (host, port) = match s.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (s, None),
        };

        // Parse the host
        let host = Host::from_str(host).map_err(|source| AddressParseError::IllegalHost { raw: host.into(), source })?;

        let port = port
            .map(|port_str| u16::from_str(port_str).map_err(|source| AddressParseError::IllegalPort { raw: port_str.into(), source }))
            .transpose()?;

        // OK
        Ok(Self { host, port })
    }
}
// Conversion
impl AsRef<AddressOpt> for AddressOpt {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&AddressOpt> for AddressOpt {
    #[inline]
    fn from(value: &AddressOpt) -> Self { value.clone() }
}
impl From<&mut AddressOpt> for AddressOpt {
    #[inline]
    fn from(value: &mut AddressOpt) -> Self { value.clone() }
}
impl From<Address> for AddressOpt {
    #[inline]
    fn from(value: Address) -> Self { Self { host: value.host, port: Some(value.port) } }
}
