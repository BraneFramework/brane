//  ADDRESS.rs
//    by Lut99
//
//  Created:
//    26 Jan 2023, 09:41:51
//  Last edited:
//    13 Nov 2024, 13:28:30
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
use log::trace;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};


/***** ERRORS *****/
/// Errors that relate to parsing [`Host`]s.
#[derive(Debug)]
pub enum HostParseError {
    /// No input was given.
    NoInput,
    /// The input contained an illegal character for a hostname.
    IllegalChar { c: char, raw: String },
}
impl Display for HostParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::NoInput => write!(f, "No host given"),
            Self::IllegalChar { c, raw } => write!(f, "Found illegal character {c:?} in host {raw:?} (only a-z, A-Z, 0-9 and '-' are accepted)"),
        }
    }
}
impl Error for HostParseError {}

/// Errors that relate to parsing [`Address`]es.
#[derive(Debug)]
pub enum AddressParseError {
    /// No input was given.
    NoInput,
    /// There wasn't a colon in the input.
    MissingColon { raw: String },
}
impl Display for AddressParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::NoInput => write!(f, "No address given"),
            Self::MissingColon { raw } => write!(f, "No colon found in input {raw:?}"),
        }
    }
}
impl Error for AddressParseError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NoInput => None,
            Self::MissingColon { .. } => None,
        }
    }
}

/// Errors that relate to parsing Addresses.
#[derive(Debug)]
pub enum AddressError {
    /// Invalid port number.
    IllegalPortNumber { raw: String, err: std::num::ParseIntError },
    /// Missing the colon separator (':') in the address.
    MissingColon { raw: String },
    /// Port not found when translating an [`AddressOpt`] into an [`Address`].
    MissingPort { addr: AddressOpt },
}
impl Display for AddressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AddressError::*;
        match self {
            IllegalPortNumber { raw, .. } => write!(f, "Illegal port number '{raw}'"),
            MissingColon { raw } => write!(f, "Missing address/port separator ':' in '{raw}' (did you forget to define a port?)"),
            MissingPort { addr } => write!(f, "Address '{addr}' does not have a port"),
        }
    }
}
impl Error for AddressError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use AddressError::*;
        match self {
            IllegalPortNumber { err, .. } => Some(err),
            MissingColon { .. } => None,
            MissingPort { .. } => None,
        }
    }
}





/***** LIBRARY *****/
/// Defines the possible types of hostnames.
///
/// # Generics
/// - `'a`: The lifetime of the source text from which this host is parsed. It refers to it
///   internally through a [copy-on-write](Cow) pointer, so if it holds by ownership, this lifetime
///   can be `'static`.
#[derive(Clone, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum Host<'a> {
    /// It's an IPv4 address.
    IPv4(Ipv4Addr),
    /// It's an IPv6 address.
    IPv6(Ipv6Addr),
    /// It's a hostname.
    Name(Cow<'a, str>),
}
// Constructors
impl<'a> Host<'static> {
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

    /// Constructor for the Host that initializes it for the given IPv6 address.
    ///
    /// # Arguments
    /// - `b1`: The first pair of bytes of the IP address.
    /// - `b2`: The second pair of bytes of the IP address.
    /// - `b3`: The third pair of bytes of the IP address.
    /// - `b4`: The fourth pair of bytes of the IP address.
    /// - `b5`: The fifth pair of bytes of the IP address.
    /// - `b6`: The sixth pair of bytes of the IP address.
    /// - `b7`: The seventh pair of bytes of the IP address.
    /// - `b8`: The eight pair of bytes of the IP address.
    ///
    /// # Returns
    /// A new Host that is referred to by IPv6.
    #[inline]
    pub const fn new_ipv6(b1: u16, b2: u16, b3: u16, b4: u16, b5: u16, b6: u16, b7: u16, b8: u16) -> Self {
        Self::IPv6(Ipv6Addr::new(b1, b2, b3, b4, b5, b6, b7, b8))
    }

    /// Constructor for the Host that initializes it for the given hostname, by ownership.
    ///
    /// # Arguments
    /// - `name`: The string name by which the host is known.
    ///
    /// # Returns
    /// A new Host that is referred to by DNS name.
    #[inline]
    pub const fn new_name_owned(name: String) -> Self { Self::Name(Cow::Owned(name)) }
}
impl<'a> Host<'a> {
    /// Constructor for the Host that initializes it for the given hostname.
    ///
    /// # Arguments
    /// - `name`: The string name by which the host is known.
    ///
    /// # Returns
    /// A new Host that is referred to by DNS name.
    #[inline]
    pub const fn new_name(name: &'a str) -> Self { Self::Name(Cow::Borrowed(name)) }
}
// Accessessors
impl<'a> Host<'a> {
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
    pub fn name_mut(&mut self) -> &mut str {
        if let Self::Name(name) = self { name.to_mut() } else { panic!("Cannot unwrap {:?} as an Host::Name", self.variant()) }
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
    pub fn into_name(self) -> Cow<'a, str> {
        if let Self::Name(name) = self { name } else { panic!("Cannot unwrap {:?} as an Host::Name", self.variant()) }
    }
}
// Formatting
impl<'a> Display for Host<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::IPv4(addr) => addr.fmt(f),
            Self::IPv6(addr) => addr.fmt(f),
            Self::Name(name) => name.fmt(f),
        }
    }
}
// De/Serialization
impl<'a> Host<'a> {
    /// Attempts to parse the given source string as an IP address.
    ///
    /// # Arguments
    /// - `s`: The source string to parse.
    ///
    /// # Returns
    /// Either [`Some(Self::IPv4)`](Host::IPv4), [`Some(Self::IPv6)`](Host::IPv6) or [`None`].
    fn parse_ip(s: &str) -> Option<Self> {
        match IpAddr::from_str(s) {
            Ok(IpAddr::V4(addr)) => Some(Self::IPv4(addr)),
            Ok(IpAddr::V6(addr)) => Some(Self::IPv6(addr)),
            Err(_) => None,
        }
    }

    /// Runs checks on a candidate hostname to see if it's legal.
    ///
    /// # Arguments
    /// - `s`: The source string to check.
    ///
    /// # Errors
    /// This function errors if the input `s`tring was somehow illegal.
    fn assert_name_validity(s: &str) -> Result<(), HostParseError> {
        // Assert there is *something*
        if s.is_empty() {
            return Err(HostParseError::NoInput);
        }

        // Assert it's only good
        for c in s.chars() {
            if (c < 'a' || c > 'z') && (c < 'A' && c > 'Z') && (c < '0' && c > '9') && c != '-' {
                return Err(HostParseError::IllegalChar { c, raw: s.into() });
            }
        }

        // OK, it's good
        Ok(())
    }

    /// Parses the Host from the given source string.
    ///
    /// If the string represents a [hostname](Host::Name), then it is stored by reference instead
    /// of clone for efficiency. You can perform the clone at any time by calling
    /// [`Host::into_owned()`].
    ///
    /// The [`Host::from_str()`]-implementation does this automatically due to lifetime constraints.
    ///
    /// # Arguments
    /// - `s`: The source string to parse.
    ///
    /// # Returns
    /// A new Host, parsed from the given `s`tring.
    ///
    /// # Errors
    /// This function errors if the given `s`tring is empty, or it consisted of non-legal hostname
    /// characters. For an overview, see this [this](https://en.wikipedia.org/wiki/Hostname#Syntax)
    /// list.
    pub fn parse_str(s: &'a str) -> Result<Host<'a>, HostParseError> {
        // Try as an IP address first
        match Self::parse_ip(s) {
            Some(host) => Ok(host),
            None => {
                Self::assert_name_validity(s)?;
                Ok(Self::Name(Cow::Borrowed(s)))
            },
        }
    }
}
impl<'de> Deserialize<'de> for Host<'de> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Visitor for the `Host`.
        pub struct HostVisitor;
        impl<'de> Visitor<'de> for HostVisitor {
            type Value = Host<'de>;

            #[inline]
            fn expecting(&self, f: &mut Formatter) -> FResult { write!(f, "an IP address or a hostname") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match Host::parse_str(v) {
                    Ok(host) => Ok(host.into_owned()),
                    Err(err) => Err(E::custom(err)),
                }
            }

            #[inline]
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Host::parse_str(v).map_err(E::custom)
            }

            #[inline]
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match Host::parse_ip(&v) {
                    Some(host) => Ok(host),
                    None => {
                        Host::assert_name_validity(&v).map_err(E::custom)?;
                        Ok(Host::Name(Cow::Owned(v)))
                    },
                }
            }
        }

        // Call it
        deserializer.deserialize_string(HostVisitor)
    }
}
impl<'a> Serialize for Host<'a> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
impl FromStr for Host<'static> {
    type Err = HostParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> { Host::parse_str(s).map(Host::into_owned) }
}
// Lifetime juggling
impl<'a> Host<'a> {
    /// Returns an owned version of the Host that does not depend on the source anymore.
    ///
    /// If self is a [`Host::Name`], and that name is a reference to the source, this function
    /// clones the source text to become `'static`. Else, this function is (almost) free.
    ///
    /// # Returns
    /// The same Host, but potentially cloned.
    #[inline]
    pub fn into_owned(self) -> Host<'static> {
        match self {
            Self::IPv4(addr) => Host::IPv4(addr),
            Self::IPv6(addr) => Host::IPv6(addr),
            Self::Name(name) => Host::Name(Cow::Owned(name.into_owned())),
        }
    }
}
// Conversion
impl From<IpAddr> for Host<'static> {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => Self::from(addr),
            IpAddr::V6(addr) => Self::from(addr),
        }
    }
}
impl From<Ipv4Addr> for Host<'static> {
    #[inline]
    fn from(value: Ipv4Addr) -> Self { Self::IPv4(value) }
}
impl From<Ipv6Addr> for Host<'static> {
    #[inline]
    fn from(value: Ipv6Addr) -> Self { Self::IPv6(value) }
}
impl<'a> From<&'a str> for Host<'a> {
    #[inline]
    fn from(value: &'a str) -> Self { Self::Name(Cow::Borrowed(value)) }
}
impl From<String> for Host<'static> {
    #[inline]
    fn from(value: String) -> Self { Self::Name(Cow::Owned(value)) }
}



/// Defines a more lenient alternative to a [`SocketAddr`](std::net::SocketAddr) that also accepts
/// hostnames.
///
/// # Generics
/// - `'a`: The lifetime of the source text from which this address is parsed. It refers to it
///   internally through a [copy-on-write](Cow) pointer, so if it holds by ownership, this lifetime
///   can be `'static`.
#[derive(Clone, Debug)]
pub struct Address<'a> {
    /// The host-part of the address.
    pub host: Host<'a>,
    /// The port-part of the address.
    pub port: u16,
}
// Constructors
impl Address<'static> {
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
        Self { host: Host::new_ipv6(b1, b2, b3, b4, b5, b6, b7, b8), port }
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
    pub fn hostname(hostname: impl Into<String>, port: u16) -> Self { Self { host: Host::new_name_owned(hostname.into()), port } }
}
// Accessors
impl<'a> Address<'a> {
    /// Returns the domain-part, as a (serialized) string version.
    ///
    /// # Returns
    /// A `Cow<str>` that either contains a reference to the already String hostname, or else a newly created string that is the serialized version of an IP.
    #[inline]
    pub fn domain(&self) -> Cow<str> {
        match &self.host {
            Host::IPv4(addr) => Cow::Owned(addr.to_string()),
            Host::IPv6(addr) => Cow::Owned(addr.to_string()),
            Host::Name(Cow::Borrowed(name)) => Cow::Borrowed(name),
            Host::Name(Cow::Owned(name)) => Cow::Owned(name.clone()),
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
impl<'a> Address<'a> {
    /// Returns a formatter that deterministically and parseably serializes the Address.
    #[inline]
    pub const fn serialize(&self) -> impl '_ + Display { self }
}
impl<'a> Display for Address<'a> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}:{}", self.host, self.port) }
}
// De/Serialization
impl<'a> Address<'a> {
    /// Splits the given source string into an address and a port.
    ///
    /// # Arguments
    /// - `s`: The source string to split.
    ///
    /// # Returns
    /// Two string slices, one with the address and one with the port.
    ///
    /// # Errors
    /// This function errors if the input `s`tring did not contain a `:`.
    fn split_on_colon(s: &str) -> Result<(&str, &str), AddressParseError> {
        // Assert there is *something*
        if s.is_empty() {
            return Err(AddressParseError::NoInput);
        }

        // Check the split
        if let Some(pos) = s.find(':') { Ok((&s[..pos], &s[pos + 1..])) } else { Err(AddressParseError::MissingColon { raw: s.into() }) }
    }

    /// Parses the Host from the given source string.
    ///
    /// If the string represents a [hostname](Host::Name), then it is stored by reference instead
    /// of clone for efficiency. You can perform the clone at any time by calling
    /// [`Host::into_owned()`].
    ///
    /// The [`Host::from_str()`]-implementation does this automatically due to lifetime constraints.
    ///
    /// # Arguments
    /// - `s`: The source string to parse.
    ///
    /// # Returns
    /// A new Host, parsed from the given `s`tring.
    ///
    /// # Errors
    /// This function errors if the given `s`tring is empty, or it consisted of non-legal hostname
    /// characters. For an overview, see this [this](https://en.wikipedia.org/wiki/Hostname#Syntax)
    /// list.
    pub fn parse_str(s: &'a str) -> Result<Host<'a>, HostParseError> {
        // Try as an IP address first
        match Self::parse_ip(s) {
            Some(host) => Ok(host),
            None => {
                Self::assert_name_validity(s)?;
                Ok(Self::Name(Cow::Borrowed(s)))
            },
        }
    }
}
impl<'a> Serialize for Address<'a> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", self.serialize()))
    }
}
impl<'de> Deserialize<'de> for Address<'de> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Defines the visitor for the Address
        struct AddressVisitor;
        impl<'de> Visitor<'de> for AddressVisitor {
            type Value = Address<'de>;

            #[inline]
            fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "an address:port pair") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Attempt to serialize the incoming string
                match Address::from_str(v) {
                    Ok(address) => Ok(address),
                    Err(err) => Err(E::custom(err)),
                }
            }
        }

        // Call the visitor
        deserializer.deserialize_str(AddressVisitor)
    }
}
impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt to find the colon first
        let colon_pos: usize = match s.rfind(':') {
            Some(pos) => pos,
            None => {
                return Err(AddressError::MissingColon { raw: s.into() });
            },
        };

        // Split it on that
        let (address, port): (&str, &str) = (&s[..colon_pos], &s[colon_pos + 1..]);

        // Parse the port
        let port: u16 = match u16::from_str(port) {
            Ok(port) => port,
            Err(err) => {
                return Err(AddressError::IllegalPortNumber { raw: port.into(), err });
            },
        };

        // Resolve the address to a new instance of ourselves
        match IpAddr::from_str(address) {
            Ok(address) => match address {
                IpAddr::V4(ip) => Ok(Self::Ipv4(ip, port)),
                IpAddr::V6(ip) => Ok(Self::Ipv6(ip, port)),
            },
            Err(err) => {
                trace!("Parsing '{}' as a hostname, but might be an invalid IP address (parser feedback: {})", address, err);
                Ok(Self::Hostname(address.into(), port))
            },
        }
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
    type Error = AddressError;

    #[inline]
    fn try_from(value: AddressOpt) -> Result<Self, Self::Error> {
        match value {
            AddressOpt::Ipv4(host, port_opt) => {
                if let Some(port) = port_opt {
                    Ok(Self::Ipv4(host, port))
                } else {
                    Err(AddressError::MissingPort { addr: AddressOpt::Ipv4(host, None) })
                }
            },

            AddressOpt::Ipv6(host, port_opt) => {
                if let Some(port) = port_opt {
                    Ok(Self::Ipv6(host, port))
                } else {
                    Err(AddressError::MissingPort { addr: AddressOpt::Ipv6(host, None) })
                }
            },

            AddressOpt::Hostname(host, port_opt) => {
                if let Some(port) = port_opt {
                    Ok(Self::Hostname(host, port))
                } else {
                    Err(AddressError::MissingPort { addr: AddressOpt::Hostname(host, None) })
                }
            },
        }
    }
}

/// Alternative to an [`Address`] that has an optional port part.
#[derive(Clone, Debug, EnumDebug)]
pub enum AddressOpt {
    /// It's an Ipv4 address.
    Ipv4(Ipv4Addr, Option<u16>),
    /// It's an Ipv6 address.
    Ipv6(Ipv6Addr, Option<u16>),
    /// It's a hostname.
    Hostname(String, Option<u16>),
}
impl AddressOpt {
    /// Constructor for the AddressOpt that initializes it for the given IPv4 address.
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
    pub fn ipv4(b1: u8, b2: u8, b3: u8, b4: u8, port: Option<u16>) -> Self { Self::Ipv4(Ipv4Addr::new(b1, b2, b3, b4), port) }

    /// Constructor for the AddressOpt that initializes it for the given IPv4 address.
    ///
    /// # Arguments
    /// - `ipv4`: The already constructed IPv4 address to use.
    /// - `port`: The port for this address, if any.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[inline]
    pub fn from_ipv4(ipv4: impl Into<Ipv4Addr>, port: Option<u16>) -> Self { Self::Ipv4(ipv4.into(), port) }

    /// Constructor for the AddressOpt that initializes it for the given IPv6 address.
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
    /// - `port`: The port for this address, if any.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn ipv6(b1: u16, b2: u16, b3: u16, b4: u16, b5: u16, b6: u16, b7: u16, b8: u16, port: Option<u16>) -> Self {
        Self::Ipv6(Ipv6Addr::new(b1, b2, b3, b4, b5, b6, b7, b8), port)
    }

    /// Constructor for the AddressOpt that initializes it for the given IPv6 address.
    ///
    /// # Arguments
    /// - `ipv6`: The already constructed IPv6 address to use.
    /// - `port`: The port for this address, if any.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[inline]
    pub fn from_ipv6(ipv6: impl Into<Ipv6Addr>, port: Option<u16>) -> Self { Self::Ipv6(ipv6.into(), port) }

    /// Constructor for the AddressOpt that initializes it for the given hostname.
    ///
    /// # Arguments
    /// - `hostname`: The hostname for this AddressOpt.
    /// - `port`: The port for this address, if any.
    ///
    /// # Returns
    /// A new AddressOpt instance.
    #[inline]
    pub fn hostname(hostname: impl Into<String>, port: Option<u16>) -> Self { Self::Hostname(hostname.into(), port) }

    /// Returns the domain-part, as a (serialized) string version.
    ///
    /// # Returns
    /// A `Cow<str>` that either contains a reference to the already String hostname, or else a newly created string that is the serialized version of an IP.
    #[inline]
    pub fn domain(&self) -> Cow<'_, str> {
        use AddressOpt::*;
        match self {
            Ipv4(addr, _) => format!("{addr}").into(),
            Ipv6(addr, _) => format!("{addr}").into(),
            Hostname(addr, _) => addr.into(),
        }
    }

    /// Returns the port-part, as a number.
    ///
    /// # Returns
    /// A `u16` that is the port.
    #[inline]
    pub fn port(&self) -> Option<u16> {
        use AddressOpt::*;
        match self {
            Ipv4(_, port) => *port,
            Ipv6(_, port) => *port,
            Hostname(_, port) => *port,
        }
    }

    /// Returns the port-part as a mutable number.
    ///
    /// # Returns
    /// A mutable reference to the `u16` that is the port.
    #[inline]
    pub fn port_mut(&mut self) -> &mut Option<u16> {
        use AddressOpt::*;
        match self {
            Ipv4(_, port) => port,
            Ipv6(_, port) => port,
            Hostname(_, port) => port,
        }
    }

    /// Returns if this AddressOpt is an `AddressOpt::Hostname`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_hostname(&self) -> bool { matches!(self, Self::Hostname(_, _)) }

    /// Returns if this AddressOpt is an `AddressOpt::Ipv4` or `AddressOpt::Ipv6`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_ip(&self) -> bool { self.is_ipv4() || self.is_ipv6() }

    /// Returns if this AddressOpt is an `AddressOpt::Ipv4`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_ipv4(&self) -> bool { matches!(self, Self::Ipv4(_, _)) }

    /// Returns if this AddressOpt is an `AddressOpt::Ipv6`.
    ///
    /// # Returns
    /// True if it is, false if it isn't.
    #[inline]
    pub fn is_ipv6(&self) -> bool { matches!(self, Self::Ipv6(_, _)) }

    /// Returns a formatter that deterministically and parseably serializes the AddressOpt.
    #[inline]
    pub fn serialize(&self) -> impl '_ + Display { self }
}
impl Display for AddressOpt {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AddressOpt::*;
        match self {
            Ipv4(addr, port) => {
                write!(f, "{addr}")?;
                if let Some(port) = port {
                    write!(f, ":{port}")?;
                };
                Ok(())
            },
            Ipv6(addr, port) => {
                write!(f, "{addr}")?;
                if let Some(port) = port {
                    write!(f, ":{port}")?;
                };
                Ok(())
            },
            Hostname(addr, port) => {
                write!(f, "{addr}")?;
                if let Some(port) = port {
                    write!(f, ":{port}")?;
                };
                Ok(())
            },
        }
    }
}
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
        impl<'de> Visitor<'de> for AddressOptVisitor {
            type Value = AddressOpt;

            #[inline]
            fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "an address:port pair") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Attempt to serialize the incoming string
                match AddressOpt::from_str(v) {
                    Ok(address) => Ok(address),
                    Err(err) => Err(E::custom(err)),
                }
            }
        }

        // Call the visitor
        deserializer.deserialize_str(AddressOptVisitor)
    }
}
impl FromStr for AddressOpt {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt to find the colon first and split the string accordingly
        let (address, port): (&str, Option<&str>) = match s.rfind(':') {
            Some(pos) => (&s[..pos], Some(&s[pos + 1..])),
            None => (s, None),
        };

        // Parse the port, if any
        let port: Option<u16> = port.map(|p| u16::from_str(p).map_err(|err| AddressError::IllegalPortNumber { raw: p.into(), err })).transpose()?;

        // Resolve the address to a new instance of ourselves
        match IpAddr::from_str(address) {
            Ok(address) => match address {
                IpAddr::V4(ip) => Ok(Self::Ipv4(ip, port)),
                IpAddr::V6(ip) => Ok(Self::Ipv6(ip, port)),
            },
            Err(err) => {
                trace!("Parsing '{}' as a hostname, but might be an invalid IP address (parser feedback: {})", address, err);
                Ok(Self::Hostname(address.into(), port))
            },
        }
    }
}
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
    fn from(value: Address) -> Self {
        match value {
            Address::Ipv4(host, port) => Self::Ipv4(host, Some(port)),
            Address::Ipv6(host, port) => Self::Ipv6(host, Some(port)),
            Address::Hostname(host, port) => Self::Hostname(host, Some(port)),
        }
    }
}
