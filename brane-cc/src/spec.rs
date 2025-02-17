//  SPEC.rs
//    by Lut99
//
//  Created:
//    18 Nov 2022, 15:03:19
//  Last edited:
//    12 Dec 2022, 17:02:27
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines (public) interfaces and structs for the `brane-cc` crate.
//

use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;
use std::str::FromStr;

use enum_debug::EnumDebug;
use url::Url;

use crate::errors::IndexLocationParseError;


/***** CONSTANTS *****/
/// The prefix for a local IndexLocation.
pub const LOCAL_PREFIX: &str = "Local<";
/// The postfix for a local IndexLocation.
pub const LOCAL_POSTFIX: &str = ">";

/// The prefix for a remote IndexLocation.
pub const REMOTE_PREFIX: &str = "Remote<";
/// The postfix for a remote IndexLocation.
pub const REMOTE_POSTFIX: &str = ">";





/***** LIBRARY *****/
/// Defins a formatter for the IndexLocation that writes it in a `IndexLocation::FromStr`-compatible way.
#[derive(Debug)]
pub struct IndexLocationSerializer<'a> {
    /// The index location to serialize.
    loc: &'a IndexLocation,
}
impl Display for IndexLocationSerializer<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use IndexLocation::*;
        match self.loc {
            Local(path) => write!(f, "{}{}{}", LOCAL_PREFIX, path.display(), LOCAL_POSTFIX),
            Remote(addr) => write!(f, "{REMOTE_PREFIX}{addr}{REMOTE_POSTFIX}"),
        }
    }
}



/// Defines an enum that either defines a local path to fetch packages / datasets from, or a remote location to fetch packages / datasets from.
#[derive(Clone, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum IndexLocation {
    /// It's a local location
    Local(PathBuf),
    /// It's a remote address
    Remote(String),
}

impl IndexLocation {
    /// Returns a formatter for the IndexLocation that writes it in an unambigious, serialized way.
    #[inline]
    pub fn serialize(&self) -> IndexLocationSerializer { IndexLocationSerializer { loc: self } }

    /// Returns whether this index location is a local path.
    #[inline]
    pub fn is_local(&self) -> bool { matches!(self, Self::Local(_)) }

    /// Returns the path in this IndexLocation as if it is a Local location.
    ///
    /// # Panics
    /// This function will panic if `self` is not a `Self::Local`.
    #[inline]
    pub fn local(&self) -> &PathBuf {
        if let Self::Local(path) = self {
            path
        } else {
            panic!("Cannot unwrap {:?} as an IndexLocation::Local", self.variant());
        }
    }

    /// Returns a mutable path in this IndexLocation as if it is a Local location.
    ///
    /// # Panics
    /// This function will panic if `self` is not a `Self::Local`.
    #[inline]
    pub fn local_mut(&mut self) -> &mut PathBuf {
        if let Self::Local(path) = self {
            path
        } else {
            panic!("Cannot unwrap {:?} as an IndexLocation::Local", self.variant());
        }
    }

    /// Consumes this IndexLocation into a local path as if it is a Local location.
    ///
    /// # Panics
    /// This function will panic if `self` is not a `Self::Local`.
    #[inline]
    pub fn into_local(self) -> PathBuf {
        if let Self::Local(path) = self {
            path
        } else {
            panic!("Cannot unwrap {:?} as an IndexLocation::Local", self.variant());
        }
    }

    /// Returns whether this index location is a remote address.
    #[inline]
    pub fn is_remote(&self) -> bool { matches!(self, Self::Remote(_)) }

    /// Returns the address in this IndexLocation as if it is a Remote location.
    ///
    /// # Panics
    /// This function will panic if `self` is not a `Self::Remote`.
    #[inline]
    pub fn remote(&self) -> &String {
        if let Self::Remote(addr) = self {
            addr
        } else {
            panic!("Cannot unwrap {:?} as an IndexLocation::Remote", self.variant());
        }
    }

    /// Returns a mutable address in this IndexLocation as if it is a Remote location.
    ///
    /// # Panics
    /// This function will panic if `self` is not a `Self::Remote`.
    #[inline]
    pub fn remote_mut(&mut self) -> &mut String {
        if let Self::Remote(addr) = self {
            addr
        } else {
            panic!("Cannot unwrap {:?} as an IndexLocation::Remote", self.variant());
        }
    }

    /// Consumes this IndexLocation into a remote address as if it is a Remote location.
    ///
    /// # Panics
    /// This function will panic if `self` is not a `Self::Remote`.
    #[inline]
    pub fn into_remote(self) -> String {
        if let Self::Remote(addr) = self {
            addr
        } else {
            panic!("Cannot unwrap {:?} as an IndexLocation::Remote", self.variant());
        }
    }
}

impl Display for IndexLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use IndexLocation::*;
        match self {
            Local(path) => write!(f, "{}", path.display()),
            Remote(addr) => write!(f, "{addr}"),
        }
    }
}

impl AsRef<IndexLocation> for IndexLocation {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&IndexLocation> for IndexLocation {
    #[inline]
    fn from(value: &IndexLocation) -> Self { value.clone() }
}
impl From<&mut IndexLocation> for IndexLocation {
    #[inline]
    fn from(value: &mut IndexLocation) -> Self { value.clone() }
}

impl FromStr for IndexLocation {
    type Err = IndexLocationParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First, attempt to find the "unambigious patterns"
        if s.len() > LOCAL_PREFIX.len()
            && &s[..LOCAL_PREFIX.len()] == LOCAL_PREFIX
            && s.len() > LOCAL_POSTFIX.len()
            && &s[s.len() - LOCAL_POSTFIX.len()..] == LOCAL_POSTFIX
        {
            // The bit in between is the local path
            return Ok(Self::Local(PathBuf::from(&s[LOCAL_PREFIX.len()..s.len() - LOCAL_POSTFIX.len()])));
        }
        if s.len() > REMOTE_PREFIX.len()
            && &s[..REMOTE_PREFIX.len()] == REMOTE_PREFIX
            && s.len() > REMOTE_POSTFIX.len()
            && &s[s.len() - REMOTE_POSTFIX.len()..] == REMOTE_POSTFIX
        {
            // The bit in between is the remote address
            return Ok(Self::Remote(s[REMOTE_PREFIX.len()..s.len() - REMOTE_POSTFIX.len()].into()));
        }

        // Next, if we can parse it as an address, use remote
        if Url::parse(s).is_ok() { Ok(Self::Remote(s.into())) } else { Ok(Self::Local(s.into())) }
    }
}
impl<T: AsRef<str>> From<T> for IndexLocation {
    fn from(value: T) -> Self { Self::from_str(value.as_ref()).unwrap() }
}
