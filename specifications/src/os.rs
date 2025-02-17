//  OS.rs
//    by Lut99
//
//  Created:
//    01 May 2024, 10:10:50
//  Last edited:
//    01 May 2024, 10:27:41
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a OS-string enum that allows us to communicate operating
//!   system (types) to/from users.
//

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::hash::Hash;
use std::str::FromStr;

use serde::{Deserialize, Serialize};


/***** ERRORS *****/
/// Defines the error that may occur when parsing operating systems
#[derive(Debug)]
pub enum ParseError {
    /// Running on an OS we do not known.
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    UnknownLocalOs,
    /// Could not deserialize the given string
    UnknownOs { raw: String },
}
impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ParseError::*;
        match self {
            #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
            UnknownLocalOs => write!(f, "Running on an unknown OS, cannot automatically resolve '$LOCAL' OS string"),
            UnknownOs { raw } => write!(f, "Unknown operating system '{raw}'"),
        }
    }
}
impl Error for ParseError {}





/***** AUXILLARY *****/
/// A formatter for operating systems that writes it in a way that is used to download cfssl binaries.
#[derive(Debug)]
pub struct OsCfsslFormatter<'o> {
    /// The operating system to format.
    os: &'o Os,
}
impl Display for OsCfsslFormatter<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self.os {
            Os::Windows => write!(f, "windows"),
            Os::MacOS => write!(f, "darwin"),
            Os::Linux => write!(f, "linux"),
        }
    }
}





/***** LIBRARY *****/
/// The Os enum defines possible operating systems that we know of and love
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    /// Windows 95/98/2000/XP/Vista/7/8/10/11/w/e
    #[serde(alias = "win")]
    Windows,
    /// Apple's operating system
    #[serde(alias = "darwin")]
    MacOS,
    /// Linux of any shape.
    Linux,
}

impl Os {
    /// Constant referring to the compiled (=host) operating system
    #[cfg(windows)]
    pub const HOST: Self = Self::Windows;
    #[cfg(target_os = "macos")]
    pub const HOST: Self = Self::MacOS;
    #[cfg(target_os = "linux")]
    pub const HOST: Self = Self::Linux;

    /// Returns if this operating system points to Windows.
    ///
    /// # Returns
    /// True if we're [`Os::Windows`], or false otherwise.
    #[inline]
    pub fn is_windows(&self) -> bool { matches!(self, Self::Windows) }

    /// Returns if this operating system is Unix-compatible.
    ///
    /// # Returns
    /// True if we're [`Os::MacOS`] or [`Os::Linux`], false if we're [`Os::Windows`].
    #[inline]
    pub fn is_unix(&self) -> bool { matches!(self, Self::MacOS) || matches!(self, Self::Linux) }

    /// Returns if this operating system points to macOS.
    ///
    /// # Returns
    /// True if we're [`Os::MacOS`], or false otherwise.
    #[inline]
    pub fn is_macos(&self) -> bool { matches!(self, Self::MacOS) }

    /// Returns if this operating system points to Linux.
    ///
    /// # Returns
    /// True if we're [`Os::Linux`], or false otherwise.
    #[inline]
    pub fn is_linux(&self) -> bool { matches!(self, Self::Linux) }

    /// Allows one to serialize the operating system for use to download cfssl binaries.
    ///
    /// # Returns
    /// An `OsCfsslFormatter` that implements [`Display`]` in a cfssl-compatible way.
    #[inline]
    pub fn cfssl(&self) -> OsCfsslFormatter { OsCfsslFormatter { os: self } }
}

impl Display for Os {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::Windows => write!(f, "Windows"),
            Self::MacOS => write!(f, "macOS"),
            Self::Linux => write!(f, "Linux"),
        }
    }
}
impl FromStr for Os {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "win" | "windows" => Ok(Self::Windows),
            "darwin" | "macos" => Ok(Self::MacOS),
            "linux" => Ok(Self::Linux),

            // Meta-argument for resolving the local architecture
            #[cfg(windows)]
            "$LOCAL" => Ok(Self::Windows),
            #[cfg(target_os = "macos")]
            "$LOCAL" => Ok(Self::MacOS),
            #[cfg(target_os = "linux")]
            "$LOCAL" => Ok(Self::Linux),
            #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
            "$LOCAL" => Err(ParseError::UnknownLocalOs),

            raw => Err(ParseError::UnknownOs { raw: raw.to_string() }),
        }
    }
}
