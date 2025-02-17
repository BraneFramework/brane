/* ARCH.rs
 *   by Lut99
 *
 * Created:
 *   22 May 2022, 17:35:56
 * Last edited:
 *   31 May 2022, 17:01:04
 * Auto updated?
 *   Yes
 *
 * Description:
 *   Defines enums and parsers to work with multiple architectures.
**/

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::hash::Hash;
use std::str::FromStr;

use serde::{Deserialize, Serialize};


/***** ERRORS *****/
/// Defines the error that may occur when parsing architectures
#[derive(Debug)]
pub enum ArchError {
    /// Could not deserialize the given string
    UnknownArchitecture { raw: String },
}
impl Display for ArchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ArchError::*;
        match self {
            UnknownArchitecture { raw } => write!(f, "Unknown architecture '{raw}'"),
        }
    }
}
impl Error for ArchError {}





/***** AUXILLARY *****/
/// A formatter for architectures that writes it in a way that Brane understands.
#[derive(Debug)]
pub struct ArchBraneFormatter<'a> {
    /// The architecture to format.
    arch: &'a Arch,
}
impl Display for ArchBraneFormatter<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self.arch {
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Aarch64 => write!(f, "aarch64"),
        }
    }
}

/// Formatter that writes the given Arch in a way that the Rust compiler ecosystem understands.
#[derive(Debug)]
pub struct ArchRustFormatter<'a> {
    /// The architecture to format.
    arch: &'a Arch,
}
impl Display for ArchRustFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Arch::*;
        match self.arch {
            X86_64 => write!(f, "x86_64"),
            Aarch64 => write!(f, "aarch64"),
        }
    }
}

/// Formatter that writes the given Arch in a way that the Docker ecosystem understands.
#[derive(Debug)]
pub struct ArchDockerFormatter<'a> {
    /// The architecture to format.
    arch: &'a Arch,
}
impl Display for ArchDockerFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Arch::*;
        match self.arch {
            X86_64 => write!(f, "x86_64"),
            Aarch64 => write!(f, "aarch64"),
        }
    }
}

/// Formatter that writes the given Arch in a way that the JuiceFS ecosystem understands.
#[derive(Debug)]
pub struct ArchJuiceFsFormatter<'a> {
    /// The architecture to format.
    arch: &'a Arch,
}
impl Display for ArchJuiceFsFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Arch::*;
        match self.arch {
            X86_64 => write!(f, "amd64"),
            Aarch64 => write!(f, "arm64"),
        }
    }
}

/// A formatter for architectures that writes it in a way that is used to download cfssl binaries.
#[derive(Debug)]
pub struct ArchCfsslFormatter<'a> {
    /// The architecture to format.
    os: &'a Arch,
}
impl Display for ArchCfsslFormatter<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self.os {
            Arch::X86_64 => write!(f, "amd64"),
            Arch::Aarch64 => write!(f, "arm64"),
        }
    }
}





/***** LIBRARY *****/
/// The Arch enum defines possible architectures that we know of and love
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Arch {
    /// The standard x86_64 architecture
    #[serde(alias = "amd64")]
    X86_64,
    /// The arm64 / macOS M1 architecture
    #[serde(alias = "arm64")]
    Aarch64,
}

impl Arch {
    /// Constant referring to the compiled (=host) architecture
    #[cfg(target_arch = "x86_64")]
    pub const HOST: Self = Self::X86_64;
    #[cfg(target_arch = "aarch64")]
    pub const HOST: Self = Self::Aarch64;

    /// Allows one to serialize the architecture for use in the Brane ecosystem.
    ///
    /// # Returns
    /// An `ArchBraneFormatter` that implements Display in a Brane-compatible way.
    #[inline]
    pub fn brane(&self) -> ArchBraneFormatter { ArchBraneFormatter { arch: self } }

    /// Allows one to serialize the architecture for use in the Rust ecosystem.
    ///
    /// # Returns
    /// An `ArchRustFormatter` that implements Display in a Rust-compatible way.
    #[inline]
    pub fn rust(&self) -> ArchRustFormatter { ArchRustFormatter { arch: self } }

    /// Allows one to serialize the architecture for use in the Docker ecosystem.
    ///
    /// # Returns
    /// An `ArchDockerFormatter` that implements Display in a Docker-compatible way.
    #[inline]
    pub fn docker(&self) -> ArchDockerFormatter { ArchDockerFormatter { arch: self } }

    /// Allows one to serialize the architecture for use in the Juice FS ecosystem.
    ///
    /// # Returns
    /// An `ArchJuiceFsFormatter` that implements Display in a Juice FS-compatible way.
    #[inline]
    pub fn juicefs(&self) -> ArchJuiceFsFormatter { ArchJuiceFsFormatter { arch: self } }

    /// Allows one to serialize the architecture for use to download cfssl binaries.
    ///
    /// # Returns
    /// An `ArchCfsslFormatter` that implements [`Display`]` in a cfssl-compatible way.
    #[inline]
    pub fn cfssl(&self) -> ArchCfsslFormatter { ArchCfsslFormatter { os: self } }
}

impl Display for Arch {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Arch::X86_64 => write!(f, "x86-64"),
            Arch::Aarch64 => write!(f, "ARM 64-bit"),
        }
    }
}
impl FromStr for Arch {
    type Err = ArchError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "x86_64" | "amd64" => Ok(Arch::X86_64),

            "aarch64" | "arm64" => Ok(Arch::Aarch64),

            // Meta-argument for resolving the local architecture
            #[cfg(target_arch = "x86_64")]
            "$LOCAL" => Ok(Self::X86_64),
            #[cfg(target_arch = "aarch64")]
            "$LOCAL" => Ok(Self::Aarch64),
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            "$LOCAL" => {
                compile_error!("Non-x86/64, non-aarch64 processor architecture not supported");
            },

            raw => Err(ArchError::UnknownArchitecture { raw: raw.to_string() }),
        }
    }
}
