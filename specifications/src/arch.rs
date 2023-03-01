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
use std::process::{Command, ExitStatus};
use std::str::FromStr;

use serde::{Deserialize, Serialize};


/***** ERRORS *****/
/// Defines the error that may occur when parsing architectures
#[derive(Debug)]
pub enum ArchError {
    /// Could not launch the `uname -m` command
    UnameLaunchError{ command: Command, err: std::io::Error },
    /// The `uname -m` command did not return a successful exit status
    UnameError{ command: Command, status: ExitStatus },

    /// Could not deserialize the given string
    UnknownArchitecture{ raw: String },
}

impl Display for ArchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ArchError::*;
        match self {
            UnameLaunchError{ command, err } => write!(f, "Could not launch '{command:?}': {err}"),
            UnameError{ command, status }    => write!(f, "Command '{:?}' returned non-zero exit code {}", command, status.code().unwrap_or(-1)),

            UnknownArchitecture{ raw } => write!(f, "Unknown architecture '{raw}'"),
        }
    }
}

impl Error for ArchError {}





/***** LIBRARY *****/
/// The Arch enum defines possible architectures that we know of and love
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Arch {
    /// The standard x86_64 architecture
    #[serde(alias="amd64")]
    x86_64,
    /// The arm64 / macOS M1 architecture
    #[serde(alias="arm64")]
    aarch64,
}

impl Arch {
    /// Serializes the Arch in a Rust-compatible way.
    #[inline]
    pub fn to_rust(&self) -> &'static str {
        match self {
            Arch::x86_64  => "x86_64",
            Arch::aarch64 => "aarch64",
        }
    }

    /// Serializes the Arch in a Docker-compatible way.
    #[inline]
    pub fn to_docker(&self) -> &'static str {
        match self {
            Arch::x86_64  => "x86_64",
            Arch::aarch64 => "aarch64",
        }
    }

    /// Serializes the Arch in a JuiceFS-binary-compatible way.
    #[inline]
    pub fn to_juicefs(&self) -> &'static str {
        match self {
            Arch::x86_64  => "amd64",
            Arch::aarch64 => "arm64",
        }
    }



    /// Attempts to parse the host architecture using `uname -m`.
    /// 
    /// # Errors
    /// This function may error if that command could not be executed, or the resulting architecture string is unsupported.
    pub fn host() -> Result<Self, ArchError> {
        // Build the command to run
        let mut uname = Command::new("uname");
        uname.arg("-m");
        let res = match uname.output() {
            Ok(res)  => res,
            Err(err) => { return Err(ArchError::UnameLaunchError{ command: uname, err }); }
        };
        if !res.status.success() { return Err(ArchError::UnameError{ command: uname, status: res.status }); }

        // Clean the stdout
        let output: String = String::from_utf8_lossy(&res.stdout).to_string();
        let output: &str = output.trim();

        // Try to parse as architecture
        Arch::from_str(output)
    }
}

impl Display for Arch {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Arch::x86_64  => write!(f, "x86_64"),
            Arch::aarch64 => write!(f, "aarch64"),
        }
    }
}

impl FromStr for Arch {
    type Err = ArchError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "x86_64" |
            "amd64"  => Ok(Arch::x86_64),

            "aarch64" |
            "arm64"   => Ok(Arch::aarch64),

            raw => Err(ArchError::UnknownArchitecture{ raw: raw.to_string() }),
        }
    }
}
