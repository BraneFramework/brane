//  VERSION.rs
//    by Lut99
//
//  Created:
//    23 Mar 2022, 15:15:12
//  Last edited:
//    10 Apr 2023, 11:28:06
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a new Version struct, which is like semver's Version but
//!   with
//

use std::cmp::Ordering;
use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub type ConcreteFunctionVersion = semver::Version;
pub use semver::Error as SemverError;

/// Version information for a Brane DSL function.
/// This version can be specified along semver, or provided as "latest".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AliasedFunctionVersion {
    Latest,
    Version(semver::Version),
}

impl Display for AliasedFunctionVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Latest => write!(f, "latest"),
            Self::Version(s) => write!(f, "{s}"),
        }
    }
}

impl FromStr for AliasedFunctionVersion {
    type Err = semver::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "latest" => Ok(Self::Latest),
            v => Ok(Self::Version(FromStr::from_str(v)?)),
        }
    }
}

impl From<&AliasedFunctionVersion> for String {
    fn from(value: &AliasedFunctionVersion) -> Self { format!("{value}") }
}


impl PartialEq for AliasedFunctionVersion {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Version(l0), Self::Version(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl PartialOrd for AliasedFunctionVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            // Latest is just latest
            (AliasedFunctionVersion::Latest, AliasedFunctionVersion::Latest) => Some(Ordering::Equal),

            // We cannot determine the concrete version of latest
            (AliasedFunctionVersion::Latest, AliasedFunctionVersion::Version(_)) => None,
            (AliasedFunctionVersion::Version(_), AliasedFunctionVersion::Latest) => None,

            // Regular comparison
            (AliasedFunctionVersion::Version(v_self), AliasedFunctionVersion::Version(v_other)) => v_self.partial_cmp(v_other),
        }
    }
}


impl AliasedFunctionVersion {
    pub fn from_package_pair(package: &str) -> Result<(String, Option<Self>), VersionError> {
        let mut parts = package.split(":");

        match (parts.next(), parts.next(), parts.next()) {
            (Some(package_name), None, None) => Ok((package_name.to_string(), None)),
            (Some(package_name), Some(package_version), None) => {
                Ok((package_name.to_string(), Some(AliasedFunctionVersion::from_str(package_version)?)))
            },
            (_, _, _) => Err(VersionError::TooManyColons { raw: package.into(), got: parts.count() + 3 }),
        }
    }

    pub fn is_latest(&self) -> bool { matches!(self, Self::Latest) }
}

impl From<ConcreteFunctionVersion> for AliasedFunctionVersion {
    fn from(value: ConcreteFunctionVersion) -> Self { AliasedFunctionVersion::Version(value) }
}

#[derive(Debug, thiserror::Error)]
pub enum VersionError {
    #[error("Something went wrong parsing a version as a semver version")]
    SemVer(
        #[source]
        #[from]
        semver::Error,
    ),
    #[error("Given 'NAME[:VERSION]' pair '{raw}' has too many colons (got {got}, expected at most 1)")]
    TooManyColons { raw: String, got: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct BraneVersion(pub semver::Version);

impl FromStr for BraneVersion {
    type Err = semver::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Ok(BraneVersion(semver::Version::from_str(s)?)) }
}

impl Display for BraneVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.0.fmt(f) }
}
