//  SPEC.rs
//    by Lut99
//
//  Created:
//    28 Nov 2022, 15:56:23
//  Last edited:
//    07 Nov 2023, 16:29:39
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines (public) interfaces and structs in the `brane-cli` crate.
//

use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use brane_exe::spec::CustomGlobalState;
use brane_tsk::docker::DockerOptions;
use parking_lot::Mutex;
use specifications::data::DataIndex;
use specifications::package::PackageIndex;
use specifications::version::ConcreteFunctionVersion;

use crate::errors::HostnameParseError;


/***** STATICS *****/
lazy_static::lazy_static! {
    /// The default Docker API version that we're using.
    pub static ref API_DEFAULT_VERSION: String = format!("{}", brane_tsk::docker::API_DEFAULT_VERSION);
}





/***** LIBRARY *****/
/// An auxillary struct that defines a hostname-only argument, optionally with some scheme.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Hostname {
    /// The name of the host
    pub hostname: String,
    /// The scheme, if any.
    pub scheme:   Option<String>,
}

impl Hostname {
    /// Constructor for the Hostname that creates it without any scheme.
    ///
    /// # Arguments
    /// - `hostname`: The hostname of the host to store in this struct.
    ///
    /// # Returns
    /// A new Hostname instance.
    #[inline]
    pub fn new(hostname: impl Into<String>) -> Self { Self { hostname: hostname.into(), scheme: None } }

    /// Contsructor for the Hostname that creates it with the given hostname and scheme set.
    ///
    /// # Arguments
    /// - `hostname`: The hostname of the host to store in this struct.
    /// - `scheme`: The scheme to connect to the host to.
    ///
    /// # Returns
    /// A new Hostname instance.
    #[inline]
    pub fn with_scheme(hostname: impl Into<String>, scheme: impl Into<String>) -> Self {
        Self { hostname: hostname.into(), scheme: Some(scheme.into()) }
    }
}

impl Display for Hostname {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match &self.scheme {
            Some(scheme) => write!(f, "{}://{}", scheme, self.hostname),
            None => write!(f, "{}", self.hostname),
        }
    }
}
impl FromStr for Hostname {
    type Err = HostnameParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // See if we can split the thing into a scheme and a non-scheme part
        let scheme_sep_pos: Option<usize> = s.find("://");
        let (scheme, hostname): (Option<String>, &str) = if let Some(scheme_sep_pos) = scheme_sep_pos {
            // Split into the scheme and non-scheme
            let scheme: &str = &s[..scheme_sep_pos];
            let host: &str = &s[scheme_sep_pos + 3..];

            // Assert the scheme only has alphanumeric characters
            for c in scheme.chars() {
                if !c.is_ascii_digit() && !c.is_ascii_lowercase() && !c.is_ascii_uppercase() {
                    return Err(HostnameParseError::IllegalSchemeChar { raw: scheme.into(), c });
                }
            }

            // Return them
            (Some(scheme.into()), host)
        } else {
            (None, s)
        };

        // Assert the host has no paths in it
        if hostname.find('/').is_some() {
            return Err(HostnameParseError::HostnameContainsPath { raw: hostname.into() });
        }

        // Alright good enough for now
        Ok(Self { hostname: hostname.into(), scheme })
    }
}



/// Parses a version number that scopes a particular operation down. In other words, can be a specific version number or `all`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionFix(pub Option<semver::Version>);
impl Display for VersionFix {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(f, "{}", if let Some(ref version) = self.0 { version.to_string() } else { "all".into() })
    }
}
impl FromStr for VersionFix {
    type Err = specifications::version::SemverError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse the auto first
        if s == "all" {
            return Ok(Self(None));
        }
        // Otherwise, delegate to the version parser
        Ok(Self(Some(ConcreteFunctionVersion::from_str(s)?)))
    }
}



/// The global state for the OfflineVm.
#[derive(Clone, Debug)]
pub struct GlobalState {
    /// The information we want to know for Docker
    pub docker_opts:     DockerOptions,
    /// Whether to keep containers after execution or not
    pub keep_containers: bool,

    /// The path to the directory where packages (and thus container images) are stored for this session.
    pub package_dir: PathBuf,
    /// The path to the directory where datasets (where we wanna copy results) are stored for this session.
    pub dataset_dir: PathBuf,
    /// The path to the directory where intermediate results will be stored for this session.
    pub results_dir: PathBuf,

    /// The package index that contains info about each package.
    pub pindex:  Arc<PackageIndex>,
    /// The data index that contains info about each package.
    pub dindex:  Arc<DataIndex>,
    /// A list of results we planned in the previous timestep.
    pub results: Arc<Mutex<HashMap<String, String>>>,
}
impl CustomGlobalState for GlobalState {}

/// The local state for the OfflineVm is unused.
pub type LocalState = ();
