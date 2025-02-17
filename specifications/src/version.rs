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
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};


/***** UNIT TESTS *****/
#[cfg(test)]
mod tests {
    use serde_test::{Token, assert_de_tokens, assert_de_tokens_error, assert_ser_tokens};

    use super::*;


    /// A test string that is used for serde, who requires 'static references
    const ACCIDENTAL_LATEST_STRING: &str = const_format::formatcp!("{}.{}.{}", u64::MAX, u64::MAX, u64::MAX);



    #[test]
    fn test_eq() {
        // Test if versions equal each other
        assert!(Version::new(42, 21, 10) == Version::new(42, 21, 10));
        assert!(Version::new(42, 21, 10) != Version::new(43, 21, 10));

        // Test the ordering
        assert!(Version::new(42, 21, 10) > Version::new(42, 21, 9));
        assert!(Version::new(42, 21, 10) > Version::new(42, 20, 10));
        assert!(Version::new(42, 21, 10) > Version::new(41, 21, 10));
        assert!(Version::new(42, 21, 10) < Version::new(42, 21, 11));
        assert!(Version::new(42, 21, 10) < Version::new(42, 22, 10));
        assert!(Version::new(42, 21, 10) < Version::new(43, 21, 10));
    }

    #[test]
    fn test_parse() {
        // Test if it can parse string versions
        assert_eq!(Version::from_str("42.21.10"), Ok(Version::new(42, 21, 10)));
        assert_eq!(Version::from_str("42.21"), Ok(Version::new(42, 21, 0)));
        assert_eq!(Version::from_str("42"), Ok(Version::new(42, 0, 0)));

        // Test if it can parse latest
        assert_eq!(Version::from_str("latest"), Ok(Version::latest()));

        // Test if it fails properly too
        assert_eq!(Version::from_str(&format!("{}.{}.{}", u64::MAX, u64::MAX, u64::MAX)), Err(ParseError::AccidentalLatest));
        assert_eq!(Version::from_str("a"), Err(ParseError::MajorParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }));
        assert_eq!(Version::from_str("42.a"), Err(ParseError::MinorParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }));
        assert_eq!(Version::from_str("42.21.a"), Err(ParseError::PatchParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }));
        assert_eq!(Version::from_str("a.b.c"), Err(ParseError::MajorParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }));
        assert_eq!(Version::from_str("42.b.c"), Err(ParseError::MinorParseError { raw: String::from("b"), err: u64::from_str("b").unwrap_err() }));
    }

    #[test]
    fn test_resolve() {
        // Create a 'latest' version
        let mut latest = Version::latest();

        // Resolve it with a list
        let versions =
            vec![Version::new(21, 21, 10), Version::new(42, 20, 10), Version::new(42, 21, 10), Version::new(42, 19, 10), Version::new(0, 0, 0)];
        assert!(latest.resolve_latest(versions.clone()).is_ok());
        assert_eq!(latest, Version::new(42, 21, 10));

        // Next, check if the errors work
        let mut latest = Version::new(42, 21, 10);
        assert_eq!(latest.resolve_latest(versions), Err(ResolveError::AlreadyResolved { version: Version::new(42, 21, 10) }));

        let mut latest = Version::latest();
        let versions = vec![Version::new(21, 21, 10), Version::latest(), Version::new(42, 21, 10)];
        assert_eq!(latest.resolve_latest(versions), Err(ResolveError::NotResolved));

        let mut latest = Version::latest();
        let versions = vec![];
        assert_eq!(latest.resolve_latest(versions), Err(ResolveError::NoVersions));
    }



    #[test]
    fn test_semver() {
        // Make sure the from (consuming) makes sense
        let semversion = semver::Version::new(42, 21, 10);
        let version = Version::from(semversion.clone());
        assert_eq!(semversion.major, version.major);
        assert_eq!(semversion.minor, version.minor);
        assert_eq!(semversion.patch, version.patch);

        // Make sure the from (reference) makes sense
        let semversion = semver::Version::new(10, 21, 42);
        let version = Version::from(&semversion);
        assert_eq!(semversion.major, version.major);
        assert_eq!(semversion.minor, version.minor);
        assert_eq!(semversion.patch, version.patch);

        // Check the eq
        assert_eq!(Version::new(42, 21, 10), semver::Version::new(42, 21, 10));
        assert_ne!(Version::latest(), semver::Version::new(u64::MAX, u64::MAX, u64::MAX));

        // Check the ord
        assert!(Version::new(42, 21, 10) > semver::Version::new(42, 21, 9));
        assert!(Version::new(42, 21, 10) > semver::Version::new(42, 20, 10));
        assert!(Version::new(42, 21, 10) > semver::Version::new(41, 21, 10));
        assert!(Version::new(42, 21, 10) < semver::Version::new(42, 21, 11));
        assert!(Version::new(42, 21, 10) < semver::Version::new(42, 22, 10));
        assert!(Version::new(42, 21, 10) < semver::Version::new(43, 21, 10));
    }



    #[test]
    fn test_serde_serialize() {
        // Try to convert some versions to serde tokens
        assert_ser_tokens(&Version::new(42, 21, 10), &[Token::Str("42.21.10")]);
        assert_ser_tokens(&Version::new(42, 0, 10), &[Token::Str("42.0.10")]);
        assert_ser_tokens(&Version::latest(), &[Token::Str("latest")]);
    }

    #[test]
    fn test_serde_deserialize() {
        // Try to convert some versions to serde tokens
        assert_de_tokens(&Version::new(42, 21, 10), &[Token::Str("42.21.10")]);
        assert_de_tokens(&Version::new(42, 0, 10), &[Token::Str("42.0.10")]);
        assert_de_tokens(&Version::latest(), &[Token::Str("latest")]);

        // Check for the same errors as test_parse()
        assert_de_tokens_error::<Version>(&[Token::Str(ACCIDENTAL_LATEST_STRING)], &format!("{}", ParseError::AccidentalLatest));
        assert_de_tokens_error::<Version>(
            &[Token::Str("a")],
            &format!("{}", ParseError::MajorParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }),
        );
        assert_de_tokens_error::<Version>(
            &[Token::Str("42.a")],
            &format!("{}", ParseError::MinorParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }),
        );
        assert_de_tokens_error::<Version>(
            &[Token::Str("42.21.a")],
            &format!("{}", ParseError::PatchParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }),
        );
        assert_de_tokens_error::<Version>(
            &[Token::Str("a.b.c")],
            &format!("{}", ParseError::MajorParseError { raw: String::from("a"), err: u64::from_str("a").unwrap_err() }),
        );
        assert_de_tokens_error::<Version>(
            &[Token::Str("42.b.c")],
            &format!("{}", ParseError::MinorParseError { raw: String::from("b"), err: u64::from_str("b").unwrap_err() }),
        );
    }
}





/***** ERRORS *****/
/// Collects errors that relate to the Version.
#[derive(Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// Could not resolve the version as it's already resolved.
    AlreadyResolved { version: Version },
    /// One of the versions we use to resolve this version is not resolved
    NotResolved,
    /// Could not resolve this version, as no versions are given
    NoVersions,
}

impl Display for ResolveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            ResolveError::AlreadyResolved { version } => write!(f, "Cannot resolve already resolved version '{version}'"),
            ResolveError::NotResolved => write!(f, "Cannot resolve version with unresolved versions"),
            ResolveError::NoVersions => write!(f, "Cannot resolve version without any versions given"),
        }
    }
}

impl Error for ResolveError {}



/// Collects errors that relate to the Version.
#[derive(Debug, Eq, PartialEq)]
pub enum ParseError {
    /// We accidentally created a 'latest' version
    AccidentalLatest,
    /// Could not parse the major version number
    MajorParseError { raw: String, err: std::num::ParseIntError },
    /// Could not parse the minor version number
    MinorParseError { raw: String, err: std::num::ParseIntError },
    /// Could not parse the patch version number
    PatchParseError { raw: String, err: std::num::ParseIntError },

    /// Got a NAME:VERSION pair with too many colons
    TooManyColons { raw: String, got: usize },
    /// Could not parse the Version in a given NAME:VERSION pair.
    IllegalVersion { raw: String, raw_version: String, err: Box<Self> },
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ParseError::*;
        match self {
            AccidentalLatest => {
                write!(f, "A version with all numbers to {} (64-bit, unsigned integer max) cannot be created; use 'latest' instead", u64::MAX)
            },
            MajorParseError { raw, err } => write!(f, "Could not parse major version number '{raw}': {err}"),
            MinorParseError { raw, err } => write!(f, "Could not parse minor version number '{raw}': {err}"),
            PatchParseError { raw, err } => write!(f, "Could not parse patch version number '{raw}': {err}"),

            TooManyColons { raw, got } => write!(f, "Given 'NAME[:VERSION]' pair '{raw}' has too many colons (got {got}, expected at most 1)"),
            IllegalVersion { raw, raw_version, err } => write!(f, "Could not parse version '{raw_version}' in '{raw}': {err}"),
        }
    }
}

impl Error for ParseError {}





/***** HELPER STRUCTS *****/
/// Implements a Visitor for the Version.
struct VersionVisitor;

impl Visitor<'_> for VersionVisitor {
    type Value = Version;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> FResult { formatter.write_str("a semanting version") }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Parse the value with the Version parser
        Version::from_str(value).map_err(|err| E::custom(format!("{err}")))
    }
}





/***** VERSION *****/
/// Implements the Version, which is used to keep track of package versions.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Version {
    /// The major version number. If all three are set to u64::MAX, is interpreted as an unresolved 'latest' version number.
    pub major: u64,
    /// The minor version number. If all three are set to u64::MAX, is interpreted as an unresolved 'latest' version number.
    pub minor: u64,
    /// The patch version number. If all three are set to u64::MAX, is interpreted as an unresolved 'latest' version number.
    pub patch: u64,
}

impl Version {
    /// Constructor for the Version.  
    /// Note that this function panics if you try to create a 'latest' function this way; use latest() instead.
    ///
    /// **Arguments**
    ///  * `major`: The major version number.
    ///  * `minor`: The minor version number.
    ///  * `patch`: The patch version number.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        // Create the version
        let result = Self { major, minor, patch };

        // If it's latest, panic; otherwise, return
        if result.is_latest() {
            panic!(
                "A version with all numbers set to 9,223,372,036,854,775,807 (64-bit, unsigned integer max) cannot be created; use 'latest' instead"
            );
        }
        result
    }

    /// Constructor for the Version that sets it to an (unresolved) 'latest' version.
    #[inline]
    pub const fn latest() -> Self { Self { major: u64::MAX, minor: u64::MAX, patch: u64::MAX } }

    /// Special factory method that creates a package name and a version from a `NAME[:VERSION]` pair.
    ///
    /// If the `VERSION` is omitted, returns `Version::latest()`.
    ///
    /// # Arguments
    /// - `package`: The package `NAME[:VERSION]` pair to parse.
    ///
    /// # Errors
    /// This function may error if parsing failed, somehow.
    pub fn from_package_pair(package: &str) -> Result<(String, Self), ParseError> {
        // Get the number of colons in the string
        let colons: usize = package.matches(':').count();

        // Switch on version present or not
        if colons == 0 {
            // Simply return the name with the latest version
            Ok((package.into(), Self::latest()))
        } else if colons == 1 {
            // Split on the colon
            let colon_pos = package.find(':').unwrap();
            let name: &str = &package[..colon_pos];
            let version: &str = &package[colon_pos + 1..];

            // Attempt to parse the Version
            let version: Self = match Self::from_str(version) {
                Ok(version) => version,
                Err(err) => {
                    return Err(ParseError::IllegalVersion { raw: package.into(), raw_version: version.into(), err: Box::new(err) });
                },
            };

            // Return them as a pair
            Ok((name.to_string(), version))
        } else {
            Err(ParseError::TooManyColons { raw: package.into(), got: colons })
        }
    }

    /// Resolves this version in case it's a 'latest' version.
    ///
    /// **Generic types**
    ///  * `I`: The type of the iterator passed to this function.
    ///
    /// **Arguments**
    ///  * `iter`: An iterator over resolved version numbers.
    ///
    /// **Returns**  
    /// Nothing on success (except that this version now is equal to the latest version in the bunch), or a VersionError otherwise.
    pub fn resolve_latest<I: IntoIterator<Item = Self>>(&mut self, iter: I) -> Result<(), ResolveError> {
        // Crash if we're already resolved
        if !self.is_latest() {
            return Err(ResolveError::AlreadyResolved { version: *self });
        }

        // Go through the iterator
        let mut last_version: Option<Version> = None;
        for version in iter {
            // If this one isn't resolved, error too
            if version.is_latest() {
                return Err(ResolveError::NotResolved);
            }

            // Then, check if we saw a version before
            if let Some(lversion) = &last_version {
                // Update if this version is newer
                if &version > lversion {
                    last_version = Some(version);
                }
            } else {
                // Simply set, as this is the first one
                last_version = Some(version);
            }
        }

        // If we found any, set it; otherwise, return failure
        if let Some(version) = last_version {
            *self = version;
            Ok(())
        } else {
            Err(ResolveError::NoVersions)
        }
    }

    /// Returns whether or not this Version represents a 'latest' version.
    #[inline]
    pub const fn is_latest(&self) -> bool { self.major == u64::MAX && self.minor == u64::MAX && self.patch == u64::MAX }
}

impl Default for Version {
    /// Default constructor for the Version, which initializes it to 0.0.0.
    #[inline]
    fn default() -> Self { Self::new(0, 0, 0) }
}

impl PartialEq for Version {
    #[inline]
    fn eq(&self, other: &Self) -> bool { self.major == other.major && self.minor == other.minor && self.patch == other.patch }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare the major number
        let order = self.major.cmp(&other.major);
        if order.is_ne() {
            return order;
        }

        // Compare the minor number
        let order = self.minor.cmp(&other.minor);
        if order.is_ne() {
            return order;
        }

        // Compare the patch
        self.patch.cmp(&other.patch)
    }
}

impl PartialOrd for Version {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl FromStr for Version {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // If the (lowercase) string is 'latest', use that
        if s.to_lowercase() == "latest" {
            return Ok(Self::latest());
        }

        // Otherwise, see if we can split the string into multiple slices
        // Compute the possible dot posses first
        let dot1 = s.find('.');
        let dot2 = match &dot1 {
            Some(pos1) => s[*pos1 + 1..].find('.').map(|pos2| *pos1 + 1 + pos2),
            None => None,
        };

        // Use those positions to populate the string parts for each version number
        let smajor: &str = match &dot1 {
            Some(pos1) => &s[..*pos1],
            None => s,
        };
        let sminor: &str = match dot1 {
            Some(pos1) => match &dot2 {
                Some(pos2) => &s[pos1 + 1..*pos2],
                None => &s[pos1 + 1..],
            },
            None => "",
        };
        let spatch: &str = match dot2 {
            Some(pos2) => &s[pos2 + 1..],
            None => "",
        };

        // If the version starts with a 'v', then skip that one (i.e., that's allowed)
        let smajor = if !smajor.is_empty() && smajor.starts_with('v') { &smajor[1..] } else { smajor };

        // Try to parse each part
        let major = match u64::from_str(smajor) {
            Ok(major) => major,
            Err(err) => {
                return Err(ParseError::MajorParseError { raw: smajor.to_string(), err });
            },
        };
        let minor = if !sminor.is_empty() {
            match u64::from_str(sminor) {
                Ok(minor) => minor,
                Err(err) => {
                    return Err(ParseError::MinorParseError { raw: sminor.to_string(), err });
                },
            }
        } else {
            // Otherwise, use the standard minor value
            0
        };
        let patch = if !spatch.is_empty() {
            match u64::from_str(spatch) {
                Ok(patch) => patch,
                Err(err) => {
                    return Err(ParseError::PatchParseError { raw: spatch.to_string(), err });
                },
            }
        } else {
            // Otherwise, use the standard patch value
            0
        };

        // Put them together in a Version
        let result = Self { major, minor, patch };

        // If this version is latest, then error
        if result.is_latest() {
            return Err(ParseError::AccidentalLatest);
        }
        Ok(result)
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        if self.is_latest() { write!(f, "latest") } else { write!(f, "{}.{}.{}", self.major, self.minor, self.patch) }
    }
}

impl AsRef<Version> for Version {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&Version> for Version {
    #[inline]
    fn from(value: &Version) -> Self { *value }
}
impl From<&mut Version> for Version {
    #[inline]
    fn from(value: &mut Version) -> Self { *value }
}



impl PartialEq<semver::Version> for Version {
    #[inline]
    fn eq(&self, other: &semver::Version) -> bool {
        !self.is_latest() && self.major == other.major && self.minor == other.minor && self.patch == other.patch
    }
}

impl PartialOrd<semver::Version> for Version {
    #[inline]
    fn partial_cmp(&self, other: &semver::Version) -> Option<Ordering> {
        // Do not compare if latest
        if self.is_latest() {
            return None;
        }

        // Compare the major number
        let order = self.major.cmp(&other.major);
        if order.is_ne() {
            return Some(order);
        }

        // Compare the minor number
        let order = self.minor.cmp(&other.minor);
        if order.is_ne() {
            return Some(order);
        }

        // Compare the patch
        Some(self.patch.cmp(&other.patch))
    }
}

impl From<semver::Version> for Version {
    #[inline]
    fn from(version: semver::Version) -> Self { Self { major: version.major, minor: version.minor, patch: version.patch } }
}

impl From<&semver::Version> for Version {
    #[inline]
    fn from(version: &semver::Version) -> Self { Self { major: version.major, minor: version.minor, patch: version.patch } }
}



impl From<Version> for String {
    #[inline]
    fn from(value: Version) -> Self { format!("{value}") }
}

impl From<&Version> for String {
    #[inline]
    fn from(value: &Version) -> Self { format!("{value}") }
}



impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(VersionVisitor)
    }
}
