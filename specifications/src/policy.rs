//  POLICY.rs
//    by Lut99
//
//  Created:
//    05 Jan 2024, 11:36:00
//  Last edited:
//    09 Jan 2024, 14:45:34
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements some cross-service specification for how to deal with
//!   policy secrets.
//

use std::error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64ct::Encoding as _;
use jsonwebtoken::jwk::{self, Jwk, JwkSet, KeyAlgorithm, OctetKeyParameters};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};


/***** ERRORS *****/
/// Defines errors originating from this module.
#[derive(Debug)]
pub enum Error {
    /// Failed to open a new file.
    SecretOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to deserialize & read an input file.
    SecretDeserializeError { path: PathBuf, err: serde_json::Error },
    /// A particular combination of policy secret settings was not supported.
    UnsupportedKeyAlgorithm { key_alg: KeyAlgorithm },
    /// A given secret did not have any keys.
    EmptySecret { path: PathBuf },
    /// A given secret had too many keys.
    TooManySecrets { path: PathBuf, got: usize },
    /// Failed to parse the given JWK octet key as valid Base64
    Base64Decode { raw: String, err: base64ct::Error },
    /// Unsupported key type encountered
    UnsupportedKeyType { ty: &'static str },
    /// Failed to encode the final JWT
    JwtEncode { alg: Algorithm, err: jsonwebtoken::errors::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            SecretOpenError { path, .. } => write!(f, "Failed to open policy secret file '{}'", path.display()),
            SecretDeserializeError { path, .. } => write!(f, "Failed to read JSON from policy secret file '{}'", path.display()),
            UnsupportedKeyAlgorithm { key_alg } => {
                write!(f, "Policy key algorithm {key_alg} is unsupported")
            },
            EmptySecret { path } => write!(f, "Policy secret '{}' does not contain any keys", path.display()),
            TooManySecrets { path, got } => write!(f, "Policy secret '{}' has too many keys: expected 1, got {}", path.display(), got),
            Base64Decode { raw, .. } => write!(f, "Failed to parse '{raw}' as a valid URL-safe base64"),
            UnsupportedKeyType { ty } => write!(f, "Unsupported policy secret type '{ty}'"),
            JwtEncode { alg, .. } => write!(f, "Failed to create JWT using {alg:?}"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            SecretOpenError { err, .. } => Some(err),
            SecretDeserializeError { err, .. } => Some(err),
            UnsupportedKeyAlgorithm { .. } => None,
            EmptySecret { .. } => None,
            TooManySecrets { .. } => None,
            Base64Decode { err, .. } => Some(err),
            UnsupportedKeyType { .. } => None,
            JwtEncode { err, .. } => Some(err),
        }
    }
}





/***** LIBRARY FUNCTIONS *****/
/// Generates a new access token for the checker.
///
/// # Arguments
/// - `initiator`: The name of the person performing the request, to embed in the token.
/// - `system`: The name or identifier of the node or other entity through which the request is performed, to embed in the token.
/// - `exp`: The duration the token will be valid for.
/// - `secret_path`: The path to the `policy_secret.json` file to use to sign the token with.
///
/// # Returns
/// The generate JSON Web Token (JWT) as a [`String`].
///
/// # Errors
/// This function may error if we encountered any I/O errors.
pub fn generate_policy_token(
    initiator: impl AsRef<str>,
    system: impl AsRef<str>,
    exp: Duration,
    secret_path: impl AsRef<Path>,
) -> Result<String, Error> {
    let initiator: &str = initiator.as_ref();
    let system: &str = system.as_ref();
    let secret_path: &Path = secret_path.as_ref();
    info!("Generating new JWT access token from secret '{}'...", secret_path.display());

    // Read the secret
    debug!("Reading secret '{}'...", secret_path.display());
    let secret: JwkSet = match File::open(secret_path) {
        Ok(handle) => match serde_json::from_reader(handle) {
            Ok(secret) => secret,
            Err(err) => return Err(Error::SecretDeserializeError { path: secret_path.into(), err }),
        },
        Err(err) => return Err(Error::SecretOpenError { path: secret_path.into(), err }),
    };

    // Resolve the set to a single key
    let key: &Jwk = match secret.keys.len().cmp(&1) {
        std::cmp::Ordering::Less => {
            return Err(Error::EmptySecret { path: secret_path.into() });
        },
        std::cmp::Ordering::Equal => {
            debug!("Single key detected in secret '{}', trivial selection", secret_path.display());
            &secret.keys[0]
        },
        std::cmp::Ordering::Greater => {
            return Err(Error::TooManySecrets { path: secret_path.into(), got: secret.keys.len() });
        },
    };

    // Now extract the information from the key we want
    debug!("Extracting algorithm and key from JWK...");
    let (alg, ekey): (Algorithm, EncodingKey) = {
        // Get the algorithm
        let alg: Algorithm = match &key.common.key_algorithm {
            Some(alg) => match Algorithm::from_str(alg.to_string().as_str()) {
                Ok(alg) => alg,
                Err(_) => return Err(Error::UnsupportedKeyAlgorithm { key_alg: *alg }),
            },
            None => {
                warn!("Policy secret '{}' has no algorithm specified; defaulting to HS256", secret_path.display());
                Algorithm::HS256
            },
        };

        // Get the encoding key from the key
        let key: EncodingKey = match &key.algorithm {
            jwk::AlgorithmParameters::OctetKey(OctetKeyParameters { value, .. }) => {
                // Decode the key as url-safe base64 manually
                let value: Vec<u8> = match base64ct::Base64Url::decode_vec(value) {
                    Ok(raw) => raw,
                    Err(err) => return Err(Error::Base64Decode { raw: value.clone(), err }),
                };

                // Now turn into a secret
                EncodingKey::from_secret(&value)
            },

            // The rest is unsupported
            jwk::AlgorithmParameters::EllipticCurve(_) => return Err(Error::UnsupportedKeyType { ty: "EllipticCurve" }),
            jwk::AlgorithmParameters::OctetKeyPair(_) => return Err(Error::UnsupportedKeyType { ty: "OctetKeyPair" }),
            jwk::AlgorithmParameters::RSA(_) => return Err(Error::UnsupportedKeyType { ty: "RSA" }),
        };

        // Done
        (alg, key)
    };

    // Build a header
    let mut header: Header = Header::new(alg);
    header.kid.clone_from(&key.common.key_id);

    // Construct a token with that secret
    let exp: u64 = (SystemTime::now() + exp).duration_since(UNIX_EPOCH).unwrap().as_secs();
    let token: String = match jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "exp": exp,
            "username": initiator,
            "system": system,
        }),
        &ekey,
    ) {
        Ok(token) => token,
        Err(err) => return Err(Error::JwtEncode { alg, err }),
    };

    // OK
    Ok(token)
}





/***** LIBRARY *****/
/// Represents the response of a reasoner. This can be used to tell the client why it went wrong.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckerResponse {}
