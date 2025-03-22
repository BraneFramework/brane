//  CERTS.rs
//    by Lut99
//
//  Created:
//    02 Nov 2022, 11:47:55
//  Last edited:
//    27 Jan 2023, 16:30:32
//  Auto updated?
//    Yes
//
//  Description:
//!   File that contains some useful functions for loading certificates
//!   and keys for `rustls`.
//

use std::path::Path;
use std::{fs, io};

use log::debug;
use rustls::{Certificate, PrivateKey, RootCertStore};
use rustls_pemfile::{Item, certs, rsa_private_keys};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

pub use crate::errors::CertsError as Error;


/***** AUXILLARY *****/
/// Retrieves the client name from the given Certificate provided by the, well, client.
///
/// # Arguments
/// - `certificate`: The Certificate to analyze.
///
/// # Returns
/// The name of the client, as provided by the Certificate's `CN` field.
///
/// # Errors
/// This function errors if we could not extract the name for some reason. You should consider the client unauthenticated, in that case.
pub fn extract_client_name(cert: Certificate) -> Result<String, Error> {
    // Attempt to parse the certificate as a real x509 one
    match X509Certificate::from_der(&cert.0) {
        Ok((_, cert)) => {
            // Get the part after 'CN = ' and before end-of-string or comma (since that's canonically the domain name)
            let subject: String = cert.subject.to_string();
            let name_loc: usize = match subject.find("CN=") {
                Some(name_loc) => name_loc + 3,
                None => {
                    return Err(Error::ClientCertNoCN { subject });
                },
            };
            let name_end: usize = subject[name_loc..].find(',').map(|c| name_loc + c).unwrap_or(subject.len());

            // Extract it as the name
            Ok(subject[name_loc..name_end].to_string())
        },
        Err(source) => Err(Error::ClientCertParseError { source }),
    }
}





/***** LIBRARY *****/
/// Loads a given .pem file by extracting all the certificates and keys from it.
///
/// # Arguments
/// - `file`: Path to the certificate/key (or both, or neither) file to load.
///
/// # Returns
/// A list of all certificates and keys found in the file. Either may be empty if we failed to find either in the given file.
///
/// # Errors
/// This function errors if we failed to access/read the file.
pub fn load_all(file: impl AsRef<Path>) -> Result<(Vec<Certificate>, Vec<PrivateKey>), Error> {
    let file: &Path = file.as_ref();

    // Open a (buffered) file handle
    let handle: fs::File = fs::File::open(file).map_err(|source| Error::FileOpenError { what: "PEM", path: file.into(), source })?;
    let mut reader: io::BufReader<fs::File> = io::BufReader::new(handle);

    // Iterate over the thing to read it
    let mut certs: Vec<Certificate> = vec![];
    let mut keys: Vec<PrivateKey> = vec![];
    while let Some(item) = rustls_pemfile::read_one(&mut reader).transpose() {
        // Unwrap the item
        let item: Item = item.map_err(|source| Error::FileReadError { what: "PEM", path: file.into(), source })?;

        // Match the item
        match item {
            Item::X509Certificate(cert) => certs.push(Certificate(cert)),

            Item::ECKey(key) | Item::PKCS8Key(key) | Item::RSAKey(key) => keys.push(PrivateKey(key)),

            _ => {
                return Err(Error::UnknownItemError { what: "PEM", path: file.into() });
            },
        }
    }

    // Done
    debug!("Loaded PEM file '{}' with {} certificate(s) and {} key(s)", file.display(), certs.len(), keys.len());
    Ok((certs, keys))
}

/// Loads a given certificate file.
///
/// # Arguments
/// - `certfile`: Path to the certificate file to load.
///
/// # Returns
/// A nlist of all certificates found in the file. May be empty if we failed to parse any.
///
/// # Errors
/// This function errors if we failed to read the file.
pub fn load_cert(certfile: impl AsRef<Path>) -> Result<Vec<Certificate>, Error> {
    let certfile: &Path = certfile.as_ref();

    // Open a (buffered) file handle
    let handle: fs::File = fs::File::open(certfile).map_err(|source| Error::FileOpenError { what: "certificate", path: certfile.into(), source })?;
    let mut reader: io::BufReader<fs::File> = io::BufReader::new(handle);

    // Read the certificates in this file
    let certs: Vec<Vec<u8>> = certs(&mut reader).map_err(|source| Error::CertFileParseError { path: certfile.into(), source })?;
    debug!("Found {} certificate(s) in '{}'", certs.len(), certfile.display());

    // Done, return
    Ok(certs.into_iter().map(Certificate).collect())
}

/// Loads a given key file.
///
/// # Arguments
/// - `keyfile`: Path to the key file to load.
///
/// # Returns
/// A list of all keys found in the file. May be empty if we failed to parse any.
///
/// # Errors
/// This function errors if we failed to read the file.
pub fn load_key(keyfile: impl AsRef<Path>) -> Result<Vec<PrivateKey>, Error> {
    let keyfile: &Path = keyfile.as_ref();

    // Open a (buffered) file handle
    let handle: fs::File = fs::File::open(keyfile).map_err(|source| Error::FileOpenError { what: "private key", path: keyfile.into(), source })?;
    let mut reader: io::BufReader<fs::File> = io::BufReader::new(handle);

    // Read the certificates in this file
    let keys: Vec<Vec<u8>> = rsa_private_keys(&mut reader).map_err(|source| Error::CertFileParseError { path: keyfile.into(), source })?;
    debug!("Found {} key(s) in '{}'", keys.len(), keyfile.display());

    // Done, return
    Ok(keys.into_iter().map(PrivateKey).collect())
}



/// Loads the an identity file (=certs + key) from the given single file.
///
/// # Arguments
/// - `file`: Path to the certificate/key file to load.
///
/// # Returns
/// A new pair of certificates and the key.
///
/// # Errors
/// This function errors if we failed to read the files.
pub fn load_identity(file: impl AsRef<Path>) -> Result<(Vec<Certificate>, PrivateKey), Error> {
    let file: &Path = file.as_ref();

    // Open the file
    let handle: fs::File = fs::File::open(file).map_err(|source| Error::FileOpenError { what: "identity", path: file.into(), source })?;
    let mut reader: io::BufReader<fs::File> = io::BufReader::new(handle);

    // Iterate over the thing to read it
    let mut certs: Vec<Certificate> = vec![];
    let mut keys: Vec<PrivateKey> = vec![];
    while let Some(item) = rustls_pemfile::read_one(&mut reader).transpose() {
        // Unwrap the item
        let item: Item = item.map_err(|source| Error::FileReadError { what: "identity", path: file.into(), source })?;

        // Match the item
        match item {
            Item::X509Certificate(cert) => certs.push(Certificate(cert)),

            Item::ECKey(key) | Item::PKCS8Key(key) | Item::RSAKey(key) => keys.push(PrivateKey(key)),

            _ => {
                return Err(Error::UnknownItemError { what: "identity", path: file.into() });
            },
        }
    }

    // We only continue with the first key
    let key: PrivateKey = if !keys.is_empty() {
        keys.swap_remove(0)
    } else {
        return Err(Error::EmptyKeyFile { path: file.into() });
    };

    // Done, return
    debug!("Loaded client identity file '{}' with {} certificate(s) and {} key(s)", file.display(), certs.len(), 1);
    Ok((certs, key))
}

/// Loads the server certificate / key pair from disk.
///
/// # Arguments
/// - `certfile`: Path to the certificate file to load.
/// - `keyfile`: Path to the keyfile to load.
///
/// # Returns
/// A new pair of certificates and the key.
///
/// # Errors
/// This function errors if we failed to read either of the files.
pub fn load_keypair(certfile: impl AsRef<Path>, keyfile: impl AsRef<Path>) -> Result<(Certificate, PrivateKey), Error> {
    let certfile: &Path = certfile.as_ref();
    let keyfile: &Path = keyfile.as_ref();

    // Read the certificate first, then the key
    let mut certs: Vec<Certificate> = load_cert(certfile)?;
    let mut keys: Vec<PrivateKey> = load_key(keyfile)?;

    // We only continue with the first certificate and key
    let cert: Certificate = if !certs.is_empty() {
        certs.swap_remove(0)
    } else {
        return Err(Error::EmptyCertFile { path: certfile.into() });
    };
    let key: PrivateKey = if !keys.is_empty() {
        keys.swap_remove(0)
    } else {
        return Err(Error::EmptyKeyFile { path: keyfile.into() });
    };

    // Done, return
    Ok((cert, key))
}

/// Loads the client certificates from disk as a CertStore.
///
/// # Arguments
/// - `storefile`: Path to the certificate file to load.
///
/// # Returns
/// A new RootCertStore with the certificates of the allowed client.
///
/// # Errors
/// This function errors if we failed to read either of the files.
pub fn load_certstore(storefile: impl AsRef<Path>) -> Result<RootCertStore, Error> {
    let storefile: &Path = storefile.as_ref();

    // Read the certificate first
    let handle: fs::File =
        fs::File::open(storefile).map_err(|source| Error::FileOpenError { what: "client certificate store", path: storefile.into(), source })?;
    let mut reader: io::BufReader<fs::File> = io::BufReader::new(handle);

    // Read the certificates in this file
    let certs: Vec<Vec<u8>> = certs(&mut reader).map_err(|source| Error::CertFileParseError { path: storefile.into(), source })?;
    debug!("Found {} certificate(s) in '{}'", certs.len(), storefile.display());

    // Read the certificates in the file to the store.
    let mut store: RootCertStore = RootCertStore::empty();
    let (added, ignored): (usize, usize) = store.add_parsable_certificates(&certs);
    debug!("Created client trust store from '{}' with {} certificates (ignored {})", storefile.display(), added, ignored);

    // Done, for now
    Ok(store)
}
