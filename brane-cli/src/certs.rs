//  CERTS.rs
//    by Lut99
// 
//  Created:
//    30 Jan 2023, 09:35:00
//  Last edited:
//    30 Jan 2023, 16:48:48
//  Auto updated?
//    Yes
// 
//  Description:
//!   Contains commands for managing certificates.
// 

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::{self, DirEntry, File, ReadDir};
use std::io::Write;
use std::path::{Path, PathBuf};

use console::{pad_str, style, Alignment};
use dialoguer::Confirm;
use enum_debug::EnumDebug;
use prettytable::Table;
use prettytable::format::FormatBuilder;
use rustls::{Certificate, PrivateKey};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{ParsedExtension, X509Extension};
use x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE;
use x509_parser::prelude::{FromDer as _};
use x509_parser::x509::X509Name;

use brane_cfg::certs::load_all;
use brane_shr::debug::PrettyListFormatter;

pub use crate::errors::CertsError as Error;
use crate::utils::{ensure_instances_dir, get_active_instance_link, get_instance_dir};


/***** HELPER FUNCTIONS *****/
/// Resolves the given maybe-instance-name to a path and a name.
/// 
/// # Returns
/// The name and the path of the resolved instance.
/// 
/// # Errors
/// This function may error if the name given was unknown, or no active instance existed if no name was given.
fn resolve_instance(name: Option<String>) -> Result<(String, PathBuf), Error> {
    if let Some(name) = name {
        match get_instance_dir(&name) {
            Ok(path) => match path.exists() {
                true  => Ok((name, path)),
                false => Err(Error::UnknownInstance{ name }),
            },
            Err(err) => Err(Error::InstanceDirError{ err }),
        }
    } else {
        match get_active_instance_link() {
            Ok(path) => match path.exists() {
                true => {
                    // Extract the _real_ path from behind this link
                    let real_path: PathBuf = match fs::read_link(&path) {
                        Ok(path) => path,
                        Err(err) => { return Err(Error::ActiveInstanceReadError{ path, err }); },
                    };
                    Ok((real_path.file_name().unwrap().to_string_lossy().into(), path))
                },
                false => Err(Error::NoActiveInstance),
            },
            Err(err) => Err(Error::ActiveInstancePathError { err }),
        }
    }
}

/// Reads a certificate and extracts the issued usage and, if present, the domain for which it is intended.
/// 
/// # Arguments
/// - `cert`: The raw Certificate to analyze.
/// - `path`: The path to this certificate. Only used for debugging purposes.
/// - `i`: The number of this certificate in that file.
/// 
/// # Returns
/// A tuple of the issued usage and the name of the domain for which it is intended (or `None` if the latter was missing).
/// 
/// # Errors
/// This function may error if we failed to parse the certificate or extract the required fields.
fn analyse_cert(cert: &Certificate, path: impl Into<PathBuf>, i: usize) -> Result<(CertificateKind, Option<String>), Error> {
    // Attempt to parse the certificate as a real x509 one
    let cert: X509Certificate = match X509Certificate::from_der(&cert.0) {
        Ok((_, cert)) => cert,
        Err(err)      => { return Err(Error::CertParseError { path: path.into(), i, err }); },
    };

    // Try to find the list of allowed usages
    let exts: HashMap<_, _> = match cert.extensions_map() {
        Ok(exts) => exts,
        Err(err) => { return Err(Error::CertExtensionsError{ path: path.into(), i, err }); },
    };
    let usage: &X509Extension = match exts.get(&OID_X509_EXT_KEY_USAGE) {
        Some(usage) => usage,
        None        => { return Err(Error::CertNoKeyUsageError{ path: path.into(), i }); },
    };

    // Attempt to find the CA one
    let kind: CertificateKind = match usage.parsed_extension() {
        ParsedExtension::KeyUsage(ext) => {
            let ds : bool = ext.digital_signature();
            let cs : bool = ext.crl_sign();
            if ds && !cs {
                CertificateKind::Client
            } else if !ds && cs {
                CertificateKind::Ca
            } else if ds && cs {
                CertificateKind::Both
            } else {
                return Err(Error::CertNoUsageError{ path: path.into(), i });
            }
        },

        // Error values
        _ => { unreachable!(); },
    };

    // Now attempt to extract the name from the issuer field
    let mut domain_name: Option<String> = None;
    let issuer: &X509Name = cert.issuer();
    for name in issuer.iter_common_name() {
        // Get it as a string
        let name: &str = match name.as_str() {
            Ok(name) => name,
            Err(err) => { return Err(Error::CertIssuerCaError{ path: path.into(), i, err }); },
        };

        // Extract the real name if any
        if &name[..7] == "CA for " {
            domain_name = Some(name[7..].into());
        }
    }

    // Done
    Ok((kind, domain_name))
}





/***** HELPER ENUMS *****/
/// Defines the possible certificate types we are interested in.
#[derive(Clone, Copy, Debug, EnumDebug, Eq, Hash, PartialEq)]
enum CertificateKind {
    /// It's both suited as a CA certificate _and_ a client certificate.
    Both,
    /// It's an authority certificate (used to verify the remote's identity)
    Ca,
    /// It's a client certificate (used to verify ourselves for the remote)
    Client,
}





/***** SERVICE FUNCTIONS *****/
/// Retrieves the path to the certificate directory of the active instance.
/// 
/// # Arguments
/// - `domain`: The name of the domain for which we want to get certificates.
/// 
/// # Returns
/// The path to the directory with the certificates of the active instance.
/// 
/// # Errors
/// This function may error if there was no active instance or we failed to get/read its directory.
pub fn get_active_certs_dir(domain: impl AsRef<Path>) -> Result<PathBuf, Error> {
    // Attempt to get the active link
    let link_path: PathBuf = match get_active_instance_link() {
        Ok(path) => path,
        Err(err) => { return Err(Error::ActiveInstancePathError{ err }); },
    };

    // Match valid links
    if !link_path.exists() { return Err(Error::NoActiveInstance); }
    if !link_path.is_symlink() { return Err(Error::ActiveInstanceNotASoftlinkError{ path: link_path }); }

    // OK return the thing
    Ok(link_path.join("certs").join(domain))
}





/***** SUBCOMMANDS *****/
/// Adds the given certificate(s) as the certificate(s) for the given domain.
/// 
/// # Arguments
/// - `instance_name`: The name of the instance for which to add them. If omitted, we should default to the active instance.
/// - `paths`: The paths of the certificate files to add.
/// - `domain_name`: The name of the domain to add. If it is not present, then the function is supposed to deduce it from the given certificates.
/// - `force`: If given, does not ask for permission to override an existing certificate but just does it$^{TM}$.
/// 
/// # Errors
/// This function errors if we failed to read any of the certificates, parse them, if not all the required certificates were given, if we failed to write them and create the directory structure _or_ if we are asked to deduce the domain name but failed.
pub fn add(instance_name: Option<String>, paths: Vec<PathBuf>, mut domain_name: Option<String>, force: bool) -> Result<(), Error> {
    info!("Adding certificate file(s) '{:?}'...", paths);

    // Resolve the instance first
    let (instance_name, instance_path): (String, PathBuf) = resolve_instance(instance_name)?;
    debug!("Adding for instance: '{}' ({})", instance_name, instance_path.display());

    // First attempt to load the given certificates using rustls
    let mut ca_cert     : Option<Certificate> = None;
    let mut client_cert : Option<Certificate> = None;
    let mut client_key  : Option<PrivateKey>  = None;
    for path in &paths {
        debug!("Reading certificate '{}'...", path.display());

        // Load any certificate and key we can find in this file
        let (certs, keys): (Vec<Certificate>, Vec<PrivateKey>) = match load_all(path) {
            Ok(res)  => res,
            Err(err) => { return Err(Error::PemLoadError{ path: path.clone(), err }); },
        };
        if certs.is_empty() && keys.is_empty() { warn!("Empty file '{}' (at least, no valid certificates or keys found)", path.display()); continue; }

        // We can add the keys by-default, since we know what they are used for
        for (i, key) in keys.into_iter().enumerate() {
            if client_key.is_some() { warn!("Multiple private keys specified, ignoring key {} in file '{}'", i, path.display()); continue; }
            client_key = Some(key);
        }

        // Sort the certificates based on their allowed usage
        for (i, c) in certs.into_iter().enumerate() {
            // Attempt to extract the properties we are interested in from the certificate
            let (kind, cert_domain): (CertificateKind, Option<String>) = match analyse_cert(&c, path, i) {
                Ok(res)  => res,
                Err(err) => { warn!("{} (skipping)", err); continue; }
            };
            debug!("Certificate {} in '{}' is a {} certificate for {:?}", i, path.display(), kind.variant(), cert_domain);

            // Do something with the domain name (i.e., store it or not
            if let Some(domain_name) = &domain_name {
                if let Some(cert_domain) = &cert_domain {
                    if cert_domain != domain_name { warn!("Certificate {} in '{}' appears to be issued for domain '{}', but you are adding it for domain '{}'", i, path.display(), cert_domain, domain_name); }
                } else {
                    warn!("Certificate {} in '{}' does not have a domain name specified", i, path.display());
                }
            } else {
                domain_name = cert_domain;
            }

            // Then assign it to the relevant file(s)
            match kind {
                CertificateKind::Both => {
                    // Try to add as CA first
                    match ca_cert.is_some() {
                        true  => { warn!("Multiple CA certificates specified, ignoring certificate {} in file '{}'", i, path.display()); continue; },
                        false => { ca_cert = Some(c.clone()); },
                    }
                    // Next try as client
                    match client_cert.is_some() {
                        true  => { warn!("Multiple client certificates specified, ignoring certificate {} in file '{}'", i, path.display()); continue; },
                        false => { client_cert = Some(c); },
                    }
                },
                CertificateKind::Ca => match ca_cert.is_some() {
                    true  => { warn!("Multiple CA certificates specified, ignoring certificate {} in file '{}'", i, path.display()); continue; },
                    false => { ca_cert = Some(c); },
                },
                CertificateKind::Client => match client_cert.is_some() {
                    true  => { warn!("Multiple client certificates specified, ignoring certificate {} in file '{}'", i, path.display()); continue; },
                    false => { client_cert = Some(c); },
                },
            }
        }
    }
    let ca_cert     : Certificate = match ca_cert     { Some(cert) => cert, None => { return Err(Error::NoCaCert); } };
    let client_cert : Certificate = match client_cert { Some(cert) => cert, None => { return Err(Error::NoClientCert); } };
    let client_key  : PrivateKey  = match client_key  { Some(key) => key,   None => { return Err(Error::NoClientKey); } };

    // Crash if the domain name is still unknown at this point
    let domain_name: String = match domain_name {
        Some(name) => name,
        None       => { return Err(Error::NoDomainName); },
    };

    // Otherwise, start adding directory structures
    let certs_path: PathBuf = instance_path.join("certs").join(&domain_name);
    if certs_path.exists() {
        if !certs_path.is_dir() { return Err(Error::CertsDirNotADir{ path: certs_path }); }
        if !force {
            // Assert we are allowed to override it
            debug!("Asking for confirmation...");
            println!("A certificate for domain {} in instance {} already exists. Overwrite?", style(&domain_name).cyan().bold(), style(&instance_name).cyan().bold());
            let consent: bool = match Confirm::new().interact() {
                Ok(consent) => consent,
                Err(err)    => { return Err(Error::ConfirmationError{ err }); }
            };
            if !consent {
                println!("Not overwriting, aborted.");
                return Ok(());
            }
            if let Err(err) = fs::remove_dir_all(&certs_path) { return Err(Error::CertsDirRemoveError{ path: certs_path, err }); }
        }
    }

    debug!("Creating directory '{}'...", certs_path.display());
    if let Err(err) = fs::create_dir_all(&certs_path) { return Err(Error::CertsDirCreateError{ path: certs_path, err }); }

    // Now write the CA certificates first
    {
        let ca_path: PathBuf = certs_path.join("ca.pem");
        debug!("Writing CA certificates to '{}'...", ca_path.display());

        // Open a handle
        let mut handle: File = match File::create(&ca_path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(Error::FileOpenError{ what: "ca", path: ca_path, err }); },
        };

        // Write the CA certificate with all the bells and whistles
        if let Err(err) = write!(handle, "-----BEGIN CERTIFICATE-----\n") { return Err(Error::FileWriteError{ what: "ca", path: ca_path, err }); }
        for chunk in base64::encode(ca_cert.0).as_bytes().chunks(64) {
            if let Err(err) = handle.write(chunk) { return Err(Error::FileWriteError{ what: "ca", path: ca_path, err }); }
            if let Err(err) = write!(handle, "\n") { return Err(Error::FileWriteError{ what: "ca", path: ca_path, err }); }
        }
        if let Err(err) = write!(handle, "-----END CERTIFICATE-----\n") { return Err(Error::FileWriteError{ what: "ca", path: ca_path, err }); }
    }

    // Next, write the client certificates and keys
    {
        let client_path: PathBuf = certs_path.join("client-id.pem");
        debug!("Writing client certificates & keys to '{}'...", client_path.display());

        // Open a handle
        let mut handle: File = match File::create(&client_path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(Error::FileOpenError{ what: "client ID", path: client_path, err }); },
        };

        // Write the client certificate with all the bells and whistles
        if let Err(err) = write!(handle, "-----BEGIN CERTIFICATE-----\n") { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }
        for chunk in base64::encode(client_cert.0).as_bytes().chunks(64) {
            if let Err(err) = handle.write(chunk) { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }
            if let Err(err) = write!(handle, "\n") { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }
        }
        if let Err(err) = write!(handle, "-----END CERTIFICATE-----\n") { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }

        // Write the client key with all the bells and whistles
        if let Err(err) = write!(handle, "-----BEGIN RSA PRIVATE KEY-----\n") { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }
        for chunk in base64::encode(client_key.0).as_bytes().chunks(64) {
            if let Err(err) = handle.write(chunk) { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }
            if let Err(err) = write!(handle, "\n") { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }
        }
        if let Err(err) = write!(handle, "-----END RSA PRIVATE KEY-----\n") { return Err(Error::FileWriteError{ what: "client ID", path: client_path, err }); }
    }

    // Done!
    println!("Successfully added certificates for domain {} in instance {}", style(domain_name).cyan().bold(), style(instance_name).cyan().bold());
    Ok(())
}

/// Removes the certificate(s) for the given domain.
/// 
/// # Arguments
/// - `domain_names`: The name(s) of the domain(s) for which to remove the certificates.
/// - `instance_name`: The name of the instance for which to remove them. If omitted, we should default to the active instance.
/// - `force`: If given, does not ask for confirmation but just does it$^{TM}$.
/// 
/// # Errors
/// This function fails if we failed to find any directories or failed to remove them.
pub fn remove(domain_names: Vec<String>, instance_name: Option<String>, force: bool) -> Result<(), Error> {
    info!("Removing certificate file(s) '{:?}'...", domain_names);

    // Do nothing if no names are given
    if domain_names.is_empty() {
        println!("No domains given for which to remove certificates.");
        return Ok(());
    }

    // Resolve the instance first
    let (instance_name, instance_path): (String, PathBuf) = resolve_instance(instance_name)?;
    debug!("Removing for instance: '{}' ({})", instance_name, instance_path.display());

    // Ask the user for permission, if needed
    if !force {
        debug!("Asking for confirmation...");
        println!("Are you sure you want to remove the certificates for domain{} {}?", if domain_names.len() > 1 { "s" } else { "" }, PrettyListFormatter::new(domain_names.iter().map(|n| style(n).bold().cyan()), "and"));
        let consent: bool = match Confirm::new().interact() {
            Ok(consent) => consent,
            Err(err)    => { return Err(Error::ConfirmationError{ err }); }
        };
        if !consent {
            println!("Aborted.");
            return Ok(());
        }
    }

    // We can continue, so let's remove them
    for name in domain_names {
        debug!("Removing certs for domain '{}' in instance '{}'...", name, instance_name);

        // Attempt to remove it if it exists
        let certs_dir: PathBuf = instance_path.join("certs").join(&name);
        if certs_dir.exists() {
            if let Err(err) = fs::remove_dir_all(&certs_dir) { warn!("Failed to remove directory '{}': {} (skipping)", certs_dir.display(), err); continue; }
        } else {
            println!("Domain {} does not have any certificates (skipping)", style(name).yellow().bold());
            continue;
        }

        // Alright done then
        println!("Removed certificates for domain {} in instance {}", style(name).cyan().bold(), style(&instance_name).cyan().bold());
    }

    // Done
    Ok(())
}



/// Lists the domains for which certificates are defined.
/// 
/// # Arguments
/// - `instance`: The name of the instance for which to list them. If omitted, we should default to the active instance.
/// - `all`: If given, shows all certificates across instances.
/// 
/// # Errors
/// This function fails if we failed to find any directories or failed to remove them.
pub fn list(instance_name: Option<String>, all: bool) -> Result<(), Error> {
    info!("Listing certificates...");

    // Prepare display table.
    let format = FormatBuilder::new()
        .column_separator('\0')
        .borders('\0')
        .padding(1, 1)
        .build();
    let mut table = Table::new();
    table.set_format(format);
    table.add_row(row!["INSTANCE", "DOMAIN", "CA", "CLIENT"]);

    // Find the instances to show
    let instances: Vec<(String, PathBuf)> = if all {
        // Get the instances dir
        debug!("Finding instances...");
        let instances_dir: PathBuf = match ensure_instances_dir(true) {
            Ok(dir)  => dir,
            Err(err) => { return Err(Error::InstancesDirError{ err }); },
        };

        // Iterate over it
        let entries: ReadDir = match fs::read_dir(&instances_dir) {
            Ok(entries) => entries,
            Err(err)    => { return Err(Error::DirReadError{ what: "instances", path: instances_dir, err }); },
        };
        let mut instances: Vec<(String, PathBuf)> = Vec::with_capacity(entries.size_hint().1.unwrap_or(entries.size_hint().0));
        for (i, entry) in entries.enumerate() {
            // Unwrap the entry
            let entry: DirEntry = match entry {
                Ok(entries) => entries,
                Err(err)    => { return Err(Error::DirEntryReadError{ what: "instances", path: instances_dir, entry: i, err }); },
            };

            // Do some checks on whether this is an instance or not
            let entry_path: PathBuf = entry.path();
            if !entry_path.is_dir() {
                debug!("Skipping entry '{}' (not a directory)", entry_path.display());
                continue;
            }
            if !entry_path.join("info.yml").is_file() {
                debug!("Skipping entry '{}' (no nested info.yml file)", entry_path.display());
                continue;
            }

            // Now add the entry
            instances.push((entry.file_name().to_string_lossy().into(), entry_path));
        }

        // Return those
        instances

    } else {
        // Resolve the instance first
        let (instance_name, instance_path): (String, PathBuf) = resolve_instance(instance_name)?;
        vec![ (instance_name, instance_path) ]
    };

    // Search each of those instances for domains
    debug!("Finding domains in instances {:?}...", instances.iter().map(|(n, p)| format!("'{}' ({})", n, p.display())).collect::<Vec<String>>());
    for (name, path) in instances {
        // Ensure the certs directory exists
        let certs_dir: PathBuf = path.join("certs");
        if !certs_dir.exists() {
            if let Err(err) = fs::create_dir_all(&certs_dir) { return Err(Error::CertsDirCreateError{ path: certs_dir, err }); }
        }

        // Iterate over the things in the 'certs' directory
        let entries: ReadDir = match fs::read_dir(&certs_dir) {
            Ok(entries) => entries,
            Err(err)    => { return Err(Error::DirReadError{ what: "certificates", path: certs_dir, err }); },
        };
        for (i, entry) in entries.enumerate() {
            // Unwrap the entry
            let entry: DirEntry = match entry {
                Ok(entries) => entries,
                Err(err)    => { return Err(Error::DirEntryReadError{ what: "certificates", path: certs_dir, entry: i, err }); },
            };

            // Do some checks on whether this is a certificate directory or not
            let entry_path: PathBuf = entry.path();
            if !entry_path.is_dir() {
                debug!("Skipping entry '{}' (not a directory)", entry_path.display());
                continue;
            }
            let ca_path: PathBuf = entry_path.join("ca.pem");
            if !ca_path.is_file() {
                debug!("Skipping entry '{}' (no nested ca.pem file)", entry_path.display());
                continue;
            }
            let client_path: PathBuf = entry_path.join("client-id.pem");
            if !client_path.is_file() {
                debug!("Skipping entry '{}' (no nested client-id.pem file)", entry_path.display());
                continue;
            }

            // Cast the things to string
            let domain_name : String   = entry.file_name().to_string_lossy().into();
            let ca_path     : Cow<str> = ca_path.to_string_lossy();
            let client_path : Cow<str> = client_path.to_string_lossy();

            // Add an entry in the table
            let instance_name : Cow<str> = pad_str(&name, 20, Alignment::Left, Some(".."));
            let domain_name   : Cow<str> = pad_str(&domain_name, 20, Alignment::Left, Some(".."));
            let ca_path       : Cow<str> = pad_str(&ca_path, 30, Alignment::Left, Some(".."));
            let client_path   : Cow<str> = pad_str(&client_path, 30, Alignment::Left, Some(".."));
            table.add_row(row![ instance_name, domain_name, ca_path, client_path ]);
        }
    }

    // Done
    table.printstd();
    Ok(())
}
