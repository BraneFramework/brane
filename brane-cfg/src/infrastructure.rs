use crate::Secrets;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::PathBuf;
use url::Url;

#[derive(Clone, Debug, Deserialize, Default)]
pub struct InfrastructureDocument {
    locations: HashMap<String, Location>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Location {
    Kube {
        address: String,
        callback_to: String,
        namespace: String,
        registry: String,
        credentials: LocationCredentials,
        proxy_address: Option<String>,
        mount_dfs: Option<String>,
    },
    Local {
        address: Option<String>,
        callback_to: String,
        network: String,
        registry: String,
        proxy_address: Option<String>,
        mount_dfs: Option<String>,
    },
    Vm {
        address: String,
        callback_to: String,
        runtime: String,
        registry: String,
        credentials: LocationCredentials,
        proxy_address: Option<String>,
        mount_dfs: Option<String>,
    },
    Slurm {
        address: String,
        callback_to: String,
        runtime: String,
        registry: String,
        credentials: LocationCredentials,
        proxy_address: Option<String>,
        mount_dfs: Option<String>,
    },
}

impl Location {
    pub fn get_address(&self) -> String {
        match self {
            Location::Kube { address, .. } | Location::Vm { address, .. } | Location::Slurm { address, .. } => {
                address.clone()
            }
            Location::Local { address, .. } => address.clone().unwrap_or_else(|| String::from("127.0.0.1")),
        }
    }

    pub fn get_registry(&self) -> String {
        match self {
            Location::Kube { registry, .. }
            | Location::Vm { registry, .. }
            | Location::Slurm { registry, .. }
            | Location::Local { registry, .. } => registry.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mechanism", rename_all = "kebab-case")]
pub enum LocationCredentials {
    Config {
        file: String,
    },
    SshCertificate {
        username: String,
        certificate: String,
        passphrase: Option<String>,
    },
    SshPassword {
        username: String,
        password: String,
    },
}

impl LocationCredentials {
    ///
    ///
    ///
    pub fn resolve_secrets(
        &self,
        secrets: &Secrets,
    ) -> Self {
        use LocationCredentials::*;

        let resolve = |value: &String| {
            // Try to resolve secret, but use the value as-is otherwise.
            if let Some(value) = value.strip_prefix("s$") {
                if let Ok(secret) = secrets.get(value) {
                    return secret;
                }
            }

            value.clone()
        };

        match self {
            Config { file } => {
                let file = resolve(file);

                Config { file }
            }
            SshCertificate {
                username,
                certificate,
                passphrase,
            } => {
                let username = resolve(username);
                let certificate = resolve(certificate);
                let passphrase = passphrase.clone().map(|p| resolve(&p));

                SshCertificate {
                    username,
                    certificate,
                    passphrase,
                }
            }
            SshPassword { username, password } => {
                let username = resolve(username);
                let password = resolve(password);

                SshPassword { username, password }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Infrastructure {
    store: Store,
}

impl Infrastructure {
    ///
    ///
    ///
    pub fn new<S: Into<String>>(store: S) -> Result<Self> {
        let store = Store::from(store)?;
        Ok(Infrastructure { store })
    }

    ///
    ///
    ///
    pub fn validate(&self) -> Result<()> {
        if let Store::File(store_file) = &self.store {
            /* TIM */
            let infra_handle = File::open(store_file);
            if let Err(reason) = infra_handle {
                let code = reason.raw_os_error().unwrap_or(-1);
                eprintln!("Could not open infrastructure file '{}': {}.", store_file.to_string_lossy(), reason);
                std::process::exit(code);
            }
            // let mut infra_reader = BufReader::new(File::open(store_file)?);
            let mut infra_reader = BufReader::new(infra_handle.ok().unwrap());
            /*******/
            let mut infra_file = String::new();
            infra_reader.read_to_string(&mut infra_file)?;

            ensure!(!infra_file.is_empty(), "Infrastrucutre file may not be empty.");

            let _: InfrastructureDocument =
                serde_yaml::from_str(&infra_file).context("Infrastructure file is not valid.")?;

            Ok(())
        } else {
            unreachable!()
        }
    }

    ///
    ///
    ///
    pub fn get_locations(&self) -> Result<Vec<String>> {
        if let Store::File(store_file) = &self.store {
            /* TIM */
            let infra_handle = File::open(store_file);
            if let Err(reason) = infra_handle {
                let code = reason.raw_os_error().unwrap_or(-1);
                eprintln!("Could not open infrastructure file '{}': {}.", store_file.to_string_lossy(), reason);
                std::process::exit(code);
            }
            // let infra_reader = BufReader::new(File::open(store_file)?);
            let infra_reader = BufReader::new(infra_handle.ok().unwrap());
            /*******/
            let infra_document: InfrastructureDocument = serde_yaml::from_reader(infra_reader)?;

            Ok(infra_document.locations.keys().map(|k| k.to_string()).collect())
        } else {
            unreachable!()
        }
    }

    ///
    ///
    ///
    pub fn get_location_metadata<S: Into<String>>(
        &self,
        location: S,
    ) -> Result<Location> {
        let location = location.into();

        if let Store::File(store_file) = &self.store {
            /* TIM */
            let infra_handle = File::open(store_file);
            if let Err(reason) = infra_handle {
                let code = reason.raw_os_error().unwrap_or(-1);
                eprintln!("Could not open infrastructure file '{}': {}.", store_file.to_string_lossy(), reason);
                std::process::exit(code);
            }
            // let infra_reader = BufReader::new(File::open(store_file)?);
            let infra_reader = BufReader::new(infra_handle.ok().unwrap());
            /*******/
            let infra_document: InfrastructureDocument = serde_yaml::from_reader(infra_reader)?;

            let metadata = infra_document.locations.get(&location).map(Location::clone);

            metadata.ok_or_else(|| anyhow!("Location '{}' not found in infrastructure metadata.", location))
        } else {
            unreachable!()
        }
    }
}

#[derive(Clone, Debug)]
enum Store {
    File(PathBuf),
    Database(Url),
}

impl Store {
    ///
    ///
    ///
    fn from<S: Into<String>>(store: S) -> Result<Self> {
        let store = store.into();

        if let Ok(url) = Url::parse(&store) {
            Ok(Store::Database(url))
        } else {
            let file_path = fs::canonicalize(&store)?;
            Ok(Store::File(file_path))
        }
    }
}
