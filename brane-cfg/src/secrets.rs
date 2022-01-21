use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;
use url::Url;

#[derive(Clone, Debug)]
pub struct Secrets {
    store: Store,
}

impl Secrets {
    ///
    ///
    ///
    pub fn new<S: Into<String>>(store: S) -> Result<Self> {
        let store = Store::from(store)?;
        Ok(Secrets { store })
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
            // let infra_reader = BufReader::new(File::open(store_file)?);
            let infra_reader = BufReader::new(infra_handle.ok().unwrap());
            /*******/
            let _: HashMap<String, String> = serde_yaml::from_reader(infra_reader)
                .context("Secrets file is not valid.")
                .unwrap_or_default();

            Ok(())
        } else {
            unreachable!()
        }
    }

    ///
    ///
    ///
    pub fn get<S: Into<String>>(
        &self,
        secret_key: S,
    ) -> Result<String> {
        let secret_key = secret_key.into();

        if let Store::File(store_file) = &self.store {
            /* TIM */
            let secrets_handle = File::open(store_file);
            if let Err(reason) = secrets_handle {
                let code = reason.raw_os_error().unwrap_or(-1);
                eprintln!("Could not open secrets file '{}': {}.", store_file.to_string_lossy(), reason);
                std::process::exit(code);
            }
            // let secrets_reader = BufReader::new(File::open(store_file)?);
            let secrets_reader = BufReader::new(secrets_handle.ok().unwrap());
            /*******/
            let secrets_document: HashMap<String, String> = serde_yaml::from_reader(secrets_reader)
                .with_context(|| format!("Error while deserializing file: {:?}", store_file))?;

            let secret = secrets_document.get(&secret_key).map(String::clone);

            secret.ok_or_else(|| anyhow!("Secret '{}' not in secrets store.", secret_key))
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
