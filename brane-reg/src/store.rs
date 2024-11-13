//  STORE.rs
//    by Lut99
//
//  Created:
//    26 Sep 2022, 15:12:59
//  Last edited:
//    06 Nov 2022, 18:09:52
//  Auto updated?
//    Yes
//
//  Description:
//!   Represents a very simple JSON-based, local store. This is to
//!   interface with the file that system administrators defined.
//

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use log::{debug, warn};
use specifications::data::AssetInfo;
use tokio::fs as tfs;

pub use crate::errors::StoreError as Error;


/***** LIBRARY *****/
/// Defines a JSON file that the administrator writes that contains the hardcoded data files.
///
/// Note that this struct is not read from its file as-is. Instead, it is defined as a vector of AssetInfos (i.e., `Vec<AssetInfo>`).
///
/// For network serialization/deserialization, it is preferred to send the entire map in one go.
#[derive(Clone, Debug)]
pub struct Store {
    /// A list of locally defined AssetInfos.
    pub datasets: HashMap<String, AssetInfo>,
    /// A list of locally defined AssetInfos for the intermediate results.
    pub results:  HashMap<String, PathBuf>,
}

impl Store {
    /// Constructor for the Store that loads it from the given path.
    ///
    /// # Arguments
    /// - `path`: The Path(-like) that tells us where the file lives.
    ///
    /// # Returns
    /// A new Store instance that contains the datasets in this domain.
    ///
    /// # Errors
    /// This function may error if we could not open or read the given File, or parse it as Store-file YAML.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        // Open the file
        let handle: File = match File::open(path.as_ref()) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(Error::FileOpenError { path: path.as_ref().into(), err });
            },
        };

        // Pass the rest to the reader constructor, but do inject additional path error if it fails
        match Self::from_reader(handle) {
            Ok(res) => Ok(res),
            Err(Error::ReaderParseError { err }) => Err(Error::FileParseError { path: path.as_ref().into(), err }),
            Err(err) => Err(err),
        }
    }

    /// Constructor for the Store that loads it from the given reader.
    ///
    /// # Arguments
    /// - `reader`: The Read-capable type that interfaces us with the Store file.
    ///
    /// # Returns
    /// A new Store instance that contains the datasets in this domain.
    ///
    /// # Errors
    /// This function may error if we could not open or read the given File, or parse it as Store-file YAML.
    pub fn from_reader(reader: impl Read) -> Result<Self, Error> {
        // Get what we actually read
        let infos: Vec<AssetInfo> = match serde_yaml::from_reader(reader) {
            Ok(res) => res,
            Err(err) => {
                return Err(Error::ReaderParseError { err });
            },
        };

        // Put that in a map
        let mut res: HashMap<String, AssetInfo> = HashMap::with_capacity(infos.len());
        for i in infos {
            res.insert(i.name.clone(), i);
        }

        // Done, return us
        Ok(Self { datasets: res, results: HashMap::new() })
    }

    /// Construtctor for the Store that deduces its contents from the contents in the given directory.
    ///
    /// # Arguments
    /// - `data_path`: The path of the directory where all datasets are stored.
    /// - `results_path`: The path of the directory where all intermediate results are stored.
    ///
    /// # Returns
    /// A new Store instance that contains the datasets & results for this domain.
    ///
    /// # Errors
    /// This function errors if we failed to read the given directory, or any of the data directories were ill-formed.
    pub async fn from_dirs(data_path: impl AsRef<Path>, results_path: impl AsRef<Path>) -> Result<Self, Error> {
        let data_path: &Path = data_path.as_ref();
        let results_path: &Path = results_path.as_ref();

        // Attempt to read the directory of datasets
        let datasets: HashMap<String, AssetInfo> = {
            // Fetch the entries in this directory
            let mut entries: tfs::ReadDir = match tfs::read_dir(&data_path).await {
                Ok(entries) => entries,
                Err(err) => {
                    return Err(Error::DirReadError { path: data_path.into(), err });
                },
            };

            // Iterate through all entries
            let mut datasets: HashMap<String, AssetInfo> = HashMap::new();
            let mut i: usize = 0;
            #[allow(irrefutable_let_patterns)]
            while let entry = entries.next_entry().await {
                // Unwrap it
                let entry: tfs::DirEntry = match entry {
                    Ok(Some(entry)) => entry,
                    Ok(None) => {
                        break;
                    },
                    Err(err) => {
                        return Err(Error::DirReadEntryError { path: data_path.into(), i, err });
                    },
                };

                // Match on directory or not
                let entry_path: PathBuf = entry.path();
                if entry_path.is_dir() {
                    // Try to find the data.yml
                    let info_path: PathBuf = entry_path.join("data.yml");
                    if !info_path.exists() {
                        warn!("Directory '{}' is in the data folder, but does not have a `data.yml` file", entry_path.display());
                        continue;
                    }
                    if !info_path.is_file() {
                        warn!("Directory '{}' is in the data folder, but the nested `data.yml` file is not a file", entry_path.display());
                        continue;
                    }

                    // Load it
                    // FIXME: The store should not fail if a single dataset is not parsible
                    let info: AssetInfo = match AssetInfo::from_path(&info_path) {
                        Ok(info) => info,
                        Err(err) => {
                            return Err(Error::AssetInfoReadError { path: info_path, err });
                        },
                    };

                    // Insert it
                    debug!("Noting down local dataset '{}'", info.name);
                    datasets.insert(info.name.clone(), info);
                }

                // Continue
                i += 1;
            }

            // Done with the datasets
            datasets
        };

        // Now do the same for the results
        let results: HashMap<String, PathBuf> = {
            // Fetch the entries in this directory
            let mut entries: tfs::ReadDir = match tfs::read_dir(&results_path).await {
                Ok(entries) => entries,
                Err(err) => {
                    return Err(Error::DirReadError { path: results_path.into(), err });
                },
            };

            // Iterate through all entries
            let mut results: HashMap<String, PathBuf> = HashMap::new();
            let mut i: usize = 0;
            #[allow(irrefutable_let_patterns)]
            while let entry = entries.next_entry().await {
                // Unwrap it
                let entry: tfs::DirEntry = match entry {
                    Ok(Some(entry)) => entry,
                    Ok(None) => {
                        break;
                    },
                    Err(err) => {
                        return Err(Error::DirReadEntryError { path: results_path.into(), i, err });
                    },
                };

                // Match on directory or not
                let entry_path: PathBuf = entry.path();
                if entry_path.is_dir() {
                    // The name of the result is the name of the folder
                    let name: String = entry.file_name().to_string_lossy().to_string();
                    // The path path is simply the directory
                    let path: PathBuf = entry_path;

                    // Insert it
                    debug!("Noting down local intermediate result '{}'", name);
                    results.insert(name, path);
                }

                // Continue
                i += 1;
            }

            // Done with the datasets
            results
        };

        // Done, return ourselves
        Ok(Self { datasets, results })
    }

    /// Get the AssetInfo for the given dataset.
    ///
    /// # Arguments
    /// - `name`: The name of the dataset to get the AssetInfo for.
    ///
    /// # Returns
    /// The dataset if it exists, or else `None`.
    #[inline]
    pub fn get_data(&self, name: impl AsRef<str>) -> Option<&AssetInfo> { self.datasets.get(name.as_ref()) }

    /// Get the path for the given intermediate result.
    ///
    /// # Arguments
    /// - `name`: The name of the intermediate result to get the AssetInfo for.
    ///
    /// # Returns
    /// The path to the intermediate result if it exists, or else `None`.
    #[inline]
    pub fn get_result(&self, name: impl AsRef<str>) -> Option<&PathBuf> { self.results.get(name.as_ref()) }
}
