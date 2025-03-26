//  INDEX.rs
//    by Lut99
// 
//  Created:
//    12 Jun 2023, 17:13:25
//  Last edited:
//    28 Jun 2023, 09:37:30
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the [`PackageIndex`] and [`DataIndex`] structs, which act as
//!   a registry for packages or datasets at some site (or local).
//!   
//!   _Note:_ If the new-syntax ever comes off the ground, we shouldn't need
//!   this one in specifications anymore, but instead we can move it to
//!   `brane-lnk` or wherever the linker then resides.
// 

use std::collections::HashMap;
use std::error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::fs::{self, DirEntry, ReadDir};
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};
use reqwest::StatusCode;
use reqwest::blocking as breqwest;
use tokio::fs::{self as tfs, DirEntry as TDirEntry, ReadDir as TReadDir};

use brane_shr::address::Address;
use brane_shr::info::{Info, Interface, JsonInterface};
use brane_shr::identifier::Identifier;
use brane_shr::version::Version;

use crate::data_new::backend::DataInfo;
use crate::packages::backend::PackageInfo;


/***** ERRORS *****/
/// Defines common errors that originate from any [`Index`].
#[derive(Debug)]
pub enum Error<E: Debug> {
    /// Failed to read the given directory.
    DirRead { path: PathBuf, err: std::io::Error },
    /// Failed to read an entry within a directory.
    DirEntryRead { path: PathBuf, entry: usize, err: std::io::Error },
    /// Failed to deserialize a particular info.
    InfoDeserialize { path: PathBuf, err: brane_shr::info::Error<E> },

    /// Failed to send GET-request to some address.
    GetRequest { address: Address, err: reqwest::Error },
    /// The GET-request succeeded from our side, but the server send a non-success status code.
    GetRequestFailure { address: Address, status: StatusCode, err: Option<String> },
    /// The server responded with non-UTF-8 (or we failed to read the body)
    GetRequestBody { address: Address, err: reqwest::Error },
    /// Failed to parse the server's contents as JSON.
    GetRequestJson { address: Address, err: serde_json::Error },
}
impl<E: Debug> Display for Error<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            DirRead { path, .. }             => write!(f, "Failed to read directory '{}'", path.display()),
            DirEntryRead { path, entry, .. } => write!(f, "Failed to read entry {entry} in directory '{}'", path.display()),
            InfoDeserialize { path, .. }     => write!(f, "Failed to deserialize info file '{}'", path.display()),

            GetRequest { address, .. }                 => write!(f, "Failed to send GET-request to '{address}'"),
            GetRequestFailure { address, status, err } => write!(f, "Remote '{address}' returned status code {} ({}) in response to GET-request{}", status.as_u16(), status.canonical_reason().unwrap_or("???"), if let Some(err) = err { format!("\n\nMessage:\n{err}") } else { String::new() }),
            GetRequestBody { address, .. }             => write!(f, "Failed to read body of response from '{address}' as UTF-8"),
            GetRequestJson { address, .. }             => write!(f, "Failed to read body of response from '{address}' as valid Index JSON"),
        }
    }
}
impl<E: 'static + error::Error> error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            DirRead { err, .. }         => Some(err),
            DirEntryRead { err, .. }    => Some(err),
            InfoDeserialize { err, .. } => Some(err),

            GetRequest { err, .. }     => Some(err),
            GetRequestFailure { .. }   => None,
            GetRequestBody { err, .. } => Some(err),
            GetRequestJson { err, .. } => Some(err),
        }
    }
}





/***** AUXILLARY *****/
/// Info that serves specifically for [`Index`]es.
pub trait IndexInfo {
    /// Returns the name of the object this info defines.
    /// 
    /// # Returns
    /// An immutable reference to the internal identifier.
    fn name(&self) -> &Identifier;

    /// Returns the version of the object this info defines.
    /// 
    /// # Returns
    /// A [`Version`] that can be used to disambiguate versions. Should not return [`Version::latest()`].
    fn version(&self) -> Version;
}

impl IndexInfo for PackageInfo {
    #[inline]
    fn name(&self) -> &Identifier { &self.metadata.name }
    #[inline]
    fn version(&self) -> Version { self.metadata.version }
}
impl IndexInfo for DataInfo {
    #[inline]
    fn name(&self) -> &Identifier { &self.metadata.name }
    #[inline]
    fn version(&self) -> Version { self.metadata.version }
}





/***** LIBRARY *****/
/// Defines an index/registry of a given Info.
#[derive(Clone, Debug)]
pub struct Index<I, N> {
    /// The map of indices that represents the registry.
    infos      : HashMap<String, HashMap<Version, I>>,
    /// Phantom interface data
    _interface : std::marker::PhantomData<N>,
}

impl<I: IndexInfo + Info<N>, N: Interface> Index<I, N> {
    /// Constructor for the Index that creates it from the information in the given directory.
    /// 
    /// It considers every nested directory to be a separate entry in the index.
    /// 
    /// Once collected, this function relies on [`From<HashMap<String, Self::Info>>`] to create the final `Self`. It likely wants to replace the found entry names with, say, the names of the info.
    /// 
    /// **Note**: Using this function _within_ a Tokio runtime will crash. Instead, see [`Index::local_async()`].
    /// 
    /// # Arguments
    /// - `directory`: The directory to load the entries for this index from.
    /// - `file`: The canonical filename of the to-be-sought-after file. Essentially, together with `directory`, this creates a path like `directory/<FOR EVERY DIR>/file`.
    /// 
    /// # Returns
    /// A new instance of Self.
    /// 
    /// # Warning
    /// This function may emit warnings (using [`log::warn`]) if there are duplicate entries for an identifier/version pair on the disk.
    /// 
    /// # Errors
    /// This function may error if something about the directory -or reading the directory- was wrong.
    pub fn local(directory: impl Send + Sync + AsRef<Path>, file: impl Send + Sync + AsRef<Path>) -> Result<Self, Error<N::Error>> {
        let directory: &Path = directory.as_ref();
        let file: &Path = file.as_ref();
        info!("Starting local construction of {} from '{}' (looking for '{}' files)", std::any::type_name::<Self>(), directory.display(), file.display());

        // Attempt to start reading the directory
        let entries: ReadDir = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(err)    => { return Err(Error::DirRead { path: directory.into(), err }); },
        };

        // Read every one of them
        let mut infos: HashMap<String, HashMap<Version, I>> = HashMap::new();
        for (i, entry) in entries.enumerate() {
            // Attempt to unwrap the entry
            let entry: DirEntry = match entry {
                Ok(entry) => entry,
                Err(err)  => { return Err(Error::DirEntryRead { path: directory.into(), entry: i, err }); },
            };

            // Check if the entry has a nested file
            let entry_path: PathBuf = entry.path();
            let info_path: PathBuf = entry_path.join(file);
            if !info_path.exists() {
                warn!("Skipping entry '{}' because it does not have a nested '{}' file", entry_path.display(), file.display());
                continue;
            }
            if !info_path.is_file() {
                warn!("Skipping entry '{}' because its nested file '{}' is not a file", entry_path.display(), info_path.display());
                continue;
            }
            debug!("Found info file '{}'", info_path.display());

            // Attempt to load it
            let info: I = match I::from_path(&info_path) {
                Ok(info) => info,
                Err(err) => { return Err(Error::InfoDeserialize { path: info_path, err }); },
            };
            let name: Identifier = info.name().clone();
            let version: Version = info.version();
            debug!("Noting '{name}':{version} in index");

            // Add the entry sorted by name, then version
            if let Some(versions) = infos.get_mut(name.as_str()) {
                if let Some(old) = versions.insert(version, info) {
                    // Should never occur, I guess, but essentially just to assert this is indeed the case
                    warn!("Duplicate info '{}':{} encountered", old.name(), old.version());
                }
            } else {
                infos.insert(name.into(), HashMap::from([ (version, info) ]));
            }
        }

        // Done!
        Ok(Self {
            infos,
            _interface : Default::default(),
        })
    }

    /// Constructor for the Index that creates it from the information in the given directory using [`tokio`]'s async library.
    /// 
    /// It considers every nested directory to be a separate entry in the index.
    /// 
    /// This function relies on [`From<HashMap<String, Self::Info>>`] to create the final `Self`. It likely wants to replace the found entry names with, say, the names of the info.
    /// 
    /// # Arguments
    /// - `directory`: The directory to load the entries for this index from.
    /// - `file`: The canonical filename of the to-be-sought-after file. Essentially, together with `directory`, this creates a path like `directory/<FOR EVERY DIR>/file`.
    /// 
    /// # Returns
    /// A new instance of Self.
    /// 
    /// # Warning
    /// This function may emit warnings (using [`log::warn`]) if there are duplicate entries for an identifier/version pair on the disk.
    /// 
    /// # Errors
    /// This function may error if something about the directory -or reading the directory- was wrong.
    pub async fn local_async(directory: impl Send + Sync + AsRef<Path>, file: impl Send + Sync + AsRef<Path>) -> Result<Self, Error<N::Error>> {
        let directory: &Path = directory.as_ref();
        let file: &Path = file.as_ref();
        info!("Starting local construction of {} from '{}' (looking for '{}' files)", std::any::type_name::<Self>(), directory.display(), file.display());

        // Attempt to start reading the directory
        let mut entries: TReadDir = match tfs::read_dir(directory).await {
            Ok(entries) => entries,
            Err(err)    => { return Err(Error::DirRead { path: directory.into(), err }); },
        };

        // Read every one of them
        debug!("Iterating through '{}'...", directory.display());
        let mut i: usize = 0;
        let mut infos: HashMap<String, HashMap<Version, I>> = HashMap::new();
        while let Some(entry) = entries.next_entry().await.transpose() {
            // Attempt to unwrap the entry
            let entry: TDirEntry = match entry {
                Ok(entry) => entry,
                Err(err)  => { return Err(Error::DirEntryRead { path: directory.into(), entry: i, err }); },
            };

            // Check if the entry has a nested file
            let entry_path: PathBuf = entry.path();
            let info_path: PathBuf = entry_path.join(file);
            if !info_path.exists() {
                warn!("Skipping entry '{}' because it does not have a nested '{}' file", entry_path.display(), file.display());
                i += 1;
                continue;
            }
            if !info_path.is_file() {
                warn!("Skipping entry '{}' because its nested file '{}' is not a file", entry_path.display(), info_path.display());
                i += 1;
                continue;
            }
            debug!("Found info file '{}'", info_path.display());

            // Attempt to load it
            let info: I = match I::from_path(&info_path) {
                Ok(info) => info,
                Err(err) => { return Err(Error::InfoDeserialize { path: info_path, err }); },
            };
            let name: Identifier = info.name().clone();
            let version: Version = info.version();
            debug!("Noting '{name}':{version} in index");

            // Add the entry sorted by name, then version
            if let Some(versions) = infos.get_mut(name.as_str()) {
                if let Some(old) = versions.insert(version, info) {
                    // Should never occur, I guess, but essentially just to assert this is indeed the case
                    warn!("Duplicate info '{}':{} encountered", old.name(), old.version());
                }
            } else {
                infos.insert(name.into(), HashMap::from([ (version, info) ]));
            }
            i += 1;
        }

        // Done!
        Ok(Self {
            infos,
            _interface : Default::default(),
        })
    }

    /// Constructor for the Index that creates it by sending a request to a particular remote.
    /// 
    /// It assumes that the host will send back a [`HashMap<String, Self::Info>`], which is then turned into a `Self` using [`From<HashMap<OsString, Self::Info>>`].
    /// 
    /// # Arguments
    /// - `address`: The [`Address`] of the remote to send a request to.
    /// 
    /// # Returns
    /// A new instance of Self.
    /// 
    /// # Errors
    /// This function may error if we failed to reach the remote, the remote returned an error or the remote returned a wrong format.
    pub fn remote(address: impl AsRef<Address>) -> Result<Self, Error<N::Error>> {
        let address: &Address = address.as_ref();
        info!("Starting remote construction of {} from '{}'", std::any::type_name::<Self>(), address);

        // Start a request to the given address
        let res: breqwest::Response = match breqwest::get(address.to_string()) {
            Ok(res)  => res,
            Err(err) => { return Err(Error::GetRequest { address: address.into(), err }); },
        };
        if !res.status().is_success() { return Err(Error::GetRequestFailure { address: address.into(), status: res.status(), err: res.text().ok() }); }

        // Attempt to get the result as a string
        let res: String = match res.text() {
            Ok(res)  => res,
            Err(err) => { return Err(Error::GetRequestBody { address: address.into(), err }); },
        };
        debug!("Remote returned:\n{}\n{res}\n{}\n\n", (0..80).map(|_| '-').collect::<String>(), (0..80).map(|_| '-').collect::<String>());

        // Attempt to parse the result as a map
        let infos: HashMap<Identifier, HashMap<Version, I>> = match serde_json::from_str(&res) {
            Ok(infos) => infos,
            Err(err)  => { return Err(Error::GetRequestJson { address: address.into(), err }); },
        };
        debug!("Got {} infos.", infos.len());

        // Done
        Ok(Self {
            infos      : infos.into_iter().map(|(i, v)| (i.into(), v)).collect(),
            _interface : Default::default(),
        })
    }

    /// Constructor for the Index that creates it by sending a request to a particular remote using [`tokio`]'s async library.
    /// 
    /// It assumes that the host will send back a [`HashMap<String, Self::Info>`], which is then turned into a `Self` using [`From<HashMap<OsString, Self::Info>>`].
    /// 
    /// # Arguments
    /// - `address`: The [`Address`] of the remote to send a request to.
    /// 
    /// # Returns
    /// A new instance of Self.
    /// 
    /// # Errors
    /// This function may error if we failed to reach the remote, the remote returned an error or the remote returned a wrong format.
    pub async fn remote_async(address: impl Send + Sync + AsRef<Address>) -> Result<Self, Error<N::Error>> {
        let address: &Address = address.as_ref();
        info!("Starting remote construction of {} from '{}'", std::any::type_name::<Self>(), address);

        // Start a request to the given address
        let res: reqwest::Response = match reqwest::get(address.to_string()).await {
            Ok(res)  => res,
            Err(err) => { return Err(Error::GetRequest { address: address.into(), err }); },
        };
        if !res.status().is_success() { return Err(Error::GetRequestFailure { address: address.into(), status: res.status(), err: res.text().await.ok() }); }

        // Attempt to get the result as a string
        let res: String = match res.text().await {
            Ok(res)  => res,
            Err(err) => { return Err(Error::GetRequestBody { address: address.into(), err }); },
        };
        debug!("Remote returned:\n{}\n{res}\n{}\n\n", (0..80).map(|_| '-').collect::<String>(), (0..80).map(|_| '-').collect::<String>());

        // Attempt to parse the result as a map
        let infos: HashMap<Identifier, HashMap<Version, I>> = match serde_json::from_str(&res) {
            Ok(entries) => entries,
            Err(err)    => { return Err(Error::GetRequestJson { address: address.into(), err }); },
        };
        debug!("Got {} infos.", infos.len());

        // Done
        Ok(Self {
            infos      : infos.into_iter().map(|(i, v)| (i.into(), v)).collect(),
            _interface : Default::default(),
        })
    }

    /// Constructor for the Index that creates it from a list of already parsed infos.
    /// 
    /// # Arguments
    /// - `infos`: The list of info structs to store in this new index.
    /// 
    /// # Returns
    /// A new instance of Self.
    /// 
    /// # Warning
    /// This function may emit warnings (using [`log::warn`]) if there are duplicate entries for an identifier/version pair in the given list.
    pub fn from_infos(infos: impl IntoIterator<Item = I>) -> Self {
        let iter = infos.into_iter();
        info!("Starting manual construction of {}", std::any::type_name::<Self>());

        // Iterate over them to insert them in a map
        debug!("Traversing given infos...");
        let mut infos: HashMap<String, HashMap<Version, I>> = HashMap::with_capacity(iter.size_hint().0);
        for info in iter {
            // We add the entry in two steps, one for every layer of map
            let name: &Identifier = info.name();
            if let Some(versions) = infos.get_mut(name.as_str()) {
                if let Some(old) = versions.insert(info.version(), info) {
                    warn!("Duplicate info '{}':{} encountered", old.name(), old.version());
                }
            } else {
                infos.insert(name.into(), HashMap::from([ (info.version(), info) ]));
            }
        }
        debug!("Found {} infos", infos.len());

        // Ok!
        Self {
            infos,
            _interface : Default::default(),
        }
    }



    /// Find the latest version of the given package in this index.
    /// 
    /// # Arguments
    /// - `identifier`: The string identifier of the info to look for.
    /// 
    /// # Returns
    /// The latest [`Version`] of the given package, or [`None`] if no such package exists.
    #[inline]
    pub fn find_latest(&self, identifier: impl AsRef<str>) -> Option<Version> {
        // Simply iterate to find it
        self.infos.get(identifier.as_ref()).map(|versions| {
            let mut latest: Option<Version> = None;
            for version in versions.keys() {
                if latest.is_none() || *version > latest.unwrap() { latest = Some(*version); }
            }
            latest
        }).flatten()
    }



    /// Provides access to the info with the given identifier and version number.
    /// 
    /// # Arguments
    /// - `identifier`: The string identifier of the info to look for.
    /// - `version`: The [`Version`]-number of the info.
    /// 
    /// # Returns
    /// A reference to the internal info, or [`None`] if no such info is found in this index.
    #[inline]
    pub fn get(&self, identifier: impl AsRef<str>, version: impl Into<Version>) -> Option<&I> {
        let identifier: &str = identifier.as_ref();
        let mut version: Version = version.into();

        // Resolve the latest first, if applicable
        if version.is_latest() {
            version = if let Some(version) = self.find_latest(identifier) { version } else { return None; };
        }

        // Then return the info according to the this pair
        self.infos.get(identifier).map(|versions| versions.get(version.as_ref())).flatten()
    }

    /// Provides mutable access to the info with the given identifier and version number.
    /// 
    /// # Arguments
    /// - `identifier`: The string identifier of the info to look for.
    /// - `version`: The [`Version`]-number of the info.
    /// 
    /// # Returns
    /// A mutable reference to the internal info, or [`None`] if no such info is found in this index.
    #[inline]
    pub fn get_mut(&mut self, identifier: impl AsRef<str>, version: impl Into<Version>) -> Option<&mut I> {
        let identifier: &str = identifier.as_ref();
        let mut version: Version = version.into();

        // Resolve the latest first, if applicable
        if version.is_latest() {
            version = if let Some(version) = self.find_latest(identifier) { version } else { return None; };
        }

        // Then return the info according to the this pair
        self.infos.get_mut(identifier).map(|versions| versions.get_mut(version.as_ref())).flatten()
    }

    /// Removes the info with the given identifier and version number.
    /// 
    /// # Arguments
    /// - `identifier`: The string identifier of the info to look for.
    /// - `version`: The [`Version`]-number of the info.
    /// 
    /// # Returns
    /// The info that was removed, or [`None`] if we did not know it.
    #[inline]
    pub fn remove(&mut self, identifier: impl AsRef<str>, version: impl Into<Version>) -> Option<I> {
        let identifier: &str = identifier.as_ref();
        let mut version: Version = version.into();

        // Resolve the latest first, if applicable
        if version.is_latest() {
            version = if let Some(version) = self.find_latest(identifier) { version } else { return None; };
        }

        // Then return the info according to the this pair
        self.infos.get_mut(identifier).map(|versions| versions.remove(version.as_ref())).flatten()
    }



    /// Returns an iterator over this Index by reference.
    /// 
    /// # Returns
    /// An [`Iter`](std::collections::hash_map::Iter) that performs the iteration over the internal map.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&String, &HashMap<Version, I>)> { self.into_iter() }

    /// Returns an iterator over this Index by mutable reference.
    /// 
    /// # Returns
    /// An [`IterMut`](std::collections::hash_map::IterMut) that performs the iteration over the internal map.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&String, &mut HashMap<Version, I>)> { self.into_iter() }
}

impl<I, N> IntoIterator for Index<I, N> {
    type IntoIter = std::collections::hash_map::IntoIter<String, HashMap<Version, I>>;
    type Item     = (String, HashMap<Version, I>);

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.infos.into_iter() }
}
impl<'i, I, N> IntoIterator for &'i Index<I, N> {
    type IntoIter = std::collections::hash_map::Iter<'i, String, HashMap<Version, I>>;
    type Item     = (&'i String, &'i HashMap<Version, I>);

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.infos.iter() }
}
impl<'i, I, N> IntoIterator for &'i mut Index<I, N> {
    type IntoIter = std::collections::hash_map::IterMut<'i, String, HashMap<Version, I>>;
    type Item     = (&'i String, &'i mut HashMap<Version, I>);

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.infos.iter_mut() }
}



/// Defines an [`Index`] over JSON packages.
pub type PackageIndex = Index<PackageInfo, JsonInterface>;
/// Defines an [`Index`] over JSON datasets.
pub type DataIndex = Index<DataInfo, JsonInterface>;
