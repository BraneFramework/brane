//  DATA.rs
//    by Lut99
// 
//  Created:
//    26 Aug 2022, 15:53:28
//  Last edited:
//    06 Jan 2023, 17:24:06
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines project-wide structs and interfaces for dealing with data
//!   registries and datasets.
// 

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};


/***** ERRORS *****/
/// Defines (parsing) errors that relate to the DataIndex struct.
#[derive(Debug)]
pub enum DataIndexError {
    /// Failed to open the given file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read/parse the given file.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to parse the given reader.
    ReaderParseError{ err: serde_yaml::Error },
    /// A given asset has appeared multiple times.
    DuplicateAsset{ location: String, name: String },
}

impl Display for DataIndexError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DataIndexError::*;
        match self {
            FileOpenError{ path, err }  => write!(f, "Failed to open data index file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse data index file '{}': {}", path.display(), err),

            ReaderParseError{ err }          => write!(f, "Failed to parse given reader as a data index file: {}", err),
            DuplicateAsset{ location, name } => write!(f, "Location '{}' defines an asset with identifier '{}' more than once", location, name),
        }
    }
}

impl Error for DataIndexError {}



/// Defines errors that relate to the RuntimeDataIndex struct.
#[derive(Debug)]
pub enum RuntimeDataIndexError {
    /// A dataset was already known under this name.
    DuplicateDataset{ name: String },
}

impl Display for RuntimeDataIndexError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use RuntimeDataIndexError::*;
        match self {
            DuplicateDataset{ name }  => write!(f, "A dataset under the name of '{}' was already defined", name),
        }
    }
}

impl Error for RuntimeDataIndexError {}



/// Defines (parsing) errors that relate to the DataInfo struct.
#[derive(Debug)]
pub enum DataInfoError {
    /// Failed to open the given file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read/parse the given file.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },
    /// Failed to create the given file.
    FileCreateError{ path: PathBuf, err: std::io::Error },
    /// Failed to write to the given file.
    FileWriteError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to parse the given reader.
    ReaderParseError{ err: serde_yaml::Error },
    /// Failed to write to the given writer.
    WriterWriteError{ err: serde_yaml::Error },
}

impl Display for DataInfoError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DataInfoError::*;
        match self {
            FileOpenError{ path, err }   => write!(f, "Failed to open data info file '{}': {}", path.display(), err),
            FileParseError{ path, err }  => write!(f, "Failed to parse data info file '{}': {}", path.display(), err),
            FileCreateError{ path, err } => write!(f, "Failed to create data info file '{}': {}", path.display(), err),
            FileWriteError{ path, err }  => write!(f, "Failed to write to data info file '{}': {}", path.display(), err),

            ReaderParseError{ err } => write!(f, "Failed to parse given reader as a data info file: {}", err),
            WriterWriteError{ err } => write!(f, "Failed to write the data info file to given writer: {}", err),
        }
    }
}

impl Error for DataInfoError {}

/// Defines (parsing) errors that relate to the AssetInfo struct.
#[derive(Debug)]
pub enum AssetInfoError {
    /// Failed to open the given file.
    FileOpenError{ path: PathBuf, err: std::io::Error },
    /// Failed to read/parse the given file.
    FileParseError{ path: PathBuf, err: serde_yaml::Error },

    /// Failed to parse the given reader.
    ReaderParseError{ err: serde_yaml::Error },
}

impl Display for AssetInfoError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AssetInfoError::*;
        match self {
            FileOpenError{ path, err }  => write!(f, "Failed to open asset info file '{}': {}", path.display(), err),
            FileParseError{ path, err } => write!(f, "Failed to parse asset info file '{}': {}", path.display(), err),

            ReaderParseError{ err } => write!(f, "Failed to parse given reader as a asset info file: {}", err),
        }
    }
}

impl Error for AssetInfoError {}





// /***** HELPER STRUCTS *****/
// /// Defines a more general DataInfo used in the DataIndex.
// #[derive(Clone, Debug, Deserialize, Serialize)]
// struct DataIndexInfo {
//     /// Maps all locations that advertise this info to the AccessKind in that locations.
//     locations : HashMap<String, AccessKind>,
// }

// impl DataIndexInfo {
//     /// Constructor for the DataIndexInfo that creates it from a location and a DataInfo.
//     /// 
//     /// # Generic arguments
//     /// - `S`: The String-like type of the `loc`ation.
//     /// 
//     /// # Arguments
//     /// - `loc`: The location that advertises being able to access the DataInfo.
//     /// - `info`: The DataInfo.
//     /// 
//     /// # Returns
//     /// A new DataIndexInfo with only this DataInfo.
//     #[inline]
//     fn from_info<S: Into<String>>(loc: S, info: DataInfo) -> Self {
//         Self {
//             locations : HashMap::from([ (loc.into(), info.kind) ]),
//         }
//     }



//     /// 'Casts' the DataIndexInfo to a DataInfo. All that it requires is the identifier of the DataInfo.
//     /// 
//     /// # Generic arguments
//     /// - `S1`: The String-like type of the `name`.
//     /// - `S2`: The &str-like type of the `loc`ation.
//     /// 
//     /// # Arguments
//     /// - `name`: The name of the dataset that we refer to here.
//     /// - `loc`: The location of which to grab the AccessKind.
//     /// 
//     /// # Returns
//     /// A new DataInfo instance that refers the same DataIndexInfo as this one.
//     #[inline]
//     fn as_info<S1: Into<String>, S2: AsRef<str>>(&self, name: S1, loc: S2) -> DataInfo {
//         DataInfo {
//             name : name.into(),
//             kind : self.locations.get(loc.as_ref()).unwrap_or_else(|| panic!("DataInfo '{}' is not advertised by location '{}'", name.into(), loc.as_ref())).clone(),
//         }
//     }
// }





/***** LIBRARY *****/
/// Placeholder for the Location's type.
pub type Location = String;



/// Defines whether a dataset is accessible locally or remotely (and thus needs to be transferred first).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AvailabilityKind {
    /// The file is locally available and ready for usage.
    Available{
        #[serde(rename = "h")]
        how: AccessKind
    },

    /// The file needs to be preprocessed first (probably transferred).
    Unavailable{
        #[serde(rename = "h")]
        how: PreprocessKind
    },
}
impl AvailabilityKind {
    /// Returns if this AvailabilityKind is an `AvailabilityKind::Available`.
    #[inline]
    pub fn is_available(&self) -> bool { matches!(self, Self::Available { .. }) }
    /// Returns if this AvailabilityKind is an `AvailabilityKind::Unvailable`.
    #[inline]
    pub fn is_unavailable(&self) -> bool { matches!(self, Self::Unavailable { .. }) }

    /// Returns the internal AccessKind is this AvailabilityKind is `AvailabilityKind::Available`.
    /// 
    /// # Panics
    /// This function panics if it is not `AvailabilityKind::Available`.
    #[inline]
    pub fn into_access(self) -> AccessKind { if let Self::Available { how: access } = self { access } else { panic!("Cannot call `AvailabilityKind::into_access()` on non-AvailabilityKind::Available"); } }
    /// Returns the internal PreprocessKind is this AvailabilityKind is `AvailabilityKind::Unavailable`.
    /// 
    /// # Panics
    /// This function panics if it is not `AvailabilityKind::Unavailable`.
    #[inline]
    pub fn into_preprocess(self) -> PreprocessKind { if let Self::Unavailable { how: preprocess } = self { preprocess } else { panic!("Cannot call `AvailabilityKind::into_preprocess()` on non-AvailabilityKind::Unavailable"); } }
}

/// Defines possible ways of accessing datasets.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AccessKind {
    /// Simply by file and thus path (namely, the given).
    File {
        /// The path to the file itself.
        path : PathBuf,
    },
}

/// Defines possible ways of downloading datasets to make them locally available.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PreprocessKind {
    /// By a `brane-reg` service, downloading as a tar file and then extracting.
    TransferRegistryTar {
        /// The location where the address is from.
        location : Location,
        /// The address + path that, once it receives a GET-request with credentials and such, downloads the referenced dataset.
        address  : String,
    },
}



/// Defines an index of all datasets known to the instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataIndex {
    /// Stores the list of all DataInfos per dataset identifier.
    index : HashMap<String, DataInfo>,
}

impl DataIndex {
    /// Constructor for the DataIndex that reads it from the given path.
    /// 
    /// # Generic arguments
    /// - `P`: The &Path-like type of the `path`.
    /// 
    /// # Arguments
    /// - `path`: The path from which we will read the DataIndex.
    /// 
    /// # Returns
    /// A new DataIndex instance with the datasets stored in the file.
    /// 
    /// # Errors
    /// This function errors if we could not read or parse the file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, DataIndexError> {
        let path: &Path = path.as_ref();

        // Open the file
        let handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(DataIndexError::FileOpenError { path: path.into(), err }); }
        };

        // Pass to the reader for the heavy lifting
        match Self::from_reader(handle) {
            Ok(res)                                      => Ok(res),
            Err(DataIndexError::ReaderParseError{ err }) => Err(DataIndexError::FileParseError { path: path.into(), err }),
            Err(err)                                     => Err(err),
        }
    }

    /// Constructor for the DataIndex that reads it from the given reader.
    /// 
    /// # Generic arguments
    /// - `R`: The Read-enabled type of the `reader`.
    /// 
    /// # Arguments
    /// - `reader`: The reader from which we will read the DataIndex.
    /// 
    /// # Returns
    /// A new DataIndex instance with the datasets stored in the reader.
    /// 
    /// # Errors
    /// This function errors if we could not read or parse the reader.
    #[inline]
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, DataIndexError> {
        match serde_yaml::from_reader(reader) {
            Ok(res)  => Ok(res),
            Err(err) => Err(DataIndexError::ReaderParseError { err }),
        }
    }

    /// Constructor for the DataIndex that creates it from a list of DataInfos.
    /// 
    /// # Arguments
    /// - `infos`: The DataInfos on which to base this index.
    /// 
    /// # Returns
    /// A new DataIndex instance with the datasets stored in each of the given infos.
    /// 
    /// # Errors
    /// This function errors if there were namespace conflicts and such.
    #[inline]
    pub fn from_infos(infos: Vec<DataInfo>) -> Result<Self, DataIndexError> {
        // Merge all datainfo's with the same name into one
        let mut index: HashMap<String, DataInfo> = HashMap::with_capacity(infos.len());
        for info in infos {
            // If it already exists, attempt to merge the locations
            if let Some(einfo) = index.get_mut(&info.name) {
                einfo.access.reserve(info.access.len());
                for (l, a) in info.access {
                    if einfo.access.contains_key(&l) { return Err(DataIndexError::DuplicateAsset { location: l, name: info.name }); }
                    einfo.access.insert(l, a);
                }
                break;
            }

            // Otherwise, add it as a new info
            index.insert(info.name.clone(), info);
        }

        // Alright, store them in a single location.
        Ok(Self {
            index,
        })
    }



    /// Returns a DataInfo that describes all locations that advertise the given dataset and how to access it per-location.
    /// 
    /// # Generic arguments
    /// - `S`: The String-like type of the `name`.
    /// 
    /// # Arguments
    /// - `name`: The dataset identifier to search for.
    /// 
    /// # Returns
    /// A DataInfo struct that represents this data asset.
    #[inline]
    pub fn get<S: AsRef<str>>(&self, name: S) -> Option<&DataInfo> {
        self.index.get(name.as_ref())
    }



    /// Returns an iterator over the internal DataIndices.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item=&DataInfo> { self.into_iter() }

    /// Returns a(n) (mutable) iterator over the internal DataIndices.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item=&mut DataInfo> { self.into_iter() }
}

impl IntoIterator for DataIndex {
    type Item     = DataInfo;
    type IntoIter = std::iter::Map<std::collections::hash_map::IntoIter<String, DataInfo>, fn ((String, DataInfo)) -> DataInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.index.into_iter().map(|(_, d)| d)
    }
}
impl<'a> IntoIterator for &'a DataIndex {
    type Item     = &'a DataInfo;
    type IntoIter = std::collections::hash_map::Values<'a, String, DataInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.index.values()
    }
}
impl<'a> IntoIterator for &'a mut DataIndex {
    type Item     = &'a mut DataInfo;
    type IntoIter = std::collections::hash_map::ValuesMut<'a, String, DataInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.index.values_mut()
    }
}



/// Defines a structure similar to the data index, except that it is used at runtime when locations have been resolved.
#[derive(Clone, Debug)]
pub struct RuntimeDataIndex {
    /// Maps locally available results and datasets (by identifier) to how to access them.
    local_data  : HashMap<String, AccessKind>,

    /// Maps externally available results and datasets (by identifier) to where to get them if needed.
    remote_data : HashMap<String, PreprocessKind>,
}

impl RuntimeDataIndex {
    /// Constructor for the RuntimeDataIndex that initializes it to empty. It is up to the planner to populate it.
    /// 
    /// # Returns
    /// A new RuntimeDataIndex instance.
    #[inline]
    pub fn new() -> Self {
        Self {
            local_data  : HashMap::new(),
            remote_data : HashMap::new(),
        }
    }



    /// Adds a new dataset as a _local_ dataset.
    /// 
    /// # Arguments
    /// - `name`: The name/identifier of the dataset to add.
    /// - `access`: The method of accessing this dataset. It should be available immediately by the tasks after this is passed.
    /// 
    /// # Errors
    /// This function may error if this dataset causes a naming conflict.
    pub fn add_local(&mut self, name: impl Into<String>, access: AccessKind) -> Result<(), RuntimeDataIndexError> {
        let name: String = name.into();
        if self.local_data.insert(name.clone(), access).is_none() {
            Ok(())
        } else {
            Err(RuntimeDataIndexError::DuplicateDataset{ name })
        }
    }

    /// Adds a new dataset as a _remote_ dataset.
    /// 
    /// # Arguments
    /// - `name`: The name/identifier of the dataset to add.
    /// - `transfer`: The method of transferring this dataset.
    /// 
    /// # Errors
    /// This function may error if this dataset causes a naming conflict.
    pub fn add_remote(&mut self, name: impl Into<String>, transfer: PreprocessKind) -> Result<(), RuntimeDataIndexError> {
        let name: String = name.into();
        if self.remote_data.insert(name.clone(), transfer).is_none() {
            Ok(())
        } else {
            Err(RuntimeDataIndexError::DuplicateDataset{ name })
        }
    }



    /// Returns whether the given dataset is locally accessible or not.
    /// 
    /// # Arguments
    /// - `name`: The name/identifier of the dataset to check.
    /// 
    /// # Returns
    /// `true` if is locally available, `false` if it is not, and `None` if we don't even know where to get it.
    pub fn is_local(&self, name: impl AsRef<str>) -> Option<bool> {
        let name: &str = name.as_ref();
        if self.local_data.contains_key(name) {
            Some(true)
        } else if self.remote_data.contains_key(name) {
            Some(false)
        } else {
            None
        }
    }

    /// Returns whether the given dataset is remotely accessible _only_ or not.
    /// 
    /// # Arguments
    /// - `name`: The name/identifier of the dataset to check.
    /// 
    /// # Returns
    /// `true` if is remotely available, `false` if it is locally available, and `None` if we don't even know where to get it.
    #[inline]
    pub fn is_remote(&self, name: impl AsRef<str>) -> Option<bool> {
        self.is_local(name).map(|b| !b)
    }

    /// Returns the method of accessing the given dataset if it is local.
    /// 
    /// # Arguments
    /// - `name`: The name/identifier of the dataset to query for.
    /// 
    /// # Returns
    /// A reference to this dataset's AccessKind that describes how to access it. If, however, the dataset isn't locally available, it returns `None`.
    #[inline]
    pub fn local(&self, name: impl AsRef<str>) -> Option<&AccessKind> {
        self.local_data.get(name.as_ref())
    }

    /// Returns the method of transferring the given dataset to the local machine if it is remotely available.
    /// 
    /// # Arguments
    /// - `name`: The name/identifier of the dataset to query for.
    /// 
    /// # Returns
    /// A reference to this dataset's TransferKind that describes how to transfer it. If, however, the dataset isn't remotely available, it returns `None`.
    #[inline]
    pub fn remote(&self, name: impl AsRef<str>) -> Option<&PreprocessKind> {
        self.remote_data.get(name.as_ref())
    }
}

impl Default for RuntimeDataIndex {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}



/// Defines a single DataInfo file that describes a dataset and how to access it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataInfo {
    /// Defines the name (=identifier) of the DataInfo. Must be unique across the instance.
    pub name        : String,
    /// The list of owners of this asset.
    pub owners      : Option<Vec<String>>,
    /// A (short) description of the asset.
    pub description : Option<String>,
    /// The created timestamp of the asset.
    pub created     : DateTime<Utc>,

    /// Defines how to access this DataInfo per location that advertises it.
    pub access : HashMap<Location, AccessKind>,
}

impl DataInfo {
    /// Constructor for the DataInfo that reads it from the given path.
    /// 
    /// # Generic arguments
    /// - `P`: The &Path-like type of the `path`.
    /// 
    /// # Arguments
    /// - `path`: The path from which we will read the DataInfo.
    /// 
    /// # Returns
    /// A new DataInfo instance representing the asset described in the given file.
    /// 
    /// # Errors
    /// This function errors if we could not read or parse the file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, DataInfoError> {
        let path: &Path = path.as_ref();

        // Open the file
        let handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(DataInfoError::FileOpenError { path: path.into(), err }); }
        };

        // Pass to the reader for the heavy lifting
        match Self::from_reader(handle) {
            Ok(res)                                     => Ok(res),
            Err(DataInfoError::ReaderParseError{ err }) => Err(DataInfoError::FileParseError { path: path.into(), err }),
            Err(err)                                    => Err(err),
        }
    }

    /// Constructor for the DataInfo that reads it from the given reader.
    /// 
    /// # Generic arguments
    /// - `R`: The Read-enabled type of the `reader`.
    /// 
    /// # Arguments
    /// - `reader`: The reader from which we will read the DataInfo.
    /// 
    /// # Returns
    /// A new DataInfo instance representing the asset described in the given reader.
    /// 
    /// # Errors
    /// This function errors if we could not read or parse the reader.
    #[inline]
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, DataInfoError> {
        match serde_yaml::from_reader(reader) {
            Ok(res)  => Ok(res),
            Err(err) => Err(DataInfoError::ReaderParseError { err }),
        }
    }



    /// Writes the DataInfo to the given path.
    /// 
    /// # Arguments
    /// - `path`: The path to write the DataInfo to.
    /// 
    /// # Returns
    /// Nothing, but does write a new file at the given path.
    /// 
    /// # Errors
    /// This function errors if we could not create or write to the new file.
    pub fn to_path(&self, path: impl AsRef<Path>) -> Result<(), DataInfoError> {
        // Open the file
        let handle: File = match File::create(path.as_ref()) {
            Ok(handle) => handle,
            Err(err)   => { return Err(DataInfoError::FileCreateError{ path: path.as_ref().into(), err }); },  
        };

        // Do the rest by virtue of `DataInfo::to_writer()`
        match self.to_writer(handle) {
            Ok(_)                                       => Ok(()),
            Err(DataInfoError::WriterWriteError{ err }) => Err(DataInfoError::FileWriteError{ path: path.as_ref().into(), err }),
            Err(err)                                    => Err(err),
        }
    }

    /// Writes the DataInfo to the given writer.
    /// 
    /// # Arguments
    /// - `writer` The Writer to write the DataInfo to.
    /// 
    /// # Returns
    /// Nothing, but does write the DataInfo to the given writer.
    /// 
    /// # Errors
    /// This function errors if we could not write to the given writer.
    #[inline]
    pub fn to_writer(&self, writer: impl Write) -> Result<(), DataInfoError> {
        match serde_yaml::to_writer(writer, self) {
            Ok(_)    => Ok(()),
            Err(err) => Err(DataInfoError::WriterWriteError{ err }),
        }
    }
}



/// Defines a single AssetInfo file that describes a dataset but for a user-facing user.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssetInfo {
    /// Defines the name (=identifier) of the AssetInfo. Must be unique across the instance.
    pub name        : String,
    /// The list of owners of this asset. This is not the domains, but rather the physical people who added it and such.
    pub owners      : Option<Vec<String>>,
    /// A (short) description of the asset.
    pub description : Option<String>,
    /// The created timestamp of the asset.
    #[serde(skip)]
    pub created     : DateTime<Utc>,

    /// Defines the way how to access & distribute this asset to containers.
    pub access : AccessKind,
}

impl AssetInfo {
    /// Constructor for the AssetInfo that reads it from the given path.
    /// 
    /// # Arguments
    /// - `path`: The path from which we will read the AssetInfo.
    /// 
    /// # Returns
    /// A new AssetInfo instance representing the asset described in the given file.
    /// 
    /// # Errors
    /// This function errors if we could not read or parse the file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, AssetInfoError> {
        let path: &Path = path.as_ref();

        // Open the file
        let handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(AssetInfoError::FileOpenError { path: path.into(), err }); }
        };

        // Pass to the reader for the heavy lifting
        match Self::from_reader(handle) {
            Ok(res)                                      => Ok(res),
            Err(AssetInfoError::ReaderParseError{ err }) => Err(AssetInfoError::FileParseError { path: path.into(), err }),
            Err(err)                                     => Err(err),
        }
    }

    /// Constructor for the AssetInfo that reads it from the given reader.
    /// 
    /// # Generic arguments
    /// - `R`: The read-capable type to read from.
    /// 
    /// # Arguments
    /// - `reader`: The reader from which we will read the AssetInfo.
    /// 
    /// # Returns
    /// A new AssetInfo instance representing the asset described in the given reader.
    /// 
    /// # Errors
    /// This function errors if we could not read or parse the reader.
    #[inline]
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, AssetInfoError> {
        match serde_yaml::from_reader::<R, Self>(reader) {
            Ok(res)  => Ok(res),
            Err(err) => Err(AssetInfoError::ReaderParseError { err }),
        }
    }



    /// Converts this AssetInfo into a DataInfo under the given domain.
    /// 
    /// # Arguments
    /// - `location`: The name of the location where this AssetInfo came from.
    /// 
    /// # Returns
    /// A new DataInfo instance that contains the same information as this AssetInfo but ordered differently.
    #[inline]
    pub fn into_data_info(self, location: impl Into<String>) -> DataInfo {
        DataInfo {
            name        : self.name,
            owners      : self.owners,
            description : self.description,
            created     : self.created,

            access : HashMap::from([ (location.into(), self.access) ]),
        }
    }
}

impl From<AssetInfo> for DataInfo {
    #[inline]
    fn from(value: AssetInfo) -> Self {
        Self {
            name        : value.name,
            owners      : value.owners,
            description : value.description,
            created     : value.created,

            access : HashMap::from([ ("localhost".into(), value.access) ]),
        }
    }
}
