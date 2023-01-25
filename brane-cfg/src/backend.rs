//  BACKEND.rs
//    by Lut99
// 
//  Created:
//    18 Oct 2022, 13:50:11
//  Last edited:
//    23 Jan 2023, 11:52:42
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the credentials and a file that describes them for the job
//!   service to connect with its backend.
// 

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use specifications::package::Capability;

pub use crate::errors::CredsFileError as Error;


/***** AUXILLARY *****/
/// Defines the possible credentials we may encounter.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Credentials {
    // Job node acting as a node
    /// Defines that this job node connects to the "backend" by simply spinning up the local Docker daemon.
    Local {
        /// If given, uses a non-default path to connect to the Docker daemon.
        path    : Option<PathBuf>,
        /// If given, uses a non-default client version to connect with the Docker daemon.
        version : Option<(usize, usize)>,
    },

    // Job node acting as a scheduler
    /// Defines that this job node connects to one node by use of SSH. This effectively allows the centralized Brane manager to orchestrate over nodes instead of clusters.
    Ssh {
        /// The address of the machine to connect to. Should include any ports if needed.
        address : String,
        /// The path to the key file to connect with.
        key     : PathBuf,
    },

    // Job node acting as a cluster connector
    /// Defines that this job node connects to a backend Slurm cluster.
    Slurm {
        /* TBD */
    },
    /// Defines that this job node connects to a backend Kubernetes cluster.
    Kubernetes {
        /// The address or URL of the machine to connect to. Should include the port if so.
        address : String,
        /// The path to the Kubernetes config file to connect with.
        config  : PathBuf,
    },
}





/***** LIBRARY *****/
/// Defines a file that describes how a job service may connect to its backend.
/// 
/// Note that this struct is designed to act as a "handle"; i.e., keep it only around when using it but otherwise refer to it only by path.
#[derive(Debug, Deserialize, Serialize)]
pub struct BackendFile {
    /// The capabilities advertised by this domain.
    pub capabilities    : Option<HashSet<Capability>>,
    /// Can be specified to disable container hash checking.
    pub hash_containers : Option<bool>,
    /// The method of connecting
    pub method          : Credentials,
}

impl BackendFile {
    /// Creates a new BackendFile by loading it from the given path.
    /// 
    /// # Arguments
    /// - `path`: The path to load the BackendFile from.
    /// 
    /// # Returns
    /// A new BackendFile instance.
    /// 
    /// # Errors
    /// This function may error if the BackendFile was missing, unreadable or incorrectly formatted.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path: &Path = path.as_ref();

        // Open the file
        let handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err)   => { return Err(Error::FileOpenError { path: path.into(), err }); },
        };

        // Read it with serde
        match serde_yaml::from_reader(handle) {
            Ok(result) => Ok(result),
            Err(err)   => Err(Error::FileParseError { path: path.into(), err }),
        }
    }

    /// Writes the BackendFile to the given writer.
    /// 
    /// # Arguments
    /// - `writer`: The writer to write the BackendFile to.
    /// 
    /// # Returns
    /// Nothing, but does obviously populate the given writer with its own serialized contents.
    /// 
    /// # Errors
    /// This function errors if we failed to write or failed to serialize ourselves.
    pub fn to_writer(&self, writer: impl Write) -> Result<(), Error> {
        let mut writer = writer;

        // Serialize the config
        let config: String = match serde_yaml::to_string(self) {
            Ok(config) => config,
            Err(err)   => { return Err(Error::ConfigSerializeError{ err }); },
        };

        // Write it
        if let Err(err) = writer.write_all(config.as_bytes()) { return Err(Error::WriterWriteError{ err }); }

        // Done
        Ok(())
    }



    /// Returns whether the user wants hash containers to be hashed, generating a default value if they didn't specify it.
    /// 
    /// # Returns
    /// Whether container hash security should be enabled (true) or not (false).
    #[inline]
    pub fn hash_containers(&self) -> bool { self.hash_containers.unwrap_or(true) }
}
