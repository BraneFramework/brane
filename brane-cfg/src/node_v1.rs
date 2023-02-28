//  NODE.rs
//    by Lut99
// 
//  Created:
//    16 Nov 2022, 16:54:43
//  Last edited:
//    28 Feb 2023, 10:32:59
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines a `node.json` file that describes the node - in particular,
//!   under which ports it is reachable, where its directories may be
//!   found, etc.
// 

use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use enum_debug::EnumDebug;
use serde::{Deserialize, Serialize};
use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;

use specifications::address::Address;

pub use crate::errors::NodeConfigError as Error;
use crate::errors::{NodeKindParseError, ProxyProtocolParseError};


/***** AUXILLARY *****/
/// Defines the supported proxy protocols (versions).
#[derive(Clone, Copy, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum ProxyProtocol {
    /// Version 5
    Socks5,
    /// Version 6
    Socks6,
}
impl Display for ProxyProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ProxyProtocol::*;
        match self {
            Socks5 => write!(f, "SOCKS5"),
            Socks6 => write!(f, "SOCKS6"),
        }
    }
}
impl FromStr for ProxyProtocol {
    type Err = ProxyProtocolParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "socks5" => Ok(Self::Socks5),
            "socks6" => Ok(Self::Socks6),
            _        => Err(ProxyProtocolParseError::UnknownProtocol { raw: s.into() }),
        }
    }
}
impl Serialize for ProxyProtocol {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for ProxyProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Visitor for the ProxyProtocol.
        struct ProxyProtocolVisitor;
        impl<'de> Visitor<'de> for ProxyProtocolVisitor {
            type Value = ProxyProtocol;

            fn expecting(&self, f: &mut Formatter<'_>) -> FResult {
                write!(f, "a proxy protocol identifier")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match ProxyProtocol::from_str(v) {
                    Ok(prot) => Ok(prot),
                    Err(err) => Err(E::custom(err)),
                }
            }
        }

        // Call the visitor
        deserializer.deserialize_str(ProxyProtocolVisitor)
    }
}



/// Defines the possible node types.
#[derive(Clone, Copy, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum NodeKind {
    /// The central node, which is the user's access point and does all the orchestration.
    Central,
    /// The worker node, which lives on a hospital and does all the heavy work.
    Worker,
}
impl Display for NodeKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use NodeKind::*;
        match self {
            Central => write!(f, "central"),
            Worker  => write!(f, "worker"),
        }
    }
}
impl FromStr for NodeKind {
    type Err = NodeKindParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "central" => Ok(Self::Central),
            "worker"  => Ok(Self::Worker),
    
            raw => Err(NodeKindParseError::UnknownNodeKind { raw: raw.into() }),
        }
    }
}





/***** LIBRARY *****/
/// Defines a `node.json` file that describes the environment layout of a node (what type it is, its location ID, where to find folders/services, etc).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    /// Defines any custom hostname -> IP mappings.
    pub hosts : HashMap<String, IpAddr>,
    /// Defines the proxy address to use for control messages, if any.
    pub proxy : Option<ProxyConfig>,

    /// Defines the names of the services that occur on every kind of node.
    pub names    : CommonNames,
    /// Defines the paths used by various services that occur on every kind of node.
    pub paths    : CommonPaths,
    /// Defines the ports where various services hosts themselves that occur on any kind of node.
    pub ports    : CommonPorts,
    /// Defines service addresses that occur on any kind of node.
    pub services : CommonServices,

    /// NodeKind-specific configuration options,
    pub node : NodeKindConfig,
}

impl NodeConfig {
    /// Constructor for the NodeConfig that reads it from the given path.
    /// 
    /// # Arguments
    /// - `path`: The path to read the NodeConfig from.
    /// 
    /// # Returns
    /// A new NodeConfig instance with the contents defined in the file.
    /// 
    /// # Errors
    /// This function errors if the given file cannot be read or has an invalid format.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path: &Path = path.as_ref();

        // Get the raw file to parse
        let mut raw: String = String::new();
        {
            // Open the file
            let mut handle: File = match File::open(path) {
                Ok(handle) => handle,
                Err(err)   => { return Err(Error::FileOpenError { path: path.into(), err }); },
            };

            // Read the file
            if let Err(err) = handle.read_to_string(&mut raw) { return Err(Error::FileReadError { path: path.into(), err }); }
        }

        // Parse with serde
        match serde_yaml::from_str(&raw) {
            Ok(config) => Ok(config),
            Err(err)   => Err(Error::FileParseError { path: path.into(), err }),
        }
    }

    /// Writes the NodeConfig to the given path.
    /// 
    /// # Arguments
    /// - `path`: The path to write the NodeConfig to.
    /// 
    /// # Returns
    /// Nothing, but does obviously create a new file with this NodeConfig's contents.
    /// 
    /// # Errors
    /// This function errors if the given file cannot be written or we failed to serialize ourselves.
    pub fn to_path(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path: &Path = path.as_ref();

        // Serialize the config
        let config: String = match serde_yaml::to_string(self) {
            Ok(config) => config,
            Err(err)   => { return Err(Error::ConfigSerializeError{ err }); },
        };

        // Write it
        {
            // Create the file
            let mut handle: File = match File::create(path) {
                Ok(handle) => handle,
                Err(err)   => { return Err(Error::FileCreateError { path: path.into(), err }); },
            };

            // Write the serialized config
            if let Err(err) = handle.write_all(config.as_bytes()) { return Err(Error::FileWriteError { path: path.into(), err }); }
        }

        // Done
        Ok(())
    }

    /// Writes the NodeConfig to the given writer.
    /// 
    /// # Arguments
    /// - `writer`: The path to write the NodeConfig to.
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
}

impl AsRef<NodeConfig> for NodeConfig {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&NodeConfig> for NodeConfig {
    #[inline]
    fn from(value: &NodeConfig) -> Self { value.clone() }
}
impl From<&mut NodeConfig> for NodeConfig {
    #[inline]
    fn from(value: &mut NodeConfig) -> Self { value.clone() }
}



/// Define configuration for control proxy traffic.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// The address of the proxy itself.
    pub address  : Address,
    /// The protocol that we use to communicate to the proxy.
    pub protocol : ProxyProtocol,
}

/// Define NodeKind-specific configuration.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NodeKindConfig {
    /// The central node, which is the user's access point and does all the orchestration.
    Central(CentralConfig),
    /// The worker node, which lives on a hospital and does all the heavy work.
    Worker(WorkerConfig),
}

impl NodeKindConfig {
    /// Returns the kind of this config.
    #[inline]
    pub fn kind(&self) -> NodeKind {
        use NodeKindConfig::*;
        match self {
            Central(_) => NodeKind::Central,
            Worker(_)  => NodeKind::Worker,
        }
    }

    /// Returns if this NodeConfigKind is a `NodeConfigKind::Central of sorts.
    #[inline]
    pub fn is_central(&self) -> bool { matches!(self, Self::Central(_)) }
    /// Returns this NodeConfigKind as if it was a `NodeConfigKind::Central`.
    /// 
    /// Will panic otherwise.
    #[inline]
    pub fn central(&self) -> &CentralConfig { if let Self::Central(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeConfigKind::Central", self.variant()); } }
    /// Returns this NodeConfigKind mutably as if it was a `NodeConfigKind::Central`.
    /// 
    /// Will panic otherwise.
    #[inline]
    pub fn central_mut(&mut self) -> &mut CentralConfig { if let Self::Central(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeConfigKind::Central", self.variant()); } }
    /// Consumes this NodeConfigKind into a `NodeConfigKind::Central`.
    /// 
    /// Will panic if it was not.
    #[inline]
    pub fn into_central(self) -> CentralConfig { if let Self::Central(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeConfigKind::Central", self.variant()); } }

    /// Returns if this NodeConfigKind is a `NodeConfigKind::Worker of sorts.
    #[inline]
    pub fn is_worker(&self) -> bool { matches!(self, Self::Worker(_)) }
    /// Returns this NodeConfigKind as if it was a `NodeConfigKind::Worker`.
    /// 
    /// Will panic otherwise.
    #[inline]
    pub fn worker(&self) -> &WorkerConfig { if let Self::Worker(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeConfigKind::Worker", self.variant()); } }
    /// Returns this NodeConfigKind mutably as if it was a `NodeConfigKind::Worker`.
    /// 
    /// Will panic otherwise.
    #[inline]
    pub fn worker_mut(&mut self) -> &mut WorkerConfig { if let Self::Worker(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeConfigKind::Worker", self.variant()); } }
    /// Consumes this NodeConfigKind into a `NodeConfigKind::Worker`.
    /// 
    /// Will panic if it was not.
    #[inline]
    pub fn into_worker(self) -> WorkerConfig { if let Self::Worker(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeConfigKind::Worker", self.variant()); } }
}

impl AsRef<NodeKindConfig> for NodeKindConfig {
   #[inline]
   fn as_ref(&self) -> &Self { self }
}
impl From<&NodeKindConfig> for NodeKindConfig {
   #[inline]
   fn from(value: &NodeKindConfig) -> Self { value.clone() }
}
impl From<&mut NodeKindConfig> for NodeKindConfig {
   #[inline]
   fn from(value: &mut NodeKindConfig) -> Self { value.clone() }
}



/// Defines common services names used on every kind of node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommonNames {
    /// Defines the name of the proxy service.
    #[serde(alias = "proxy")]
    pub prx : String,
}

/// Defines common paths used on every kind of node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommonPaths {
    /// The path of the certificate directory.
    pub certs   : PathBuf,
    /// The path of the package directory.
    pub packages : PathBuf,
}

/// Defines common hosted services that are available on every kind of node.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct CommonPorts {
    /// Defines where the proxy service hosts itself.
    #[serde(alias = "proxy")]
    pub prx : SocketAddr,
}

/// Defines common services that are available on every kind of node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommonServices {
    /// Defines where the proxy service may be found.
    #[serde(alias = "proxy")]
    pub prx : Address,
}



/// Defines the properties that are specific to a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralConfig {
    /// Defines the names of services on the central node.
    pub names    : CentralNames,
    /// Defines the paths configuration for the central node.
    pub paths    : CentralPaths,
    /// Defines where various externally available services bind themselves to.
    pub ports    : CentralPorts,
    /// Defines how to reach services.
    pub services : CentralServices,
    /// Defines Kafka topics shared across services.
    pub topics   : CentralKafkaTopics,
}

/// Defines service names used on a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralNames {
    /// Defines the name of the API service.
    #[serde(alias = "registry")]
    pub api : String,
    /// Defines the name of the driver service.
    #[serde(alias = "driver")]
    pub drv : String,
    /// Defines the name of the planner service.
    #[serde(alias = "planner")]
    pub plr : String,
}

/// Defines where to find various paths for a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralPaths {
    /// The path of the infrastructure file.
    pub infra : PathBuf,
}

/// Defines various ports for external services on the central node.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct CentralPorts {
    /// The port of the API service
    #[serde(alias = "registry")]
    pub api : SocketAddr,
    /// The port of the driver service
    #[serde(alias = "driver")]
    pub drv : SocketAddr,
}

/// Defines where central node internal services are hosted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralServices {
    /// Defines where the Kafka broker(s) live(s).
    #[serde(alias = "kafka_brokers")]
    pub brokers : Vec<Address>,
    /// Defines where to find the Scylla database.
    #[serde(alias = "scylla_database")]
    pub scylla  : Address,

    /// Defines how to reach the API service.
    #[serde(alias = "registry")]
    pub api : Address,
}

/// Defines topics and such used on a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralKafkaTopics {
    /// The topic for the planner to receive new planning requests on.
    pub planner_command : String,
    /// The topic for the planner to send planning results on.
    pub planner_results : String,
}



/// Defines the properties that are specific to a worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerConfig {
    /// Defines the location ID of this location.
    #[serde(alias = "id")]
    pub location_id : String,

    /// Defines the names of services on the worker node.
    pub names    : WorkerNames,
    /// Defines the paths configuration for the worker node.
    pub paths    : WorkerPaths,
    /// Defines the ports for various _external_ services on this worker node.
    pub ports    : WorkerPorts,
    /// Defines where to find the various worker services.
    pub services : WorkerServices,
}

/// Defines service names used on a worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerNames {
    /// Defines the name of the local registr service.
    #[serde(alias = "registr")]
    pub reg : String,
    /// Defines the name of the local delegate service.
    #[serde(alias = "delegate")]
    pub job : String,
    /// Defines the name of the local checker service.
    #[serde(alias = "checker")]
    pub chk : String,
}

/// Defines where to find various paths for a worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerPaths {
    /// The path of the backend file (`backend.yml`).
    pub backend  : PathBuf,
    /// The path to the "policy" file (`policies.yml` - temporary)
    pub policies : PathBuf,

    /// The path of the dataset directory.
    pub data         : PathBuf,
    /// The path of the results directory.
    pub results      : PathBuf,
    /// The path to the temporary dataset directory.
    pub temp_data    : PathBuf,
    /// The path of the temporary results directory.
    pub temp_results : PathBuf,
}

/// Defines various ports for external services on the worker node.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct WorkerPorts {
    /// The port of the registry service.
    #[serde(alias = "registry")]
    pub reg : SocketAddr,
    /// The port of the job service.
    #[serde(alias = "delegate")]
    pub job : SocketAddr,
}

/// Defines where central node internal services are hosted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerServices {
    /// Defines where the registry service lives.
    #[serde(alias = "registr")]
    pub reg : Address,
    /// Defines where the checker service lives.
    #[serde(alias = "checker")]
    pub chk : Address,
}
