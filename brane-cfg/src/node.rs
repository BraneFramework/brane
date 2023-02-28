//  NODE V 2.rs
//    by Lut99
// 
//  Created:
//    28 Feb 2023, 10:01:27
//  Last edited:
//    28 Feb 2023, 18:56:31
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines an improved and more sensible version of the `node.yml`
//!   file.
// 

use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FResult};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use enum_debug::EnumDebug;
use serde::{Deserialize, Serialize};
use serde::ser::Serializer;
use serde::de::{self, Deserializer, Visitor};

use specifications::address::Address;

pub use crate::errors::NodeConfigError as Error;
use crate::errors::{NodeKindParseError, ProxyProtocolParseError};
use crate::spec::YamlConfig;


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
    
            raw => Err(NodeKindParseError::UnknownNodeKind{ raw: raw.into() }),
        }
    }
}





/***** LIBRARY *****/
/// Defines the toplevel `node.yml` layout.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    /// Custom hostname <-> IP mappings to satisfy rustls
    pub hostnames : HashMap<String, IpAddr>,
    /// The proxy to use for control messages, if any.
    pub proxy     : Option<ProxyConfig>,

    /// Any node-specific config
    pub node : NodeSpecificConfig,
}
impl<'de> YamlConfig<'de> for NodeConfig {}

/// Define configuration for control proxy traffic.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// The address of the proxy itself.
    pub address  : Address,
    /// The protocol that we use to communicate to the proxy.
    pub protocol : ProxyProtocol,
}



/// Defines the services from the various nodes.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeSpecificConfig {
    /// Defines the services for the control node
    #[serde(alias = "control")]
    Central(CentralConfig),
    /// Defines the services for the worker node
    Worker(WorkerConfig),
}
impl NodeSpecificConfig {
    /// Returns the kind of this config.
    #[inline]
    pub fn kind(&self) -> NodeKind {
        use NodeSpecificConfig::*;
        match self {
            Central(_) => NodeKind::Central,
            Worker(_)  => NodeKind::Worker,
        }
    }

    /// Returns if this NodeSpecificConfig is a `NodeSpecificConfig::Central`.
    /// 
    /// # Returns
    /// True if it is, or false otherwise.
    #[inline]
    pub fn is_central(&self) -> bool { matches!(self, Self::Central(_)) }
    /// Provides immutable access to the central-node specific configuration.
    /// 
    /// # Returns
    /// A reference to the internal CentralConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Central`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_central()` instead.
    #[inline]
    pub fn central(&self) -> &CentralConfig { if let Self::Central(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Central", self.variant()); } }
    /// Provides mutable access to the central-node specific configuration.
    /// 
    /// # Returns
    /// A mutable reference to the internal CentralConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Central`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_central_mut()` instead.
    #[inline]
    pub fn central_mut(&mut self) -> &mut CentralConfig { if let Self::Central(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Central", self.variant()); } }
    /// Returns the internal central-node specific configuration.
    /// 
    /// # Returns
    /// The internal CentralConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Central`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_into_central()` instead.
    #[inline]
    pub fn into_central(self) -> CentralConfig { if let Self::Central(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Central", self.variant()); } }
    /// Provides immutable access to the central-node specific configuration.
    /// 
    /// # Returns
    /// A reference to the internal CentralConfig struct if we were a `NodeSpecificConfig::Central`. Will return `None` otherwise.
    #[inline]
    pub fn try_central(&self) -> Option<&CentralConfig> { if let Self::Central(config) = self { Some(config) } else { None } }
    /// Provides mutable access to the central-node specific configuration.
    /// 
    /// # Returns
    /// A mutable reference to the internal CentralConfig struct if we were a `NodeSpecificConfig::Central`. Will return `None` otherwise.
    #[inline]
    pub fn try_central_mut(&mut self) -> Option<&mut CentralConfig> { if let Self::Central(config) = self { Some(config) } else { None } }
    /// Returns the internal central-node specific configuration.
    /// 
    /// # Returns
    /// The internal CentralConfig struct if we were a `NodeSpecificConfig::Central`. Will return `None` otherwise.
    #[inline]
    pub fn try_into_central(self) -> Option<CentralConfig> { if let Self::Central(config) = self { Some(config) } else { None } }

    /// Returns if this NodeSpecificConfig is a `NodeSpecificConfig::Worker`.
    /// 
    /// # Returns
    /// True if it is, or false otherwise.
    #[inline]
    pub fn is_worker(&self) -> bool { matches!(self, Self::Worker(_)) }
    /// Provides immutable access to the worker-node specific configuration.
    /// 
    /// # Returns
    /// A reference to the internal WorkerConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Worker`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_worker()` instead.
    #[inline]
    pub fn worker(&self) -> &WorkerConfig { if let Self::Worker(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Worker", self.variant()); } }
    /// Provides mutable access to the worker-node specific configuration.
    /// 
    /// # Returns
    /// A mutable reference to the internal WorkerConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Worker`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_worker_mut()` instead.
    #[inline]
    pub fn worker_mut(&mut self) -> &mut WorkerConfig { if let Self::Worker(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Worker", self.variant()); } }
    /// Returns the internal worker-node specific configuration.
    /// 
    /// # Returns
    /// The internal WorkerConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Worker`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_into_worker()` instead.
    #[inline]
    pub fn into_worker(self) -> WorkerConfig { if let Self::Worker(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Worker", self.variant()); } }
    /// Provides immutable access to the worker-node specific configuration.
    /// 
    /// # Returns
    /// A reference to the internal WorkerConfig struct if we were a `NodeSpecificConfig::Worker`. Will return `None` otherwise.
    #[inline]
    pub fn try_worker(&self) -> Option<&WorkerConfig> { if let Self::Worker(config) = self { Some(config) } else { None } }
    /// Provides mutable access to the worker-node specific configuration.
    /// 
    /// # Returns
    /// A mutable reference to the internal WorkerConfig struct if we were a `NodeSpecificConfig::Worker`. Will return `None` otherwise.
    #[inline]
    pub fn try_worker_mut(&mut self) -> Option<&mut WorkerConfig> { if let Self::Worker(config) = self { Some(config) } else { None } }
    /// Returns the internal worker-node specific configuration.
    /// 
    /// # Returns
    /// The internal WorkerConfig struct if we were a `NodeSpecificConfig::Worker`. Will return `None` otherwise.
    #[inline]
    pub fn try_into_worker(self) -> Option<WorkerConfig> { if let Self::Worker(config) = self { Some(config) } else { None } }
}



/// Defines the configuration for the central/control node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralConfig {
    /// Defines the paths for this node.
    pub paths    : CentralPaths,
    /// Defines the services for this node.
    pub services : CentralServices,
}

/// Defines the paths for the central/control node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralPaths {
    /// The path to the certificate directory.
    pub certs    : PathBuf,
    /// The path to the package directory.
    pub packages : PathBuf,

    /// The path to the infrastructure file.
    pub infra    : PathBuf,
}

/// Defines the services for the central/control node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralServices {
    // Brane services
    /// Describes the API (global registry) service.
    #[serde(alias = "registry")]
    pub api : PublicService,
    /// Describes the driver service.
    #[serde(alias = "driver")]
    pub drv : PublicService,
    /// Describes the planner service.
    #[serde(alias = "planner")]
    pub plr : KafkaService,
    /// Describes the proxy service.
    #[serde(alias = "proxy")]
    pub prx : PrivateService,

    // Auxillary services
    /// Describes the Scylla service.
    #[serde(alias = "scylla")]
    pub aux_scylla    : PrivateService,
    /// Describes the Kafka service.
    #[serde(alias = "kafka")]
    pub aux_kafka     : PrivateService,
    /// Describes the Kafka Zookeeper service.
    #[serde(alias = "zookeeper")]
    pub aux_zookeeper : PrivateService,
    // /// Describes the Xenon service.
    // #[serde(alias = "xenon")]
    // pub aux_xenon     : PrivateService,
}



/// Defines the configuration for the worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerConfig {
    /// Defines the name for this worker.
    #[serde(alias = "location_id")]
    pub name : String,

    /// Defines the paths for this node.
    pub paths    : WorkerPaths,
    /// Defines the services for this node.
    pub services : WorkerServices,
}

/// Defines the paths for the worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerPaths {
    /// The path to the certificate directory.
    pub certs    : PathBuf,
    /// The path to the package directory.
    pub packages : PathBuf,

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

/// Defines the services for the worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerServices {
    /// Defines the (local) registry service.
    #[serde(alias = "registry")]
    pub reg : PublicService,
    /// Defines the job (local driver) service.
    #[serde(alias = "driver")]
    pub job : PublicService,
    /// Defines the checker service.
    #[serde(alias = "checker")]
    pub chk : PublicService,
    /// Defines the proxy service.
    #[serde(alias = "proxy")]
    pub prx : PrivateService,
}



/// Defines what we need to know for a public service (i.e., a service that is reachable from outside the Docker network, i.e., the node).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicService {
    /// Defines the name of the Docker container.
    pub name    : String,
    /// Defines how the services on the same node can reach this service (which can be optimized due to the same-Docker-network property).
    pub address : Address,
    /// Defines the port (and hostname) to which the Docker container will bind itself. This is also the port on which the service will be externally reachable.
    pub bind    : SocketAddr,

    /// Defines how the services on _other_ nodes can reach this service.
    pub external_address : Address,
}

/// Defines what we need to know for a private service (i.e., a service that is only reachable from within the Docker network, i.e., the node).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateService {
    /// Defines the name of the Docker container.
    pub name    : String,
    /// Defines how the services on the same node can reach this service (which can be optimized due to the same-Docker-network property).
    pub address : Address,
    /// Defines the port (and hostname) to which the Docker container will bind itself.
    pub bind    : SocketAddr,
}

/// Defines a service that is only reachable over Kafka.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KafkaService {
    /// Defines the name of the Docker container.
    pub name : String,
    /// The topic on which we can send commands to the service.
    #[serde(alias = "command_topic")]
    pub cmd  : String,
    /// The topic on which we can receive results of the service.
    #[serde(alias = "result_topic")]
    pub res  : String,
}
