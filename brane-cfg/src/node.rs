//  NODE V 2.rs
//    by Lut99
// 
//  Created:
//    28 Feb 2023, 10:01:27
//  Last edited:
//    09 Mar 2023, 16:19:06
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

use specifications::address::Address;

pub use crate::errors::NodeConfigError as Error;
use crate::errors::NodeKindParseError;
use crate::spec::YamlConfig;


/***** AUXILLARY *****/
/// Defines the possible node types.
#[derive(Clone, Copy, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum NodeKind {
    /// The central node, which is the user's access point and does all the orchestration.
    Central,
    /// The worker node, which lives on a hospital and does all the heavy work.
    Worker,
    /// The proxy node is essentially an external proxy for a central or worker node.
    Proxy,
}
impl Display for NodeKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use NodeKind::*;
        match self {
            Central => write!(f, "central"),
            Worker  => write!(f, "worker"),
            Proxy   => write!(f, "proxy"),
        }
    }
}
impl FromStr for NodeKind {
    type Err = NodeKindParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "central" => Ok(Self::Central),
            "worker"  => Ok(Self::Worker),
            "proxy"   => Ok(Self::Proxy),
    
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

    /// Any node-specific config
    pub node : NodeSpecificConfig,
}
impl<'de> YamlConfig<'de> for NodeConfig {}



/// Defines the services from the various nodes.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeSpecificConfig {
    /// Defines the services for the control node.
    #[serde(alias = "control")]
    Central(CentralConfig),
    /// Defines the services for the worker node.
    Worker(WorkerConfig),
    /// Defines the services for the proxy node.
    Proxy(ProxyConfig),
}
impl NodeSpecificConfig {
    /// Returns the kind of this config.
    #[inline]
    pub fn kind(&self) -> NodeKind {
        use NodeSpecificConfig::*;
        match self {
            Central(_) => NodeKind::Central,
            Worker(_)  => NodeKind::Worker,
            Proxy(_)   => NodeKind::Proxy,
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

    /// Returns if this NodeSpecificConfig is a `NodeSpecificConfig::Proxy`.
    /// 
    /// # Returns
    /// True if it is, or false otherwise.
    #[inline]
    pub fn is_proxy(&self) -> bool { matches!(self, Self::Proxy(_)) }
    /// Provides immutable access to the proxy-node specific configuration.
    /// 
    /// # Returns
    /// A reference to the internal ProxyConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Proxy`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_proxy()` instead.
    #[inline]
    pub fn proxy(&self) -> &ProxyConfig { if let Self::Proxy(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Proxy", self.variant()); } }
    /// Provides mutable access to the proxy-node specific configuration.
    /// 
    /// # Returns
    /// A mutable reference to the internal ProxyConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Proxy`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_proxy_mut()` instead.
    #[inline]
    pub fn proxy_mut(&mut self) -> &mut ProxyConfig { if let Self::Proxy(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Proxy", self.variant()); } }
    /// Returns the internal proxy-node specific configuration.
    /// 
    /// # Returns
    /// The internal ProxyConfig struct.
    /// 
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Proxy`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_into_proxy()` instead.
    #[inline]
    pub fn into_proxy(self) -> ProxyConfig { if let Self::Proxy(config) = self { config } else { panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Proxy", self.variant()); } }
    /// Provides immutable access to the proxy-node specific configuration.
    /// 
    /// # Returns
    /// A reference to the internal ProxyConfig struct if we were a `NodeSpecificConfig::Proxy`. Will return `None` otherwise.
    #[inline]
    pub fn try_proxy(&self) -> Option<&ProxyConfig> { if let Self::Proxy(config) = self { Some(config) } else { None } }
    /// Provides mutable access to the proxy-node specific configuration.
    /// 
    /// # Returns
    /// A mutable reference to the internal ProxyConfig struct if we were a `NodeSpecificConfig::Proxy`. Will return `None` otherwise.
    #[inline]
    pub fn try_proxy_mut(&mut self) -> Option<&mut ProxyConfig> { if let Self::Proxy(config) = self { Some(config) } else { None } }
    /// Returns the internal proxy-node specific configuration.
    /// 
    /// # Returns
    /// The internal ProxyConfig struct if we were a `NodeSpecificConfig::Proxy`. Will return `None` otherwise.
    #[inline]
    pub fn try_into_proxy(self) -> Option<ProxyConfig> { if let Self::Proxy(config) = self { Some(config) } else { None } }
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
    pub infra : PathBuf,
    /// The path to the proxy file, if applicable. Ignored if no service is present.
    pub proxy : Option<PathBuf>,
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
    /// The path to the proxy file, if applicable. Ignored if no service is present.
    pub proxy    : Option<PathBuf>,

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



/// Defines the configuration for the proxy node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Defines the paths for this node.
    pub paths    : ProxyPaths,
    /// Defines the services for this node.
    pub services : ProxyServices,
}

/// Defines the paths for the proxy node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyPaths {
    /// The path to the certificate directory.
    pub certs : PathBuf,
    /// The path to the proxy file.
    pub proxy : PathBuf,
}

/// Defines the services for the proxy node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyServices {
    /// For the Proxy node, the proxy services is a) public, and b) required.
    #[serde(alias = "proxy")]
    pub prx : PublicService,
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
