//  NODE V 2.rs
//    by Lut99
//
//  Created:
//    28 Feb 2023, 10:01:27
//  Last edited:
//    07 Mar 2024, 09:52:57
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
use crate::info::YamlInfo;


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
            Worker => write!(f, "worker"),
            Proxy => write!(f, "proxy"),
        }
    }
}
impl FromStr for NodeKind {
    type Err = NodeKindParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "central" => Ok(Self::Central),
            "worker" => Ok(Self::Worker),
            "proxy" => Ok(Self::Proxy),

            raw => Err(NodeKindParseError::UnknownNodeKind { raw: raw.into() }),
        }
    }
}





/***** LIBRARY *****/
/// Defines the toplevel `node.yml` layout.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    /// Custom hostname <-> IP mappings to satisfy rustls
    pub hostnames: HashMap<String, IpAddr>,
    /// The Docker Compose project name.
    #[serde(alias = "project")]
    pub namespace: String,

    /// Any node-specific config
    pub node: NodeSpecificConfig,
}
impl YamlInfo<'_> for NodeConfig {}



/// Defines the services from the various nodes.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeSpecificConfig {
    /// Defines the services for the central node.
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
            Worker(_) => NodeKind::Worker,
            Proxy(_) => NodeKind::Proxy,
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
    pub fn central(&self) -> &CentralConfig {
        if let Self::Central(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Central", self.variant());
        }
    }

    /// Provides mutable access to the central-node specific configuration.
    ///
    /// # Returns
    /// A mutable reference to the internal CentralConfig struct.
    ///
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Central`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_central_mut()` instead.
    #[inline]
    pub fn central_mut(&mut self) -> &mut CentralConfig {
        if let Self::Central(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Central", self.variant());
        }
    }

    /// Returns the internal central-node specific configuration.
    ///
    /// # Returns
    /// The internal CentralConfig struct.
    ///
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Central`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_into_central()` instead.
    #[inline]
    pub fn into_central(self) -> CentralConfig {
        if let Self::Central(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Central", self.variant());
        }
    }

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
    pub fn worker(&self) -> &WorkerConfig {
        if let Self::Worker(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Worker", self.variant());
        }
    }

    /// Provides mutable access to the worker-node specific configuration.
    ///
    /// # Returns
    /// A mutable reference to the internal WorkerConfig struct.
    ///
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Worker`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_worker_mut()` instead.
    #[inline]
    pub fn worker_mut(&mut self) -> &mut WorkerConfig {
        if let Self::Worker(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Worker", self.variant());
        }
    }

    /// Returns the internal worker-node specific configuration.
    ///
    /// # Returns
    /// The internal WorkerConfig struct.
    ///
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Worker`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_into_worker()` instead.
    #[inline]
    pub fn into_worker(self) -> WorkerConfig {
        if let Self::Worker(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Worker", self.variant());
        }
    }

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
    pub fn proxy(&self) -> &ProxyConfig {
        if let Self::Proxy(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Proxy", self.variant());
        }
    }

    /// Provides mutable access to the proxy-node specific configuration.
    ///
    /// # Returns
    /// A mutable reference to the internal ProxyConfig struct.
    ///
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Proxy`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_proxy_mut()` instead.
    #[inline]
    pub fn proxy_mut(&mut self) -> &mut ProxyConfig {
        if let Self::Proxy(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Proxy", self.variant());
        }
    }

    /// Returns the internal proxy-node specific configuration.
    ///
    /// # Returns
    /// The internal ProxyConfig struct.
    ///
    /// # Panics
    /// This function panics if we were not `NodeSpecificConfig::Proxy`. If you are looking for a more user-friendly version, check `NodeSpecificConfig::try_into_proxy()` instead.
    #[inline]
    pub fn into_proxy(self) -> ProxyConfig {
        if let Self::Proxy(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeSpecificConfig::Proxy", self.variant());
        }
    }

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



/// Defines the configuration for the central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralConfig {
    /// Defines the paths for this node.
    pub paths:    CentralPaths,
    /// Defines the services for this node.
    pub services: CentralServices,
}

/// Defines the paths for the central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralPaths {
    /// The path to the certificate directory.
    pub certs:    PathBuf,
    /// The path to the package directory.
    pub packages: PathBuf,

    /// The path to the infrastructure file.
    pub infra: PathBuf,
    /// The path to the proxy file, if applicable. Ignored if no service is present.
    pub proxy: Option<PathBuf>,
}

/// Defines the services for the central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralServices {
    // Brane services
    /// Describes the API (global registry) service.
    #[serde(alias = "registry")]
    pub api: PublicService,
    /// Describes the driver service.
    #[serde(alias = "driver")]
    pub drv: PublicService,
    /// Describes the planner service.
    #[serde(alias = "planner")]
    pub plr: PrivateService,
    /// Describes the proxy service.
    #[serde(alias = "proxy")]
    pub prx: PrivateOrExternalService,

    // Auxillary services
    /// Describes the Scylla service.
    #[serde(alias = "scylla")]
    pub aux_scylla: PrivateService,
}



/// Defines the configuration for the worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerConfig {
    /// Defines the name for this worker.
    #[serde(alias = "location_id")]
    pub name: String,

    /// Defines the use case registries for this node.
    ///
    /// This is used to resolve the location of a remote registry, for example, based on what use-case we're working for.
    #[serde(alias = "use_cases")]
    pub usecases: HashMap<String, WorkerUsecase>,
    /// Defines the paths for this node.
    pub paths:    WorkerPaths,
    /// Defines the services for this node.
    pub services: WorkerServices,
}

/// Defines everything we need to know based on a use-case identifier.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerUsecase {
    /// The location of the generic registry for this use-case.
    #[serde(alias = "registry")]
    pub api: Address,
}

/// Defines the paths for the worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerPaths {
    /// The path to the certificate directory.
    pub certs:    PathBuf,
    /// The path to the package directory.
    pub packages: PathBuf,

    /// The path of the backend file (`backend.yml`).
    pub backend: PathBuf,
    /// The path to the policy SQLite database file (`policy.db`)
    #[serde(alias = "policy_db")]
    pub policy_database: PathBuf,
    /// The path to the secret used for the deliberation endpoint in the checker.
    pub policy_deliberation_secret: PathBuf,
    /// The path to the secret used for the policy expert endpoint in the checker.
    pub policy_expert_secret: PathBuf,
    /// The path the (persistent) audit log. Can be omitted to not have a persistent log.
    pub policy_audit_log: Option<PathBuf>,
    /// The path to the proxy file, if applicable. Ignored if no service is present.
    pub proxy: Option<PathBuf>,

    /// The path of the dataset directory.
    pub data: PathBuf,
    /// The path of the results directory.
    pub results: PathBuf,
    /// The path to the temporary dataset directory.
    pub temp_data: PathBuf,
    /// The path of the temporary results directory.
    pub temp_results: PathBuf,
}

/// Defines the services for the worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerServices {
    /// Defines the (local) registry service.
    #[serde(alias = "registry")]
    pub reg: PublicService,
    /// Defines the job (local driver) service.
    #[serde(alias = "delegate")]
    pub job: PublicService,
    /// Defines the checker service.
    #[serde(alias = "checker")]
    pub chk: PrivateService,
    /// Defines the proxy service.
    #[serde(alias = "proxy")]
    pub prx: PrivateOrExternalService,
}



/// Defines the configuration for the proxy node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Defines the paths for this node.
    pub paths:    ProxyPaths,
    /// Defines the services for this node.
    pub services: ProxyServices,
}

/// Defines the paths for the proxy node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyPaths {
    /// The path to the certificate directory.
    pub certs: PathBuf,
    /// The path to the proxy file.
    pub proxy: PathBuf,
}

/// Defines the services for the proxy node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyServices {
    /// For the Proxy node, the proxy services is a) public, and b) required.
    #[serde(alias = "proxy")]
    pub prx: PublicService,
}



/// Defines an abstraction over _either_ a private service, _or_ an external service.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOrExternalService {
    /// It's a private service.
    Private(PrivateService),
    /// It's an external service.
    External(ExternalService),
}
impl PrivateOrExternalService {
    /// Returns whether this is a private service or not.
    ///
    /// # Returns
    /// True if it is, false if it is an external service.
    #[inline]
    pub fn is_private(&self) -> bool { matches!(self, Self::Private(_)) }

    /// Provides access to the internal `PrivateService` object, assuming this is one.
    ///
    /// # Returns
    /// A reference to the internal `PrivateService` object.
    ///
    /// # Panics
    /// This function panics if we were not a `Private` service.
    #[inline]
    pub fn private(&self) -> &PrivateService {
        if let Self::Private(svc) = self {
            svc
        } else {
            panic!("Cannot unwrap {:?} as PrivateOrExternalService::Private", self.variant());
        }
    }

    /// Provides mutable access to the internal `PrivateService` object, assuming this is one.
    ///
    /// # Returns
    /// A mutable reference to the internal `PrivateService` object.
    ///
    /// # Panics
    /// This function panics if we were not a `Private` service.
    #[inline]
    pub fn private_mut(&mut self) -> &mut PrivateService {
        if let Self::Private(svc) = self {
            svc
        } else {
            panic!("Cannot unwrap {:?} as PrivateOrExternalService::Private", self.variant());
        }
    }

    /// Returns the internal `PrivateService` object, assuming this is one.
    ///
    /// # Returns
    /// The internal `PrivateService` object. This consumes `self`.
    ///
    /// # Panics
    /// This function panics if we were not a `Private` service.
    #[inline]
    pub fn into_private(self) -> PrivateService {
        if let Self::Private(svc) = self {
            svc
        } else {
            panic!("Cannot unwrap {:?} as PrivateOrExternalService::Private", self.variant());
        }
    }

    /// Provides access to the internal `PrivateService` object, assuming this is one.
    ///
    /// # Returns
    /// A reference to the internal `PrivateService` object if this is a `PrivateOrExternalService::Private`, or else `None`.
    #[inline]
    pub fn try_private(&self) -> Option<&PrivateService> { if let Self::Private(svc) = self { Some(svc) } else { None } }

    /// Provides mutable access to the internal `PrivateService` object, assuming this is one.
    ///
    /// # Returns
    /// A mutable reference to the internal `PrivateService` object if this is a `PrivateOrExternalService::Private`, or else `None`.
    #[inline]
    pub fn try_private_mut(&mut self) -> Option<&mut PrivateService> { if let Self::Private(svc) = self { Some(svc) } else { None } }

    /// Returns the internal `PrivateService` object, assuming this is one.
    ///
    /// # Returns
    /// The internal `PrivateService` object if this is a `PrivateOrExternalService::Private`, or else `None`. This consumes `self`.
    #[inline]
    pub fn try_into_private(self) -> Option<PrivateService> { if let Self::Private(svc) = self { Some(svc) } else { None } }

    /// Returns whether this is an external service or not.
    ///
    /// # Returns
    /// True if it is, false if it is a private service.
    #[inline]
    pub fn is_external(&self) -> bool { matches!(self, Self::External(_)) }

    /// Provides access to the internal `ExternalService` object, assuming this is one.
    ///
    /// # Returns
    /// A reference to the internal `ExternalService` object.
    ///
    /// # Panics
    /// This function panics if we were not an `External` service.
    #[inline]
    pub fn external(&self) -> &ExternalService {
        if let Self::External(svc) = self {
            svc
        } else {
            panic!("Cannot unwrap {:?} as PrivateOrExternalService::External", self.variant());
        }
    }

    /// Provides mutable access to the internal `ExternalService` object, assuming this is one.
    ///
    /// # Returns
    /// A mutable reference to the internal `ExternalService` object.
    ///
    /// # Panics
    /// This function panics if we were not an `External` service.
    #[inline]
    pub fn external_mut(&mut self) -> &mut ExternalService {
        if let Self::External(svc) = self {
            svc
        } else {
            panic!("Cannot unwrap {:?} as PrivateOrExternalService::External", self.variant());
        }
    }

    /// Returns the internal `ExternalService` object, assuming this is one.
    ///
    /// # Returns
    /// The internal `ExternalService` object. This consumes `self`.
    ///
    /// # Panics
    /// This function panics if we were not an `External` service.
    #[inline]
    pub fn into_external(self) -> ExternalService {
        if let Self::External(svc) = self {
            svc
        } else {
            panic!("Cannot unwrap {:?} as PrivateOrExternalService::External", self.variant());
        }
    }

    /// Provides access to the internal `ExternalService` object, assuming this is one.
    ///
    /// # Returns
    /// A reference to the internal `ExternalService` object if this is a `PrivateOrExternalService::External`, or else `None`.
    #[inline]
    pub fn try_external(&self) -> Option<&ExternalService> { if let Self::External(svc) = self { Some(svc) } else { None } }

    /// Provides mutable access to the internal `ExternalService` object, assuming this is one.
    ///
    /// # Returns
    /// A mutable reference to the internal `ExternalService` object if this is a `PrivateOrExternalService::External`, or else `None`.
    #[inline]
    pub fn try_external_mut(&mut self) -> Option<&mut ExternalService> { if let Self::External(svc) = self { Some(svc) } else { None } }

    /// Returns the internal `ExternalService` object, assuming this is one.
    ///
    /// # Returns
    /// The internal `ExternalService` object if this is a `PrivateOrExternalService::External`, or else `None`. This consumes `self`.
    #[inline]
    pub fn try_into_external(self) -> Option<ExternalService> { if let Self::External(svc) = self { Some(svc) } else { None } }

    /// Provides access to the internal (private) address that services can connect to.
    ///
    /// # Returns
    /// A reference to the internal `Address`-object.
    #[inline]
    pub fn address(&self) -> &Address {
        match self {
            Self::Private(svc) => &svc.address,
            Self::External(svc) => &svc.address,
        }
    }

    /// Provides mutable access to the internal (private) address that services can connect to.
    ///
    /// # Returns
    /// A mutable reference to the internal `Address`-object.
    #[inline]
    pub fn address_mut(&mut self) -> &mut Address {
        match self {
            Self::Private(svc) => &mut svc.address,
            Self::External(svc) => &mut svc.address,
        }
    }

    /// Returns the internal (private) address that services can connect to.
    ///
    /// # Returns
    /// The internal `Address`-object. This consumes `self`.
    #[inline]
    pub fn into_address(self) -> Address {
        match self {
            Self::Private(svc) => svc.address,
            Self::External(svc) => svc.address,
        }
    }
}



/// Defines what we need to know for a public service (i.e., a service that is reachable from outside the Docker network, i.e., the node).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicService {
    /// Defines the name of the Docker container.
    pub name:    String,
    /// Defines how the services on the same node can reach this service (which can be optimized due to the same-Docker-network property).
    pub address: Address,
    /// Defines the port (and hostname) to which the Docker container will bind itself. This is also the port on which the service will be externally reachable.
    pub bind:    SocketAddr,

    /// Defines how the services on _other_ nodes can reach this service.
    pub external_address: Address,
}

/// Defines what we need to know for a private service (i.e., a service that is only reachable from within the Docker network, i.e., the node).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateService {
    /// Defines the name of the Docker container.
    pub name:    String,
    /// Defines how the services on the same node can reach this service (which can be optimized due to the same-Docker-network property).
    pub address: Address,
    /// Defines the port (and hostname) to which the Docker container will bind itself.
    pub bind:    SocketAddr,
}

/// Defines a service that we do not host, but only use.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExternalService {
    /// Defines the address to connect to.
    pub address: Address,
}
