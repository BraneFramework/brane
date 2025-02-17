//  NODE.rs
//    by Lut99
//
//  Created:
//    16 Nov 2022, 16:54:43
//  Last edited:
//    05 Jan 2023, 11:40:32
//  Auto updated?
//    No
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
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use enum_debug::EnumDebug;
use serde::{Deserialize, Serialize};


/***** PATCHED OLD FILES *****/
/// Errors that relate to a NodeConfig.
#[derive(Debug)]
pub enum NodeConfigError {
    /// The given NodeKind was unknown to us.
    UnknownNodeKind { raw: String },

    /// Failed to open the given config path.
    FileOpenError { path: PathBuf, err: std::io::Error },
    /// Failed to read from the given config path.
    FileReadError { path: PathBuf, err: std::io::Error },
    /// Failed to parse the given file.
    FileParseError { path: PathBuf, err: serde_yaml::Error },

    /// Failed to open the given config path.
    FileCreateError { path: PathBuf, err: std::io::Error },
    /// Failed to write to the given config path.
    FileWriteError { path: PathBuf, err: std::io::Error },
    /// Failed to serialze the NodeConfig.
    ConfigSerializeError { err: serde_yaml::Error },

    /// Failed to write to the given writer.
    WriterWriteError { err: std::io::Error },
}
impl Display for NodeConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use NodeConfigError::*;
        match self {
            UnknownNodeKind { raw } => write!(f, "Unknown node kind '{}'", raw),

            FileOpenError { path, err } => write!(f, "Failed to open the node config file '{}': {}", path.display(), err),
            FileReadError { path, err } => write!(f, "Failed to read the ndoe config file '{}': {}", path.display(), err),
            FileParseError { path, err } => write!(f, "Failed to parse node config file '{}' as YAML: {}", path.display(), err),

            FileCreateError { path, err } => write!(f, "Failed to create the node config file '{}': {}", path.display(), err),
            FileWriteError { path, err } => write!(f, "Failed to write to the ndoe config file '{}': {}", path.display(), err),
            ConfigSerializeError { err } => write!(f, "Failed to serialize node config to YAML: {}", err),

            WriterWriteError { err } => write!(f, "Failed to write to given writer: {}", err),
        }
    }
}
impl std::error::Error for NodeConfigError {}
type Error = NodeConfigError;

/// Errors that relate to parsing Addresses.
#[derive(Debug)]
pub enum AddressParseError {
    /// Missing the colon separator (':') in the address.
    MissingColon { raw: String },
    /// Invalid port number.
    IllegalPortNumber { raw: String, err: std::num::ParseIntError },
}
impl Display for AddressParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AddressParseError::*;
        match self {
            MissingColon { raw } => write!(f, "Missing address/port separator ':' in '{}' (did you forget to define a port?)", raw),
            IllegalPortNumber { raw, err } => write!(f, "Illegal port number '{}': {}", raw, err),
        }
    }
}
impl std::error::Error for AddressParseError {}



/// Defines a more lenient alternative to a SocketAddr that also accepts hostnames.
#[derive(Clone, Debug, EnumDebug)]
pub enum Address {
    /// It's an Ipv4 address.
    Ipv4(std::net::Ipv4Addr, u16),
    /// It's an Ipv6 address.
    Ipv6(std::net::Ipv6Addr, u16),
    /// It's a hostname.
    Hostname(String, u16),
}

impl Address {
    /// Constructor for the Address that initializes it for the given IPv4 address.
    ///
    /// # Arguments
    /// - `b1`: The first byte of the IPv4 address.
    /// - `b2`: The second byte of the IPv4 address.
    /// - `b3`: The third byte of the IPv4 address.
    /// - `b4`: The fourth byte of the IPv4 address.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn ipv4(b1: u8, b2: u8, b3: u8, b4: u8, port: u16) -> Self { Self::Ipv4(std::net::Ipv4Addr::new(b1, b2, b3, b4), port) }

    /// Constructor for the Address that initializes it for the given IPv4 address.
    ///
    /// # Arguments
    /// - `ipv4`: The already constructed IPv4 address to use.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn from_ipv4(ipv4: impl Into<std::net::Ipv4Addr>, port: u16) -> Self { Self::Ipv4(ipv4.into(), port) }

    /// Constructor for the Address that initializes it for the given IPv6 address.
    ///
    /// # Arguments
    /// - `b1`: The first pair of bytes of the IPv6 address.
    /// - `b2`: The second pair of bytes of the IPv6 address.
    /// - `b3`: The third pair of bytes of the IPv6 address.
    /// - `b4`: The fourth pair of bytes of the IPv6 address.
    /// - `b5`: The fifth pair of bytes of the IPv6 address.
    /// - `b6`: The sixth pair of bytes of the IPv6 address.
    /// - `b7`: The seventh pair of bytes of the IPv6 address.
    /// - `b8`: The eight pair of bytes of the IPv6 address.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn ipv6(b1: u16, b2: u16, b3: u16, b4: u16, b5: u16, b6: u16, b7: u16, b8: u16, port: u16) -> Self {
        Self::Ipv6(std::net::Ipv6Addr::new(b1, b2, b3, b4, b5, b6, b7, b8), port)
    }

    /// Constructor for the Address that initializes it for the given IPv6 address.
    ///
    /// # Arguments
    /// - `ipv6`: The already constructed IPv6 address to use.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn from_ipv6(ipv6: impl Into<std::net::Ipv6Addr>, port: u16) -> Self { Self::Ipv6(ipv6.into(), port) }

    /// Constructor for the Address that initializes it for the given hostname.
    ///
    /// # Arguments
    /// - `hostname`: The hostname for this Address.
    /// - `port`: The port for this address.
    ///
    /// # Returns
    /// A new Address instance.
    #[inline]
    pub fn hostname(hostname: impl Into<String>, port: u16) -> Self { Self::Hostname(hostname.into(), port) }

    /// Returns the domain-part, as a (serialized) string version.
    ///
    /// # Returns
    /// A `Cow<str>` that either contains a reference to the already String hostname, or else a newly created string that is the serialized version of an IP.
    #[inline]
    pub fn domain(&self) -> std::borrow::Cow<'_, str> {
        use Address::*;
        match self {
            Ipv4(addr, _) => format!("{}", addr).into(),
            Ipv6(addr, _) => format!("{}", addr).into(),
            Hostname(addr, _) => addr.into(),
        }
    }

    /// Returns the port-part, as a number.
    ///
    /// # Returns
    /// A `u16` that is the port.
    #[inline]
    pub fn port(&self) -> u16 {
        use Address::*;
        match self {
            Ipv4(_, port) => *port,
            Ipv6(_, port) => *port,
            Hostname(_, port) => *port,
        }
    }

    /// Returns the port-part as a mutable number.
    ///
    /// # Returns
    /// A mutable reference to the `u16` that is the port.
    #[inline]
    pub fn port_mut(&mut self) -> &mut u16 {
        use Address::*;
        match self {
            Ipv4(_, port) => port,
            Ipv6(_, port) => port,
            Hostname(_, port) => port,
        }
    }

    /// Returns a formatter that deterministically and parseably serializes the Address.
    #[inline]
    pub fn serialize(&self) -> impl '_ + Display { self }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Address::*;
        match self {
            Ipv4(addr, port) => write!(f, "{}:{}", addr, port),
            Ipv6(addr, port) => write!(f, "{}:{}", addr, port),
            Hostname(addr, port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl Serialize for Address {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&format!("{}", self.serialize()))
    }
}
impl<'de> Deserialize<'de> for Address {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        /// Defines the visitor for the Address
        struct AddressVisitor;
        impl serde::de::Visitor<'_> for AddressVisitor {
            type Value = Address;

            #[inline]
            fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "an address:port pair") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Attempt to serialize the incoming string
                match Address::from_str(v) {
                    Ok(address) => Ok(address),
                    Err(err) => Err(E::custom(err)),
                }
            }
        }

        // Call the visitor
        deserializer.deserialize_str(AddressVisitor)
    }
}
impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt to find the colon first
        let colon_pos: usize = match s.rfind(':') {
            Some(pos) => pos,
            None => {
                return Err(AddressParseError::MissingColon { raw: s.into() });
            },
        };

        // Split it on that
        let (address, port): (&str, &str) = (&s[..colon_pos], &s[colon_pos + 1..]);

        // Parse the port
        let port: u16 = match u16::from_str(port) {
            Ok(port) => port,
            Err(err) => {
                return Err(AddressParseError::IllegalPortNumber { raw: port.into(), err });
            },
        };

        // Resolve the address to a new instance of ourselves
        match IpAddr::from_str(address) {
            Ok(address) => match address {
                IpAddr::V4(ip) => Ok(Self::Ipv4(ip, port)),
                IpAddr::V6(ip) => Ok(Self::Ipv6(ip, port)),
            },
            Err(err) => {
                log::debug!("Parsing '{}' as a hostname, but might be an invalid IP address (parser feedback: {})", address, err);
                Ok(Self::Hostname(address.into(), port))
            },
        }
    }
}

impl AsRef<Address> for Address {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&Address> for Address {
    #[inline]
    fn from(value: &Address) -> Self { value.clone() }
}
impl From<&mut Address> for Address {
    #[inline]
    fn from(value: &mut Address) -> Self { value.clone() }
}





/***** AUXILLARY *****/
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
            Worker => write!(f, "worker"),
        }
    }
}

impl FromStr for NodeKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "central" => Ok(Self::Central),
            "worker" => Ok(Self::Worker),

            raw => Err(Error::UnknownNodeKind { raw: raw.into() }),
        }
    }
}





/***** LIBRARY *****/
/// Defines a `node.json` file that describes the environment layout of a node (what type it is, its location ID, where to find folders/services, etc).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    /// Defines any custom hostname -> IP mappings.
    pub hosts: HashMap<String, IpAddr>,
    /// Defines the proxy address to use for control messages, if any.
    pub proxy: Option<Address>,

    /// Defines the names of the services that occur on every kind of node.
    pub names:    CommonNames,
    /// Defines the paths used by various services that occur on every kind of node.
    pub paths:    CommonPaths,
    /// Defines the ports where various services hosts themselves that occur on any kind of node.
    pub ports:    CommonPorts,
    /// Defines service addresses that occur on any kind of node.
    pub services: CommonServices,

    /// NodeKind-specific configuration options,
    pub node: NodeKindConfig,
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
                Err(err) => {
                    return Err(Error::FileOpenError { path: path.into(), err });
                },
            };

            // Read the file
            if let Err(err) = handle.read_to_string(&mut raw) {
                return Err(Error::FileReadError { path: path.into(), err });
            }
        }

        // Parse with serde
        match serde_yaml::from_str(&raw) {
            Ok(config) => Ok(config),
            Err(err) => Err(Error::FileParseError { path: path.into(), err }),
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
            Err(err) => {
                return Err(Error::ConfigSerializeError { err });
            },
        };

        // Write it
        {
            // Create the file
            let mut handle: File = match File::create(path) {
                Ok(handle) => handle,
                Err(err) => {
                    return Err(Error::FileCreateError { path: path.into(), err });
                },
            };

            // Write the serialized config
            if let Err(err) = handle.write_all(config.as_bytes()) {
                return Err(Error::FileWriteError { path: path.into(), err });
            }
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
            Err(err) => {
                return Err(Error::ConfigSerializeError { err });
            },
        };

        // Write it
        if let Err(err) = writer.write_all(config.as_bytes()) {
            return Err(Error::WriterWriteError { err });
        }

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
            Worker(_) => NodeKind::Worker,
        }
    }

    /// Returns if this NodeConfigKind is a `NodeConfigKind::Central of sorts.
    #[inline]
    pub fn is_central(&self) -> bool { matches!(self, Self::Central(_)) }

    /// Returns this NodeConfigKind as if it was a `NodeConfigKind::Central`.
    ///
    /// Will panic otherwise.
    #[inline]
    pub fn central(&self) -> &CentralConfig {
        if let Self::Central(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeConfigKind::Central", self.variant());
        }
    }

    /// Returns this NodeConfigKind mutably as if it was a `NodeConfigKind::Central`.
    ///
    /// Will panic otherwise.
    #[inline]
    pub fn central_mut(&mut self) -> &mut CentralConfig {
        if let Self::Central(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeConfigKind::Central", self.variant());
        }
    }

    /// Consumes this NodeConfigKind into a `NodeConfigKind::Central`.
    ///
    /// Will panic if it was not.
    #[inline]
    pub fn into_central(self) -> CentralConfig {
        if let Self::Central(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeConfigKind::Central", self.variant());
        }
    }

    /// Returns if this NodeConfigKind is a `NodeConfigKind::Worker of sorts.
    #[inline]
    pub fn is_worker(&self) -> bool { matches!(self, Self::Worker(_)) }

    /// Returns this NodeConfigKind as if it was a `NodeConfigKind::Worker`.
    ///
    /// Will panic otherwise.
    #[inline]
    pub fn worker(&self) -> &WorkerConfig {
        if let Self::Worker(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeConfigKind::Worker", self.variant());
        }
    }

    /// Returns this NodeConfigKind mutably as if it was a `NodeConfigKind::Worker`.
    ///
    /// Will panic otherwise.
    #[inline]
    pub fn worker_mut(&mut self) -> &mut WorkerConfig {
        if let Self::Worker(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeConfigKind::Worker", self.variant());
        }
    }

    /// Consumes this NodeConfigKind into a `NodeConfigKind::Worker`.
    ///
    /// Will panic if it was not.
    #[inline]
    pub fn into_worker(self) -> WorkerConfig {
        if let Self::Worker(config) = self {
            config
        } else {
            panic!("Cannot unwrap a {:?} as a NodeConfigKind::Worker", self.variant());
        }
    }
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
    pub prx: String,
}

/// Defines common paths used on every kind of node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommonPaths {
    /// The path of the certificate directory.
    pub certs:    PathBuf,
    /// The path of the package directory.
    pub packages: PathBuf,
}

/// Defines common hosted services that are available on every kind of node.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct CommonPorts {
    /// Defines where the proxy service hosts itself.
    #[serde(alias = "proxy")]
    pub prx: SocketAddr,
}

/// Defines common services that are available on every kind of node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommonServices {
    /// Defines where the proxy service may be found.
    #[serde(alias = "proxy")]
    pub prx: Address,
}



/// Defines the properties that are specific to a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralConfig {
    /// Defines the names of services on the central node.
    pub names:    CentralNames,
    /// Defines the paths configuration for the central node.
    pub paths:    CentralPaths,
    /// Defines where various externally available services bind themselves to.
    pub ports:    CentralPorts,
    /// Defines how to reach services.
    pub services: CentralServices,
    /// Defines Kafka topics shared across services.
    pub topics:   CentralKafkaTopics,
}

/// Defines service names used on a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralNames {
    /// Defines the name of the API service.
    #[serde(alias = "registry")]
    pub api: String,
    /// Defines the name of the driver service.
    #[serde(alias = "driver")]
    pub drv: String,
    /// Defines the name of the planner service.
    #[serde(alias = "planner")]
    pub plr: String,
}

/// Defines where to find various paths for a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralPaths {
    /// The path of the infrastructure file.
    pub infra: PathBuf,
}

/// Defines various ports for external services on the central node.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct CentralPorts {
    /// The port of the API service
    #[serde(alias = "registry")]
    pub api: SocketAddr,
    /// The port of the driver service
    #[serde(alias = "driver")]
    pub drv: SocketAddr,
}

/// Defines where central node internal services are hosted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralServices {
    /// Defines where the Kafka broker(s) live(s).
    #[serde(alias = "kafka_brokers")]
    pub brokers: Vec<Address>,
    /// Defines where to find the Scylla database.
    #[serde(alias = "scylla_database")]
    pub scylla:  Address,

    /// Defines how to reach the API service.
    #[serde(alias = "registry")]
    pub api: Address,
}

/// Defines topics and such used on a central node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CentralKafkaTopics {
    /// The topic for the planner to receive new planning requests on.
    pub planner_command: String,
    /// The topic for the planner to send planning results on.
    pub planner_results: String,
}



/// Defines the properties that are specific to a worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerConfig {
    /// Defines the location ID of this location.
    #[serde(alias = "id")]
    pub location_id: String,

    /// Defines the names of services on the worker node.
    pub names:    WorkerNames,
    /// Defines the paths configuration for the worker node.
    pub paths:    WorkerPaths,
    /// Defines the ports for various _external_ services on this worker node.
    pub ports:    WorkerPorts,
    /// Defines where to find the various worker services.
    pub services: WorkerServices,
}

/// Defines service names used on a worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerNames {
    /// Defines the name of the local registr service.
    #[serde(alias = "registr")]
    pub reg: String,
    /// Defines the name of the local delegate service.
    #[serde(alias = "delegate")]
    pub job: String,
    /// Defines the name of the local checker service.
    #[serde(alias = "checker")]
    pub chk: String,
}

/// Defines where to find various paths for a worker node.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerPaths {
    /// The path of the backend file (`backend.yml`).
    pub backend:  PathBuf,
    /// The path to the "policy" file (`policies.yml` - temporary)
    pub policies: PathBuf,

    /// The path of the dataset directory.
    pub data: PathBuf,
    /// The path of the results directory.
    pub results: PathBuf,
    /// The path to the temporary dataset directory.
    pub temp_data: PathBuf,
    /// The path of the temporary results directory.
    pub temp_results: PathBuf,
}

/// Defines various ports for external services on the worker node.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct WorkerPorts {
    /// The port of the registry service.
    #[serde(alias = "registry")]
    pub reg: SocketAddr,
    /// The port of the job service.
    #[serde(alias = "delegate")]
    pub job: SocketAddr,
}

/// Defines where central node internal services are hosted.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerServices {
    /// Defines where the registry service lives.
    #[serde(alias = "registr")]
    pub reg: Address,
    /// Defines where the checker service lives.
    #[serde(alias = "checker")]
    pub chk: Address,
}
