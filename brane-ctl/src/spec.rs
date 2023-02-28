//  SPEC.rs
//    by Lut99
// 
//  Created:
//    21 Nov 2022, 17:27:52
//  Last edited:
//    28 Feb 2023, 19:12:18
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines specifications and interfaces used across modules.
// 

use std::fmt::{Display, Formatter, Result as FResult};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str::FromStr;

use clap::Subcommand;
use enum_debug::EnumDebug;

use brane_tsk::docker::{ClientVersion, ImageSource};
use specifications::address::Address;

use crate::errors::{ArchParseError, DockerClientVersionParseError, HostnamePairParseError, LocationPairParseError};


/***** STATICS *****/
lazy_static::lazy_static!{
    /// The default Docker API version that we're using.
    pub static ref API_DEFAULT_VERSION: String = format!("{}", brane_tsk::docker::API_DEFAULT_VERSION);
}





/***** AUXILLARY *****/
/// A formatter for architectures that writes it in a way that Brane understands.
#[derive(Debug)]
pub struct ArchBraneFormatter<'a> {
    /// The architecture to format.
    arch : &'a Arch,
}
impl<'a> Display for ArchBraneFormatter<'a> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self.arch {
            Arch::X86_64  => write!(f, "x86_64"),
            Arch::Aarch64 => write!(f, "aarch64"),
        }
    }
}

/// Defines the possible architectures for which we can download images.
#[derive(Clone, Copy, Debug, EnumDebug)]
pub enum Arch {
    /// Typical Intel/AMD machines.
    X86_64,
    /// Apple ARM
    Aarch64,
}
impl Arch {
    /// Returns a formatter that writes the architecture in a Brane-friendly way.
    #[inline]
    pub fn brane(&self) -> ArchBraneFormatter { ArchBraneFormatter{ arch: self } }
}
impl FromStr for Arch {
    type Err = ArchParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // User-specified ones
            "x86_64"  | "amd64" => Ok(Self::X86_64),
            "aarch64" | "arm64" => Ok(Self::Aarch64),

            // Meta-argument for resolving the local architecture
            "$LOCAL" => {
                // Prepare our magic command to run (`uname -m`)
                let mut cmd: Command = Command::new("uname");
                cmd.arg("-m");

                // Call it
                let res: Output = match cmd.output() {
                    Ok(res)  => res,
                    Err(err) => { return Err(ArchParseError::SpawnError{ command: cmd, err }); },
                };
                if !res.status.success() { return Err(ArchParseError::SpawnFailure { command: cmd, status: res.status, err: String::from_utf8_lossy(&res.stderr).into() }); }

                // Attempt to parse the default output again
                Self::from_str(String::from_utf8_lossy(&res.stdout).trim())
            },

            // Any other is a failure
            _ => Err(ArchParseError::UnknownArch{ raw: s.into() }),
        }
    }
}



/// Defines a wrapper around ClientVersion that allows it to be parsed.
#[derive(Clone, Copy, Debug)]
pub struct DockerClientVersion(pub ClientVersion);
impl FromStr for DockerClientVersion {
    type Err = DockerClientVersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Find the dot to split on
        let dot_pos: usize = match s.find('.') {
            Some(pos) => pos,
            None      => { return Err(DockerClientVersionParseError::MissingDot{ raw: s.into() }); },
        };

        // Split it
        let major: &str = &s[..dot_pos];
        let minor: &str = &s[dot_pos + 1..];

        // Attempt to parse each of them as the appropriate integer type
        let major: usize = match usize::from_str(major) {
            Ok(major) => major,
            Err(err)  => { return Err(DockerClientVersionParseError::IllegalMajorNumber{ raw: s.into(), err }); },
        };
        let minor: usize = match usize::from_str(minor) {
            Ok(minor) => minor,
            Err(err)  => { return Err(DockerClientVersionParseError::IllegalMinorNumber{ raw: s.into(), err }); },
        };

        // Done, return the value
        Ok(DockerClientVersion(ClientVersion{ major_version: major, minor_version: minor }))
    }
}



/// Defines a `<hostname>:<ip>` pair that is conveniently parseable.
#[derive(Clone, Debug)]
pub struct HostnamePair(pub String, pub IpAddr);

impl Display for HostnamePair {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(f, "{} -> {}", self.0, self.1)
    }
}

impl FromStr for HostnamePair {
    type Err = HostnamePairParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Find the colon to split on
        let colon_pos: usize = match s.find(':') {
            Some(pos) => pos,
            None      => { return Err(HostnamePairParseError::MissingColon{ raw: s.into() }); },
        };

        // Split it
        let hostname : &str = &s[..colon_pos];
        let ip       : &str = &s[colon_pos + 1..];

        // Attempt to parse the IP as either an IPv4 _or_ an IPv6
        match IpAddr::from_str(ip) {
            Ok(ip)   => Ok(Self(hostname.into(), ip)),
            Err(err) => Err(HostnamePairParseError::IllegalIpAddr{ raw: ip.into(), err }),
        }
    }
}

impl AsRef<HostnamePair> for HostnamePair {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&HostnamePair> for HostnamePair {
    #[inline]
    fn from(value: &HostnamePair) -> Self { value.clone() }
}
impl From<&mut HostnamePair> for HostnamePair {
    #[inline]
    fn from(value: &mut HostnamePair) -> Self { value.clone() }
}

/// Defines a `<location>=<something>` pair that is conveniently parseable.
#[derive(Clone, Debug)]
pub struct LocationPair<const C: char, T>(pub String, pub T);

impl<const C: char, T: Display> Display for LocationPair<C, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl<const C: char, T: FromStr> FromStr for LocationPair<C, T> {
    type Err = LocationPairParseError<T::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Find the separator to split on
        let sep_pos: usize = match s.find(C) {
            Some(pos) => pos,
            None      => { return Err(LocationPairParseError::<T::Err>::MissingSeparator{ separator: C, raw: s.into() }); },
        };

        // Split it
        let location  : &str = &s[..sep_pos];
        let something : &str = &s[sep_pos + 1..];

        // Attempt to parse the something as the thing
        match T::from_str(something) {
            Ok(something) => Ok(Self(location.into(), something)),
            Err(err)      => Err(LocationPairParseError::<T::Err>::IllegalSomething{ what: std::any::type_name::<T>(), raw: something.into(), err }),
        }
    }
}





/***** LIBRARY *****/
/// A bit awkward here, but defines the subcommand for downloading service images from the repo.
#[derive(Debug, EnumDebug, Subcommand)]
pub enum DownloadServicesSubcommand {
    /// Download the services for a central node.
    #[clap(name = "central", about = "Downloads the central node services (brane-api, brane-drv, brane-plr, brane-prx)")]
    Central,
    /// Download the services for a worker node.
    #[clap(name = "worker", about = "Downloads the worker node services (brane-reg, brane-job, brane-prx)")]
    Worker,
    /// Download the auxillary services for the central node.
    #[clap(name = "auxillary", about = "Downloads the auxillary services for the central node. Note that most of these are actually downloaded using Docker.")]
    Auxillary {
        /// The path of the Docker socket.
        #[clap(short, long, default_value="/var/run/docker.sock", help="The path of the Docker socket to connect to.")]
        socket         : PathBuf,
        /// The client version to connect with.
        #[clap(short, long, default_value=API_DEFAULT_VERSION.as_str(), help="The client version to connect to the Docker instance with.")]
        client_version : DockerClientVersion,
    },
}

/// A bit awkward here, but defines the generate subcommand for the node file. This basically defines the possible kinds of nodes to generate.
#[derive(Debug, EnumDebug, Subcommand)]
pub enum GenerateNodeSubcommand {
    /// Starts a central node.
    #[clap(name = "central", about = "Generates a node.yml file for a central node with default values.")]
    Central {
        /// The hostname of this node.
        #[clap(name = "HOSTNAME", help = "The hostname that other nodes in the instance can use to reach this node.")]
        hostname : Address,

        /// Custom `infra.yml` path.
        #[clap(short, long, default_value = "$CONFIG/infra.yml", help = "The location of the 'infra.yml' file. Use '$CONFIG' to reference the value given by --config-path.")]
        infra    : PathBuf,
        /// Custom certificates path.
        #[clap(short, long, default_value = "$CONFIG/certs", help = "The location of the certificate directory. Use '$CONFIG' to reference the value given by --config-path.")]
        certs    : PathBuf,
        /// Custom packages path.
        #[clap(long, default_value = "./packages", help = "The location of the package directory.")]
        packages : PathBuf,

        /// The name of the proxy service.
        #[clap(long, default_value = "brane-prx", help = "The name of the proxy service's container.")]
        prx_name : String,
        /// The name of the API service.
        #[clap(long, default_value = "brane-api", help = "The name of the API service's container.")]
        api_name : String,
        /// The name of the driver service.
        #[clap(long, default_value = "brane-drv", help = "The name of the driver service's container.")]
        drv_name : String,
        /// The name of the planner service.
        #[clap(long, default_value = "brane-plr", help = "The name of the planner service's container.")]
        plr_name : String,

        /// The port of the proxy service.
        #[clap(short, long, default_value = "50050", help = "The port on which the proxy service is available.")]
        prx_port : u16,
        /// The port of the API service.
        #[clap(short, long, default_value = "50051", help = "The port on which the API service is available.")]
        api_port : u16,
        /// The port of the driver service.
        #[clap(short, long, default_value = "50053", help = "The port on which the driver service is available.")]
        drv_port : u16,

        /// The topic for planner commands.
        #[clap(long, default_value = "plr-cmd", help = "The Kafka topic used to submit planner commands on.")]
        plr_cmd_topic : String,
        /// The topic for planner results.
        #[clap(long, default_value = "plr-res", help = "The Kafka topic used to emit planner results on.")]
        plr_res_topic : String,
    },

    /// Starts a worker node.
    #[clap(name = "worker", about = "Generate a node.yml file for a worker node with default values.")]
    Worker {
        /// The location ID of this node.
        #[clap(name = "LOCATION_ID", help = "The location identifier (location ID) of this node.")]
        location_id : String,
        /// The hostname of this node.
        #[clap(name = "HOSTNAME", help = "The hostname that other nodes in the instance can use to reach this node.")]
        hostname    : Address,

        /// Custom backend file path.
        #[clap(long, default_value = "$CONFIG/backend.yml", help = "The location of the `backend.yml` file. Use `$CONFIG` to reference the value given by --config-path. ")]
        backend      : PathBuf,
        /// Custom hash file path.
        #[clap(long, default_value = "$CONFIG/policies.yml", help = "The location of the `policies.yml` file that determines which containers and users are allowed to be executed. Use `$CONFIG` to reference the value given by --config-path.")]
        policies     : PathBuf,
        /// Custom certificates path.
        #[clap(short, long, default_value = "$CONFIG/certs", help = "The location of the certificate directory. Use '$CONFIG' to reference the value given by --config-path.")]
        certs        : PathBuf,
        /// Custom packages path.
        #[clap(long, default_value = "./packages", help = "The location of the package directory.")]
        packages     : PathBuf,
        /// Custom data path,
        #[clap(short, long, default_value = "./data", help = "The location of the data directory.")]
        data         : PathBuf,
        /// Custom results path.
        #[clap(short, long, default_value = "./results", help = "The location of the results directory.")]
        results      : PathBuf,
        /// Custom results path.
        #[clap(short = 'D', long, default_value = "/tmp/data", help = "The location of the temporary/downloaded data directory.")]
        temp_data    : PathBuf,
        /// Custom results path.
        #[clap(short = 'R', long, default_value = "/tmp/results", help = "The location of the temporary/download results directory.")]
        temp_results : PathBuf,

        /// The name of the proxy service.
        #[clap(long, default_value = "brane-prx-$LOCATION", help = "The name of the local proxy service's container. Use '$LOCATION' to use the location ID.")]
        prx_name : String,
        /// The address on which to launch the registry service.
        #[clap(long, default_value = "brane-reg-$LOCATION", help = "The name of the local registry service's container. Use '$LOCATION' to use the location ID.")]
        reg_name : String,
        /// The address on which to launch the driver service.
        #[clap(long, default_value = "brane-job-$LOCATION", help = "The name of the local delegate service's container. Use '$LOCATION' to use the location ID.")]
        job_name : String,
        /// The address on which to launch the checker service.
        #[clap(long, default_value = "brane-chk-$LOCATION", help = "The name of the local checker service's container. Use '$LOCATION' to use the location ID.")]
        chk_name : String,

        /// The port of the proxy service.
        #[clap(short, long, default_value = "50050", help = "The port on which the local proxy service is available.")]
        prx_port : u16,
        /// The address on which to launch the registry service.
        #[clap(long, default_value = "50051", help = "The port on which the local registry service is available.")]
        reg_port : u16,
        /// The address on which to launch the driver service.
        #[clap(long, default_value = "50052", help = "The port on which the local delegate service is available.")]
        job_port : u16,
        /// The address on which to launch the checker service.
        #[clap(long, default_value = "50053", help = "The port on which the local checker service is available.")]
        chk_port : u16,
    },
}

/// A bit awkward here, but defines the generate subcommand for certificates. This basically defines the possible certificate kinds to generate.
#[derive(Debug, EnumDebug, Subcommand)]
pub enum GenerateCertsSubcommand {
    /// It's a server certificate (which includes generating the CA).
    Server {
        /// The domain name for which to generate the certificates.
        #[clap(name="LOCATION_ID", help = "The name of the location for which we are generating server certificates.")]
        location_id : String,
        /// The hostname for which to generate the certificates.
        #[clap(short='H', long, default_value="$LOCATION_ID", help = "The hostname of the location for which we are generating server certificates. Can use '$LOCATION_ID' to use the same value as given for the location ID.")]
        hostname    : String,
    },

    /// It's a client certificate.
    Client {
        /// The domain name for which to generate the certificates.
        #[clap(name="LOCATION_ID", help = "The name of the location for which we are generating server certificates. Note that this the location ID of the client, not the server.")]
        location_id : String,
        /// The hostname for which to generate the certificates.
        #[clap(short='H', long, default_value="$LOCATION_ID", help = "The hostname of the location for which we are generating server certificates. Note that this the hostname of the client, not the server. Can use '$LOCATION_ID' to use the same value as given for the location ID.")]
        hostname    : String,

        /// The location of the certificate authority's certificate.
        #[clap(short, long, default_value = "./ca.pem", help = "The path to the certificate authority's certificate file that we will use to sign the client certificate.")]
        ca_cert : PathBuf,
        /// The location of the certificate authority's key.
        #[clap(short='k', long, default_value = "./ca-key.pem", help = "The path to the certificate authority's private key file that we will use to sign the client certificate.")]
        ca_key  : PathBuf,
    },
}
impl GenerateCertsSubcommand {
    /// Resolves the internal hostname iff it's currently referring to the internal location ID.
    #[inline]
    pub fn resolve_hostname(&mut self) {
        use GenerateCertsSubcommand::*;
        match self {
            Server{ location_id, hostname, .. } |
            Client{ location_id, hostname, .. } => {
                if hostname == "$LOCATION_ID" {
                    *hostname = location_id.clone();
                }
            },
        }
    }



    /// Helper function that returns the location ID irrespective of the variant.
    #[inline]
    pub fn location_id(&self) -> &str {
        use GenerateCertsSubcommand::*;
        match self {
            Server{ location_id, .. } |
            Client{ location_id, .. } => location_id,
        }
    }

    /// Helper function that returns the hostname irrespective of the variant.
    #[inline]
    pub fn hostname(&self) -> &str {
        use GenerateCertsSubcommand::*;
        match self {
            Server{ hostname, .. } |
            Client{ hostname, .. } => hostname,
        }
    }
}

/// A bit awkward here, but defines the generate subcommand for the backend file. This basically defines the possible kinds of backends to generate.
#[derive(Debug, EnumDebug, Subcommand)]
pub enum GenerateBackendSubcommand {
    /// A backend on the local Docker engine.
    #[clap(name = "local", about = "Generate a backend.yml for a local backend.")]
    Local {
        /// The location of the Docker socket to connect to.
        #[clap(short, long, default_value = "/var/run/docker.sock", help = "The location of the Docker socket that the delegate service should connect to.")]
        socket         : PathBuf,
        /// The client version to connect to the local Docker daemon with.
        #[clap(short, long, help = "If given, fixes the Docker client version to the given one.")]
        client_version : Option<DockerClientVersion>,
    },
}



/// Defines the start subcommand, which basically defines the possible kinds of nodes to start.
#[derive(Debug, Subcommand)]
pub enum StartSubcommand {
    /// Starts a central node.
    #[clap(name = "central", about = "Starts a central node based on the values in the local node.yml file.")]
    Central {
        /// THe path (or other source) to the `aux-scylla` service.
        #[clap(short = 's', long, default_value = "Registry<scylladb/scylla:4.6.3>", help = "The image to load for the aux-scylla service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters.")]
        aux_scylla    : ImageSource,
        /// The path (or other source) to the `aux-kafka` service.
        #[clap(short = 'k', long, default_value = "Registry<ubuntu/kafka:3.1-22.04_beta>", help = "The image to load for the aux-kafka service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters.")]
        aux_kafka     : ImageSource,
        /// The path (or other source) to the `aux-zookeeper` service.
        #[clap(short = 'z', long, default_value = "Registry<ubuntu/zookeeper:3.1-22.04_beta>", help = "The image to load for the aux-zookeeper service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters.")]
        aux_zookeeper : ImageSource,
        /// The path (or other source) to the `aux-xenon` service.
        #[clap(short = 'm', long, default_value = "Path<./target/release/aux-xenon.tar>", help = "The image to load for the aux-xenon service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters.")]
        aux_xenon     : ImageSource,

        /// The path (or other source) to the `brane-prx` service.
        #[clap(short = 'P', long, default_value = "Path<./target/$MODE/brane-prx.tar>", help = "The image to load for the brane-prx service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$MODE' to reference the value indicated by --mode.")]
        brane_prx : ImageSource,
        /// The path (or other source) to the `brane-api` service.
        #[clap(short = 'a', long, default_value = "Path<./target/$MODE/brane-api.tar>", help = "The image to load for the brane-plr service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$MODE' to reference the value indicated by --mode.")]
        brane_api : ImageSource,
        /// The path (or other source) to the `brane-drv` service.
        #[clap(short = 'd', long, default_value = "Path<./target/$MODE/brane-drv.tar>", help = "The image to load for the brane-drv service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$MODE' to reference the value indicated by --mode.")]
        brane_drv : ImageSource,
        /// The path (or other source) to the `brane-plr` service.
        #[clap(short = 'p', long, default_value = "Path<./target/$MODE/brane-plr.tar>", help = "The image to load for the brane-plr service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$MODE' to reference the value indicated by --mode.")]
        brane_plr : ImageSource,
    },

    /// Starts a worker node.
    #[clap(name = "worker", about = "Starts a worker node based on the values in the local node.yml file.")]
    Worker {
        /// The path (or other source) to the `brane-prx` service.
        #[clap(short = 'P', long, default_value = "Path<./target/$MODE/brane-prx.tar>", help = "The image to load for the brane-prx service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$MODE' to reference the value indicated by --mode.")]
        brane_prx : ImageSource,
        /// The path (or other source) to the `brane-api` service.
        #[clap(short = 'r', long, default_value = "Path<./target/$MODE/brane-reg.tar>", help = "The image to load for the brane-reg service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$MODE' to reference the value indicated by --mode.")]
        brane_reg : ImageSource,
        /// The path (or other source) to the `brane-drv` service.
        #[clap(short = 'j', long, default_value = "Path<./target/$MODE/brane-job.tar>", help = "The image to load for the brane-job service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$MODE' to reference the value indicated by --mode.")]
        brane_job : ImageSource,
    },
}
