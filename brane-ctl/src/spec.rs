//  SPEC.rs
//    by Lut99
// 
//  Created:
//    21 Nov 2022, 17:27:52
//  Last edited:
//    28 Mar 2023, 10:40:26
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines specifications and interfaces used across modules.
// 

use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::ops::RangeInclusive;
use std::str::FromStr;

use clap::Subcommand;
use enum_debug::EnumDebug;

use brane_cfg::node::NodeKind;
use brane_tsk::docker::{ClientVersion, ImageSource};
use specifications::address::Address;
use specifications::version::Version;

use crate::errors::{ArchParseError, DockerClientVersionParseError, InclusiveRangeParseError, PairParseError};


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



/// Defines a wrapper around a `NodeKind` that also allows it to be resolved later from the contents of the `node.yml` file.
#[derive(Clone, Copy, Debug)]
pub struct ResolvableNodeKind(pub Option<NodeKind>);
impl Display for ResolvableNodeKind {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self.0 {
            Some(kind) => write!(f, "{kind}"),
            None       => write!(f, "$NODECFG"),
        }
    }
}
impl FromStr for ResolvableNodeKind {
    type Err = brane_cfg::errors::NodeKindParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "$NODECFG" => Ok(Self(None)),
            raw        => Ok(Self(Some(NodeKind::from_str(raw)?))),
        }
    }
}



/// Defines an _inclusive_ range of numbers.
#[derive(Clone, Debug)]
pub struct InclusiveRange<T>(pub RangeInclusive<T>);
impl<T: FromStr + PartialOrd> FromStr for InclusiveRange<T> where T::Err: 'static + Send + Sync + std::error::Error, {
    type Err = InclusiveRangeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Find the dash
        let dpos: usize = match s.find('-') {
            Some(pos) => pos,
            None      => { return Err(InclusiveRangeParseError::MissingDash { raw: s.into() }); },
        };

        // Split into the start and end number
        let sstart : &str = &s[..dpos];
        let send   : &str = &s[dpos + 1..];

        // Parse them
        let start : T = T::from_str(sstart).map_err(|err| InclusiveRangeParseError::NumberParseError { what: std::any::type_name::<T>(), raw: sstart.into(), err: Box::new(err) })?;
        let end   : T = T::from_str(send).map_err(|err| InclusiveRangeParseError::NumberParseError { what: std::any::type_name::<T>(), raw: send.into(), err: Box::new(err) })?;

        // Assert the order is correct
        if start > end { return Err(InclusiveRangeParseError::StartLargerThanEnd { start: sstart.into(), end: send.into() }); }

        // OK
        Ok(Self(start..=end))
    }
}



/// Defines a `<something><char><something>` pair that is conveniently parseable, e.g., `<hostname>:<ip>` or `<domain>=<property>`.
/// 
/// # Generics
/// - `K`: The type of the key to parse.
/// - `C`: The separator character to use.
/// - `V`: The type of the value to parse.
#[derive(Clone, Debug)]
pub struct Pair<K, const C: char, V>(pub K, pub V);
impl<K: Display, const C: char, V: Display> Display for Pair<K, C, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(f, "{}: {}", self.0, self.1)
    }
}
impl<K: FromStr, const C: char, V: FromStr> FromStr for Pair<K, C, V> where K::Err: 'static + Send + Sync + std::error::Error, V::Err: 'static + Send + Sync + std::error::Error, {
    type Err = PairParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Find the separator to split on
        let sep_pos: usize = match s.find(C) {
            Some(pos) => pos,
            None      => { return Err(PairParseError::MissingSeparator{ separator: C, raw: s.into() }); },
        };

        // Split it
        let skey   : &str = &s[..sep_pos];
        let svalue : &str = &s[sep_pos + 1..];

        // Attempt to parse the something as the key
        let key   : K = K::from_str(skey).map_err(|err| PairParseError::IllegalSomething{ what: std::any::type_name::<K>(), raw: skey.into(), err: Box::new(err) })?;
        let value : V = V::from_str(svalue).map_err(|err| PairParseError::IllegalSomething{ what: std::any::type_name::<V>(), raw: svalue.into(), err: Box::new(err) })?;

        // OK, return ourselves
        Ok(Self(key, value))
    }
}





/***** LIBRARY *****/
/// Defines a collection of Docker options to pass to the `start`-subcommand handler.
#[derive(Clone, Debug)]
pub struct StartDockerOpts {
    /// The location of the Docker socket with which to connect.
    pub socket  : PathBuf,
    /// The client version with which to connect.
    pub version : DockerClientVersion, 
}

/// Defines a collection of options to pass to the `start`-subcommand handler.
#[derive(Clone, Debug)]
pub struct StartOpts {
    /// Whether to enable extra verbosity for Docker Compose.
    pub compose_verbose : bool,

    /// The Brane version to start.
    pub version     : Version,
    /// The image base directory, which is used to easily switch between using `./target/release` and `./target/debug`.
    pub image_dir   : PathBuf,
    /// Use local .tars for auxillary images instead of DockerHub ones.
    pub local_aux   : bool,
    /// Do not import any images if given, but instead assume they are already loaded.
    pub skip_import : bool,
    /// If given, mounts the given profile directory to examine profiling results conveniently.
    pub profile_dir : Option<PathBuf>
}



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
        hostname : String,

        /// Custom `infra.yml` path.
        #[clap(short, long, default_value = "$CONFIG/infra.yml", help = "The location of the 'infra.yml' file. Use '$CONFIG' to reference the value given by '--config-path'.")]
        infra    : PathBuf,
        /// Custom `proxy.yml` path.
        #[clap(short='P', long, default_value = "$CONFIG/proxy.yml", help = "The location of the 'proxy.yml' file. Use '$CONFIG' to reference the value given by '--config-path'.")]
        proxy    : PathBuf,
        /// Custom certificates path.
        #[clap(short, long, default_value = "$CONFIG/certs", help = "The location of the certificate directory. Use '$CONFIG' to reference the value given by '--config-path'.")]
        certs    : PathBuf,
        /// Custom packages path.
        #[clap(long, default_value = "./packages", help = "The location of the package directory.")]
        packages : PathBuf,

        /// If given, disables the proxy service on this host.
        #[clap(long, conflicts_with_all = [ "prx_name", "prx_port" ], help = "If given, will use a proxy service running on the external address instead of one in this Docker service. This will mean that it will _not_ be spawned when running 'branectl start'.")]
        external_proxy : Option<Address>,

        /// The name of the API service.
        #[clap(long, default_value = "brane-api", help = "The name of the API service's container.")]
        api_name : String,
        /// The name of the driver service.
        #[clap(long, default_value = "brane-drv", help = "The name of the driver service's container.")]
        drv_name : String,
        /// The name of the planner service.
        #[clap(long, default_value = "brane-plr", help = "The name of the planner service's container.")]
        plr_name : String,
        /// The name of the proxy service.
        #[clap(long, default_value = "brane-prx", help = "The name of the proxy service's container.")]
        prx_name : String,

        /// The port of the API service.
        #[clap(short, long, default_value = "50051", help = "The port on which the API service is available.")]
        api_port : u16,
        /// The port of the driver service.
        #[clap(short, long, default_value = "50053", help = "The port on which the driver service is available.")]
        drv_port : u16,
        /// The port of the proxy service.
        #[clap(short, long, default_value = "50050", help = "The port on which the proxy service is available.")]
        prx_port : u16,

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
        /// The hostname of this node.
        #[clap(name = "HOSTNAME", help = "The hostname that other nodes in the instance can use to reach this node.")]
        hostname    : String,
        /// The location ID of this node.
        #[clap(name = "LOCATION_ID", help = "The location identifier (location ID) of this node.")]
        location_id : String,

        /// Custom backend file path.
        #[clap(long, default_value = "$CONFIG/backend.yml", help = "The location of the `backend.yml` file. Use `$CONFIG` to reference the value given by --config-path. ")]
        backend      : PathBuf,
        /// Custom hash file path.
        #[clap(long, default_value = "$CONFIG/policies.yml", help = "The location of the `policies.yml` file that determines which containers and users are allowed to be executed. Use `$CONFIG` to reference the value given by --config-path.")]
        policies     : PathBuf,
        /// Custom `proxy.yml` path.
        #[clap(short='P', long, default_value = "$CONFIG/proxy.yml", help = "The location of the 'proxy.yml' file. Use '$CONFIG' to reference the value given by '--config-path'.")]
        proxy        : PathBuf,
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

        /// If given, disables the proxy service on this host.
        #[clap(long, conflicts_with_all = [ "prx_name", "prx_port" ], help = "If given, will use a proxy service running on the external address instead of one in this Docker service. This will mean that it will _not_ be spawned when running 'branectl start'.")]
        external_proxy : Option<Address>,

        /// The address on which to launch the registry service.
        #[clap(long, default_value = "brane-reg-$LOCATION", help = "The name of the local registry service's container. Use '$LOCATION' to use the location ID.")]
        reg_name : String,
        /// The address on which to launch the driver service.
        #[clap(long, default_value = "brane-job-$LOCATION", help = "The name of the local delegate service's container. Use '$LOCATION' to use the location ID.")]
        job_name : String,
        /// The address on which to launch the checker service.
        #[clap(long, default_value = "brane-chk-$LOCATION", help = "The name of the local checker service's container. Use '$LOCATION' to use the location ID.")]
        chk_name : String,
        /// The name of the proxy service.
        #[clap(long, default_value = "brane-prx-$LOCATION", help = "The name of the local proxy service's container. Use '$LOCATION' to use the location ID.")]
        prx_name : String,

        /// The address on which to launch the registry service.
        #[clap(long, default_value = "50051", help = "The port on which the local registry service is available.")]
        reg_port : u16,
        /// The address on which to launch the driver service.
        #[clap(long, default_value = "50052", help = "The port on which the local delegate service is available.")]
        job_port : u16,
        /// The address on which to launch the checker service.
        #[clap(long, default_value = "50053", help = "The port on which the local checker service is available.")]
        chk_port : u16,
        /// The port of the proxy service.
        #[clap(short, long, default_value = "50050", help = "The port on which the local proxy service is available.")]
        prx_port : u16,
    },

    /// Starts a proxy node.
    #[clap(name = "proxy", about = "Generate a node.yml file for a proxy node with default values.")]
    Proxy {
        /// The hostname of this node.
        #[clap(name = "HOSTNAME", help = "The hostname that other nodes in the instance can use to reach this node.")]
        hostname : String,

        /// Custom `proxy.yml` path.
        #[clap(short='P', long, default_value = "$CONFIG/proxy.yml", help = "The location of the 'proxy.yml' file. Use '$CONFIG' to reference the value given by '--config-path'.")]
        proxy : PathBuf,
        /// Custom certificates path.
        #[clap(short, long, default_value = "$CONFIG/certs", help = "The location of the certificate directory. Use '$CONFIG' to reference the value given by --config-path.")]
        certs : PathBuf,

        /// The name of the proxy service.
        #[clap(long, default_value = "brane-prx", help = "The name of the local proxy service's container.")]
        prx_name : String,

        /// The port of the proxy service.
        #[clap(short, long, default_value = "50050", help = "The port on which the local proxy service is available.")]
        prx_port : u16,
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
        #[clap(short = 's', long, help = "The image to load for the aux-scylla service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Default: 'Registry<scylladb/scylla:4.6.3>', unless '--local-aux' is given. In that case, 'Path<$IMG_DIR/aux-scylla.tar>' is used as default instead.")]
        aux_scylla    : Option<ImageSource>,
        /// The path (or other source) to the `aux-kafka` service.
        #[clap(short = 'k', long, help = "The image to load for the aux-kafka service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Default: 'Registry<ubuntu/kafka:3.1-22.04_beta>', unless '--local-aux' is given. In that case, 'Path<$IMG_DIR/aux-kafka.tar>' is used as default instead.")]
        aux_kafka     : Option<ImageSource>,
        /// The path (or other source) to the `aux-zookeeper` service.
        #[clap(short = 'z', long, help = "The image to load for the aux-zookeeper service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Default: 'Registry<ubuntu/zookeeper:3.1-22.04_beta>', unless '--local-aux' is given. In that case, 'Path<$IMG_DIR/aux-zookeeper.tar>' is used as default instead.")]
        aux_zookeeper : Option<ImageSource>,
        /// The path (or other source) to the `aux-xenon` service.
        #[clap(short = 'm', long, default_value = "Path<$IMG_DIR/aux-xenon.tar>", help = "The image to load for the aux-xenon service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        aux_xenon     : ImageSource,

        /// The path (or other source) to the `brane-prx` service.
        #[clap(short = 'P', long, default_value = "Path<$IMG_DIR/brane-prx.tar>", help = "The image to load for the brane-prx service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_prx : ImageSource,
        /// The path (or other source) to the `brane-api` service.
        #[clap(short = 'a', long, default_value = "Path<$IMG_DIR/brane-api.tar>", help = "The image to load for the brane-plr service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_api : ImageSource,
        /// The path (or other source) to the `brane-drv` service.
        #[clap(short = 'd', long, default_value = "Path<$IMG_DIR/brane-drv.tar>", help = "The image to load for the brane-drv service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_drv : ImageSource,
        /// The path (or other source) to the `brane-plr` service.
        #[clap(short = 'p', long, default_value = "Path<$IMG_DIR/brane-plr.tar>", help = "The image to load for the brane-plr service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_plr : ImageSource,
    },

    /// Starts a worker node.
    #[clap(name = "worker", about = "Starts a worker node based on the values in the local node.yml file.")]
    Worker {
        /// The path (or other source) to the `brane-prx` service.
        #[clap(short = 'P', long, default_value = "Path<$IMG_DIR/brane-prx.tar>", help = "The image to load for the brane-prx service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_prx : ImageSource,
        /// The path (or other source) to the `brane-api` service.
        #[clap(short = 'r', long, default_value = "Path<$IMG_DIR/brane-reg.tar>", help = "The image to load for the brane-reg service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_reg : ImageSource,
        /// The path (or other source) to the `brane-drv` service.
        #[clap(short = 'j', long, default_value = "Path<$IMG_DIR/brane-job.tar>", help = "The image to load for the brane-job service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_job : ImageSource,
    },

    /// Starts a proxy node.
    #[clap(name = "proxy", about = "Starts a proxy node based on the values in the local node.yml file.")]
    Proxy {
        /// The path (or other source) to the `brane-prx` service.
        #[clap(short = 'P', long, default_value = "Path<$IMG_DIR/brane-prx.tar>", help = "The image to load for the brane-prx service. If it's a path that exists, will attempt to load that file; otherwise, assumes it's an image name in a remote registry. You can wrap your names in either `Path<...>` or `Registry<...>` if it matters. Finally, use '$IMG_DIR' to reference the value indicated by '--image-dir'.")]
        brane_prx : ImageSource,
    },
}
