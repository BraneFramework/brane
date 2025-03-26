//  WIZARD.rs
//    by Lut99
//
//  Created:
//    01 Jun 2023, 12:43:20
//  Last edited:
//    07 Mar 2024, 09:54:57
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a CLI wizard for setting up nodes, making the process
//!   _even_ easier.
//

use std::borrow::Cow;
use std::collections::HashMap;
use std::error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use brane_cfg::info::Info;
use brane_cfg::node::{self, NodeConfig, NodeKind, NodeSpecificConfig};
use brane_cfg::proxy::{ForwardConfig, ProxyConfig, ProxyProtocol};
use brane_shr::input::{FileHistory, confirm, input, input_map, input_path, select};
use console::style;
use dirs::config_dir;
use enum_debug::EnumDebug as _;
use specifications::address::Address;
use tracing::{debug, info};
use validator::{FromStrValidator, MapValidator, PortValidator, RangeValidator};

pub mod validator;

use crate::spec::InclusiveRange;

type PortRangeValidator = RangeValidator<PortValidator>;
type AddressValidator = FromStrValidator<Address>;
type PortMapValidator = MapValidator<PortValidator, AddressValidator>;

/***** HELPER MACROS *****/
/// Generates a FileHistory that points to some branectl-specific directory in the [`config_dir()`].
macro_rules! hist {
    ($name:literal) => {{
        let hist = FileHistory::new(config_dir().unwrap().join("branectl").join("history").join($name));
        debug!("{hist:?}");
        hist
    }};
}

/// Writes a few lines that generate a directory, with logging statements.
///
/// # Arguments
/// - `[$name, $value]`: The name and subsequent value of the variable that contains the given path.
macro_rules! generate_dir {
    ($value:ident) => {
        if !$value.exists() {
            debug!("Generating '{}'...", $value.display());
            if let Err(err) = fs::create_dir(&$value) {
                return Err(Error::GenerateDir { path: $value, err });
            }
        }
    };

    ($name:ident, $value:expr) => {
        let $name: PathBuf = $value;
        generate_dir!($name);
    };
}





/***** ERRORS *****/
/// Defines errors that relate to the wizard.
#[derive(Debug)]
pub enum Error {
    /// Failed to query the user for the node config file.
    NodeConfigQuery { err: Box<Self> },
    /// Failed to write the node config file.
    NodeConfigWrite { err: Box<Self> },
    /// Failed to query the user for the proxy config file.
    ProxyConfigQuery { err: Box<Self> },
    /// Failed to write the proxy config file.
    ProxyConfigWrite { err: Box<Self> },

    /// Failed to create a new file.
    ConfigCreate { path: PathBuf, err: std::io::Error },
    /// Failed to generate a configuration file.
    ConfigSerialize { path: PathBuf, err: brane_cfg::info::YamlError },
    /// Failed to write to the config file.
    ConfigWrite { path: PathBuf, err: std::io::Error },
    /// Failed to generate a directory.
    GenerateDir { path: PathBuf, err: std::io::Error },
    /// Failed the query the user for input.
    ///
    /// The `what` should fill in: `Failed to query the user for ...`
    Input { what: &'static str, err: brane_shr::input::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            NodeConfigQuery { .. } => write!(f, "Failed to query node configuration"),
            NodeConfigWrite { .. } => write!(f, "Failed to write node config file"),
            ProxyConfigQuery { .. } => write!(f, "Failed to query proxy service configuration"),
            ProxyConfigWrite { .. } => write!(f, "Failed to write proxy service config file"),

            ConfigCreate { path, .. } => write!(f, "Failed to create config file '{}'", path.display()),
            ConfigSerialize { path, .. } => write!(f, "Failed to serialize config to '{}'", path.display()),
            ConfigWrite { path, .. } => write!(f, "Failed to write to config file '{}'", path.display()),
            GenerateDir { path, .. } => write!(f, "Failed to generate directory '{}'", path.display()),
            Input { what, .. } => write!(f, "Failed to query the user for {what}"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn 'static + error::Error)> {
        use Error::*;
        match self {
            NodeConfigQuery { err } => Some(err),
            NodeConfigWrite { err } => Some(err),
            ProxyConfigQuery { err } => Some(err),
            ProxyConfigWrite { err } => Some(err),

            ConfigCreate { err, .. } => Some(err),
            ConfigSerialize { err, .. } => Some(err),
            ConfigWrite { err, .. } => Some(err),
            GenerateDir { err, .. } => Some(err),
            Input { err, .. } => Some(err),
        }
    }
}





/***** HELPER FUNCTIONS *****/
/// Writes a given [`Config`] to disk.
///
/// This wraps the default [`Config::to_path()`] function to also include a nice header.
///
/// # Arguments
/// - `config`: The [`Config`]-file to write.
/// - `path`: The path to write the file to.
/// - `url`: The wiki-URL to write in the file.
///
/// # Errors
/// This function may error if we failed to write any of this.
///
/// # Panics
/// This function may panic if the given path has no filename.
fn write_config<C>(config: C, path: impl AsRef<Path>, url: impl AsRef<str>) -> Result<(), Error>
where
    C: Info<Error = serde_yaml::Error>,
{
    let path: &Path = path.as_ref();
    let url: &str = url.as_ref();
    debug!("Generating config file '{}'...", path.display());

    // Deduce the filename
    let filename: Cow<str> = match path.file_name() {
        Some(filename) => filename.to_string_lossy(),
        None => {
            panic!("No filename found in '{}'", path.display());
        },
    };

    // Convert the filename to nice header
    let mut header_name: String = String::with_capacity(filename.len());
    let mut saw_lowercase: bool = false;
    let mut ext: bool = false;
    for c in filename.chars() {
        if !ext && c == '.' {
            // Move to extension mode
            header_name.push('.');
            ext = true;
        } else if !ext && (c == ' ' || c == '-' || c == '_') {
            // Write it as a space
            header_name.push(' ');
        } else if !ext && saw_lowercase && c.is_ascii_uppercase() {
            // Write is with a space, since we assume it's a word boundary in camelCase
            header_name.push(' ');
            header_name.push(c);
        } else if !ext && c.is_ascii_lowercase() {
            // Capitalize it
            header_name.push((c as u8 - b'a' + b'A') as char);
        } else {
            // The rest is pushed as-is
            header_name.push(c);
        }

        // Update whether we saw a lowercase last step
        saw_lowercase = c.is_ascii_lowercase();
    }

    // Create a file, now
    let mut handle: File = match File::create(path) {
        Ok(handle) => handle,
        Err(err) => {
            return Err(Error::ConfigCreate { path: path.into(), err });
        },
    };

    // Write the header to a string
    if let Err(err) = writeln!(handle, "# {header_name}") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle, "#   by branectl") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle, "# ") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle, "# This file has been generated using the `branectl wizard` subcommand. You can") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle, "# manually change this file after generation; it is just a normal YAML file.") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle, "# Documentation for how to do so can be found here:") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle, "# {url}") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle, "# ") {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };
    if let Err(err) = writeln!(handle) {
        return Err(Error::ConfigWrite { path: path.into(), err });
    };

    // Write the remainder of the file
    if let Err(err) = config.to_writer(handle, true) {
        return Err(Error::ConfigSerialize { path: path.into(), err });
    }
    Ok(())
}

/***** QUERY FUNCTIONS *****/
/// Queries the user for the proxy services configuration.
///
/// # Returns
/// A new [`ProxyConfig`] that reflects the user's choices.
///
/// # Errors
/// This function may error if we failed to query the user.
pub fn query_proxy_config() -> Result<ProxyConfig, Error> {
    // Query the user for the range
    let range: InclusiveRange<u16> = match input(
        "port range",
        "P1. Enter the range of ports allocated for outgoing connections",
        Some(InclusiveRange::new(4200, 4299)),
        Some(PortRangeValidator::default()),
        Some(hist!("prx-outgoing_range.hist")),
    ) {
        Ok(range) => range,
        Err(err) => {
            return Err(Error::Input { what: "outgoing range", err });
        },
    };
    debug!("Outgoing range: [{}, {}]", range.0.start(), range.0.end());
    println!();

    // Read the map of incoming ports
    let incoming: HashMap<u16, Address> = match input_map(
        "port",
        "address",
        "P2.1. Enter an incoming port map as '<incoming port>:<destination address>:<destination port>' (or leave empty to specify none)",
        "P2.%I. Enter an additional incoming port map as '<port>:<destination address>' (or leave empty to finish)",
        ":",
        // None::<NoValidator>,
        Some(PortMapValidator { allow_empty: true, ..Default::default() }),
        Some(hist!("prx-incoming.hist")),
    ) {
        Ok(incoming) => incoming,
        Err(err) => {
            return Err(Error::Input { what: "outgoing range", err });
        },
    };
    debug!("Incoming ports map:\n{:#?}", incoming);
    println!();

    // Finally, read any proxy
    let to_proxy_or_not_to_proxy: bool = match confirm("P3. Do you want to route outgoing traffic through a SOCKS proxy?", Some(false)) {
        Ok(yesno) => yesno,
        Err(err) => {
            return Err(Error::Input { what: "proxy confirmation", err });
        },
    };
    let forward: Option<ForwardConfig> = if to_proxy_or_not_to_proxy {
        // Query the address
        let address: Address = match input(
            "address",
            "P3a. Enter the target address (including port) to route the traffic to",
            None::<Address>,
            Some(AddressValidator::default()),
            Some(hist!("prx-forward-address.hist")),
        ) {
            Ok(address) => address,
            Err(err) => {
                return Err(Error::Input { what: "forwarding address", err });
            },
        };

        // Query the protocol
        let protocol: ProxyProtocol =
            match select("P3b. Enter the protocol to use to route traffic", vec![ProxyProtocol::Socks5, ProxyProtocol::Socks6], Some(0)) {
                Ok(prot) => prot,
                Err(err) => {
                    return Err(Error::Input { what: "forwarding protocol", err });
                },
            };

        // Construct the config
        Some(ForwardConfig { address, protocol })
    } else {
        None
    };
    debug!("Using forward config: {:?}", forward);
    println!();

    // Construct the ProxyConfig to return it
    Ok(ProxyConfig { outgoing_range: range.0, incoming, forward })
}

/// Queries the user for the node file configuration.
///
/// # Returns
/// A new [`NodeConfig`] that reflects the user's choices.
///
/// # Errors
/// This function may error if we failed to query the user.
pub fn query_proxy_node_config() -> Result<NodeConfig, Error> {
    // Construct the ProxyConfig to return it
    Ok(NodeConfig {
        hostnames: HashMap::new(),
        namespace: String::new(),
        node:      NodeSpecificConfig::Proxy(node::ProxyConfig {
            paths:    node::ProxyPaths { certs: "".into(), proxy: "".into() },
            services: node::ProxyServices {
                prx: node::PublicService {
                    name: "brane-prx".into(),
                    address: Address::Hostname("test.com".into(), 42),
                    bind: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 0)),
                    external_address: Address::Hostname("test.com".into(), 42),
                },
            },
        }),
    })
}





/***** LIBRARY *****/
/// Main handler for the `branectl wizard setup` (or `branectl wizard node`) subcommand.
///
/// # Arguments
///
/// # Errors
/// This function may error if any of the wizard steps fail.
pub fn setup() -> Result<(), Error> {
    info!("Running wizard to setup a new node...");

    // Let us setup the history structure
    generate_dir!(_path, config_dir().unwrap().join("branectl"));
    generate_dir!(_path, config_dir().unwrap().join("branectl").join("history"));

    // Do an intro prompt
    println!();
    println!(
        "{}{}{}",
        style("Welcome to ").bold(),
        style("Node Setup Wizard").bold().green(),
        style(format!(" for BRANE v{}", env!("CARGO_PKG_VERSION"))).bold()
    );
    println!();
    println!("This wizard will guide you through the process of setting up a node interactively.");
    println!("Simply answer the questions, and the required configuration files will be generated as you go.");
    println!();
    println!("You can abort the wizard at any time by pressing {}.", style("Ctrl+C").bold().green());
    println!();

    // Select the path where we will go to
    let mut prompt: Cow<str> = Cow::Borrowed("1. Select the location of the node configuration files");
    let path: PathBuf = loop {
        // Query the path
        let path: PathBuf = match input_path(prompt, Some("./"), Some(hist!("output_path.hist"))) {
            Ok(path) => path,
            Err(err) => {
                return Err(Error::Input { what: "config path", err });
            },
        };

        // Ask to create it if it does not exist
        if !path.exists() {
            // Do the question
            let ok: bool = match confirm("Directory '{}' does not exist. Create it?", Some(true)) {
                Ok(ok) => ok,
                Err(err) => {
                    return Err(Error::Input { what: "directory creation confirmation", err });
                },
            };

            // Create it, lest continue and try again
            if ok {
                generate_dir!(path);
            }
        }

        // Assert it's a directory
        if path.is_dir() {
            break path;
        }
        prompt = Cow::Owned(format!("Path '{}' does not point to a directory; specify another", path.display()));
    };
    debug!("Configuration directory: '{}'", path.display());
    println!();

    // Generate the configuration directories already
    generate_dir!(config_dir, path.join("config"));
    generate_dir!(certs_dir, config_dir.join("certs"));

    // Let us query the user for the type of node
    let kind: NodeKind = match select("2. Select the type of node to generate", [NodeKind::Central, NodeKind::Worker, NodeKind::Proxy], None) {
        Ok(kind) => kind,
        Err(err) => {
            return Err(Error::Input { what: "node kind", err });
        },
    };
    debug!("Building for node kind '{}'", kind.variant());
    println!();

    // Do a small intermittent text, which will be finished by node-specific contexts
    println!("You have selected to create a new {} node.", style(kind).bold().green());
    println!("For this node type, the following configuration files have to be generated:");

    // The rest is node-dependent
    match kind {
        NodeKind::Central => {},

        NodeKind::Worker => {},

        NodeKind::Proxy => {
            println!(" - {}", style(config_dir.join("proxy.yml").display()).bold());
            println!();

            // Note: we don't check if the user wants a custom config, since they very likely want it if they are setting up a proxy node
            // For the proxy, we only need to read the proxy config
            println!("=== proxy.yml===");
            let cfg: ProxyConfig = match query_proxy_config() {
                Ok(cfg) => cfg,
                Err(err) => {
                    return Err(Error::ProxyConfigQuery { err: Box::new(err) });
                },
            };
            let proxy_path: PathBuf = config_dir.join("proxy.yml");
            if let Err(err) = write_config(cfg, proxy_path, "https://wiki.enablingpersonalizedinterventions.nl/user-guide/config/admins/proxy.html") {
                return Err(Error::ProxyConfigWrite { err: Box::new(err) });
            }

            // Now we generate the node.yml file
            println!("=== node.yml ===");
            let node: NodeConfig = match query_proxy_node_config() {
                Ok(node) => node,
                Err(err) => {
                    return Err(Error::NodeConfigQuery { err: Box::new(err) });
                },
            };
            let node_path: PathBuf = path.join("node.yml");
            if let Err(err) = write_config(node, node_path, "https://wiki.enablingpersonalizedinterventions.nl/user-guide/config/admins/node.html") {
                return Err(Error::NodeConfigWrite { err: Box::new(err) });
            }
        },
    }

    // Done!
    Ok(())
}
