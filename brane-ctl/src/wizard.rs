//  WIZARD.rs
//    by Lut99
//
//  Created:
//    01 Jun 2023, 12:43:20
//  Last edited:
//    07 Mar 2024, 09:54:57
//  Auto updated?
//   Yes
//
//  Description:
//!   Implements a CLI wizard for setting up nodes, making the process
//!   _even_ easier.
//
//
//
//! This module assumes the following default file structure.
//! Where possible the framework will attempt not to enforce this structure, but
//! adhering to this file structure will hopefully allow the framework to infer
//! a lot of locations, which in turn can save a lot of configuration work.
//!
//! If you are setting up only a single node, you can try to use the relevant
//! subdirectory and the framework should be able to work pretty well with this as well
//!
//! ```text
//! configuration
//! ├──central
//! │  ├──config
//! │  │  ├──certs
//! │  │  │  └──hospital1
//! │  │  │     └──ca.pem
//! │  │  ├──infra.yml
//! │  │  └──proxy.yml
//! │  └──node.yml
//! │
//! ├──workers
//! │  ├──hospital1
//! │  │  ├──config
//! │  │  │  ├──certs
//! │  │  │  │  └──<domain certs>
//! │  │  │  ├──backend.yml
//! │  │  │  ├──policy_deliberation_secret.yml
//! │  │  │  ├──policy_expert_secret.yml
//! │  │  │  └──proxy.yml
//! │  │  ├──policies.db
//! │  │  └──node.yml
//! │  │
//! │  └──research_centre2
//! │     ├──config
//! │     │  ├──certs
//! │     │  │  └──<domain certs>
//! │     │  ├──backend.yml
//! │     │  ├──policy_deliberation_secret.yml
//! │     │  ├──policy_expert_secret.yml
//! │     │  └──proxy.yml
//! │     ├──policies.db
//! │     └──node.yml
//! │
//! └──users
//!    ├──tim
//!    │  ├──jwt_expert.json
//!    │  └──jwt_delib.json
//!    └──dan
//!       └──jwt_expert.json
//! ```

use std::borrow::Cow;
use std::collections::HashMap;
use std::error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::fs::{self, File};
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

// I think we might be able to do better than foo, however it is the default in generate as well
const DEFAULT_KEY_ID: &str = "foo";

use brane_cfg::info::{Info, InfoError};
use brane_cfg::infra::{InfraFile, InfraLocation};
use brane_cfg::node::{self, NodeConfig, NodeKind, NodeSpecificConfig};
use brane_cfg::proxy::{ForwardConfig, ProxyConfig, ProxyProtocol};
use brane_shr::input::{FileHistory, confirm, input, input_map, input_option, input_path, select, select_enum};
use console::style;
use dirs::data_dir;
use enum_debug::EnumDebug as _;
use error_trace::trace;
use jsonwebtoken::jwk::KeyAlgorithm;
use log::{debug, info, warn};
use specifications::address::{Address, Host};
use specifications::constants::*;
use validator::{FromStrValidator, MapValidator, OptionValidator, PortValidator, RangeValidator};

pub mod validator;

use crate::generate;
use crate::spec::InclusiveRange;

type PortRangeValidator = RangeValidator<PortValidator>;
type AddressValidator = FromStrValidator<Address>;
type HostValidator = FromStrValidator<Host>;
type PortMapValidator = MapValidator<PortValidator, AddressValidator>;

type LocationId = String;
type LocationIdValidator = FromStrValidator<LocationId>;
type LocationMapValidator = MapValidator<LocationIdValidator, HostValidator>;

type HostnameMapping = HashMap<Host, IpAddr>;

/// Generates a FileHistory that points to some branectl-specific directory in the [`data_dir()`].
// TODO: We could create something like a history service that will only complain once if we cannot
// create the directory
#[inline(always)]
fn hist(filename: impl AsRef<Path>) -> Option<FileHistory> {
    let Some(data_path) = data_dir() else {
        debug!("Could not find path to store history file in.");
        return None;
    };
    let history_dir = data_path.join("branectl").join("history");

    let history_path = history_dir.join(filename);

    if !history_path.exists() {
        if let Err(err) = fs::create_dir_all(history_dir) {
            debug!("{}", trace!(("Could not create directory for history files"), err));
            return None;
        }

        return Some(FileHistory::new(history_path));
    }

    Some(FileHistory::from_file_or_new(history_path))
}


#[inline(always)]
fn generate_dir(path: impl AsRef<Path>) -> Result<(), Error> {
    let path = path.as_ref();
    if !path.exists() {
        debug!("Generating '{}'...", path.display());
        if let Err(err) = fs::create_dir(path) {
            return Err(Error::GenerateDir { path: path.to_owned(), err });
        }
    }

    Ok(())
}

/// Ensures the directory either exists or will ask the user to create it.
/// The functions returns whether the directory exists after the function
#[inline(always)]
fn ensure_dir_with_confirmation(path: impl AsRef<Path>, prompt: Option<String>) -> Result<bool, Error> {
    let path = path.as_ref();

    if path.exists() {
        return Ok(true);
    }

    let prompt = prompt.unwrap_or_else(|| format!("Directory '{}' does not exist. Create it?", path.display()));

    if !confirm(prompt, Some(true)).map_err(|err| Error::Input { what: "directory creation confirmation", err })? {
        return Ok(false);
    }

    debug!("Generating '{}'...", path.display());
    fs::create_dir(path).map_err(|err| Error::GenerateDir { path: path.to_owned(), err })?;

    Ok(true)
}

#[derive(PartialEq)]
pub enum Wizard {
    /// A wizard to set up the node types
    Node,
    /// A wizard to create the different secrets used in brane
    Secrets,
    /// A wizard that triggers the wizard for single files
    PartialConfiguration,
}

impl From<&Wizard> for &'static str {
    fn from(value: &Wizard) -> Self {
        match value {
            Wizard::Node => "Node",
            Wizard::Secrets => "Secrets",
            Wizard::PartialConfiguration => "Partial configuration",
        }
    }
}

impl Wizard {
    /// The entry point for the wizard. It will start the wizard and start prompting the user to
    /// figure out what it wants to create
    pub async fn run() -> Result<(), Error> {
        info!("Started the branectl wizard");

        // Do an intro prompt
        indoc::printdoc!(
            "

            {welcome}{wizard}{brane_version}

            This wizard will guide you through the process of setting up a node interactively.
            Simply answer the questions, and the required configuration files will be generated as you go.

            You can abort the wizard a any time by pressing {ctrl_c}.

        ",
            ctrl_c = style("Ctrl+C").bold().green(),
            welcome = style("Welcome to ").bold(),
            wizard = style("Node Setup Wizard").bold().green(),
            brane_version = style(format!(" for BRANE v{}", env!("CARGO_PKG_VERSION"))).bold(),
        );

        let mut prompt: Cow<str> = Cow::Borrowed("1. Select the location of the node configuration files");
        let path: PathBuf = loop {
            // Query the path
            let path: PathBuf = input_path(prompt, Some("./"), hist("output_path.hist")).map_err(|err| Error::Input { what: "config path", err })?;

            // Ask to create it if it does not exist
            ensure_dir_with_confirmation(&path, Some(String::from("The configuration directory does not exist yet? Do you want to create it?")))?;

            // Assert it's a directory
            if path.is_dir() {
                break path;
            }
            prompt = Cow::Owned(format!("Path '{}' does not point to a directory; specify another", path.display()));
        };
        debug!("Configuration directory: '{}'", path.display());

        match select_enum::<Wizard>("What would you like to create/configure?", [Wizard::Node, Wizard::Secrets, Wizard::PartialConfiguration], None)
            .map_err(|err| Error::Input { what: "Wizard type", err })?
        {
            Wizard::Node => {
                NodeWizard::run(path).await?;
            },
            Wizard::Secrets => {
                SecretWizard::run(path)?;
            },
            Wizard::PartialConfiguration => {
                todo!("In the future it should be possible to separately generate all the configuration files");
            },
        }

        Ok(())
    }
}

impl Display for Wizard {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", std::convert::Into::<&str>::into(self)) }
}

enum NodeWizard {
    Central,
    Worker,
}

impl NodeWizard {
    async fn run(path: impl AsRef<Path>) -> Result<(), Error> {
        let config_dir = path.as_ref();
        // Select the path where we will go to
        println!();

        // Let us query the user for the type of node
        let kind: NodeKind = select("2. Select the type of node to generate", [NodeKind::Central, NodeKind::Worker, NodeKind::Proxy], None)
            .map_err(|err| Error::Input { what: "node kind", err })?;

        debug!("Building for node kind '{}'", kind.variant());

        // Do a small intermittent text, which will be finished by node-specific contexts
        indoc::printdoc!(
            "
            You have selected to create a new {kind} node.
            For this node type, the following configuration files have to be generated:
        ",
            kind = style(kind).bold().green()
        );


        // The rest is node-dependent
        match kind {
            NodeKind::Central => CentralNodeWizard::run(config_dir).await?,
            NodeKind::Worker => WorkerNodeWizard::run(config_dir).await?,
            NodeKind::Proxy => ProxyNodeWizard::run(config_dir)?,
        }

        // Done!
        Ok(())
    }
}


// FIXME: This structure is not entirely correct, we are using a non-constructable enum as a
// namepsace here, we probably want something like modules, but for now we just need to split up
// these 1500 lines into _some_ structure.
enum CentralNodeWizard {}

impl CentralNodeWizard {
    async fn run(configuration_dir: impl AsRef<Path>) -> Result<(), Error> {
        let configuration_dir = configuration_dir.as_ref();

        // TODO: Prompt user for input
        let hosts = Default::default();

        let location_id: LocationId =
            input("Enter the <location_id>", "<location_id>", None::<&str>, Some(LocationIdValidator::default()), hist("location_id"))
                .map_err(|err| Error::Input { what: "Location id", err })?;

        let central_node_dir = configuration_dir.join(&location_id);
        let central_node_config_dir = central_node_dir.join("config");

        generate_dir(&central_node_dir)?;
        generate_dir(&central_node_config_dir)?;

        println!(" - {}", style(central_node_config_dir.join("infra.yml").display()).bold());
        println!(" - {}", style(central_node_config_dir.join("proxy.yml").display()).bold());
        println!(" - {}", style(central_node_config_dir.join("node.yml").display()).bold());
        println!();

        // === infra.yml ===
        let infra_path = Self::create_infra_config(configuration_dir, &central_node_config_dir)?;

        // === proxy.yml ===
        let proxy_path = ProxyNodeWizard::create_proxy_config(&central_node_config_dir)?;

        println!("{}", style("=== node.yml ===").bold());
        println!("The default settings for node.yml are listed below:");

        let use_node_defaults =
            confirm("Do you wish to use these defaults?", Some(true)).map_err(|err| Error::Input { what: "default central node", err })?;

        let prx_port = Self::query_service_port("Proxy (PRX)", BRANE_CENTRAL_PRX_PORT, use_node_defaults)?;
        let plr_port = Self::query_service_port("Planner (PLR)", BRANE_CENTRAL_PLR_PORT, use_node_defaults)?;
        let api_port = Self::query_service_port("Registry (API)", BRANE_CENTRAL_API_PORT, use_node_defaults)?;
        let drv_port = Self::query_service_port("Driver (DRV)", BRANE_CENTRAL_DRV_PORT, use_node_defaults)?;

        let prx_name = Self::query_service_name("Proxy (PRX)", BRANE_CENTRAL_PRX_NAME, use_node_defaults)?;
        let plr_name = Self::query_service_name("Planner (PLR)", BRANE_CENTRAL_PLR_NAME, use_node_defaults)?;
        let api_name = Self::query_service_name("Registry (API)", BRANE_CENTRAL_API_NAME, use_node_defaults)?;
        let drv_name = Self::query_service_name("Driver (DRV)", BRANE_CENTRAL_DRV_NAME, use_node_defaults)?;

        type OptionalAddressValidator = OptionValidator<String, AddressValidator>;

        let package_path = central_node_dir.join(PACKAGE_PATH);
        if !ensure_dir_with_confirmation(
            &package_path,
            Some(format!("Package directory located at {} does not exist, do you wish to create it?", package_path.display())),
        )? {
            println!("Did not create a package directory, note that this may impact the functionality of the system");
        }

        let external_proxy: Option<Address> = input_option(
            "external proxy",
            "Enter the address on which the proxy can be reached from external addresses. Or leave empty to disable",
            None::<Address>,
            Some(OptionalAddressValidator::default()),
            hist("external-proxy"),
        )
        .map_err(|err| Error::Input { what: "external proxy", err })?;

        let default_hostname = Host::from_str(&gethostname::gethostname().to_string_lossy())
            .inspect_err(|err| warn!("system hostname could not be parsed as a valid hostname: {err:#}"))
            .ok();

        let hostname: Host =
            input("hostname", "Enter the hostname for this node", default_hostname, Some(HostValidator::default()), hist("central-hostname"))
                .map_err(|err| Error::Input { what: "central hostname", err })?;

        let certs_path = central_node_config_dir.join(CERTIFICATE_PATH);
        // TODO: This can be done more elegantly

        if ensure_dir_with_confirmation(
            &certs_path,
            Some(format!("Certificate directory located at: {} does not exist, do you wish to create it?", certs_path.display())),
        )? {
            if confirm("Do you wish to create a server certificate?", Some(false))
                .map_err(|err| Error::Input { what: "Create certificate confirmation", err })?
            {
                let tempdir = tempfile::tempdir().map_err(|err| Error::TempDir { err })?;
                generate::certs(true, &certs_path, tempdir.into_path(), crate::spec::GenerateCertsSubcommand::Server {
                    location_id,
                    hostname: hostname.to_string(),
                })
                .await
                .map_err(|err| Error::GenerateError { what: String::from("Server certificate"), err })?;
            }
        } else {
            println!("Could not create certificates without a directory, continuing")
        }

        let node_params = crate::spec::GenerateNodeSubcommand::Central {
            hostname: hostname.to_string(),
            infra: infra_path,
            proxy: proxy_path,
            certs: certs_path,
            packages: package_path,
            external_proxy,
            api_name,
            drv_name,
            plr_name,
            prx_name,
            api_port,
            plr_port,
            drv_port,
            prx_port,
        };

        let node = generate::generate_node(hosts, true, configuration_dir, node_params)
            .map_err(|err| Error::GenerateError { what: String::from("central node"), err })?;

        write_config(node, central_node_dir.join("node.yml"), CENTRAL_NODE_CONFIG_URL, Some(NODE_HEADER))
            .map_err(|err| Error::NodeConfigWrite { err: Box::new(err) })?;

        Ok(())
    }

    fn query_service_port(port_name: &str, default_port: u16, use_default: bool) -> Result<u16, Error> {
        if use_default {
            Ok(default_port)
        } else {
            let port = input(
                format!("What port would you like for the {port_name} service?"),
                "port",
                Some(default_port),
                Some(PortValidator {}),
                hist("port"),
            )
            .map_err(|err| Error::Input { what: "port", err })?;

            Ok(port)
        }
    }

    fn query_service_name(service_description: &str, default_service_name: &str, use_default: bool) -> Result<String, Error> {
        if use_default {
            Ok(default_service_name.to_string())
        } else {
            let x = input(
                format!("What port would you like for the {service_description} service?"),
                "port",
                Some(default_service_name),
                // FIXME: Wrong validator
                Some(PortValidator {}),
                hist("service_name"),
            )
            .map_err(|err| Error::Input { what: "port", err })?;

            Ok(x)
        }
    }

    async fn create_central_node_prerequisites(
        configuration_dir: impl AsRef<Path>,
        central_node_dir: impl AsRef<Path>,
    ) -> Result<(PathBuf, PathBuf), Error> {
        let config_dir = central_node_dir.as_ref();

        println!(" - {}", style(config_dir.join("infra.yml").display()).bold());
        println!(" - {}", style(config_dir.join("proxy.yml").display()).bold());
        println!(" - {}", style(config_dir.join("node.yml").display()).bold());
        println!();

        let proxy_config_path = ProxyNodeWizard::create_proxy_config(&central_node_dir)?;
        let infra_config_path = Self::create_infra_config(&configuration_dir, &central_node_dir)?;

        println!("{}", style("=== node.yml ===").bold());

        Ok((infra_config_path, proxy_config_path))
    }

    fn create_infra_config(configuration_dir: impl AsRef<Path>, central_node_dir: impl AsRef<Path>) -> Result<PathBuf, Error> {
        let _path = configuration_dir.as_ref();
        let central_node_dir = central_node_dir.as_ref();

        println!("{}", style("=== infra.yml ===").bold());

        generate_dir(central_node_dir)?;

        let infra_file = query_infra_config()?;

        indoc::printdoc!(
            "
            One can set the ports for all services on the worker in case these are different from the defaults.
            This however is not yet supported in the generator. If you need this behaviour. It is recommended you use `branectl generate` instead."
        );
        let infra_path = central_node_dir.join("infra.yml");

        write_config(infra_file, &infra_path, "https://wiki.enablingpersonalizedinterventions.nl/user-guide/config/admins/infra.html", None)
            .map_err(|err| Error::InfraConfigWrite { err: Box::new(err) })?;

        Ok(infra_path)
    }
}

enum WorkerNodeWizard {}

impl WorkerNodeWizard {
    async fn run(config_dir: impl AsRef<Path>) -> Result<(), Error> {
        let config_dir = config_dir.as_ref();

        let location_id: LocationId = input(
            "worker location id",
            "What is the location id of this worker?",
            None::<&str>,
            Some(LocationIdValidator::default()),
            hist("worker-location-id"),
        )
        .map_err(|err| Error::Input { what: "worker location id", err })?;

        // TODO: Sanitize name for path use
        let worker_path = config_dir.join(&location_id);

        println!(" - {}", style(config_dir.join("backend.yml").display()).bold());
        println!(" - {}", style(config_dir.join("proxy.yml").display()).bold());
        println!(" - {}", style(config_dir.join("node.yml").display()).bold());
        println!();

        println!("And lastly:");
        println!(" - {}", style("A 802.1X certificate").bold());
        println!(" - {}", style("policies.db").bold());
        println!();

        println!("{}", style("=== backend.yml ===").bold());
        println!("{}", style("=== proxy.yml ===").bold());
        println!("{}", style("=== node.yml ===").bold());

        Self::create_policy_database(&worker_path).await?;
        Self::create_certificate(&worker_path, &location_id).await?;

        Ok(())
    }

    async fn create_policy_database(worker_path: impl AsRef<Path>) -> Result<(), Error> {
        let worker_path = worker_path.as_ref();

        println!("{}", style("=== policies.db ===").bold());
        if confirm("Would you like to generate a new policy database?", Some(true))
            .map_err(|err| Error::Input { what: "new policy database", err })?
        {
            let policy_database_path = worker_path.join("policies.db");

            if !policy_database_path.exists()
                || confirm(
                    indoc::formatdoc!(
                        "
                        There already exists a policy database on this location, would you like to override it and create a new one?

                        {warning}
                        ",
                        warning = style("Warning: This will erase all the data in the old database.").bold().red()
                    ),
                    Some(false),
                )
                .map_err(|err| Error::Input { what: "remove old policy database", err })?
            {
                generate::policy_database(true, policy_database_path, "main")
                    .await
                    .map_err(|err| Error::GenerateError { what: String::from("policy database"), err })?;
            }
        }

        Ok(())
    }

    async fn create_certificate(worker_path: impl AsRef<Path>, location_id: &LocationId) -> Result<PathBuf, Error> {
        let worker_path = worker_path.as_ref();
        let certificate_path = worker_path.join("certs");

        println!("{}", style("=== 801.1X certificate ===").bold());

        if confirm("Do you want to create a 801.1X certificate?", Some(true))
            .map_err(|err| Error::Input { what: "Confirmation creation 801.1X certificate", err })?
        {
            let default_hostname = Host::from_str(&gethostname::gethostname().to_string_lossy())
                .inspect_err(|err| warn!("system hostname could not be parsed as a valid hostname: {err:#}"))
                .ok();

            let hostname: Host = input(
                "What hostname will be used in this certificate?",
                "hostname",
                default_hostname,
                None::<validator::NoValidator>,
                hist("ca-hostname"),
            )
            .map_err(|err| Error::Input { what: "hostname", err })?;

            let tmp = tempfile::tempdir()
                // FIXME: This is not the right error, but bigger fish to fry first
                .map_err(|err| Error::ConfigCreate { path: "temporary path".into(), err })?;

            generate::certs(true, &certificate_path, tmp.into_path(), crate::spec::GenerateCertsSubcommand::Client {
                location_id: location_id.to_string(),
                hostname:    hostname.to_string(),
                ca_cert:     "ca.pem".into(),
                ca_key:      "ca-key.pem".into(),
            })
            .await
            .map_err(|err| Error::GenerateError { what: String::from("certificate"), err })?;

            if confirm("Do you want to install the certificate on another node?", None)
                .map_err(|err| Error::Input { what: "confirmation installation certificate", err })?
            {
                // TODO: Guess default path
                let destination_path =
                    input_path("Select a node (node.yml) where you want to install this certificate.", None::<&str>, hist("certificate-dest.hist"))
                        .map_err(|err| Error::Input { what: "certificate destination", err })?;

                let destination_node =
                    NodeConfig::from_path(destination_path).map_err(|err| Error::NodeSerialize { what: "certificate destination node", err })?;

                Self::install_certificate(&certificate_path, location_id, destination_node)
                    .map_err(|err| Error::InstallCertificate { path: certificate_path.clone(), err })?;
            }
        }

        Ok(certificate_path)
    }

    fn install_certificate(
        certificate_path: impl AsRef<Path>,
        source_location_id: &LocationId,
        destination_node: NodeConfig,
    ) -> Result<PathBuf, std::io::Error> {
        let certificate_path = certificate_path.as_ref();
        let destination = match destination_node.node {
            NodeSpecificConfig::Central(config) => config.paths.certs,
            NodeSpecificConfig::Worker(config) => config.paths.certs,
            NodeSpecificConfig::Proxy(config) => config.paths.certs,
        };

        let destination_path = destination.join(source_location_id);

        std::fs::copy(certificate_path, &destination_path)?;

        Ok(destination_path)
    }

    fn create_policy_token(dir: impl AsRef<Path>, secret_path: impl AsRef<Path>) -> Result<(), Error> {
        let dir = dir.as_ref();
        let secret_path = secret_path.as_ref();

        println!("{}", style("=== policy_token.json ===").bold());
        if confirm("Would you like to generate a `policy_token.json`", Some(true))
            .map_err(|err| Error::Input { what: "confirmation policy token", err })?
        {
            let initiator = input(
                "initiator",
                "Enter the initiator. The name of the person performing the request.",
                None::<&str>,
                None::<validator::NoValidator>,
                hist("policy-token-initiator.hist"),
            )
            .map_err(|err| Error::Input { what: "policy token initiator", err })?;

            let system = input(
                "system",
                "Enter the system. The name or identifier of the node or other entity through which the request is performed, to embed in the token.",
                None::<&str>,
                None::<validator::NoValidator>,
                hist("policy-token-initiator.hist"),
            )
            .map_err(|err| Error::Input { what: "policy token initiator", err })?;

            // TODO: Add validator
            let exp: String = input(
                "expiration duration",
                "Enter the duration after which the token will expire. E.g. 1y",
                Some(String::from("1 year")),
                Some(|inp: &String| {
                    humantime::parse_duration(inp).map(|_| ())
                }),
                hist("expiration-duration.hist"),
            )
            .map_err(|err| Error::Input { what: "expiration duration", err })?;

            // Is validated so should never happen anyway
            let exp = humantime::parse_duration(&exp).expect("policy token expiration duration");

            // TODO: Handle error
            let _ = generate::policy_token(true, dir.join("policy_token.json"), secret_path.to_path_buf(), initiator, system, exp);
            todo!("Generating secret is not yet supported via the wizard")
        }

        Ok(())
    }

    fn create_expert_secret(worker_path: impl AsRef<Path>) -> Result<(), Error> {
        let worker_path = worker_path.as_ref();

        println!("{}", style("=== policy_expert_secret.json ===").bold());
        if confirm("Would you like to generate a `policy_expert_secret.json`", Some(true))
            .map_err(|err| Error::Input { what: "confirmation policy_expert_secret", err })?
        {
            // TODO: Generate secret
            // TODO: Make key id optionally overridable
            generate::policy_secret(true, worker_path.join("policy_expert_secret.json"), DEFAULT_KEY_ID.to_owned(), KeyAlgorithm::HS256)
                .map_err(|err| Error::GenerateError { what: String::from("policy expert secret"), err })?;
            todo!("Generating secret is not yet supported via the wizard")
        }

        Ok(())
    }

    fn create_deliberation_secret(worker_path: impl AsRef<Path>) -> Result<(), Error> {
        let worker_path = worker_path.as_ref();

        println!("{}", style("=== policy_deliberation_secret.json ===").bold());
        if confirm("Would you like to generate a `policy_deliberation_secret.json`", Some(true))
            .map_err(|err| Error::Input { what: "confirmation policy_deliberation_secret", err })?
        {
            // TODO: Generate secret
            // generate::policy_secret(fix_dirs, path, key_id, key_alg);
            generate::policy_secret(true, worker_path.join("policy_deliberation_secret.json"), DEFAULT_KEY_ID.to_owned(), KeyAlgorithm::HS256)
                .map_err(|err| Error::GenerateError { what: String::from("deliberation secret"), err })?;
            todo!("Generating secret is not yet supported via the wizard")
        }

        Ok(())
    }
}

enum ProxyNodeWizard {}

impl ProxyNodeWizard {
    fn run(config_dir: impl AsRef<Path>) -> Result<(), Error> {
        let config_dir = config_dir.as_ref();

        println!(" - {}", style(config_dir.join("proxy.yml").display()).bold());
        println!();

        // Note: we don't check if the user wants a custom config, since they very likely want it if they are setting up a proxy node
        // For the proxy, we only need to read the proxy config
        println!("{}", style("=== proxy.yml ===").bold());

        let cfg = query_proxy_config().map_err(|err| Error::ProxyConfigQuery { err: Box::new(err) })?;

        let proxy_path = config_dir.join("proxy.yml");

        write_config(cfg, proxy_path, "https://wiki.enablingpersonalizedinterventions.nl/user-guide/config/admins/proxy.html", Some(PROXY_HEADER))
            .map_err(|err| Error::ProxyConfigWrite { err: Box::new(err) })?;

        // Now we generate the node.yml file
        println!("{}", style("=== node.yml ==="));
        let node = query_proxy_node_config().map_err(|err| Error::NodeConfigQuery { err: Box::new(err) })?;

        let node_path = config_dir.join("node.yml");

        write_config(node, node_path, "https://wiki.enablingpersonalizedinterventions.nl/user-guide/config/admins/node.html", None)
            .map_err(|err| Error::NodeConfigWrite { err: Box::new(err) })?;

        Ok(())
    }

    // FIXME: This method overlaps to much with the method above
    fn create_proxy_config(central_node_dir: impl AsRef<Path>) -> Result<PathBuf, Error> {
        let central_node_dir = central_node_dir.as_ref();

        println!("{}", style("=== proxy.yml ===").bold());
        let proxy_config_source = select_enum::<ProxyConfigSource>(
            "How do you prefer to configure proxy.yml?",
            // TODO: Maybe use strum or something to get 'm all
            [ProxyConfigSource::Default, ProxyConfigSource::ExistingFile, ProxyConfigSource::Prompt],
            None,
        )
        .map_err(|err| Error::Input { what: "config source", err })?;

        let proxy = match proxy_config_source {
            ProxyConfigSource::Default => ProxyConfig::default(),
            ProxyConfigSource::ExistingFile => {
                let path = input_path("Select the existing proxy.yml on your system", None::<PathBuf>, hist("proxy-path.hist"))
                    .map_err(|err| Error::Input { what: "proxy.yml path", err })?;
                println!("Using proxy.yml from: `{}`", path.display());
                println!("Note: that this will make a copy of this file. So changing it afterwards will have no effect.");
                ProxyConfig::from_path(path).map_err(|err| Error::ProxyConfigRead { err })?
            },
            ProxyConfigSource::Prompt => query_proxy_config()?,
        };

        let proxy_path = central_node_dir.join("proxy.yml");

        write_config(proxy, &proxy_path, "https://wiki.enablingpersonalizedinterventions.nl/user-guide/config/admins/proxy.html", None)
            .map_err(|err| Error::ProxyConfigWrite { err: Box::new(err) })?;

        Ok(proxy_path)
    }
}

pub enum SecretWizard {
    ExpertToken,
    DeliberationToken,
}

impl SecretWizard {
    pub fn run(path: impl AsRef<Path>) -> Result<(), Error> {
        let _path = path.as_ref();

        // TODO: Make general (worker) node selector
        let worker_path = input_path("Select the `node.yml` for the worker node you like to interact with.", None::<&str>, hist("worker-node"))
            .map_err(|err| Error::Input { what: "worker node configuration", err })?;

        use SecretWizard::*;
        // TODO: Allow the selection of multiple
        match select("What secret would you like to create?", [ExpertToken, DeliberationToken], None)
            .map_err(|err| Error::Input { what: "node kind", err })?
        {
            DeliberationToken => Self::create_deliberation_token(worker_path)?,
            ExpertToken => Self::create_expert_token(worker_path)?,
        }

        Ok(())
    }

    pub fn create_expert_token(worker_path: impl AsRef<Path>) -> Result<(), Error> {
        let username: String =
            input("username", "What username would you like to use?", std::env::var("USER").ok(), None::<validator::NoValidator>, hist("username"))
                .map_err(|err| Error::Input { what: "policy token username", err })?;
        let system: String =
            input("username", "What system is this token for?", std::env::var("USER").ok(), None::<validator::NoValidator>, hist("system"))
                .map_err(|err| Error::Input { what: "policy token system", err })?;

        todo!();
    }

    pub fn create_deliberation_token(worker_path: impl AsRef<Path>) -> Result<(), Error> {
        let worker_path = worker_path.as_ref();

        let username: String =
            input("username", "What username would you like to use?", std::env::var("USER").ok(), None::<validator::NoValidator>, hist("username"))
                .map_err(|err| Error::Input { what: "policy token username", err })?;

        // TODO: Clarify, I suspect the system in the case of Brane would be the worker.
        let system: String = input("username", "What system is this token for?", None::<&str>, None::<validator::NoValidator>, hist("system"))
            .map_err(|err| Error::Input { what: "policy token system", err })?;

        // TODO: How do we know what worker this token is for in case of multiple workers
        let default_secret_path = worker_path.join("policy_deliberation_secret.yml");
        let default_secret_path = if default_secret_path.exists() { Some(default_secret_path) } else { None };

        let secret_path: PathBuf = input_path("Using what secret do you want to use for this token?", default_secret_path, hist("system"))
            .map_err(|err| Error::Input { what: "policy token system", err })?;

        // TODO: Use some "smart" logic to most likely location of the secret.
        let destination_path: PathBuf = input_path("Where would you like to store this token?", None::<&Path>, hist("system"))
            .map_err(|err| Error::Input { what: "policy token system", err })?;

        // TODO: We default to 1 year now, but we have to make this configurable

        generate::policy_token(true, destination_path.clone(), secret_path, username, system, std::time::Duration::from_secs(86400 * 365))
            .map_err(|err| Error::GenerateError { what: String::from("Deliberation secret"), err })?;

        println!("Succesfully generated a deliberation token at: {path}", path = destination_path.display());

        Ok(())
    }
}

impl From<&SecretWizard> for &'static str {
    fn from(value: &SecretWizard) -> Self {
        match value {
            // SecretWizard::ExpertSecret => "Policy expert secret",
            // SecretWizard::DeliberationSecret => "Policy deliberation secret",
            SecretWizard::ExpertToken => "Policy expert token",
            SecretWizard::DeliberationToken => "Policy deliberation token",
        }
    }
}

impl Display for SecretWizard {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", std::convert::Into::<&str>::into(self)) }
}


/***** ERRORS *****/
/// Defines errors that relate to the wizard.
#[derive(Debug)]
pub enum Error {
    /// Failed to query the user for the node config file.
    NodeConfigQuery {
        err: Box<Self>,
    },
    /// Failed to write the node config file.
    NodeConfigWrite {
        err: Box<Self>,
    },
    /// Failed to query the user for the proxy config file.
    ProxyConfigQuery {
        err: Box<Self>,
    },
    /// Failed to write the proxy config file.
    ProxyConfigWrite {
        err: Box<Self>,
    },
    /// Failed to write the proxy config file.
    ProxyConfigRead {
        err: brane_cfg::info::YamlError,
    },

    /// Failed to create a new file!().
    ConfigCreate {
        path: PathBuf,
        err:  std::io::Error,
    },
    /// Failed to generate a configuration file.
    ConfigSerialize {
        path: PathBuf,
        err:  brane_cfg::info::YamlError,
    },
    /// Failed to write to the config file.
    ConfigWrite {
        path: PathBuf,
        err:  std::io::Error,
    },

    /// Failed to generate a directory.
    GenerateDir {
        path: PathBuf,
        err:  std::io::Error,
    },

    /// Failed the query the user for input.
    /// The `what` should fill in: `Failed to query the user for ...`
    Input {
        what: &'static str,
        err:  brane_shr::input::Error,
    },
    InfraConfigWrite {
        err: Box<Error>,
    },
    PathCanonicalize {
        what: &'static str,
        path: PathBuf,
        err:  std::io::Error,
    },
    GenerateError {
        what: String,
        err:  generate::Error,
    },

    TempDir {
        err: std::io::Error,
    },
    NodeSerialize {
        what: &'static str,
        err:  InfoError<serde_yaml::Error>,
    },
    InstallCertificate {
        path: PathBuf,
        err:  std::io::Error,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            NodeConfigQuery { .. } => write!(f, "Failed to query node configuration"),
            NodeConfigWrite { .. } => write!(f, "Failed to write node config file"),
            ProxyConfigQuery { .. } => write!(f, "Failed to query proxy service configuration"),
            ProxyConfigWrite { .. } => write!(f, "Failed to write proxy service config file"),
            // TODO: Maybe we should elaborate on this error. I realise that it is easy to
            // misinterpret this error as writing the error.
            ProxyConfigRead { .. } => write!(f, "Failed to read proxy service config file"),
            InfraConfigWrite { .. } => write!(f, "Failed to write infra config file"),

            ConfigCreate { path, .. } => write!(f, "Failed to create config file '{}'", path.display()),
            ConfigSerialize { path, .. } => write!(f, "Failed to serialize config to '{}'", path.display()),
            ConfigWrite { path, .. } => write!(f, "Failed to write to config file '{}'", path.display()),
            GenerateDir { path, .. } => write!(f, "Failed to generate directory '{}'", path.display()),
            Input { what, .. } => write!(f, "Failed to query the user for {what}"),
            PathCanonicalize { what, path, .. } => write!(f, "Failed to canonicalize the {what} path: {}", path.display()),
            GenerateError { .. } => todo!(),
            TempDir { .. } => write!(f, "Could not generate temporary directory"),
            NodeSerialize { what, .. } => write!(f, "Could not serialize {}", what),
            InstallCertificate { path, .. } => write!(f, "Could not install certificate to {}", path.display()),
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
            ProxyConfigRead { err } => Some(err),

            InfraConfigWrite { err } => Some(err),

            ConfigCreate { err, .. } => Some(err),
            ConfigSerialize { err, .. } => Some(err),
            ConfigWrite { err, .. } => Some(err),
            GenerateDir { err, .. } => Some(err),
            Input { err, .. } => Some(err),
            PathCanonicalize { err, .. } => Some(err),
            GenerateError { .. } => todo!(),
            TempDir { err } => Some(err),
            NodeSerialize { err, .. } => Some(err),
            InstallCertificate { err, .. } => Some(err),
        }
    }
}

/***** HELPER FUNCTIONS *****/
fn create_header(filename: impl AsRef<str>) -> String {
    let filename = filename.as_ref();
    let mut header = String::with_capacity(filename.len());

    let mut last_char_lowercase = false;
    let mut chars = filename.chars().peekable();
    for c in chars.by_ref().take_while(|&c| c != '.') {
        if c == ' ' || c == '-' || c == '_' {
            // Write it as a space
            header.push(' ');
        } else if last_char_lowercase && c.is_ascii_uppercase() {
            // Write is with a space, since we assume it's a word boundary in camelCase
            header.push(' ');
            header.push(c);
        } else if c.is_ascii_lowercase() {
            // Capitalize it
            header.push(c.to_ascii_uppercase());
        }

        // Update whether we saw a lowercase last step
        last_char_lowercase = c.is_ascii_lowercase();
    }

    if chars.peek().is_some() {
        header.push('.');
        header.extend(chars);
    }

    header
}
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
fn write_config<C>(config: C, path: impl AsRef<Path>, url: impl AsRef<str>, header: Option<&str>) -> Result<(), Error>
where
    C: Info<Error = serde_yaml::Error>,
{
    let path: &Path = path.as_ref();
    let url: &str = url.as_ref();
    debug!("Generating config file '{}'...", path.display());

    // Deduce the filename
    let filename: Cow<str> = match path.file_name() {
        Some(filename) => filename.to_string_lossy(),
        // FIXME: Panic seems excessive
        None => panic!("No filename found in '{}'", path.display()),
    };

    // Create a file, now
    let mut handle = File::create(path).map_err(|err| Error::ConfigCreate { path: path.into(), err })?;

    // Write the header to a string
    let wizard_header = indoc::formatdoc!(
        "
        # {name}
        #   generated by branectl v{brane_version}
        #
        # This file has been generated using the `branectl wizard` subcommand. You can,
        # manually change this file after generation; it is just a normal YAML file.,
        # Documentation for how to do so can be found here:,
        # {url}
        ",
        name = create_header(filename),
        url = url,
        brane_version = env!("CARGO_PKG_VERSION"),
    );

    writeln!(handle, "{}", wizard_header).map_err(|err| Error::ConfigWrite { path: path.into(), err })?;

    if let Some(file_header) = header {
        writeln!(handle, "{}", file_header).map_err(|err| Error::ConfigWrite { path: path.into(), err })?;
    }

    // Write the remainder of the file
    config.to_writer(handle, true).map_err(|err| Error::ConfigSerialize { path: path.into(), err })?;

    Ok(())
}

/***** PROXY FUNCTIONS *****/
/// Queries the user for the proxy services configuration.
///
/// # Returns
/// A new [`ProxyConfig`] that reflects the user's choices.
///
/// # Errors
/// This function may error if we failed to query the user.
pub fn query_proxy_config() -> Result<ProxyConfig, Error> {
    // Query the user for the range
    let range: InclusiveRange<u16> = input(
        "port range",
        "P1. Enter the range of ports allocated for outgoing connections",
        Some(InclusiveRange::new(4200, 4299)),
        Some(PortRangeValidator::default()),
        hist("prx-outgoing_range.hist"),
    )
    .map_err(|err| Error::Input { what: "outgoing range", err })?;

    debug!("Outgoing range: [{}, {}]", range.0.start(), range.0.end());
    println!();

    // Read the map of incoming ports
    let incoming: HashMap<u16, Address> = input_map(
        "port",
        "address",
        "P2.1. Enter an incoming port map as '<incoming port>:<destination address>:<destination port>' (or leave empty to specify none)",
        "P2.%I. Enter an additional incoming port map as '<port>:<destination address>' (or leave empty to finish)",
        ":",
        // None::<NoValidator>,
        Some(PortMapValidator { allow_empty: true, ..Default::default() }),
        hist("prx-incoming.hist"),
    )
    .map_err(|err| Error::Input { what: "outgoing range", err })?;

    debug!("Incoming ports map:\n{:#?}", incoming);
    println!();

    // Finally, read any proxy
    let to_proxy_or_not_to_proxy: bool = confirm("P3. Do you want to route outgoing traffic through a SOCKS proxy?", Some(false))
        .map_err(|err| Error::Input { what: "proxy confirmation", err })?;
    let forward: Option<ForwardConfig> = if to_proxy_or_not_to_proxy {
        // Query the address
        let address: Address = input(
            "address",
            "P3a. Enter the target address (including port) to route the traffic to",
            None::<Address>,
            Some(AddressValidator::default()),
            hist("prx-forward-address.hist"),
        )
        .map_err(|err| Error::Input { what: "forwarding address", err })?;

        // Query the protocol
        let protocol: ProxyProtocol =
            select("P3b. Enter the protocol to use to route traffic", vec![ProxyProtocol::Socks5, ProxyProtocol::Socks6], Some(0))
                .map_err(|err| Error::Input { what: "forwarding protocol", err })?;

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
    let hostnames: HostnameMapping = input_map(
        "<Location ID>",
        "<Address>",
        "P2.1. Enter an worker mapping as: '<Location ID>:<Host>' (or leave empty to specify none)",
        "P2.%I. Enter an additional worker mapping as '<Location ID>:<Host>' (or leave empty to finish)",
        ":",
        // None::<NoValidator>,
        Some(LocationMapValidator { allow_empty: true, ..Default::default() }),
        hist("location-map.hist"),
    )
    .map_err(|err| Error::Input { what: "outgoing range", err })?;

    let namespace: String = input(
        "docker compose namespace",
        "Enter the docker compose namespace (project name) for this node",
        None::<&str>,
        Some(LocationMapValidator { allow_empty: true, ..Default::default() }),
        hist("namespace.hist"),
    )
    .map_err(|err| Error::Input { what: "outgoing range", err })?;

    // FIXME: Bind address and port can be combined in an more clever way
    let bind_address: IpAddr = input(
        "bind address",
        "What address should the proxy bind to?",
        Some(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        None::<validator::NoValidator>,
        hist("bind_address.hist"),
    )
    .map_err(|err| Error::Input { what: "bind address", err })?;

    let bind_port: u16 = input(
        "docker compose namespace",
        "Enter the docker compose namespace (project name) for this node",
        None::<u16>,
        None::<validator::NoValidator>,
        hist("bind_port.hist"),
    )
    .map_err(|err| Error::Input { what: "bind port", err })?;
    let hostnames = Default::default();
    let bind_address = std::net::SocketAddr::from((bind_address, bind_port));

    // FIXME: Bind address and port can be combined in an more clever way
    let external_address: Host =
        input("external address", "What address should the proxy bind to?", None::<Host>, None::<validator::NoValidator>, hist("bind_address.hist"))
            .map_err(|err| Error::Input { what: "bind address", err })?;

    Ok(NodeConfig {
        hostnames,
        namespace,
        node: NodeSpecificConfig::Proxy(node::ProxyConfig {
            paths:    node::ProxyPaths { certs: "".into(), proxy: "".into() },
            services: node::ProxyServices {
                prx: node::PublicService {
                    name: "brane-prx".into(),
                    address: Address::Hostname("brane-prx".into(), bind_port),
                    bind: bind_address,
                    external_address: (external_address, bind_port).into(),
                },
            },
        }),
    })
}

#[derive(PartialEq)]
enum ProxyConfigSource {
    Default,
    ExistingFile,
    Prompt,
}

impl From<&ProxyConfigSource> for &'static str {
    fn from(value: &ProxyConfigSource) -> Self {
        match value {
            ProxyConfigSource::Default => "Use the default configuration (often recommended)",
            ProxyConfigSource::ExistingFile => "Use existing proxy.yml on your filesystem",
            ProxyConfigSource::Prompt => "Configure it right now.",
        }
    }
}

impl Display for ProxyConfigSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", Into::<&str>::into(self)) }
}


/***** INFRA FUNCTIONS *****/
/// TODO: Documentation
pub fn query_infra_config() -> Result<InfraFile, Error> {
    // Read the map of incoming ports
    let _worker_mapping: HashMap<LocationId, Host> = input_map(
        "<Location ID>",
        "<Address>",
        "P2.1. Enter an worker mapping as: '<Location ID>:<Host>' (or leave empty to specify none)",
        "P2.%I. Enter an additional worker mapping as '<Location ID>:<Host>' (or leave empty to finish)",
        ":",
        // None::<NoValidator>,
        Some(LocationMapValidator { allow_empty: true, ..Default::default() }),
        hist("location-map.hist"),
    )
    .map_err(|err| Error::Input { what: "outgoing range", err })?;

    let infra_locations = _worker_mapping
        .into_iter()
        .map(|(location_id, host)| {
            (location_id.clone(), InfraLocation {
                // TODO: Prompt for the human readable name
                name:     location_id,
                registry: Address::hostname(format!("https://{}", host), BRANE_WORKER_JOB_PORT),
                delegate: Address::hostname(format!("grpc://{}", host), BRANE_WORKER_REG_PORT),
            })
        })
        .collect::<HashMap<_, _>>();

    Ok(InfraFile::new(infra_locations))
}
