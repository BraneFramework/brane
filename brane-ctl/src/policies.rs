//  POLICIES.rs
//    by Lut99
//
//  Created:
//    10 Jan 2024, 15:57:54
//  Last edited:
//    01 May 2025, 17:11:24
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements handlers for subcommands to `branectl policies ...`
//

use std::borrow::Cow;
use std::collections::HashMap;
use std::error;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::{Path, PathBuf};
use std::time::Duration;

use brane_cfg::info::Info;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig, WorkerConfig};
use brane_shr::formatters::BlockFormatter;
use chrono::{DateTime, Local};
use console::style;
use dialoguer::theme::ColorfulTheme;
use enum_debug::EnumDebug;
use error_trace::trace;
use log::{debug, info};
use policy_store::servers::axum::spec::{ActivateRequest, GetActiveVersionResponse, GetVersionsResponse};
use policy_store::spec::metadata::{AttachedMetadata, Metadata};
use rand::Rng;
use rand::distr::Alphanumeric;
use reqwest::{Client, Request, Response, StatusCode};
use serde_json::Value;
use specifications::address::{Address, AddressOpt};
use specifications::checking::store::{
    ACTIVATE_PATH, ADD_VERSION_PATH, AddVersionRequest, AddVersionResponse, EFlintHaskellReasonerWithInterfaceContext, GET_ACTIVE_VERSION_PATH,
    GET_CONTEXT_PATH, GET_VERSION_CONTENT_PATH, GET_VERSIONS_PATH, GetContextResponse,
};
use tokio::fs::{self as tfs, File as TFile};

use crate::spec::PolicyInputLanguage;


/***** ERRORS *****/
/// Defines errors that may originate in `branectl policies ...` subcommands.
#[derive(Debug)]
pub enum Error {
    /// Failed to get the active version of the policy.
    ActiveVersionGet { addr: Address, err: Box<Self> },
    /// Given JSON policy was not a phrases request.
    IllegalInput { path: PathBuf, got: String },
    /// Failed to deserialize the read input file as JSON.
    InputDeserialize { path: PathBuf, raw: String, err: serde_json::Error },
    /// Failed to read the input file.
    InputRead { path: PathBuf, err: std::io::Error },
    /// Failed to prompt the user for a string input.
    InputString { what: &'static str, err: dialoguer::Error },
    /// The wrong policy was activated on the remote checker, somehow.
    InvalidPolicyActivated { addr: Address, got: Option<i64>, expected: Option<i64> },
    /// A policy language was attempted to derive from a path without extension.
    MissingExtension { path: PathBuf },
    /// The given node config file was not a worker config file.
    NodeConfigIncompatible { path: PathBuf, got: String },
    /// Failed to load the node configuration file for this node.
    NodeConfigLoad { path: PathBuf, err: brane_cfg::info::YamlError },
    /// Found a policy on a checker without a version defined.
    PolicyWithoutVersion { addr: Address, which: String },
    /// Failed to prompt the user for version selection.
    PromptVersions { err: Box<Self> },
    /// Failed to build a request.
    RequestBuild { kind: &'static str, addr: String, err: reqwest::Error },
    /// A request failed for some reason.
    RequestFailure { addr: String, code: StatusCode, response: Option<String> },
    /// Failed to send a request.
    RequestSend { kind: &'static str, addr: String, err: reqwest::Error },
    /// Failed to deserialize the checker response as valid JSON.
    ResponseDeserialize { addr: String, raw: String, err: serde_json::Error },
    /// Failed to download the body of the checker's response.
    ResponseDownload { addr: String, err: reqwest::Error },
    /// Failed to create a temporary file.
    TempFileCreate { path: PathBuf, err: std::io::Error },
    /// Failed to write to a temporary file from stdin.
    TempFileWrite { path: PathBuf, err: std::io::Error },
    /// Failed to generate a new token.
    TokenGenerate { secret: PathBuf, err: specifications::policy::Error },
    /// A policy language was attempted to derive from the extension but we didn't know it.
    UnknownExtension { path: PathBuf, ext: String },
    /// The policy was given on stdout but no language was specified.
    UnspecifiedInputLanguage,
    /// Failed to query the checker about a specific version.
    VersionGetBody { addr: Address, version: u64, err: Box<Self> },
    /// Failed to query the user which version to select.
    VersionSelect { err: dialoguer::Error },
    /// Failed to get the versions on the remote checker.
    VersionsGet { addr: Address, err: Box<Self> },
    /// Failed to serialize a given policy version.
    VersionSerialize { version: u64, err: serde_json::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            ActiveVersionGet { addr, .. } => write!(f, "Failed to get active version of checker '{addr}'"),
            IllegalInput { path, got } => {
                write!(f, "eFLINT JSON file {:?} is not a list of phrases or a phrases request (got: {:?})", path.display(), got)
            },
            InputDeserialize { path, raw, .. } => {
                write!(f, "Failed to deserialize contents of '{}' to JSON\n\nRaw value:\n{}\n", path.display(), BlockFormatter::new(raw))
            },
            InputRead { path, .. } => write!(f, "Failed to read input file '{}'", path.display()),
            InputString { what, .. } => write!(f, "Failed to ask you {what}"),
            InvalidPolicyActivated { addr, got, expected } => write!(
                f,
                "Checker '{}' activated wrong policy; it says it activated {}, but we requested to activate {}",
                addr,
                if let Some(got) = got { got.to_string() } else { "None".into() },
                if let Some(expected) = expected { expected.to_string() } else { "None".into() }
            ),
            MissingExtension { path } => {
                write!(f, "Cannot derive input language from '{}' that has no extension; manually specify it using '--language'", path.display())
            },
            NodeConfigIncompatible { path, got } => {
                write!(f, "Given node configuration file '{}' is for a {} node, but expected a Worker node", path.display(), got)
            },
            NodeConfigLoad { path, .. } => write!(f, "Failed to load node configuration file '{}'", path.display()),
            PolicyWithoutVersion { addr, which } => write!(f, "{which} policy return by checker '{addr}' has no version number set"),
            PromptVersions { .. } => write!(f, "Failed to prompt the user (you!) to select a version"),
            RequestBuild { kind, addr, .. } => write!(f, "Failed to build new {kind}-request to '{addr}'"),
            RequestFailure { addr, code, response } => write!(
                f,
                "Request to '{}' failed with status {} ({}){}",
                addr,
                code.as_u16(),
                code.canonical_reason().unwrap_or("???"),
                if let Some(response) = response { format!("\n\nResponse:\n{}\n", BlockFormatter::new(response)) } else { String::new() }
            ),
            RequestSend { kind, addr, .. } => write!(f, "Failed to send {kind}-request to '{addr}'"),
            ResponseDeserialize { addr, raw, .. } => {
                write!(f, "Failed to deserialize response from '{}' as JSON\n\nResponse:\n{}\n", addr, BlockFormatter::new(raw))
            },
            ResponseDownload { addr, .. } => write!(f, "Failed to download response from '{addr}'"),
            TempFileCreate { path, .. } => write!(f, "Failed to create temporary file '{}'", path.display()),
            TempFileWrite { path, .. } => write!(f, "Failed to copy stdin to temporary file '{}'", path.display()),
            TokenGenerate { secret, .. } => write!(
                f,
                "Failed to generate one-time authentication token from secret file '{}' (you can manually specify a token using '--token')",
                secret.display()
            ),
            UnknownExtension { path, ext } => write!(
                f,
                "Cannot derive input language from '{}' that has unknown extension '{}'; manually specify it using '--language'",
                path.display(),
                ext
            ),
            UnspecifiedInputLanguage => write!(f, "Cannot derive input language when giving input via stdin; manually specify it using '--language'"),
            VersionGetBody { addr, version, .. } => write!(f, "Failed to get policy body of policy '{version}' stored in checker '{addr}'"),
            VersionSelect { .. } => write!(f, "Failed to ask you which version to make active"),
            VersionsGet { addr, .. } => write!(f, "Failed to get policy versions stored in checker '{addr}'"),
            VersionSerialize { version, .. } => write!(f, "Failed to serialize policy {version}"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            ActiveVersionGet { err, .. } => Some(&**err),
            IllegalInput { .. } => None,
            InputDeserialize { err, .. } => Some(err),
            InputRead { err, .. } => Some(err),
            InputString { err, .. } => Some(err),
            InvalidPolicyActivated { .. } => None,
            MissingExtension { .. } => None,
            NodeConfigIncompatible { .. } => None,
            NodeConfigLoad { err, .. } => Some(err),
            PolicyWithoutVersion { .. } => None,
            PromptVersions { err } => Some(err),
            RequestBuild { err, .. } => Some(err),
            RequestFailure { .. } => None,
            RequestSend { err, .. } => Some(err),
            ResponseDeserialize { err, .. } => Some(err),
            ResponseDownload { err, .. } => Some(err),
            TempFileCreate { err, .. } => Some(err),
            TempFileWrite { err, .. } => Some(err),
            TokenGenerate { err, .. } => Some(err),
            UnknownExtension { .. } => None,
            UnspecifiedInputLanguage => None,
            VersionGetBody { err, .. } => Some(&**err),
            VersionSelect { err } => Some(err),
            VersionsGet { err, .. } => Some(&**err),
            VersionSerialize { err, .. } => Some(err),
        }
    }
}





/***** HELPER FUNCTIONS *****/
/// Resolves the node.yml file so that it's only loaded when needed to resolve information not given.
///
/// # Arguments
/// - `node_config_path`: The path to load the file from if it doesn't exist.
/// - `worker`: The [`WorkerConfig`] to potentially pass.
///
/// # Returns
/// A new [`WorkerConfig`] if `worker` was [`None`], or else the given one.
///
/// # Errors
/// This function may error if we failed to load a node config from the given path, or the node config was not for a worker node.
fn resolve_worker_config(node_config_path: impl AsRef<Path>, worker: Option<WorkerConfig>) -> Result<WorkerConfig, Error> {
    worker.map(Ok).unwrap_or_else(|| {
        let node_config_path: &Path = node_config_path.as_ref();

        debug!("Loading node configuration file '{}'...", node_config_path.display());
        let node: NodeConfig = match NodeConfig::from_path(node_config_path) {
            Ok(node) => node,
            Err(err) => return Err(Error::NodeConfigLoad { path: node_config_path.into(), err }),
        };

        // Assert it's of the correct type
        match node.node {
            NodeSpecificConfig::Worker(worker) => Ok(worker),
            other => Err(Error::NodeConfigIncompatible { path: node_config_path.into(), got: other.variant().to_string() }),
        }
    })
}

/// Resolves a token by either using the given one or generating a new one.
///
/// When generating a new one, the token in the given [`WorkerConfig`] is used. This, too, will be resolved in that case.
///
/// # Arguments
/// - `node_config_path`: The path to load the worker config from if `worker_config` if [`None`].
/// - `worker_config`: An optional [`WorkerConfig`] that will be loaded from disk and updated if [`None`].
/// - `token`: An optional token that will be returned if [`Some`].
///
/// # Returns
/// A new token if `token` was [`None`], or else the given one.
///
/// # Errors
/// This function may error if we failed to load the node config file correctly or if we failed to generate the token.
fn resolve_token(node_config_path: impl AsRef<Path>, worker: &mut Option<WorkerConfig>, token: Option<String>) -> Result<String, Error> {
    if let Some(token) = token {
        debug!("Using given token '{token}'");
        Ok(token)
    } else {
        // Resolve the worker
        let worker_cfg: WorkerConfig = resolve_worker_config(&node_config_path, worker.take())?;

        // Attempt to generate a new token based on the secret in the `node.yml` file
        match specifications::policy::generate_policy_token(
            names::three::lowercase::rand(),
            "branectl",
            Duration::from_secs(60),
            &worker_cfg.paths.policy_store_secret,
        ) {
            Ok(token) => {
                debug!("Using generated token '{token}'");
                *worker = Some(worker_cfg);
                Ok(token)
            },
            Err(err) => Err(Error::TokenGenerate { secret: worker_cfg.paths.policy_store_secret, err }),
        }
    }
}

/// Resolves the port in the given address.
///
/// If it has one, nothing happens and it's returned as an [`Address`]; else, the port defined for the checker service in the given `worker` is given.
///
/// # Arguments
/// - `node_config_path`: The path to load the worker config from if `worker_config` if [`None`].
/// - `worker_config`: An optional [`WorkerConfig`] that will be loaded from disk and updated if [`None`].
/// - `address`: The [`AddressOpt`] who's port to resolve.
///
/// # Returns
/// The given `address` as an [`Address`] if it has a port, or else an [`Address`] with the same hostname but a port taken from the (resolved) `worker_config`.
///
/// # Errors
/// This function may error if we have to load a new worker config but fail to do so.
fn resolve_addr_opt(node_config_path: impl AsRef<Path>, worker: &mut Option<WorkerConfig>, mut address: AddressOpt) -> Result<Address, Error> {
    // Resolve the address port if needed
    if address.port.is_none() {
        // Resolve the worker and store the port of the checker
        let worker_cfg: WorkerConfig = resolve_worker_config(&node_config_path, worker.take())?;
        address.port = Some(worker_cfg.services.chk.store);
        *worker = Some(worker_cfg);
    }

    // Return the address as an [`Address`], which we can unwrap because we asserted the port is `Some(...)`.
    Ok(Address::try_from(address).unwrap())
}



/// Helper function that pulls the reasoner context from a checker.
///
/// # Arguments
/// - `address`: The address where the checker may be reached.
/// - `token`: The token used for authenticating the checker.
///
/// # Returns
/// The context, as a parsed [`EFlintJsonReasonerWithInterfaceContext`].
///
/// # Errors
/// This function may error if we failed to reach the checker, failed to authenticate or failed to download/parse the result.
async fn get_context_from_checker(address: &Address, token: &str) -> Result<EFlintHaskellReasonerWithInterfaceContext, Error> {
    info!("Retrieving context from checker '{address}'");

    // Prepare the request
    let url: String = format!("http://{}{}", address, GET_CONTEXT_PATH.instantiated_path::<String>(None));
    debug!("Building GET-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(GET_CONTEXT_PATH.method, &url).bearer_auth(token).build() {
        Ok(req) => req,
        Err(err) => return Err(Error::RequestBuild { kind: "GET", addr: url, err }),
    };

    // Send it
    debug!("Sending request to '{url}'...");
    let res: Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RequestSend { kind: "GET", addr: url, err }),
    };
    debug!("Server responded with {}", res.status());
    if !res.status().is_success() {
        return Err(Error::RequestFailure { addr: url, code: res.status(), response: res.text().await.ok() });
    }

    // Attempt to parse the result as a list of policy versions
    match res.text().await {
        Ok(body) => {
            // Log the full response first
            debug!("Response:\n{}\n", BlockFormatter::new(&body));
            // Parse it as a [`Policy`]
            match serde_json::from_str::<GetContextResponse>(&body) {
                Ok(body) => Ok(body.context),
                Err(err) => Err(Error::ResponseDeserialize { addr: url, raw: body, err }),
            }
        },
        Err(err) => Err(Error::ResponseDownload { addr: url, err }),
    }
}

/// Helper function that pulls a specific version's body from a checker.
///
/// # Arguments
/// - `address`: The address where the checker may be reached.
/// - `token`: The token used for authenticating the checker.
/// - `version`: The policy version to retrieve the body of.
///
/// # Returns
/// The policy's body, as a JSON [`Value`].
///
/// # Errors
/// This function may error if we failed to reach the checker, failed to authenticate or failed to download/parse the result.
async fn get_version_body_from_checker(address: &Address, token: &str, version: u64) -> Result<Value, Error> {
    info!("Retrieving policy '{version}' from checker '{address}'");

    // Prepare the request
    let url: String = format!("http://{}{}", address, GET_VERSION_CONTENT_PATH.instantiated_path([version]));
    debug!("Building GET-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(GET_VERSION_CONTENT_PATH.method, &url).bearer_auth(token).build() {
        Ok(req) => req,
        Err(err) => return Err(Error::RequestBuild { kind: "GET", addr: url, err }),
    };

    // Send it
    debug!("Sending request to '{url}'...");
    let res: Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RequestSend { kind: "GET", addr: url, err }),
    };
    debug!("Server responded with {}", res.status());
    if !res.status().is_success() {
        return Err(Error::RequestFailure { addr: url, code: res.status(), response: res.text().await.ok() });
    }

    // Attempt to parse the result as a list of policy versions
    match res.text().await {
        Ok(body) => {
            // Log the full response first
            debug!("Response:\n{}\n", BlockFormatter::new(&body));
            // Parse it as a [`Policy`]
            match serde_json::from_str(&body) {
                Ok(body) => Ok(body),
                Err(err) => Err(Error::ResponseDeserialize { addr: url, raw: body, err }),
            }
        },
        Err(err) => Err(Error::ResponseDownload { addr: url, err }),
    }
}

/// Helper function that pulls the versions in a checker.
///
/// # Arguments
/// - `address`: The address where the checker may be reached.
/// - `token`: The token used for authenticating the checker.
///
/// # Returns
/// A map of versions to metadata found on the remote checkers.
///
/// # Errors
/// This function may error if we failed to reach the checker, failed to authenticate or failed to download/parse the result.
async fn get_versions_on_checker(address: &Address, token: &str) -> Result<HashMap<u64, Metadata>, Error> {
    info!("Retrieving policies on checker '{address}'");

    // Prepare the request
    let url: String = format!("http://{}{}", address, GET_VERSIONS_PATH.instantiated_path::<String>(None));
    debug!("Building GET-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(GET_VERSIONS_PATH.method, &url).bearer_auth(token).build() {
        Ok(req) => req,
        Err(err) => return Err(Error::RequestBuild { kind: "GET", addr: url, err }),
    };

    // Send it
    debug!("Sending request to '{url}'...");
    let res: Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RequestSend { kind: "GET", addr: url, err }),
    };
    debug!("Server responded with {}", res.status());
    if !res.status().is_success() {
        return Err(Error::RequestFailure { addr: url, code: res.status(), response: res.text().await.ok() });
    }

    // Attempt to parse the result as a list of policy versions
    match res.text().await {
        Ok(body) => {
            // Log the full response first
            debug!("Response:\n{}\n", BlockFormatter::new(&body));
            // Parse it as a [`Policy`]
            match serde_json::from_str::<GetVersionsResponse>(&body) {
                Ok(body) => Ok(body.versions),
                Err(err) => Err(Error::ResponseDeserialize { addr: url, raw: body, err }),
            }
        },
        Err(err) => Err(Error::ResponseDownload { addr: url, err }),
    }
}

/// Helper function that pulls the currently active versions on a checker.
///
/// # Arguments
/// - `address`: The address where the checker may be reached.
/// - `token`: The token used for authenticating the checker.
///
/// # Returns
/// A single version number that describes the active policy, or [`None`] is none is active.
///
/// # Errors
/// This function may error if we failed to reach the checker, failed to authenticate or failed to download/parse the result.
async fn get_active_version_on_checker(address: &Address, token: &str) -> Result<Option<u64>, Error> {
    info!("Retrieving active policy of checker '{address}'");

    // Prepare the request
    let url: String = format!("http://{}{}", address, GET_ACTIVE_VERSION_PATH.instantiated_path::<String>(None));
    debug!("Building GET-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(GET_ACTIVE_VERSION_PATH.method, &url).bearer_auth(token).build() {
        Ok(req) => req,
        Err(err) => return Err(Error::RequestBuild { kind: "GET", addr: url, err }),
    };

    // Send it
    debug!("Sending request to '{url}'...");
    let res: Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RequestSend { kind: "GET", addr: url, err }),
    };
    debug!("Server responded with {}", res.status());
    match res.status() {
        StatusCode::OK => {},
        // No policy was active
        StatusCode::NOT_FOUND => return Ok(None),
        code => return Err(Error::RequestFailure { addr: url, code, response: res.text().await.ok() }),
    }

    // Attempt to parse the result as a list of policy versions
    match res.text().await {
        Ok(body) => {
            // Log the full response first
            debug!("Response:\n{}\n", BlockFormatter::new(&body));
            // Parse it as a [`Policy`]
            match serde_json::from_str::<GetActiveVersionResponse>(&body) {
                Ok(body) => Ok(body.version),
                Err(err) => Err(Error::ResponseDeserialize { addr: url, raw: body, err }),
            }
        },
        Err(err) => Err(Error::ResponseDownload { addr: url, err }),
    }
}



/// Prompts to supply a string with an optional value.
///
/// # Arguments
/// - `what`: Some abstract description of what is prompted. Only used for error handling.
/// - `question`: The question to ask the input of.
/// - `default`: A default value to give, if any.
///
/// # Returns
/// The information selected by the user. May be the `default` if given and the user selected it.
///
/// # Errors
/// This function may error if we failed to query the user.
fn prompt_user_string(what: &'static str, question: impl Into<String>, default: Option<&str>) -> Result<String, Error> {
    // Ask the user using dialoguer, then return that version
    let theme = ColorfulTheme::default();
    let mut prompt = dialoguer::Input::with_theme(&theme).with_prompt(question).show_default(default.is_some());
    if let Some(default) = default {
        prompt = prompt.default(default.to_string());
    }
    match prompt.interact() {
        Ok(res) => Ok(res),
        Err(err) => Err(Error::InputString { what, err }),
    }
}

/// Prompts the user to select one of the given list of versions.
///
/// # Arguments
/// - `question`: The question to ask the input of.
/// - `active_version`: If there is any active version.
/// - `versions`: The list of versions to select from.
/// - `exit`: Whether to provide an exit button to the prompt or not.
///
/// # Returns
/// An index into the given list, which is what the user selected. If `exit` is true, then this may return [`None`] when selected.
///
/// # Errors
/// This function may error if we failed to query the user.
fn prompt_user_version(
    question: impl Into<String>,
    active_version: Option<u64>,
    versions: &HashMap<u64, Metadata>,
    exit: bool,
) -> Result<Option<u64>, Error> {
    // First: go by order
    let mut ids: Vec<u64> = versions.keys().cloned().collect();
    ids.sort();

    // Preprocess the versions into neat representations
    let mut sversions: Vec<String> = Vec::with_capacity(versions.len() + 1);
    for id in &ids {
        // Get the version for this ID
        let version: &Metadata = versions.get(id).unwrap();

        // See if it's selected to print either bold or not
        let mut line: String = if active_version == Some(version.version) { style("Version ").bold().to_string() } else { "Version ".into() };
        line.push_str(&style(version.version).bold().green().to_string());
        if active_version == Some(version.version) {
            line.push_str(
                &style(format!(
                    " (created at {}, by {} ({}))",
                    version.created.format("%H:%M:%S %d-%m-%Y"),
                    version.creator.name,
                    version.creator.id
                ))
                .to_string(),
            );
        } else {
            line.push_str(&format!(
                " (created at {}, by {} ({}))",
                version.created.format("%H:%M:%S %d-%m-%Y"),
                version.creator.name,
                version.creator.id
            ));
        }

        // Add the rendered line to the list
        sversions.push(line);
    }

    // Add the exit button
    if exit {
        sversions.push("<exit>".into());
    }

    // Ask the user using dialoguer, then return that version
    match dialoguer::Select::with_theme(&ColorfulTheme::default()).with_prompt(question).items(&sversions).interact() {
        Ok(idx) => {
            if !exit || idx < versions.len() {
                // Exit wasn't selected
                Ok(Some(ids[idx]))
            } else {
                // Exit was selected
                Ok(None)
            }
        },
        Err(err) => Err(Error::VersionSelect { err }),
    }
}





/***** AUXILLARY *****/
/// Defines supported reasoners in the checker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetReasoner {
    /// It's an eFLINT Haskell reasoner
    EFlintHaskell,
}
impl TargetReasoner {
    /// Returns the string identifier of the reasoner that can be send to a checker.
    ///
    /// # Returns
    /// A [`String`] that the checker uses to verify if the sent policy matches the backend.
    pub fn id(&self) -> String {
        match self {
            Self::EFlintHaskell => "eflint-haskell".into(),
        }
    }
}





/***** LIBRARY *****/
/// Activates a remote policy in the checker.
///
/// # Arguments
/// - `node_config_path`: The path to the node configuration file that determines which node we're working for.
/// - `version`: The version to activate in the checker. Should do some TUI stuff if not given.
/// - `address`: The address on which to reach the checker. May be missing a port, to be resolved in the node.yml.
/// - `token`: A token used for authentication with the remote checker. If omitted, will attempt to generate one based on the secret file in the node.yml file.
pub async fn activate(node_config_path: PathBuf, version: Option<u64>, address: AddressOpt, token: Option<String>) -> Result<(), Error> {
    info!(
        "Activating policy{} on checker of node defined by '{}'",
        if let Some(version) = &version { format!(" version '{version}'") } else { String::new() },
        node_config_path.display()
    );

    // See if we need to resolve the token & address
    let mut worker: Option<WorkerConfig> = None;
    let token: String = resolve_token(&node_config_path, &mut worker, token)?;
    let address: Address = resolve_addr_opt(&node_config_path, &mut worker, address)?;

    // Now we resolve the version
    let version: u64 = if let Some(version) = version {
        version
    } else {
        // Alrighty; first, pull a list of all available versions from the checker
        let versions: HashMap<u64, Metadata> = match get_versions_on_checker(&address, &token).await {
            Ok(versions) => versions,
            Err(err) => return Err(Error::VersionsGet { addr: address, err: Box::new(err) }),
        };
        // Then fetch the already active version
        let active_version: Option<u64> = match get_active_version_on_checker(&address, &token).await {
            Ok(version) => version,
            Err(err) => return Err(Error::ActiveVersionGet { addr: address, err: Box::new(err) }),
        };

        // Prompt the user to select it
        match prompt_user_version("Which version do you want to make active?", active_version, &versions, false) {
            Ok(Some(id)) => id,
            Ok(None) => unreachable!(),
            Err(err) => return Err(Error::PromptVersions { err: Box::new(err) }),
        }
    };
    debug!("Activating policy version {version}");

    // Now build the request and send it
    let url: String = format!("http://{}{}", address, ACTIVATE_PATH.instantiated_path::<String>(None));
    debug!("Building PUT-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(ACTIVATE_PATH.method, &url).bearer_auth(token).json(&ActivateRequest { version }).build() {
        Ok(req) => req,
        Err(err) => return Err(Error::RequestBuild { kind: "GET", addr: url, err }),
    };

    // Send it
    debug!("Sending request to '{url}'...");
    let res: Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RequestSend { kind: "GET", addr: url, err }),
    };
    debug!("Server responded with {}", res.status());
    if !res.status().is_success() {
        return Err(Error::RequestFailure { addr: url, code: res.status(), response: res.text().await.ok() });
    }

    // Done!
    println!("Successfully activated policy {} to checker {}.", style(version).bold().green(), style(address).bold().green(),);
    Ok(())
}



/// Adds the given policy to the checker defined in the given node config file.
///
/// # Arguments
/// - `node_config_path`: The path to the node configuration file that determines which node we're working for.
/// - `input`: The policy (or rather, a path thereto) to submit.
/// - `language`: The language of the input.
/// - `address`: The address on which to reach the checker. May be missing a port, to be resolved in the node.yml.
/// - `token`: A token used for authentication with the remote checker. If omitted, will attempt to generate one based on the secret file in the node.yml file.
///
/// # Errors
/// This function may error if we failed to read configs, read the input, contact the checker of if the checker errored.
pub async fn add(
    node_config_path: PathBuf,
    input: String,
    language: Option<PolicyInputLanguage>,
    address: AddressOpt,
    token: Option<String>,
) -> Result<(), Error> {
    info!("Adding policy '{}' to checker of node defined by '{}'", input, node_config_path.display());

    // See if we need to resolve the token & address
    let mut worker: Option<WorkerConfig> = None;
    let token: String = resolve_token(&node_config_path, &mut worker, token)?;
    let address: Address = resolve_addr_opt(&node_config_path, &mut worker, address)?;

    // Next stop: resolve the input to a path to read from
    let (input, from_stdin): (PathBuf, bool) = if input == "-" {
        // Create a temporary file to write stdin to
        let id: String = rand::rng().sample_iter(Alphanumeric).take(4).map(char::from).collect::<String>();
        let temp_path: PathBuf = std::env::temp_dir().join(format!("branectl-stdin-{id}.txt"));
        debug!("Writing stdin to temporary file '{}'...", temp_path.display());
        let mut temp: TFile = match TFile::create(&temp_path).await {
            Ok(temp) => temp,
            Err(err) => return Err(Error::TempFileCreate { path: temp_path, err }),
        };

        // Perform the write
        if let Err(err) = tokio::io::copy(&mut tokio::io::stdin(), &mut temp).await {
            return Err(Error::TempFileWrite { path: temp_path, err });
        }

        // Done
        (temp_path, true)
    } else {
        (input.into(), false)
    };

    // Query the user for some metadata
    debug!("Prompting user (you!) for metadata...");
    let name: String = prompt_user_string(
        "for a policy name",
        "Provide a descriptive name of the policy",
        input.file_name().map(OsStr::to_string_lossy).as_ref().map(Cow::as_ref),
    )?;
    debug!("Policy name: {name:?}");
    let description: String =
        prompt_user_string("for a policy description", "Provide a short description of the policy", Some("A very dope policy"))?;
    debug!("Policy description: {description:?}");

    // If the language is not given, resolve it from the file extension
    let language: PolicyInputLanguage = if let Some(language) = language {
        debug!("Interpreting input as {language}");
        language
    } else if let Some(ext) = input.extension() {
        debug!("Attempting to derive input language from extension '{}' (part of '{}')", ext.to_string_lossy(), input.display());

        // Else, attempt to resolve from the extension
        if ext == OsStr::new("eflint") {
            PolicyInputLanguage::EFlint
        } else if from_stdin {
            return Err(Error::UnspecifiedInputLanguage);
        } else {
            let ext: String = ext.to_string_lossy().into();
            return Err(Error::UnknownExtension { path: input, ext });
        }
    } else if from_stdin {
        return Err(Error::UnspecifiedInputLanguage);
    } else {
        return Err(Error::MissingExtension { path: input });
    };

    // Read the input file
    let (eflint, target_reasoner): (String, TargetReasoner) = match language {
        PolicyInputLanguage::EFlint => {
            // We read it as eFLINT to JSON
            debug!("Reading input file {:?}...", input.display());
            match tfs::read_to_string(&input).await {
                Ok(phrases) => (phrases, TargetReasoner::EFlintHaskell),
                Err(err) => panic!("{}", trace!(("serde_json::from_slice() did not return a serializable policy"), err)),
            }
        },
    };

    // Ask the checker for the reasoner context
    let context: EFlintHaskellReasonerWithInterfaceContext = get_context_from_checker(&address, &token).await?;

    // Finally, construct a request for the checker
    let url: String = format!("http://{}{}", address, ADD_VERSION_PATH.instantiated_path::<String>(None));
    debug!("Building POST-request to '{url}'...");
    let client: Client = Client::new();
    let contents: AddVersionRequest<String> = AddVersionRequest {
        metadata: AttachedMetadata {
            name,
            description,
            language: format!("{}-{}", target_reasoner.id(), base16ct::lower::encode_string(&context.base_policy_hash)),
        },
        contents: eflint,
    };
    let req: Request = match client.request(ADD_VERSION_PATH.method, &url).bearer_auth(token).json(&contents).build() {
        Ok(req) => req,
        Err(err) => return Err(Error::RequestBuild { kind: "POST", addr: url, err }),
    };

    // Now send it!
    debug!("Sending request to '{url}'...");
    let res: Response = match client.execute(req).await {
        Ok(res) => res,
        Err(err) => return Err(Error::RequestSend { kind: "POST", addr: url, err }),
    };
    debug!("Server responded with {}", res.status());
    if !res.status().is_success() {
        return Err(Error::RequestFailure { addr: url, code: res.status(), response: res.text().await.ok() });
    }

    // Log the response body
    let body: AddVersionResponse = match res.text().await {
        Ok(body) => {
            // Log the full response first
            debug!("Response:\n{}\n", BlockFormatter::new(&body));
            // Parse it as a [`Policy`]
            match serde_json::from_str(&body) {
                Ok(body) => body,
                Err(err) => return Err(Error::ResponseDeserialize { addr: url, raw: body, err }),
            }
        },
        Err(err) => return Err(Error::ResponseDownload { addr: url, err }),
    };

    // Done!
    println!(
        "Successfully added policy {} to checker {} as version {}.",
        style(if from_stdin { "<stdin>".into() } else { input.display().to_string() }).bold().green(),
        style(address).bold().green(),
        style(body.version).bold().green()
    );
    Ok(())
}



/// Lists (and allows the inspection of) the policies on the node's checker.
///
/// # Arguments
/// - `node_config_path`: The path to the node configuration file that determines which node we're working for.
/// - `address`: The address on which to reach the checker. May be missing a port, to be resolved in the node.yml.
/// - `token`: A token used for authentication with the remote checker. If omitted, will attempt to generate one based on the secret file in the node.yml file.
///
/// # Errors
/// This function may error if we failed to read configs, read the input, contact the checker of if the checker errored.
pub async fn list(node_config_path: PathBuf, address: AddressOpt, token: Option<String>) -> Result<(), Error> {
    info!("Listing policy on checker of node defined by '{}'", node_config_path.display());

    // See if we need to resolve the token & address
    let mut worker: Option<WorkerConfig> = None;
    let token: String = resolve_token(&node_config_path, &mut worker, token)?;
    let address: Address = resolve_addr_opt(&node_config_path, &mut worker, address)?;

    // Send the request to the reasoner to fetch the active versions
    let versions: HashMap<u64, Metadata> = match get_versions_on_checker(&address, &token).await {
        Ok(versions) => versions,
        Err(err) => return Err(Error::VersionsGet { addr: address, err: Box::new(err) }),
    };
    // Then fetch the already active version
    let active_version: Option<u64> = match get_active_version_on_checker(&address, &token).await {
        Ok(version) => version,
        Err(err) => return Err(Error::ActiveVersionGet { addr: address, err: Box::new(err) }),
    };

    // Enter a loop where we let the user decide for themselves
    loop {
        // Display them to the user, with name, to select the policy they want to see more info about
        let version: u64 = match prompt_user_version("Select a version to inspect:", active_version, &versions, true) {
            Ok(Some(idx)) => idx,
            Ok(None) => return Ok(()),
            Err(err) => return Err(Error::PromptVersions { err: Box::new(err) }),
        };

        // Attempt to pull this version from the remote
        let contents: Value = match get_version_body_from_checker(&address, &token, version).await {
            Ok(contents) => contents,
            Err(err) => return Err(Error::VersionGetBody { addr: address, version, err: Box::new(err) }),
        };

        // Render it
        let md: &Metadata = versions.get(&version).unwrap();
        println!("Policy {} ({})", style(format!("{:?}", md.attached.name)).bold().green(), style(md.version).bold());
        println!("  For {}", style(format!("{:?}", md.attached.language)).bold());
        println!("  By  {} ({})", style(format!("{:?}", md.creator.name)).bold(), style(format!("{:?}", md.creator.id)).bold());
        println!("  At  {}", style(DateTime::<Local>::from(md.created).format("%Y-%m-%d %H:%M:%S")).bold());
        println!("  {:?}", md.attached.description);
        println!("{}", "-".repeat(80));
        if let Err(err) = serde_json::to_writer_pretty(std::io::stdout(), &contents) {
            return Err(Error::VersionSerialize { version, err });
        }
        println!("{}", "-".repeat(80));
        println!();
    }
}
