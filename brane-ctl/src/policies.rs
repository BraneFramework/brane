//  POLICIES.rs
//    by Lut99
//
//  Created:
//    10 Jan 2024, 15:57:54
//  Last edited:
//    24 Jun 2024, 17:40:43
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements handlers for subcommands to `branectl policies ...`
//

use std::error;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::{Path, PathBuf};
use std::time::Duration;

use brane_cfg::info::Info;
use brane_cfg::node::{NodeConfig, NodeSpecificConfig, WorkerConfig};
use brane_shr::formatters::BlockFormatter;
use console::style;
use dialoguer::theme::ColorfulTheme;
use enum_debug::EnumDebug;
use error_trace::trace;
use log::{debug, info};
use policy::{Policy, PolicyVersion};
use rand::Rng;
use rand::distr::Alphanumeric;
use reqwest::{Client, Request, Response, StatusCode};
use serde_json::value::RawValue;
use specifications::address::{Address, AddressOpt};
use specifications::checking::{
    POLICY_API_ADD_VERSION, POLICY_API_GET_ACTIVE_VERSION, POLICY_API_GET_VERSION, POLICY_API_LIST_POLICIES, POLICY_API_SET_ACTIVE_VERSION,
};
use srv::models::{AddPolicyPostModel, PolicyContentPostModel, SetVersionPostModel};
use tokio::fs::{self as tfs, File as TFile};

use crate::spec::PolicyInputLanguage;


/***** ERRORS *****/
/// Defines errors that may originate in `branectl policies ...` subcommands.
#[derive(Debug)]
pub enum Error {
    /// Failed to get the active version of the policy.
    ActiveVersionGet { addr: Address, err: Box<Self> },
    /// Failed to deserialize the read input file as JSON.
    InputDeserialize { path: PathBuf, raw: String, err: serde_json::Error },
    /// Failed to read the input file.
    InputRead { path: PathBuf, err: std::io::Error },
    /// Failed to compile the input file to eFLINT JSON.
    InputToJson { path: PathBuf, err: eflint_to_json::Error },
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
    VersionGetBody { addr: Address, version: i64, err: Box<Self> },
    /// Failed to query the user which version to select.
    VersionSelect { err: dialoguer::Error },
    /// Failed to get the versions on the remote checker.
    VersionsGet { addr: Address, err: Box<Self> },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            ActiveVersionGet { addr, .. } => write!(f, "Failed to get active version of checker '{addr}'"),
            InputDeserialize { path, raw, .. } => {
                write!(f, "Failed to deserialize contents of '{}' to JSON\n\nRaw value:\n{}\n", path.display(), BlockFormatter::new(raw))
            },
            InputRead { path, .. } => write!(f, "Failed to read input file '{}'", path.display()),
            InputToJson { path, .. } => write!(f, "Failed to compile input file '{}' to eFLINT JSON", path.display()),
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
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            ActiveVersionGet { err, .. } => Some(&**err),
            InputDeserialize { err, .. } => Some(err),
            InputRead { err, .. } => Some(err),
            InputToJson { err, .. } => Some(err),
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
            &worker_cfg.paths.policy_expert_secret,
        ) {
            Ok(token) => {
                debug!("Using generated token '{token}'");
                *worker = Some(worker_cfg);
                Ok(token)
            },
            Err(err) => Err(Error::TokenGenerate { secret: worker_cfg.paths.policy_expert_secret, err }),
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
    if address.port().is_none() {
        // Resolve the worker and store the port of the checker
        let worker_cfg: WorkerConfig = resolve_worker_config(&node_config_path, worker.take())?;
        *address.port_mut() = Some(worker_cfg.services.chk.address.port());
        *worker = Some(worker_cfg);
    }

    // Return the address as an [`Address`], which we can unwrap because we asserted the port is `Some(...)`.
    Ok(Address::try_from(address).unwrap())
}

/// Helper function that pulls a specific version's body from a checker.
///
/// # Arguments
/// - `address`: The address where the checker may be reached.
/// - `token`: The token used for authenticating the checker.
/// - `version`: The policy version to retrieve the body of.
///
/// # Returns
/// The policy's body, as a parsed [`Policy`].
///
/// # Errors
/// This function may error if we failed to reach the checker, failed to authenticate or failed to download/parse the result.
async fn get_version_body_from_checker(address: &Address, token: &str, version: i64) -> Result<Policy, Error> {
    info!("Retrieving policy '{version}' from checker '{address}'");

    // Prepare the request
    let url: String = format!("http://{}/{}", address, POLICY_API_GET_VERSION.1(version));
    debug!("Building GET-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(POLICY_API_GET_VERSION.0, &url).bearer_auth(token).build() {
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
/// A list of versions found on the remote checkers.
///
/// # Errors
/// This function may error if we failed to reach the checker, failed to authenticate or failed to download/parse the result.
async fn get_versions_on_checker(address: &Address, token: &str) -> Result<Vec<PolicyVersion>, Error> {
    info!("Retrieving policies on checker '{address}'");

    // Prepare the request
    let url: String = format!("http://{}/{}", address, POLICY_API_LIST_POLICIES.1);
    debug!("Building GET-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(POLICY_API_LIST_POLICIES.0, &url).bearer_auth(token).build() {
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

/// Helper function that pulls the currently active versions on a checker.
///
/// # Arguments
/// - `address`: The address where the checker may be reached.
/// - `token`: The token used for authenticating the checker.
///
/// # Returns
/// A single [`Policy`] that describes the active policy, or [`None`] is none is active.
///
/// # Errors
/// This function may error if we failed to reach the checker, failed to authenticate or failed to download/parse the result.
async fn get_active_version_on_checker(address: &Address, token: &str) -> Result<Option<Policy>, Error> {
    info!("Retrieving active policy of checker '{address}'");

    // Prepare the request
    let url: String = format!("http://{}/{}", address, POLICY_API_GET_ACTIVE_VERSION.1);
    debug!("Building GET-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(POLICY_API_GET_ACTIVE_VERSION.0, &url).bearer_auth(token).build() {
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
            match serde_json::from_str(&body) {
                Ok(body) => Ok(body),
                Err(err) => Err(Error::ResponseDeserialize { addr: url, raw: body, err }),
            }
        },
        Err(err) => Err(Error::ResponseDownload { addr: url, err }),
    }
}

/// Prompts the user to select one of the given list of versions.
///
/// # Arguments
/// - `address`: The address (or some other identifier) of the checker/source we retrieved the policy from. Only used for debugging.
/// - `active_version`: If there is any active version.
/// - `versions`: The list of versions to select from.
///
/// # Returns
/// An index into the given list, which is what the user selected. If `exit` is true, then this may return [`None`] when selected.
///
/// # Errors
/// This function may error if we failed to query the user.
fn prompt_user_version(
    address: impl Into<Address>,
    active_version: Option<i64>,
    versions: &[PolicyVersion],
    exit: bool,
) -> Result<Option<usize>, Error> {
    // Preprocess the versions into neat representations
    let mut sversions: Vec<String> = Vec::with_capacity(versions.len() + 1);
    for (i, version) in versions.iter().enumerate() {
        // Discard it if it has no version
        if version.version.is_none() {
            return Err(Error::PolicyWithoutVersion { addr: address.into(), which: format!("{i}th") });
        }

        // See if it's selected to print either bold or not
        let mut line: String = if version.version == active_version { style("Version ").bold().to_string() } else { "Version ".into() };
        line.push_str(&style(version.version.unwrap()).bold().green().to_string());
        if version.version == active_version {
            line.push_str(
                &style(format!(
                    " (created at {}, by {})",
                    version.created_at.format("%H:%M:%S %d-%m-%Y"),
                    version.creator.as_deref().unwrap_or("<unknown>")
                ))
                .to_string(),
            );
        } else {
            line.push_str(&format!(
                " (created at {}, by {})",
                version.created_at.format("%H:%M:%S %d-%m-%Y"),
                version.creator.as_deref().unwrap_or("<unknown>")
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
    match dialoguer::Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Which version do you want to make active?")
        .items(&sversions)
        .interact()
    {
        Ok(idx) => {
            if !exit || idx < versions.len() {
                // Exit wasn't selected
                Ok(Some(idx))
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
    /// It's an eFLINT JSON Specification reasoner
    EFlintJson(EFlintJsonVersion),
}
impl TargetReasoner {
    /// Returns the string identifier of the reasoner that can be send to a checker.
    ///
    /// # Returns
    /// A [`String`] that the checker uses to verify if the sent policy matches the backend.
    pub fn id(&self) -> String {
        match self {
            Self::EFlintJson(_) => "eflint-json".into(),
        }
    }

    /// Returns the string identifier of the reasoner version that can be send to a checker.
    ///
    /// # Returns
    /// A [`String`] version that the checker uses to verify if the sent policy matches the backend.
    pub fn version(&self) -> String {
        match self {
            Self::EFlintJson(v) => v.to_string(),
        }
    }
}

/// Defines supported [`TargetReasoner::EFlintJson`] specification versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EFlintJsonVersion {
    /// Specification version 0.1.0 (see <https://gitlab.com/eflint/json-specification/-/releases/v0.1.0>).
    V0_1_0,
}
impl Display for EFlintJsonVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::V0_1_0 => write!(f, "0.1.0"),
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
pub async fn activate(node_config_path: PathBuf, version: Option<i64>, address: AddressOpt, token: Option<String>) -> Result<(), Error> {
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
    let version: i64 = if let Some(version) = version {
        version
    } else {
        // Alrighty; first, pull a list of all available versions from the checker
        let mut versions: Vec<PolicyVersion> = match get_versions_on_checker(&address, &token).await {
            Ok(versions) => versions,
            Err(err) => return Err(Error::VersionsGet { addr: address, err: Box::new(err) }),
        };
        // Then fetch the already active version
        let active_version: Option<i64> = match get_active_version_on_checker(&address, &token).await {
            Ok(version) => version.and_then(|v| v.version.version),
            Err(err) => return Err(Error::ActiveVersionGet { addr: address, err: Box::new(err) }),
        };

        // Prompt the user to select it
        let idx: usize = match prompt_user_version(&address, active_version, &versions, false) {
            Ok(Some(idx)) => idx,
            Ok(None) => unreachable!(),
            Err(err) => return Err(Error::PromptVersions { err: Box::new(err) }),
        };
        versions.swap_remove(idx).version.unwrap()
    };
    debug!("Activating policy version {version}");

    // Now build the request and send it
    let url: String = format!("http://{}/{}", address, POLICY_API_SET_ACTIVE_VERSION.1);
    debug!("Building PUT-request to '{url}'...");
    let client: Client = Client::new();
    let req: Request = match client.request(POLICY_API_SET_ACTIVE_VERSION.0, &url).bearer_auth(token).json(&SetVersionPostModel { version }).build() {
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

    // Attempt to parse the result as a Policy
    let res: Policy = match res.text().await {
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
    if res.version.version != Some(version) {
        return Err(Error::InvalidPolicyActivated { addr: address, got: res.version.version, expected: Some(version) });
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

    // If the language is not given, resolve it from the file extension
    let language: PolicyInputLanguage = if let Some(language) = language {
        debug!("Interpreting input as {language}");
        language
    } else if let Some(ext) = input.extension() {
        debug!("Attempting to derive input language from extension '{}' (part of '{}')", ext.to_string_lossy(), input.display());

        // Else, attempt to resolve from the extension
        if ext == OsStr::new("eflint") {
            PolicyInputLanguage::EFlint
        } else if ext == OsStr::new("json") {
            PolicyInputLanguage::EFlintJson
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
    let (json, target_reasoner): (String, TargetReasoner) = match language {
        PolicyInputLanguage::EFlint => {
            // We read it as eFLINT to JSON
            debug!("Compiling eFLINT input file '{}' to eFLINT JSON", input.display());
            let mut json: Vec<u8> = Vec::new();
            if let Err(err) = eflint_to_json::compile_async(&input, &mut json, None).await {
                return Err(Error::InputToJson { path: input, err });
            }

            // Serialize it to a string
            match String::from_utf8(json) {
                Ok(json) => (json, TargetReasoner::EFlintJson(EFlintJsonVersion::V0_1_0)),
                Err(err) => panic!("{}", trace!(("eflint_to_json::compile_async() did not return valid UTF-8"), err)),
            }
        },
        PolicyInputLanguage::EFlintJson => {
            // Read the file in one go
            debug!("Reading eFLINT JSON input file '{}'", input.display());
            match tfs::read_to_string(&input).await {
                Ok(json) => (json, TargetReasoner::EFlintJson(EFlintJsonVersion::V0_1_0)),
                Err(err) => return Err(Error::InputRead { path: input, err }),
            }
        },
    };

    // Ensure it is JSON
    debug!("Deserializing input as JSON...");
    let json: Box<RawValue> = match serde_json::from_str(&json) {
        Ok(json) => json,
        Err(err) => return Err(Error::InputDeserialize { path: input, raw: json, err }),
    };

    // Finally, construct a request for the checker
    let url: String = format!("http://{}/{}", address, POLICY_API_ADD_VERSION.1);
    debug!("Building POST-request to '{url}'...");
    let client: Client = Client::new();
    let contents: AddPolicyPostModel = AddPolicyPostModel {
        version_description: "".into(),
        description: None,
        content: vec![PolicyContentPostModel { reasoner: target_reasoner.id(), reasoner_version: target_reasoner.version(), content: json }],
    };
    let req: Request = match client.request(POLICY_API_ADD_VERSION.0, &url).bearer_auth(token).json(&contents).build() {
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
    let body: Policy = match res.text().await {
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
        "Successfully added policy {} to checker {}{}.",
        style(if from_stdin { "<stdin>".into() } else { input.display().to_string() }).bold().green(),
        style(address).bold().green(),
        if let Some(version) = body.version.version { format!(" as version {}", style(version).bold().green()) } else { String::new() }
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
    let mut versions: Vec<PolicyVersion> = match get_versions_on_checker(&address, &token).await {
        Ok(versions) => versions,
        Err(err) => return Err(Error::VersionsGet { addr: address, err: Box::new(err) }),
    };
    // Then fetch the already active version
    let active_version: Option<i64> = match get_active_version_on_checker(&address, &token).await {
        Ok(version) => version.and_then(|v| v.version.version),
        Err(err) => return Err(Error::ActiveVersionGet { addr: address, err: Box::new(err) }),
    };

    // Enter a loop where we let the user decide for themselves
    loop {
        // Display them to the user, with name, to select the policy they want to see more info about
        let idx: usize = match prompt_user_version(&address, active_version, &versions, true) {
            Ok(Some(idx)) => idx,
            Ok(None) => break,
            Err(err) => return Err(Error::PromptVersions { err: Box::new(err) }),
        };
        let version: i64 = versions.swap_remove(idx).version.unwrap();

        // Attempt to pull this version from the remote
        let _version: Policy = match get_version_body_from_checker(&address, &token, version).await {
            Ok(version) => version,
            Err(err) => return Err(Error::VersionGetBody { addr: address, version, err: Box::new(err) }),
        };
    }

    // TODO: Finish this. The idea is show a particular version to the user, then re-enter the loop until they quit
    //       (empty version, as above)
    todo!();
}
