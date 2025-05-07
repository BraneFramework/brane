//  DATA.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 17:39:06
//  Last edited:
//    02 May 2025, 15:03:01
//  Auto updated?
//    Yes
//
//  Description:
//!   Does things relating to datasets (and the `data` subcommand).
//

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use brane_shr::fs::copy_dir_recursively_async;
use brane_shr::utilities::is_ip_addr;
use brane_tsk::spec::LOCALHOST;
use chrono::Utc;
use console::{Alignment, Term, pad_str, style};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Select};
use indicatif::HumanDuration;
use prettytable::Table;
use prettytable::format::FormatBuilder;
use rand::prelude::IteratorRandom;
use reqwest::tls::{Certificate, Identity};
use reqwest::{Client, ClientBuilder, Proxy};
use specifications::data::{AccessKind, AssetInfo, DataIndex, DataInfo, DataName};
use specifications::registering::DownloadAssetRequest;
use specifications::wir::{Edge, Workflow};
use tempfile::TempDir;
use tokio::fs as tfs;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

use crate::errors::DataError;
use crate::instance::InstanceInfo;
use crate::utils::{ensure_dataset_dir, ensure_datasets_dir, get_dataset_dir};


/***** LIBRARY *****/
/// Attempts to download the given dataset from the instance.
///
/// For now, this function uses a random selection since it assumes there will usually only be one location that advertises having it. However, this is super bad practise and will lead to undefined results if there are multiple.
///
/// # Arguments
/// - `api_endpoint`: The remote `brane-api` endpoint that we use to download the possible registries.
/// - `proxy_addr`: If given, the any data transfers will be proxied through this address.
/// - `certs_dir`: The directory where certificates are stored. Expected to contain nested directories that store the certs by domain ID.
/// - `data_dir`: The directory to download the dataset to.
/// - `name`: The name of the dataset to download.
/// - `workflow`: A workflow for which we're downloading a result.
/// - `access`: The locations where it is available.
///
/// # Returns
/// The AccessKind with how to download the dataset if it was downloaded successfully, or `None` if it wasn't available.
///
/// # Errors
/// This function errors if we failed to download the dataset somehow.
#[allow(clippy::too_many_arguments)]
pub async fn download_data(
    api_endpoint: impl AsRef<str>,
    proxy_addr: &Option<String>,
    certs_dir: impl AsRef<Path>,
    data_dir: impl AsRef<Path>,
    use_case: String,
    name: impl AsRef<str>,
    workflow: Workflow,
    access: &HashMap<String, AccessKind>,
) -> Result<Option<AccessKind>, DataError> {
    let api_endpoint: &str = api_endpoint.as_ref();
    let certs_dir: &Path = certs_dir.as_ref();
    let data_dir: &Path = data_dir.as_ref();
    let name: &str = name.as_ref();

    /* Step 1: Get target registry address */
    // Choose a random location to attempt to download the asset from.
    if access.is_empty() {
        return Ok(None);
    }
    let mut rng = rand::rng();
    let location: &str = access.keys().choose(&mut rng).unwrap();

    // Send a GET-request to resolve that location to a delegate
    let registry_addr = format!("http://{api_endpoint}/infra/registries/{location}");
    let res =
        reqwest::get(&registry_addr).await.map_err(|source| DataError::RequestError { what: "registry", address: registry_addr.clone(), source })?;

    // Attempt to get its body if it was a success
    if !res.status().is_success() {
        return Err(DataError::RequestFailure { address: registry_addr, code: res.status(), message: res.text().await.ok() });
    }

    let registry_addr: String = res.text().await.map_err(|source| DataError::ResponseTextError { address: registry_addr, source })?;

    debug!("Remote registry: '{}'", registry_addr);

    /* Step 2: Load the required certificates */
    debug!("Loading certificate for location '{}'...", location);
    let (identity, ca_cert): (Identity, Certificate) = {
        // Compute the paths
        let cert_dir = certs_dir.join(location);
        let idfile = cert_dir.join("client-id.pem");
        let cafile = cert_dir.join("ca.pem");

        // Load the keypair for this location as an Identity file (for which we just smash 'em together and hope that works)
        let ident_raw =
            tfs::read(&idfile).await.map_err(|source| DataError::FileReadError { what: "client identity", path: idfile.clone(), source })?;

        let ident = Identity::from_pem(&ident_raw).map_err(|source| DataError::IdentityFileError { path: idfile.clone(), source })?;

        // Load the root store for this location (also as a list of certificates)
        let raw_root =
            tfs::read(&cafile).await.map_err(|source| DataError::FileReadError { what: "server cert root", path: cafile.clone(), source })?;

        // Load the root store for this location (also as a list of certificates)
        let root = Certificate::from_pem(&raw_root).map_err(|source| DataError::CertificateError { path: cafile, source })?;

        // Return them, with the cert and key as identity
        (ident, root)
    };

    /* Step 3: Prepare the filesystem */
    debug!("Preparing filesystem...");

    // Make sure the temporary tarfile directory exists
    let tar_dir = TempDir::new().map_err(|source| DataError::TempDirError { source })?;
    let tar_path = tar_dir.path().join(format!("data_{name}.tar.gz"));

    // Make sure the old data path doesn't exist anymore
    let data_path = data_dir.join("data");
    if data_path.exists() {
        if !data_path.is_dir() {
            return Err(DataError::DirNotADirError { what: "target data", path: data_path });
        }
        tfs::remove_dir_all(&data_path).await.map_err(|source| DataError::DirRemoveError { what: "target data", path: data_path.clone(), source })?;
    }

    /* Step 4: Build the client. */
    let download_addr: String = format!("https://{registry_addr}/data/download/{name}");
    debug!("Sending download request to '{}'...", download_addr);
    let mut client: ClientBuilder =
        Client::builder().use_rustls_tls().add_root_certificate(ca_cert).identity(identity).tls_sni(!is_ip_addr(&download_addr));

    if let Some(proxy_addr) = proxy_addr {
        client = client.proxy(Proxy::all(proxy_addr).map_err(|source| DataError::ProxyCreateError { address: proxy_addr.into(), source })?);
    }

    let client = client.build().map_err(|source| DataError::ClientCreateError { source })?;

    // Send a reqwest
    let res = client
        .get(&download_addr)
        .json(&DownloadAssetRequest {
            use_case,
            workflow: serde_json::to_value(workflow)
                .map_err(|source| DataError::WorkflowSerializeError { context: String::from("creating download asset request"), source })?,
            task: None,
        })
        .send()
        .await
        .map_err(|source| DataError::RequestError { what: "download", address: download_addr.clone(), source })?;

    if !res.status().is_success() {
        return Err(DataError::RequestFailure { address: download_addr, code: res.status(), message: res.text().await.ok() });
    }

    /* Step 5: Download the raw file in parts */
    debug!("Downloading file to '{}'...", tar_path.display());
    {
        let mut handle = tfs::File::create(&tar_path).await.map_err(|source| DataError::TarCreateError { path: tar_path.clone(), source })?;

        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            // Unwrap the chunk
            let mut chunk = chunk.map_err(|source| DataError::DownloadStreamError { address: download_addr.clone(), source })?;

            // Write it to the file
            handle.write_all_buf(&mut chunk).await.map_err(|source| DataError::TarWriteError { path: tar_path.clone(), source })?;
        }
    }

    /* Step 6: Extract the tar. */
    debug!("Unpacking '{}' to '{}'...", tar_path.display(), data_path.display());
    brane_shr::fs::unarchive_async(tar_path, &data_path).await.map_err(|source| DataError::TarExtractError { source })?;

    /* Step 7: In the case of brane-cli, also write a DataInfo. */
    let access = AccessKind::File { path: data_path };
    {
        let info_path = data_dir.join("data.yml");
        debug!("Writing data info to '{}'...", info_path.display());

        // Populate the info itself
        let info = DataInfo {
            name: name.into(),
            owners: None,
            description: None,
            created: Utc::now(),

            access: HashMap::from([(LOCALHOST.into(), access.clone())]),
        };

        // Write it
        info.to_path(&info_path).map_err(|source| DataError::DataInfoWriteError { source })?;
    }

    /* Step 7: Done */
    Ok(Some(access))
}



/// Builds the given data.yml file to a locally usable package.
///
/// # Arguments
/// - `file`: The `data.yml` file to use as the definition.
/// - `workdir`: The directory to resolve all relative paths to.
/// - `keep_files`: Keep any intermediate build files.
/// - `no_links`: Always copy files to the Brane data folder to prevent links going all over the system.
///
/// # Returns
/// Nothing, but does build a new dataset in the `~/.local/share/brane/data` folder.
///
/// # Errors
/// This function may error if the build failed for any reason. Typically, this may be filesystem/IO errors or malformed data.yml / paths.
pub async fn build(file: impl AsRef<Path>, workdir: impl AsRef<Path>, _keep_files: bool, no_links: bool) -> Result<(), DataError> {
    let file: &Path = file.as_ref();
    let workdir: &Path = workdir.as_ref();

    /* Step 1: Read the input */
    // Parse the input file as a AssetFile (which is a datafile but with user info attached to it).
    let mut info: AssetInfo = AssetInfo::from_path(file).map_err(|source| DataError::AssetFileError { path: file.into(), source })?;
    // Inject the current time if not already
    info.created = Utc::now();

    // Make sure the files exist and resolve them to absolute paths
    match &mut info.access {
        AccessKind::File { ref mut path } => {
            // If it is relative, then make sure it's relative according to the data path
            if path.is_relative() {
                // Create a new relative path
                let apath: PathBuf = workdir.join(&path);
                let apath: PathBuf = apath.canonicalize().map_err(|source| DataError::FileCanonicalizeError { path: apath.clone(), source })?;
                *path = apath;
            }

            // Make sure exists & it's a file and not a directory
            // Nah, actually, why couldn't it be a directory?
            if !path.exists() {
                return Err(DataError::FileNotFoundError { path: path.clone() });
            }
            // if !path.is_file() { return Err(DataError::FileNotAFileError{ path: path.clone() }); }
        },
    }

    /* Step 2: Prepare the build directory. */
    // Before we create it though, if it happens to exist, then moan about it
    if let Ok(dir) = get_dataset_dir(&info.name) {
        if dir.exists() {
            return Err(DataError::DuplicateDatasetError { name: info.name });
        }
    }

    // Simple use our ensure thing for this
    let build_dir: PathBuf = ensure_dataset_dir(&info.name, true).map_err(|source| DataError::DatasetDirCreateError { source })?;

    /* Step 3: Move any files if we don't want no links. */
    if no_links {
        match &mut info.access {
            AccessKind::File { ref mut path } => {
                // Perform the copy
                let target: PathBuf = build_dir.join(path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "data".into()));
                copy_dir_recursively_async(&path, &target).await.map_err(|source| DataError::DataCopyError { source })?;

                // Update the path to the target
                *path = target;
            },
        }
    }

    /* Step 4: Write the AssetInfo to a DataInfo. */
    let data_info: DataInfo = info.into();

    data_info.to_path(build_dir.join("data.yml")).map_err(|source| DataError::DataInfoWriteError { source })?;

    /* Step 5: Done */
    println!("Successfully built dataset {}", style(&data_info.name).bold().cyan());
    Ok(())
}

/// Downloads a dataset from one or more remote hosts.
///
/// # Arguments
/// - `names`: The names of the dataset to download.
/// - `locs`: A name=loc keymap to specify locations for each dataset.
/// - `proxy_addr`: The proxy address to proxy the transfer through, if any.
/// - `force`: Forces a download, even if the dataset is already available.
///
/// # Returns
/// The method for accessing the new data file. Clearly, this means it also creates a new local entry for a dataset upon success.
///
/// # Errors
/// This function may error if the download failed for any reason.
pub async fn download(
    names: Vec<String>,
    locs: Vec<String>,
    use_case: String,
    user: String,
    proxy_addr: &Option<String>,
    force: bool,
) -> Result<(), DataError> {
    // Parse the locations into a map
    let mut locations: HashMap<String, String> = HashMap::with_capacity(locs.len());
    for l in locs {
        // Go through each comma-separated pair
        for l in l.split(',') {
            // Find the equals
            if let Some(equals_pos) = l.find('=') {
                // Split it and store the halves
                locations.insert(l[..equals_pos].into(), l[equals_pos + 1..].into());
            } else {
                return Err(DataError::NoEqualsInKeyPair { raw: l.into() });
            }
        }
    }

    // Fetch the endpoint from the login file
    let instance_info: InstanceInfo = InstanceInfo::from_active_path().map_err(|source| DataError::InstanceInfoError { source })?;

    // Fetch a new, remote DataIndex to get up-to-date entries
    let data_addr: String = format!("http://{}/data/info", instance_info.api);
    let index: DataIndex =
        brane_tsk::api::get_data_index(&data_addr).await.map_err(|source| DataError::RemoteDataIndexError { address: data_addr, source })?;

    // Iterate over the to-be-downloaded datasets
    for name in names {
        // Make sure we know it
        let info: &DataInfo = index.get(&name).ok_or_else(|| DataError::UnknownDataset { name: name.clone() })?;

        debug!("Selecting download location for '{}'...", name);
        let loc: String = {
            // Make sure the dataset is available _somewhere_
            if info.access.is_empty() {
                return Err(DataError::UnavailableDataset { name: name.clone(), locs: vec![] });
            }
            // If we're given one, use it
            if let Some(loc) = locations.get(&name) {
                loc.clone()
            } else {
                // More effort is needed

                // ...unless it's available locally
                if !force && info.access.contains_key(LOCALHOST) {
                    println!("Dataset {} is already locally available; not initiating a download", style(name).cyan().bold());
                    return Ok(());
                }

                // Now, pick the only one or ask the user
                if info.access.len() == 1 {
                    info.access.keys().next().unwrap().clone()
                } else {
                    // Prepare the prompt with beautiful themes and such
                    let colorful = ColorfulTheme::default();
                    let items: Vec<&String> = info.access.keys().collect();
                    let mut prompt = Select::with_theme(&colorful);
                    prompt = prompt.items(&items).with_prompt("Select download location").default(0usize);

                    // Ask the user
                    match prompt.interact_on_opt(&Term::stderr()) {
                        Ok(res) => res.map(|i| items[i].clone()).unwrap_or_else(|| items[0].clone()),
                        Err(source) => {
                            return Err(DataError::DataSelectError { source });
                        },
                    }
                }
            }
        };

        println!("Downloading {} from {}...", style(&name).bold().cyan(), style(&loc).bold().cyan());

        // Create an access map with only the location entry
        let mut access: HashMap<String, AccessKind> = HashMap::with_capacity(1);
        if let Some(a) = info.access.get(&loc) {
            access.insert(loc, a.clone());
        } else {
            return Err(DataError::UnknownLocation { name: loc });
        }

        // Fetch the method of its availability
        let access: AccessKind = match info.access.get(LOCALHOST) {
            Some(access) => access.clone(),
            None => {
                let mut workflow = Workflow::with_random_id(
                    Default::default(),
                    vec![Edge::Return { result: HashSet::from([DataName::Data(name.clone())]) }],
                    Default::default(),
                );

                *Arc::get_mut(&mut workflow.user).expect("Could not set user on workflow") = Some(user.clone());

                // Get the certificate path
                let certs_dir: PathBuf = match InstanceInfo::get_active_name() {
                    Ok(name) => match InstanceInfo::get_instance_path(&name) {
                        Ok(path) => path.join("certs"),
                        Err(source) => {
                            return Err(DataError::InstancePathError { name, source });
                        },
                    },
                    Err(source) => {
                        return Err(DataError::ActiveInstanceReadError { source });
                    },
                };

                // Get the path to download it to
                let data_dir: PathBuf =
                    ensure_dataset_dir(&name, true).map_err(|source| DataError::DatasetDirError { name: name.clone(), source })?;

                // Run the download
                download_data(instance_info.api.to_string(), proxy_addr, certs_dir, data_dir, use_case.clone(), &name, workflow, &access)
                    .await?
                    .ok_or_else(|| DataError::UnavailableDataset { name, locs: info.access.keys().cloned().collect() })?
            },
        };

        // Write the method of access
        println!("Download {}", style("success").bold().cyan());
        match access {
            AccessKind::File { path } => println!("(It's available under '{}')", path.display()),
        }
    }

    // Done
    Ok(())
}

/// Lists all locally built/available datasets.
///
/// # Returns
/// Nothing, but does print a neat table to stdout.
///
/// # Errors
/// This function may error if we somehow failed to discover all the files.
pub fn list() -> Result<(), DataError> {
    // Prepare display table.
    let format = FormatBuilder::new().column_separator('\0').borders('\0').padding(1, 1).build();
    let mut table = Table::new();
    table.set_format(format);
    table.add_row(row!["ID/NAME", "KIND", "CREATED", "LINKED?", "ACCESS"]);

    // Get the local datasets folder
    let datasets_dir: PathBuf = ensure_datasets_dir(false).map_err(|source| DataError::DatasetsError { source })?;

    // Get the local DataIndex, which contains the local data infos
    let now: i64 = Utc::now().timestamp();
    let index: DataIndex = brane_tsk::local::get_data_index(datasets_dir).map_err(|source| DataError::LocalDataIndexError { source })?;

    for d in index {
        // Add the name/id of the dataset
        let name = pad_str(&d.name, 20, Alignment::Left, Some(".."));

        // Add the kind of the dataset
        let (kind, access, is_linked): (&str, String, bool) =
            match d.access.get("localhost").expect("Local dataset does not have 'localhost' as location; this should never happen!") {
                AccessKind::File { path } => {
                    // Determine if this file is linked (it is if the path points outside the data directory itself)
                    let is_linked: bool = if let Ok(dir) = get_dataset_dir(&d.name) {
                        !path.starts_with(dir)
                    } else {
                        panic!("DataInfo '{}' points to non-existing dataset; this should never happen!", d.name);
                    };

                    // The kind is the name, the access is the path to the file
                    ("File", path.to_string_lossy().into(), is_linked)
                },
            };
        let sis_linked: String = if is_linked { String::from("yes") } else { String::from("no") };
        let (kind, access, is_linked): (Cow<str>, Cow<str>, Cow<str>) = (
            pad_str(kind, 10, Alignment::Left, Some("..")),
            pad_str(&access, 60, Alignment::Left, Some("..")),
            pad_str(&sis_linked, 5, Alignment::Left, Some("..")),
        );

        // Fetch the created (or rather, elapsed)
        let elapsed = Duration::from_secs((now - d.created.timestamp()) as u64);
        let created = format!("{} ago", HumanDuration(elapsed));
        let created = pad_str(&created, 15, Alignment::Left, Some(".."));

        // Finally, add a row with it
        table.add_row(row![name, kind, created, is_linked, access]);
    }

    // Write to stdout and done!
    table.printstd();
    Ok(())
}

/// Returns the paths to the locally available datasets.
///
/// # Arguments
/// - `datasets`: The names of the datasets to list the paths for.
///
/// # Returns
/// Nothing, but does print the paths to stdout in a machine-readable fashion.
///
/// # Errors
/// This function may error if we failed to read any of the files or directories.
pub fn path(datasets: Vec<impl AsRef<str>>) -> Result<(), DataError> {
    // Get the local datasets folder
    let datasets_dir: PathBuf = ensure_datasets_dir(false).map_err(|source| DataError::DatasetsError { source })?;

    // Simply attempt to find all of the datasets in the local index
    let index: DataIndex = brane_tsk::local::get_data_index(datasets_dir).map_err(|source| DataError::LocalDataIndexError { source })?;

    for d in datasets {
        let d: &str = d.as_ref();

        // Check if the dataset exists
        if let Some(info) = index.get(d) {
            if let Some(access) = info.access.get(LOCALHOST) {
                // Match on the access kind
                match access {
                    AccessKind::File { path } => {
                        println!("{}", path.display());
                    },

                    #[allow(unreachable_patterns)]
                    _ => {
                        println!("<none>")
                    },
                }
            } else {
                return Err(DataError::UnavailableDataset { name: d.into(), locs: info.access.keys().cloned().collect() });
            }
        } else {
            return Err(DataError::UnknownDataset { name: d.into() });
        }
    }

    // Done
    Ok(())
}

/// Removes the dataset with the given identifier from the local database.
///
/// # Arguments
/// - `datasets`: The list of datasets to delete.
/// - `force`: Whether or not to force the removal (i.e., if true, do not ask the user for confirmation).
///
/// # Returns
/// Nothing, but does delete the datasets from the `~/.local/share/brane/data` folder.
///
/// # Errors
/// This function may error if the removal of one of the datasets failed (after which no other will be removed). This is typically due to the dataset not being found or not having permissions to remove it.
pub fn remove(datasets: Vec<impl AsRef<str>>, force: bool) -> Result<(), DataError> {
    // Remove them all
    for d in datasets {
        let d: &str = d.as_ref();

        // Fetch the directory of this dataset
        let dir: PathBuf = get_dataset_dir(d).map_err(|source| DataError::DatasetDirError { name: d.into(), source })?;

        // Ask the user if they are sure
        if !force {
            println!("Are you sure you want to remove dataset {}?", style(&d).bold().cyan());
            println!("(Note that, if the dataset is linked, the dataset itself will not be removed)");
            println!();
            let consent: bool = Confirm::new().interact().map_err(|source| DataError::ConfirmationError { source })?;

            if !consent {
                return Ok(());
            }
        }

        // Everything checks out so just delete that folder
        fs::remove_dir_all(&dir).map_err(|source| DataError::RemoveError { path: dir, source })?;

        println!("Successfully removed dataset {}", style(&d).bold().cyan());
    }

    // Done
    Ok(())
}
