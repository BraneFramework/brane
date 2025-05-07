use std::collections::HashMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use brane_tsk::local::get_package_versions;
use chrono::{DateTime, Utc};
use console::{Alignment, pad_str, style};
use dialoguer::Confirm;
use flate2::Compression;
use flate2::write::GzEncoder;
use graphql_client::{GraphQLQuery, Response};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::Table;
use prettytable::format::FormatBuilder;
use reqwest::{self, Body, Client};
use specifications::package::{PackageInfo, PackageKind};
use specifications::version::Version;
use tokio::fs::File as TokioFile;
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;

use crate::errors::RegistryError;
use crate::instance::InstanceInfo;
use crate::utils::{ensure_package_dir, ensure_packages_dir, get_packages_dir};


type DateTimeUtc = DateTime<Utc>;


/***** HELPER FUNCTIONS *****/
/// Get the GraphQL endpoint of the Brane API.
///
/// # Returns
/// The endpoint (as a String).
///
/// # Errors
/// This function may error if we could not find, read or parse the config file with the login data. If not found, this likely indicates the user hasn't logged-in yet.
#[inline]
pub fn get_graphql_endpoint() -> Result<String, RegistryError> {
    Ok(format!("http://{}/graphql", InstanceInfo::from_active_path().map_err(|source| RegistryError::InstanceInfoError { source })?.api))
}

/// Get the package endpoint of the Brane API.
///
/// # Returns
/// The endpoint (as a String).
///
/// # Errors
/// This function may error if we could not find, read or parse the config file with the login data. If not found, this likely indicates the user hasn't logged-in yet.
#[inline]
pub fn get_packages_endpoint() -> Result<String, RegistryError> {
    Ok(format!("http://{}/packages", InstanceInfo::from_active_path().map_err(|source| RegistryError::InstanceInfoError { source })?.api))
}

/// Get the data endpoint of the Brane API.
///
/// # Returns
/// The endpoint (as a String).
///
/// # Errors
/// This function may error if we could not find, read or parse the config file with the login data. If not found, this likely indicates the user hasn't logged-in yet.
#[inline]
pub fn get_data_endpoint() -> Result<String, RegistryError> {
    Ok(format!("http://{}/data", InstanceInfo::from_active_path().map_err(|source| RegistryError::InstanceInfoError { source })?.api))
}



/// Pulls packages from a remote registry to the local registry.
///
/// # Arguments
/// - `packages`: The list of `NAME[:VERSION]` pairs indicating what to pull.
///
/// # Errors
/// This function may error for about a million different reasons, chief of which are the remote not being reachable, the user not being logged-in, not being able to write to the package folder, etc.
pub async fn pull(packages: Vec<(String, Version)>) -> Result<(), RegistryError> {
    // Compile the GraphQL schema
    #[derive(GraphQLQuery)]
    #[graphql(schema_path = "src/graphql/api_schema.json", query_path = "src/graphql/get_package.graphql", response_derives = "Debug")]
    pub struct GetPackage;

    // Iterate over the packages
    for (name, version) in packages {
        debug!("Pulling package '{}' version {}", name, version);

        // Get the package directory
        debug!("Downloading container...");
        let packages_dir = get_packages_dir().map_err(|source| RegistryError::PackagesDirError { source })?;
        let package_dir = packages_dir.join(&name);
        let mut temp_file = tempfile::NamedTempFile::new().expect("Failed to create temporary file.");

        // Create the target endpoint for this package
        let url = format!("{}/{}/{}", get_packages_endpoint()?, name, version);
        let mut package_archive: reqwest::Response =
            reqwest::get(&url).await.map_err(|source| RegistryError::PullRequestError { url: url.clone(), source })?;

        if package_archive.status() != reqwest::StatusCode::OK {
            return Err(RegistryError::PullRequestFailure { url, status: package_archive.status() });
        }

        // Fetch the content length from the response headers
        let content_length =
            package_archive.headers().get("content-length").ok_or_else(|| RegistryError::MissingContentLength { url: url.clone() })?;
        let content_length = content_length.to_str().map_err(|source| RegistryError::ContentLengthStrError { url: url.clone(), source })?;
        let content_length: u64 = content_length.parse().map_err(|source| RegistryError::ContentLengthParseError {
            url: url.clone(),
            raw: content_length.into(),
            source,
        })?;

        // Write package archive to temporary file
        let progress = ProgressBar::new(content_length);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("Downloading... [{elapsed_precise}] {bar:40.cyan/blue} {percent}/100%")
                .unwrap()
                .progress_chars("##-"),
        );

        while let Some(chunk) = package_archive.chunk().await.map_err(|source| RegistryError::PackageDownloadError { url: url.clone(), source })? {
            progress.inc(chunk.len() as u64);
            temp_file.write_all(&chunk).map_err(|source| RegistryError::PackageWriteError {
                url: url.clone(),
                path: temp_file.path().into(),
                source,
            })?;
        }

        progress.finish();

        // Retreive package information from API.
        let client = reqwest::Client::new();
        let graphql_endpoint = get_graphql_endpoint()?;
        debug!("Fetching package metadata from '{}'...", graphql_endpoint);

        // Prepare GraphQL query.
        let variables = get_package::Variables { name: name.clone(), version: version.to_string() };
        let graphql_query = GetPackage::build_query(variables);

        // Request/response for GraphQL query.
        let graphql_response = client
            .post(&graphql_endpoint)
            .json(&graphql_query)
            .send()
            .await
            .map_err(|source| RegistryError::GraphQLRequestError { url: graphql_endpoint.clone(), source })?;
        let graphql_response: Response<get_package::ResponseData> =
            graphql_response.json().await.map_err(|source| RegistryError::GraphQLResponseError { url: graphql_endpoint.clone(), source })?;

        // Attempt to parse the response data as a PackageInfo
        let version = if let Some(data) = graphql_response.data {
            // Extract the packages from the list
            let package = data.packages.first().ok_or_else(|| RegistryError::NoPackageInfo { url: url.clone() })?;

            // Parse the package kind first
            let kind = PackageKind::from_str(&package.kind).map_err(|source| RegistryError::KindParseError {
                url: url.clone(),
                raw: package.kind.clone(),
                source,
            })?;

            // Next, the version
            let version = Version::from_str(&package.version).map_err(|source| RegistryError::VersionParseError {
                url: url.clone(),
                raw: package.version.clone(),
                source,
            })?;

            let functions: HashMap<String, specifications::common::Function> = match package.functions_as_json.as_ref() {
                Some(functions) => serde_json::from_str(functions).map_err(|source| RegistryError::FunctionsParseError {
                    url: url.clone(),
                    raw: functions.clone(),
                    source,
                })?,
                None => HashMap::new(),
            };

            let types: HashMap<String, specifications::common::Type> = match package.types_as_json.as_ref() {
                Some(types) => serde_json::from_str(types).map_err(|source| RegistryError::TypesParseError { url, raw: types.clone(), source })?,
                None => HashMap::new(),
            };

            // Finally, combine everything in a fully-fledged PackageInfo
            let package_info = PackageInfo {
                created: package.created,
                description: package.description.clone().unwrap_or_default(),
                detached: package.detached,
                digest: package.digest.clone(),
                functions,
                id: package.id,
                kind,
                name: package.name.clone(),
                owners: package.owners.clone(),
                types,
                version,
            };

            // Create the directory
            let package_dir = package_dir.join(version.to_string());
            fs::create_dir_all(&package_dir).map_err(|source| RegistryError::PackageDirCreateError { path: package_dir.clone(), source })?;

            // Write package.yml to package directory
            let package_info_path = package_dir.join("package.yml");
            let handle = File::create(&package_info_path)
                .map_err(|source| RegistryError::PackageInfoCreateError { path: package_info_path.clone(), source })?;
            serde_yaml::to_writer(handle, &package_info)
                .map_err(|source| RegistryError::PackageInfoWriteError { path: package_info_path.clone(), source })?;

            // Done!
            version
        } else {
            // The server did not return a package info at all :(
            return Err(RegistryError::NoPackageInfo { url });
        };

        // Copy package to package directory.
        let package_dir = package_dir.join(version.to_string());
        fs::copy(temp_file.path(), package_dir.join("image.tar")).map_err(|source| RegistryError::PackageCopyError {
            original: temp_file.path().into(),
            target: package_dir,
            source,
        })?;

        println!("\nSuccessfully pulled version {} of package {}.", style(&version).bold().cyan(), style(&name).bold().cyan(),);
    }

    // Done
    Ok(())
}

/* TIM */
/// **Edited: the version is now optional.**
///
/// Pushes the given package to the remote instance that we're currently logged into.
///
/// **Arguments**
///  * `packages`: A list with name/ID / version pairs of the packages to push.
///
/// **Returns**  
/// Nothing on success, or an anyhow error on failure.
pub async fn push(packages: Vec<(String, Version)>) -> Result<(), RegistryError> {
    // Try to get the general package directory
    let packages_dir = ensure_packages_dir(false).map_err(|source| RegistryError::PackagesDirError { source })?;
    debug!("Using Brane package directory: {}", packages_dir.display());

    // Iterate over the packages
    for (name, version) in packages {
        // Add the package name to the general directory
        let package_dir = packages_dir.join(&name);

        // Resolve the version number
        let version = if version.is_latest() {
            // Get the list of versions
            let mut versions =
                get_package_versions(&name, &package_dir).map_err(|source| RegistryError::VersionsError { name: name.clone(), source })?;

            // Sort the versions and return the last one
            versions.sort();
            versions[versions.len() - 1]
        } else {
            // Simply use the version given
            version
        };

        // Construct the full package directory with version
        let package_dir = ensure_package_dir(&name, Some(&version), false).map_err(|source| RegistryError::PackageDirError {
            name: name.clone(),
            version,
            source,
        })?;
        // let temp_file = match tempfile::NamedTempFile::new() {
        //     Ok(file) => file,
        //     Err(err) => { return Err(RegistryError::TempFileError{ err }); }
        // };
        let temp_path: std::path::PathBuf = std::env::temp_dir().join("temp.tar.gz");
        let temp_file: File = File::create(&temp_path).unwrap();

        // We do a nice progressbar while compressing the package
        let progress = ProgressBar::new(0);
        progress.set_style(ProgressStyle::default_bar().template("Compressing... [{elapsed_precise}]").unwrap());
        progress.enable_steady_tick(Duration::from_millis(250));

        // Create package tarball, effectively compressing it
        let gz = GzEncoder::new(&temp_file, Compression::fast());
        let mut tar = tar::Builder::new(gz);
        tar.append_path_with_name(package_dir.join("package.yml"), "package.yml").map_err(|source| RegistryError::CompressionError {
            name: name.clone(),
            version,
            path: temp_path.clone(),
            source,
        })?;
        tar.append_path_with_name(package_dir.join("image.tar"), "image.tar").map_err(|source| RegistryError::CompressionError {
            name: name.clone(),
            version,
            path: temp_path.clone(),
            source,
        })?;
        tar.into_inner().map_err(|source| RegistryError::CompressionError { name: name.clone(), version, path: temp_path.clone(), source })?;
        progress.finish();

        // Upload file (with progress bar, of course)
        let url = get_packages_endpoint()?;
        debug!("Pushing package '{}' to '{}'...", temp_path.display(), url);
        let request = Client::new().post(&url);
        let progress = ProgressBar::new(0);
        progress.set_style(ProgressStyle::default_bar().template("Uploading...   [{elapsed_precise}]").unwrap());
        progress.enable_steady_tick(Duration::from_millis(250));

        // Re-open the temporary file we've just written to
        // let handle = match TokioFile::open(&temp_file).await {
        let handle =
            TokioFile::open(&temp_path).await.map_err(|source| RegistryError::PackageArchiveOpenError { path: temp_path.clone(), source })?;
        let file = FramedRead::new(handle, BytesCodec::new());

        // Upload the file as a request
        // let content_length = temp_file.path().metadata().unwrap().len();
        let content_length = temp_path.metadata().unwrap().len();
        let request = request.body(Body::wrap_stream(file)).header("Content-Type", "application/gzip").header("Content-Length", content_length);
        let response = request.send().await.map_err(|source| RegistryError::UploadError { path: temp_path, endpoint: url, source })?;
        let response_status = response.status();
        progress.finish();

        // Analyse the response result
        if response_status.is_success() {
            println!("\nSuccessfully pushed version {} of package {}.", style(&version).bold().cyan(), style(&name).bold().cyan(),);
        } else {
            match response.text().await {
                Ok(text) => {
                    println!("\nFailed to push package: {text}");
                },
                Err(err) => {
                    println!("\nFailed to push package (and failed to retrieve response text: {err})");
                },
            };
        }
    }

    // Done!
    Ok(())
}
/*******/

pub async fn search(term: Option<String>) -> Result<()> {
    #[derive(GraphQLQuery)]
    #[graphql(schema_path = "src/graphql/api_schema.json", query_path = "src/graphql/search_packages.graphql", response_derives = "Debug")]
    pub struct SearchPackages;

    let client = reqwest::Client::new();
    let graphql_endpoint = get_graphql_endpoint()?;

    // Prepare GraphQL query.
    let variables = search_packages::Variables { term };
    let graphql_query = SearchPackages::build_query(variables);

    // Request/response for GraphQL query.
    let graphql_response = client.post(graphql_endpoint).json(&graphql_query).send().await?;
    let graphql_response: Response<search_packages::ResponseData> = graphql_response.json().await?;

    if let Some(data) = graphql_response.data {
        let packages = data.packages;

        // Present results in a table.
        let format = FormatBuilder::new().column_separator('\0').borders('\0').padding(1, 1).build();

        let mut table = Table::new();
        table.set_format(format);
        table.add_row(row!["NAME", "VERSION", "KIND", "DESCRIPTION"]);

        for package in packages {
            let name = pad_str(&package.name, 20, Alignment::Left, Some(".."));
            let version = pad_str(&package.version, 10, Alignment::Left, Some(".."));
            let kind = pad_str(&package.kind, 10, Alignment::Left, Some(".."));
            let description = package.description.clone().unwrap_or_default();
            let description = pad_str(&description, 50, Alignment::Left, Some(".."));

            table.add_row(row![name, version, kind, description]);
        }

        table.printstd();
    } else {
        eprintln!("{:?}", graphql_response.errors);
    };

    Ok(())
}

pub async fn unpublish(name: String, version: Version, force: bool) -> Result<()> {
    #[derive(GraphQLQuery)]
    #[graphql(schema_path = "src/graphql/api_schema.json", query_path = "src/graphql/unpublish_package.graphql", response_derives = "Debug")]
    pub struct UnpublishPackage;

    let client = reqwest::Client::new();
    let graphql_endpoint = get_graphql_endpoint()?;

    // Ask for permission, if --force is not provided
    if !force {
        println!("Do you want to remove the following version(s)?");
        println!("- {version}");

        // Abort, if not approved
        if !Confirm::new().interact()? {
            return Ok(());
        }

        println!();
    }

    // Prepare GraphQL query.
    if version.is_latest() {
        return Err(anyhow!("Cannot unpublish 'latest' package version; choose a version."));
    }
    let variables = unpublish_package::Variables { name, version: version.to_string() };
    let graphql_query = UnpublishPackage::build_query(variables);

    // Request/response for GraphQL query.
    let graphql_response = client.post(graphql_endpoint).json(&graphql_query).send().await?;
    let graphql_response: Response<unpublish_package::ResponseData> = graphql_response.json().await?;

    if let Some(data) = graphql_response.data {
        println!("{}", data.unpublish_package);
    } else {
        eprintln!("{:?}", graphql_response.errors);
    };

    Ok(())
}
