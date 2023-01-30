use std::collections::HashMap;
use std::fs::{self, File};
use std::io::prelude::*;
use std::str::FromStr;

use anyhow::Result;
use chrono::DateTime;
use chrono::Utc;
use console::style;
use console::{pad_str, Alignment};
use dialoguer::Confirm;
use flate2::write::GzEncoder;
use flate2::Compression;
use graphql_client::{GraphQLQuery, Response};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::format::FormatBuilder;
use prettytable::Table;
use reqwest::{self, Body, Client};
use tokio::fs::File as TokioFile;
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;

use brane_tsk::local::get_package_versions;
use specifications::package::{PackageKind, PackageInfo};
use specifications::version::Version;

use crate::errors::RegistryError;
use crate::utils::{get_packages_dir, ensure_package_dir, ensure_packages_dir};
use crate::instance::InstanceInfo;


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
    Ok(format!("{}/graphql", InstanceInfo::from_active_path().map_err(|err| RegistryError::InstanceInfoError{ err })?.api))
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
    Ok(format!("{}/packages", InstanceInfo::from_active_path().map_err(|err| RegistryError::InstanceInfoError{ err })?.api))
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
    Ok(format!("{}/data", InstanceInfo::from_active_path().map_err(|err| RegistryError::InstanceInfoError{ err })?.api))
}



/// Pulls packages from a remote registry to the local registry. 
/// 
/// # Arguments
/// - `packages`: The list of `NAME[:VERSION]` pairs indicating what to pull.
/// 
/// # Errors
/// This function may error for about a million different reasons, chief of which are the remote not being reachable, the user not being logged-in, not being able to write to the package folder, etc.
pub async fn pull(
    packages: Vec<(String, Version)>,
) -> Result<(), RegistryError> {
    // Compile the GraphQL schema
    #[derive(GraphQLQuery)]
    #[graphql(
        schema_path = "src/graphql/api_schema.json",
        query_path = "src/graphql/get_package.graphql",
        response_derives = "Debug"
    )]
    pub struct GetPackage;

    // Iterate over the packages
    for (name, version) in packages {
        debug!("Pulling package '{}' version {}", name, version);

        // Get the package directory
        debug!("Downloading container...");
        let packages_dir = match get_packages_dir() {
            Ok(packages_dir) => packages_dir,
            Err(err)         => { return Err(RegistryError::PackagesDirError{ err }); }
        };
        let package_dir = packages_dir.join(&name);
        let mut temp_file = tempfile::NamedTempFile::new().expect("Failed to create temporary file.");

        // Create the target endpoint for this package
        let url = format!("{}/{}/{}", get_packages_endpoint()?, name, version);
        let mut package_archive: reqwest::Response = match reqwest::get(&url).await {
            Ok(archive) => archive,
            Err(err)    => { return Err(RegistryError::PullRequestError{ url, err }); }
        };
        if package_archive.status() != reqwest::StatusCode::OK {
            return Err(RegistryError::PullRequestFailure{ url, status: package_archive.status() });
        }

        // Fetch the content length from the response headers
        let content_length = match package_archive.headers().get("content-length") {
            Some(length) => length,
            None         => { return Err(RegistryError::MissingContentLength{ url }); }
        };
        let content_length = match content_length.to_str() {
            Ok(length) => length,
            Err(err)   => { return Err(RegistryError::ContentLengthStrError{ url, err }); }
        };
        let content_length: u64 = match content_length.parse() {
            Ok(length) => length,
            Err(err)   => { return Err(RegistryError::ContentLengthParseError{ url, raw: content_length.into(), err }); }
        };

        // Write package archive to temporary file
        let progress = ProgressBar::new(content_length);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("Downloading... [{elapsed_precise}] {bar:40.cyan/blue} {percent}/100%")
                .progress_chars("##-"),
        );
        while let Some(chunk) = match package_archive.chunk().await {
            Ok(chunk) => chunk,
            Err(err)  => { return Err(RegistryError::PackageDownloadError{ url, err }); }
        } {
            progress.inc(chunk.len() as u64);
            if let Err(err) = temp_file.write_all(&chunk) {
                return Err(RegistryError::PackageWriteError{ url, path: temp_file.path().into(), err });
            };
        }
        progress.finish();

        // Retreive package information from API.
        let client = reqwest::Client::new();
        let graphql_endpoint = get_graphql_endpoint()?;
        debug!("Fetching package metadata from '{}'...", graphql_endpoint);

        // Prepare GraphQL query.
        let variables = get_package::Variables {
            name: name.clone(),
            version: version.to_string(),
        };
        let graphql_query = GetPackage::build_query(variables);

        // Request/response for GraphQL query.
        let graphql_response = match client.post(&graphql_endpoint).json(&graphql_query).send().await {
            Ok(response) => response,
            Err(err)     => { return Err(RegistryError::GraphQLRequestError{ url: graphql_endpoint, err }); }
        };
        let graphql_response: Response<get_package::ResponseData> = match graphql_response.json().await {
            Ok(response) => response,
            Err(err)     => { return Err(RegistryError::GraphQLResponseError{ url: graphql_endpoint, err }); }
        };

        // Attempt to parse the response data as a PackageInfo
        let version = if let Some(data) = graphql_response.data {
            // Extract the packages from the list
            let package = match data.packages.first() {
                Some(package) => package,
                None          => { return Err(RegistryError::NoPackageInfo{ url }); }
            };

            // Parse the package kind first
            let kind = match PackageKind::from_str(&package.kind) {
                Ok(kind) => kind,
                Err(err) => { return Err(RegistryError::KindParseError{ url, raw: package.kind.clone(), err }); }
            };

            // Next, the version
            let version = match Version::from_str(&package.version) {
                Ok(version) => version,
                Err(err)    => { return Err(RegistryError::VersionParseError{ url, raw: package.version.clone(), err }); }
            };

            // Then parse the package functions
            let functions: HashMap<String, specifications::common::Function> = match package.functions_as_json.as_ref() {
                Some(functions) => match serde_json::from_str(functions) {
                    Ok(functions) => functions,
                    Err(err)      => { return Err(RegistryError::FunctionsParseError{ url, raw: functions.clone(), err }); }
                },
                None => HashMap::new(),
            };

            // Parse the types as last
            let types: HashMap<String, specifications::common::Type> = match package.types_as_json.as_ref() {
                Some(types) => match serde_json::from_str(types) {
                    Ok(types) => types,
                    Err(err)  => { return Err(RegistryError::TypesParseError{ url, raw: types.clone(), err }); }
                },
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
                version : version.clone(),
            };

            // Create the directory
            let package_dir = package_dir.join(version.to_string());
            if let Err(err) = fs::create_dir_all(&package_dir) { return Err(RegistryError::PackageDirCreateError{ path: package_dir, err }); }

            // Write package.yml to package directory
            let package_info_path = package_dir.join("package.yml");
            let handle = match File::create(&package_info_path) {
                Ok(handle) => handle,
                Err(err)   => { return Err(RegistryError::PackageInfoCreateError{ path: package_info_path, err }); }
            };
            if let Err(err) = serde_yaml::to_writer(handle, &package_info) {
                return Err(RegistryError::PackageInfoWriteError{ path: package_info_path, err });
            }

            // Done!
            version
        } else {
            // The server did not return a package info at all :(
            return Err(RegistryError::NoPackageInfo{ url });
        };

        // Copy package to package directory.
        let package_dir = package_dir.join(version.to_string());
        if let Err(err) = fs::copy(temp_file.path(), package_dir.join("image.tar")) { return Err(RegistryError::PackageCopyError{ source: temp_file.path().into(), target: package_dir, err }); }

        println!(
            "\nSuccessfully pulled version {} of package {}.",
            style(&version).bold().cyan(),
            style(&name).bold().cyan(),
        );
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
    let packages_dir = match ensure_packages_dir(false) {
        Ok(dir)  => dir,
        Err(err) => { return Err(RegistryError::PackagesDirError{ err }); }
    };
    debug!("Using Brane package directory: {}", packages_dir.display());

    // Iterate over the packages
    for (name, version) in packages {
        // Add the package name to the general directory
        let package_dir = packages_dir.join(&name);

        // Resolve the version number
        let version = if version.is_latest() {
            // Get the list of versions
            let mut versions = match get_package_versions(&name, &package_dir) {
                Ok(versions) => versions,
                Err(err)     => { return Err(RegistryError::VersionsError{ name, err }); }
            };

            // Sort the versions and return the last one
            versions.sort();
            versions[versions.len() - 1].clone()
        } else {
            // Simply use the version given
            version.clone()
        };

        // Construct the full package directory with version
        let package_dir = match ensure_package_dir(&name, Some(&version), false) {
            Ok(dir)  => dir,
            Err(err) => { return Err(RegistryError::PackageDirError{ name, version, err }); }
        };
        // let temp_file = match tempfile::NamedTempFile::new() {
        //     Ok(file) => file,
        //     Err(err) => { return Err(RegistryError::TempFileError{ err }); }
        // };
        let temp_path: std::path::PathBuf = std::path::PathBuf::from("/tmp/temp.tar.gz");
        let temp_file: File = File::create(&temp_path).unwrap();

        // We do a nice progressbar while compressing the package
        let progress = ProgressBar::new(0);
        progress.set_style(ProgressStyle::default_bar().template("Compressing... [{elapsed_precise}]"));
        progress.enable_steady_tick(250);

        // Create package tarball, effectively compressing it
        let gz = GzEncoder::new(&temp_file, Compression::fast());
        let mut tar = tar::Builder::new(gz);
        if let Err(err) = tar.append_path_with_name(package_dir.join("package.yml"), "package.yml") {
            // return Err(RegistryError::CompressionError{ name, version, path: temp_file.path().into(), err });
            return Err(RegistryError::CompressionError { name, version, path: temp_path, err });
        };
        if let Err(err) = tar.append_path_with_name(package_dir.join("image.tar"), "image.tar") {
            // return Err(RegistryError::CompressionError{ name, version, path: temp_file.path().into(), err });
            return Err(RegistryError::CompressionError { name, version, path: temp_path, err });
        };
        if let Err(err) = tar.into_inner() {
            // return Err(RegistryError::CompressionError{ name, version, path: temp_file.path().into(), err });
            return Err(RegistryError::CompressionError { name, version, path: temp_path, err });
        };
        progress.finish();

        // Upload file (with progress bar, of course)
        let url = get_packages_endpoint()?;
        debug!("Pushing package '{}' to '{}'...", temp_path.display(), url);
        let request = Client::new().post(&url);
        let progress = ProgressBar::new(0);
        progress.set_style(ProgressStyle::default_bar().template("Uploading...   [{elapsed_precise}]"));
        progress.enable_steady_tick(250);

        // Re-open the temporary file we've just written to
        // let handle = match TokioFile::open(&temp_file).await {
        let handle = match TokioFile::open(&temp_path).await {
            Ok(handle) => handle,
            // Err(err)   => { return Err(RegistryError::PackageArchiveOpenError{ path: temp_file.path().into(), err }); }
            Err(err)   => { return Err(RegistryError::PackageArchiveOpenError{ path: temp_path, err }); }
        };
        let file = FramedRead::new(handle, BytesCodec::new());

        // Upload the file as a request
        // let content_length = temp_file.path().metadata().unwrap().len();
        let content_length = temp_path.metadata().unwrap().len();
        let request = request
            .body(Body::wrap_stream(file))
            .header("Content-Type", "application/gzip")
            .header("Content-Length", content_length);
        let response = match request.send().await {
            Ok(response) => response,
            // Err(err)     => { return Err(RegistryError::UploadError{ path: temp_file.path().into(), endpoint: url, err }); }
            Err(err)     => { return Err(RegistryError::UploadError{ path: temp_path, endpoint: url, err }); }
        };
        let response_status = response.status();
        progress.finish();

        // Analyse the response result
        if response_status.is_success() {
            println!(
                "\nSuccessfully pushed version {} of package {}.",
                style(&version).bold().cyan(),
                style(&name).bold().cyan(),
            );
        } else {
            match response.text().await {
                Ok(text) => { println!("\nFailed to push package: {}", text); }
                Err(err) => { println!("\nFailed to push package (and failed to retrieve response text: {})", err); }
            };
        }
    }

    // Done!
    Ok(())
}
/*******/

///
///
///
pub async fn search(term: Option<String>) -> Result<()> {
    #[derive(GraphQLQuery)]
    #[graphql(
        schema_path = "src/graphql/api_schema.json",
        query_path = "src/graphql/search_packages.graphql",
        response_derives = "Debug"
    )]
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
        let format = FormatBuilder::new()
            .column_separator('\0')
            .borders('\0')
            .padding(1, 1)
            .build();

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

///
///
///
pub async fn unpublish(
    name: String,
    version: Version,
    force: bool,
) -> Result<()> {
    #[derive(GraphQLQuery)]
    #[graphql(
        schema_path = "src/graphql/api_schema.json",
        query_path = "src/graphql/unpublish_package.graphql",
        response_derives = "Debug"
    )]
    pub struct UnpublishPackage;

    let client = reqwest::Client::new();
    let graphql_endpoint = get_graphql_endpoint()?;

    // Ask for permission, if --force is not provided
    if !force {
        println!("Do you want to remove the following version(s)?");
        println!("- {}", version);

        // Abort, if not approved
        if !Confirm::new().interact()? {
            return Ok(());
        }

        println!();
    }

    // Prepare GraphQL query.
    if version.is_latest() { return Err(anyhow!("Cannot unpublish 'latest' package version; choose a version.")); }
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
