//  UTILITIES.rs
//    by Lut99
//
//  Created:
//    18 Aug 2022, 14:58:16
//  Last edited:
//    14 Jun 2024, 16:40:49
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines common utilities across the Brane project.
//

use std::borrow::Cow;
use std::fs::{self, DirEntry, ReadDir};
use std::future::Future;
use std::path::{Path, PathBuf};

use regex::Regex;
use specifications::container::ContainerInfo;
use specifications::data::{AssetInfo, DataIndex, DataInfo};
use specifications::package::{PackageIndex, PackageInfo};
use tokio::runtime::{Builder, Runtime};
use tracing::{debug, warn};
use url::{Host, Url};


/***** TEST HELPERS *****/
/// Defines the path of the tests folder.
pub const TESTS_DIR: &str = "../tests";



/// Collects all .yml files in the 'tests' folder as a single PackageIndex.
///
/// # Returns
/// A [`PackageIndex`] with a collection of all package files in the tests older.
///
/// # Panics
/// This function panics if we failed to do so.
#[inline]
pub fn create_package_index() -> PackageIndex {
    // Simply call `create_package_index_from` with the default tests package directory
    create_package_index_from(PathBuf::from(TESTS_DIR).join("packages"))
}
/// Collects all .yml files in the given folder as a single PackageIndex.
///
/// Note that this function is mostly for testing purposes. Typically, using functions directly on [`PackageIndex`] provides a more canonical experience (mostly relating to error handling).
///
/// # Arguments
/// - `path`: The path to load the packages in.
///
/// # Returns
/// A [`PackageIndex`] with a collection of all package files in the given folder.
///
/// # Panics
/// This function may panic if any of the steps fail.
pub fn create_package_index_from(path: impl AsRef<Path>) -> PackageIndex {
    let path: &Path = path.as_ref();

    // Try to open the folder
    let dir = match fs::read_dir(path) {
        Ok(dir) => dir,
        Err(err) => {
            panic!("Failed to list tests directory '{}': {}", path.display(), err);
        },
    };

    // Start a 'recursive' process where we run all '*.bscript' files.
    let mut infos: Vec<PackageInfo> = vec![];
    let mut todo: Vec<(PathBuf, ReadDir)> = vec![(path.into(), dir)];
    while let Some((path, dir)) = todo.pop() {
        // Iterate through it
        for entry in dir {
            // Attempt to unwrap the entry
            let entry: DirEntry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    panic!("Failed to read entry in directory '{}': {}", path.display(), err);
                },
            };

            // Check whether it's a directory or not
            if entry.path().is_file() {
                // Check if it ends with '.yml'
                if let Some(ext) = entry.path().extension() {
                    if ext.to_str().unwrap_or("") == "yml" || ext.to_str().unwrap_or("") == "yaml" {
                        let info: ContainerInfo = match ContainerInfo::from_path(entry.path()) {
                            Ok(info) => info,
                            Err(err) => {
                                panic!("Failed to read '{}' as ContainerInfo: {}", entry.path().display(), err);
                            },
                        };
                        infos.push(PackageInfo::from(info));
                    }
                }
            } else if entry.path().is_dir() {
                // Recurse, i.e., list and add to the todo list
                let new_dir = match fs::read_dir(entry.path()) {
                    Ok(dir) => dir,
                    Err(err) => {
                        panic!("Failed to list nested tests directory '{}': {}", entry.path().display(), err);
                    },
                };
                if todo.len() == todo.capacity() {
                    todo.reserve(todo.capacity());
                }
                todo.push((entry.path(), new_dir));
            } else {
                // Dunno what to do with it
                println!("Ignoring entry '{}' in '{}' (unknown entry type)", entry.path().display(), path.display());
            }
        }
    }

    // Done
    match PackageIndex::from_packages(infos) {
        Ok(index) => index,
        Err(err) => {
            panic!("Failed to create package index from package infos: {}", err);
        },
    }
}

/// Collects all data index files in the test folder as a DataIndex.
///
/// # Returns
/// A [`DataIndex`] with a collection of all data files in the tests older.
///
/// # Panics
/// This function panics if we failed to do so.
#[inline]
pub fn create_data_index() -> DataIndex {
    // Simply call `create_data_index_from` with the default tests data directory
    create_data_index_from(PathBuf::from(TESTS_DIR).join("data"))
}
/// Collects all data index files in the given folder as a single DataIndex.
///
/// Note that this function is mostly for testing purposes. Typically, using functions directly on [`DataIndex`] provides a more canonical experience (mostly relating to error handling).
///
/// # Arguments
/// - `path`: The path to load the data in.
///
/// # Returns
/// A [`DataIndex`] with a collection of all data files in the given folder.
///
/// # Panics
/// This function may panic if any of the steps fail.
pub fn create_data_index_from(path: impl AsRef<Path>) -> DataIndex {
    let path: &Path = path.as_ref();

    // Try to open the folder
    let dir = match fs::read_dir(path) {
        Ok(dir) => dir,
        Err(err) => {
            panic!("Failed to list tests directory '{}': {}", path.display(), err);
        },
    };

    // Start a 'recursive' process where we run all '*.bscript' files.
    let mut infos: Vec<DataInfo> = vec![];
    let mut todo: Vec<(PathBuf, ReadDir)> = vec![(path.into(), dir)];
    while let Some((path, dir)) = todo.pop() {
        // Iterate through it
        for entry in dir {
            // Attempt to unwrap the entry
            let entry: DirEntry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    panic!("Failed to read entry in directory '{}': {}", path.display(), err);
                },
            };

            // Check whether it's a directory or not
            if entry.path().is_file() {
                // Check if it ends with '.yml'
                if let Some(ext) = entry.path().extension() {
                    if ext.to_str().unwrap_or("") == "yml" || ext.to_str().unwrap_or("") == "yaml" {
                        // Read it as a DataInfo
                        let info: AssetInfo = match AssetInfo::from_path(entry.path()) {
                            Ok(info) => info,
                            Err(err) => {
                                panic!("Failed to read '{}' as AssetInfo: {}", entry.path().display(), err);
                            },
                        };
                        infos.push(info.into());
                    }
                }
            } else if entry.path().is_dir() {
                // Recurse, i.e., list and add to the todo list
                let new_dir = match fs::read_dir(entry.path()) {
                    Ok(dir) => dir,
                    Err(err) => {
                        panic!("Failed to list nested tests directory '{}': {}", entry.path().display(), err);
                    },
                };
                if todo.len() == todo.capacity() {
                    todo.reserve(todo.capacity());
                }
                todo.push((entry.path(), new_dir));
            } else {
                // Dunno what to do with it
                println!("Ignoring entry '{}' in '{}' (unknown entry type)", entry.path().display(), path.display());
            }
        }
    }

    // Done
    match DataIndex::from_infos(infos) {
        Ok(index) => index,
        Err(err) => {
            panic!("Failed to create data index from data infos: {}", err);
        },
    }
}

/// Runs a given closure on all files in the `tests` folder (see the constant defined in this function's source file).
///
/// # Generic arguments
/// - `F`: The function signature of the closure. It simply accepts the path and source text of a single file, and returns nothing. Instead, it can panic if the test fails.
///
/// # Arguments
/// - `mode`: The mode to run in. May either be 'BraneScript' or 'Bakery'.
/// - `exec`: The closure that runs code on every file in the appropriate language's text.
///
/// # Panics
/// This function panics if the test failed (i.e., if the files could not be found or the closure panics).
#[inline]
pub fn test_on_dsl_files<F>(mode: &'static str, exec: F)
where
    F: Fn(PathBuf, String),
{
    test_on_dsl_files_in(mode, PathBuf::from(TESTS_DIR), exec)
}
/// Runs a given closure on all files in the given folder.
///
/// # Generic arguments
/// - `F`: The function signature of the closure. It simply accepts the path and source text of a single file, and returns nothing. Instead, it can panic if the test fails.
///
/// # Arguments
/// - `mode`: The mode to run in. May either be 'BraneScript' or 'Bakery'.
/// - `path`: The path to search for files in.
/// - `exec`: The closure that runs code on every file in the appropriate language's text.
///
/// # Panics
/// This function panics if the test failed (i.e., if the files could not be found or the closure panics).
#[inline]
pub fn test_on_dsl_files_in<F>(mode: &'static str, path: impl AsRef<Path>, exec: F)
where
    F: Fn(PathBuf, String),
{
    // Create a runtime on this thread and then do the async version
    let runtime: Runtime = Builder::new_current_thread().build().unwrap_or_else(|err| panic!("Failed to launch Tokio runtime: {}", err));

    // Run the test_on_dsl_files_async
    runtime.block_on(test_on_dsl_files_in_async(mode, path, |path, code| async { exec(path, code) }))
}

/// Runs a given closure on all files in the `tests` folder (see the constant defined in this function's source file).
///
/// This function runs the searching and loading of files asynchronously, for server contexts.
///
/// # Generic arguments
/// - `F`: The function signature of the closure. It simply accepts the path and source text of a single file, and returns a future that represents the test code. If it should cause the test to fail, that future should panic.
///
/// # Arguments
/// - `mode`: The mode to run in. May either be 'BraneScript' or 'Bakery'.
/// - `exec`: The closure that runs code on every file in the appropriate language's text.
///
/// # Panics
/// This function panics if the test failed (i.e., if the files could not be found or the closure panics).
pub async fn test_on_dsl_files_async<F, R>(mode: &'static str, exec: F)
where
    F: Fn(PathBuf, String) -> R,
    R: Future<Output = ()>,
{
    test_on_dsl_files_in_async(mode, PathBuf::from(TESTS_DIR), exec).await
}
/// Runs a given closure on all files in the given folder.
///
/// This function runs the searching and loading of files asynchronously, for server contexts.
///
/// # Generic arguments
/// - `F`: The function signature of the closure. It simply accepts the path and source text of a single file, and returns a future that represents the test code. If it should cause the test to fail, that future should panic.
///
/// # Arguments
/// - `mode`: The mode to run in. May either be 'BraneScript' or 'Bakery'.
/// - `path`: The path to search for files in.
/// - `exec`: The closure that runs code on every file in the appropriate language's text.
///
/// # Panics
/// This function panics if the test failed (i.e., if the files could not be found or the closure panics).
pub async fn test_on_dsl_files_in_async<F, R>(mode: &'static str, path: impl AsRef<Path>, exec: F)
where
    F: Fn(PathBuf, String) -> R,
    R: Future<Output = ()>,
{
    // Setup logger if told
    // TODO: Set up tracing subscriber

    // See if we need to limit ourselves to particular files
    let test_files: Option<Vec<String>> =
        std::env::var("TEST_FILES").ok().map(|test_file| test_file.split(',').map(|test_file| test_file.to_string()).collect());

    // Setup some variables and checks
    let mut path: Cow<Path> = Cow::Borrowed(path.as_ref());
    let exts: Vec<&'static str> = match mode {
        "BraneScript" => {
            path = Cow::Owned(path.join("branescript"));
            vec!["bs", "bscript"]
        },
        "Bakery" => {
            path = Cow::Owned(path.join("bakery"));
            vec!["bakery"]
        },
        val => {
            panic!("Unknown mode '{}'", val);
        },
    };

    // Try to open the folder
    let dir = match fs::read_dir(&path) {
        Ok(dir) => dir,
        Err(err) => {
            panic!("Failed to list tests directory '{}': {}", path.display(), err);
        },
    };

    // Start a 'recursive' process where we run all '*.bscript' files.
    let mut todo: Vec<(PathBuf, ReadDir)> = vec![(path.into(), dir)];
    let mut counter = 0;
    while let Some((path, dir)) = todo.pop() {
        // Iterate through it
        for entry in dir {
            // Attempt to unwrap the entry
            let entry: DirEntry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    panic!("Failed to read entry in directory '{}': {}", path.display(), err);
                },
            };

            // Check whether it's a directory or not
            let entry_path: PathBuf = entry.path();
            if entry_path.is_file() {
                // Check if it ends with '.bscript';
                if let Some(ext) = entry_path.extension() {
                    if exts.contains(&ext.to_str().unwrap_or("")) {
                        // Skip the file if told
                        if let Some(test_files) = &test_files {
                            // Continue if not all filters match false
                            let mut allowed: bool = false;
                            for test_file in test_files {
                                if entry_path.ends_with(test_file) {
                                    allowed = true;
                                    break;
                                }
                            }
                            if !allowed {
                                continue;
                            }
                        }

                        // Read the file to a buffer
                        let code: String = match fs::read_to_string(&entry_path) {
                            Ok(code) => code,
                            Err(err) => {
                                panic!("Failed to read {} file '{}': {}", mode, entry_path.display(), err);
                            },
                        };

                        // Run the closure on this file
                        exec(entry_path, code).await;
                        counter += 1;
                    } else if entry_path.extension().is_some()
                        && entry_path.extension().unwrap() != "yml"
                        && entry_path.extension().unwrap() != "yaml"
                    {
                        println!(
                            "Ignoring entry '{}' in '{}' (does not have extensions {})",
                            entry_path.display(),
                            path.display(),
                            exts.iter().map(|e| format!("'.{e}'")).collect::<Vec<String>>().join(", ")
                        );
                    }
                } else {
                    println!("Ignoring entry '{}' in '{}' (cannot extract extension)", entry_path.display(), path.display());
                }
            } else if entry_path.is_dir() {
                // Recurse, i.e., list and add to the todo list
                let new_dir = match fs::read_dir(&entry_path) {
                    Ok(dir) => dir,
                    Err(err) => {
                        panic!("Failed to list nested tests directory '{}': {}", entry_path.display(), err);
                    },
                };
                if todo.len() == todo.capacity() {
                    todo.reserve(todo.capacity());
                }
                todo.push((entry_path, new_dir));
            } else {
                // Dunno what to do with it
                println!("Ignoring entry '{}' in '{}' (unknown entry type)", entry_path.display(), path.display());
            }
        }
    }

    // Do a finishing debug print
    if counter == 0 {
        println!("No files to run.");
    } else {
        println!("Tested {counter} files in total");
    }
}





/***** ADDRESS CHECKING *****/
pub fn ensure_http_schema<S>(url: S, secure: bool) -> Result<String, url::ParseError>
where
    S: Into<String>,
{
    let url = url.into();
    let re = Regex::new(r"^https?://.*").unwrap();

    let url = if re.is_match(&url) { url } else { format!("{}://{}", if secure { "https" } else { "http" }, url) };

    // Check if url is valid.
    let _ = Url::parse(&url)?;

    Ok(url)
}



/// Returns whether the given address is an IP address or not.
///
/// The address can already involve paths or an HTTP schema. In that case, only the 'host' part is checked.
///
/// Both IPv4 and IPv6 addresses are matched.
///
/// # Arguments
/// - `address`: The address to check.
///
/// # Returns
/// true if the address is an IP-address, or false otherwise.
pub fn is_ip_addr(address: impl AsRef<str>) -> bool {
    let address: &str = address.as_ref();

    // Attempt to parse with the URL thing
    let url: Url = match Url::parse(address) {
        Ok(url) => url,
        Err(err) => {
            warn!("Given URL '{}' is not a valid URL to begin with: {}", address, err);
            return false;
        },
    };

    // Examine the base
    if let Some(host) = url.host() {
        let res: bool = matches!(host, Host::Ipv4(_) | Host::Ipv6(_));
        debug!("Address '{}' has a{} as hostname", address, if res { "n IP address" } else { " domain" });
        matches!(host, Host::Ipv4(_) | Host::Ipv6(_))
    } else {
        debug!("Address '{}' has no hostname (so also no IP address)", address);
        false
    }
}





/***** TESTS *****/
#[cfg(test)]
mod tests {
    use super::*;

    /// Test some basic HTTP schemas
    #[test]
    fn ensurehttpschema_noschema_added() {
        let url = ensure_http_schema("localhost", true).unwrap();
        assert_eq!(url, "https://localhost");

        let url = ensure_http_schema("localhost", false).unwrap();
        assert_eq!(url, "http://localhost");
    }

    /// Test some more basic HTTP schemas
    #[test]
    fn ensurehttpschema_schema_nothing() {
        let url = ensure_http_schema("http://localhost", true).unwrap();
        assert_eq!(url, "http://localhost");

        let url = ensure_http_schema("https://localhost", false).unwrap();
        assert_eq!(url, "https://localhost");
    }
}
