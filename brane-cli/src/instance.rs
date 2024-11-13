//  IDENTITY.rs
//    by Lut99
//
//  Created:
//    26 Jan 2023, 09:22:13
//  Last edited:
//    08 Jan 2024, 10:43:17
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements subcommands that relate to identity management of the
//!   user on the instances to which we will want to connect.
//

use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::{self, DirEntry, File, ReadDir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use brane_shr::formatters::PrettyListFormatter;
use console::{Alignment, pad_str, style};
use dialoguer::Confirm;
use log::{debug, info, warn};
use prettytable::Table;
use prettytable::format::FormatBuilder;
use serde::{Deserialize, Serialize};
use specifications::address::Address;

pub use crate::errors::InstanceError as Error;
use crate::spec::Hostname;
use crate::utils::{ensure_instance_dir, ensure_instances_dir, get_active_instance_link, get_instance_dir};


/***** HELPER FUNCTIONS *****/
/// Reads the active instance from the special active_instance file.
///
/// # Returns
/// The name of the instance in the active_instance file.
///
/// # Errors
/// This function errors if, say, the instance link does not exist or was unreadable.
fn read_active_instance_link() -> Result<String, Error> {
    // Get the active path
    let link_path: PathBuf = match get_active_instance_link() {
        Ok(link_path) => link_path,
        Err(err) => {
            return Err(Error::ActiveInstancePathError { err });
        },
    };

    // Assert it exists
    if !link_path.exists() {
        return Err(Error::NoActiveInstance);
    }
    if !link_path.is_file() {
        return Err(Error::ActiveInstanceNotAFileError { path: link_path });
    }

    // Get the path from it
    match fs::read_to_string(&link_path) {
        Ok(name) => Ok(name),
        Err(err) => Err(Error::ActiveInstanceReadError { path: link_path, err }),
    }
}





/***** FILE STRUCTS *****/
/// Defines the layout of an InstanceInfo, which describes what we remember about each instance.
///
/// Note that the name is encoded as the file's name.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceInfo {
    /// The place where we can find the API service for this instance.
    pub api:  Address,
    /// The place where we can find the driver service for this instance.
    pub drv:  Address,
    /// A username to send with workflow requests as receiver of the final result.
    pub user: String,
}

impl InstanceInfo {
    /// Reads this InstanceInfo from the active instance's directory in the local configuration directory.
    ///
    /// # Returns
    /// A new InstanceInfo instance that is populated with the contents of the file pointed to by the active-instance symlink.
    ///
    /// # Errors
    /// This function errors if we failed to get the local path, there is no active instance, if we failed to read the file or if we failed to parse it.
    pub fn from_active_path() -> Result<Self, Error> {
        // Get the path
        let name: String = read_active_instance_link()?;

        // Now return reading from that instance
        Self::from_default_path(name)
    }

    /// Asserts whether there is a selected instance or nay.
    ///
    /// # Returns
    /// true if there is an active instance link, or false otherwise.
    ///
    /// # Errors
    /// This function errors if we failed to get the default link path.
    #[inline]
    pub fn active_instance_exists() -> Result<bool, Error> {
        match get_active_instance_link() {
            Ok(link_path) => Ok(link_path.exists()),
            Err(err) => Err(Error::ActiveInstancePathError { err }),
        }
    }

    /// Reads this InstanceInfo from the default path in the local configuration directory.
    ///
    /// # Arguments
    /// - `name`: The name for this instance. Will cause errors if it contains characters incompatible for paths of OS.
    ///
    /// # Returns
    /// A new InstanceInfo instance that is populated with the contents of the file.
    ///
    /// # Errors
    /// This function errors if we failed to get the local path, if we failed to read the file or if we failed to parse it.
    #[inline]
    pub fn from_default_path(name: impl AsRef<str>) -> Result<Self, Error> { Self::from_path(Self::get_default_path(name)?) }

    /// Reads this InstanceInfo from the given path.
    ///
    /// # Arguments
    /// - `path`: The path to read it from.
    ///
    /// # Returns
    /// A new InstanceInfo instance that is populated with the contents of the file.
    ///
    /// # Errors
    /// This function errors if we failed to read the file or if we failed to parse it.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path: &Path = path.as_ref();

        // Open a file
        let mut handle: File = match File::open(path) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(Error::InstanceInfoOpenError { path: path.into(), err });
            },
        };

        // Read it to a string
        let mut contents: String = String::new();
        if let Err(err) = handle.read_to_string(&mut contents) {
            return Err(Error::InstanceInfoReadError { path: path.into(), err });
        }

        // Now parse it
        match serde_yaml::from_str(&contents) {
            Ok(info) => Ok(info),
            Err(err) => Err(Error::InstanceInfoParseError { path: path.into(), err }),
        }
    }

    // /// Writes this InstanceInfo to the active path in the local configuration directory.
    // ///
    // /// # Errors
    // /// This function errors if we failed to get the local path, there is no active instance, if we failed to write the file or if we failed to serialize ourselves.
    // fn to_active_path(&self) -> Result<(), Error> {
    //     // Get the active path
    //     let link_path: PathBuf = match get_active_instance_link() {
    //         Ok(link_path) => link_path,
    //         Err(err)      => { return Err(Error::ActiveInstancePathError{ err }); },
    //     };

    //     // Assert it exists
    //     if !link_path.exists() { return Err(Error::NoActiveInstance); }
    //     if !link_path.is_symlink() { return Err(Error::ActiveInstanceNotASoftlinkError{ path: link_path }); }

    //     // Now return the path
    //     self.to_path(link_path.join("infra.yml"))
    // }

    /// Writes this InstanceInfo to the its path in the local configuration directory.
    ///
    /// # Arguments
    /// - `name`: The name for this instance. Will cause errors if it contains characters incompatible for paths of OS.
    ///
    /// # Errors
    /// This function errors if we failed to get the local path, if we failed to write the file or if we failed to serialize ourselves.
    #[inline]
    fn to_default_path(&self, name: impl AsRef<str>) -> Result<(), Error> { self.to_path(Self::get_default_path(name)?) }

    /// Writes this InstanceInfo to the given path.
    ///
    /// # Arguments
    /// - `path`: The path to write this InstanceInfo to.
    ///
    /// # Errors
    /// This function errors if we failed to write the file or if we failed to serialize ourselves.
    fn to_path(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path: &Path = path.as_ref();

        // Serialize ourselves next
        let sself: String = match serde_yaml::to_string(self) {
            Ok(sself) => sself,
            Err(err) => {
                return Err(Error::InstanceInfoSerializeError { err });
            },
        };

        // Open a file to write us to
        let mut handle: File = match File::create(path) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(Error::InstanceInfoCreateError { path: path.into(), err });
            },
        };

        // Finally write it
        match write!(handle, "{sself}") {
            Ok(_) => Ok(()),
            Err(err) => Err(Error::InstanceInfoWriteError { path: path.into(), err }),
        }
    }

    /// Computes the name of the active instance and returns it.
    ///
    /// # Returns
    /// The name of the instance currently set active.
    ///
    /// # Errors
    /// This function errors if we failed to get the active instance or read the file.
    #[inline]
    pub fn get_active_name() -> Result<String, Error> { read_active_instance_link() }

    /// Computes the active path and returns it.
    ///
    /// This is not the path of the active instance link itself, but rather the instance it points to.
    ///
    /// # Returns
    /// The path to the active instance.
    ///
    /// # Errors
    /// This function errors if we failed to get the local path, or there is no active instance.
    #[inline]
    pub fn get_active_path() -> Result<PathBuf, Error> {
        // Read the name, then use the default path to get the actual path itself
        Self::get_default_path(read_active_instance_link()?)
    }

    /// Computes the path to which to write this InstanceInfo given the instance's name.
    ///
    /// Mostly used as a helper function for other functions in this struct.
    ///
    /// # Arguments
    /// - `name`: The name for this instance. Will cause errors down the line if it contains characters incompatible for a path on this OS.
    ///
    /// # Returns
    /// The path of the instance with the given name.
    ///
    /// # Errors
    /// This function errors if we failed to get the local path.
    #[inline]
    fn get_default_path(name: impl AsRef<str>) -> Result<PathBuf, Error> {
        match ensure_instance_dir(&name, true) {
            Ok(dir) => Ok(dir.join("info.yml")),
            Err(err) => Err(Error::InstanceDirError { err }),
        }
    }

    /// Computes the path to the directory of the instance with the given name.
    ///
    /// # Arguments
    /// - `name`: The name of the instance to get the directory of.
    ///
    /// # Returns
    /// The path to this instance's directory.
    ///
    /// # Errors
    /// This function may error if we failed to get the base config directory, or no such instance exists.
    #[inline]
    pub fn get_instance_path(name: impl AsRef<str>) -> Result<PathBuf, Error> {
        match ensure_instance_dir(&name, false) {
            Ok(dir) => Ok(dir),
            Err(err) => Err(Error::InstanceDirError { err }),
        }
    }
}





/***** SUBCOMMANDS *****/
/// Registers a new instance to which we can hot-swap using switch.
///
/// # Arguments
/// - `name`: The name of the instance.
/// - `hostname`: The hostname of the instance.
/// - `api_port`: The port where we can find the API service.
/// - `drv_port`: The port where we can find the driver service.
/// - `user`: The name of the user to login as.
/// - `use_immediately`: Whether to switch to it or not.
/// - `unchecked`: Whether to skip instance alive checking (true) or not (false).
/// - `force`: Whether to ask for permission before overwriting an existing instance.
///
/// # Errors
/// This function errors if we failed to generate any files, or if some check failed for this instance.
#[allow(clippy::too_many_arguments)]
pub async fn add(
    name: String,
    hostname: Hostname,
    api_port: u16,
    drv_port: u16,
    user: String,
    use_immediately: bool,
    unchecked: bool,
    force: bool,
) -> Result<(), Error> {
    info!("Creating new instance '{}'...", name);

    // Assert the name is valid
    debug!("Asserting name validity...");
    for c in name.chars() {
        if !c.is_ascii_lowercase() && !c.is_ascii_uppercase() && !c.is_ascii_digit() && c != '_' && c != '.' && c != '-' {
            return Err(Error::IllegalInstanceName { raw: name, illegal_char: c });
        }
    }

    // Attempt to find out if the instance exists
    if !force {
        debug!("Checking if instance already exists...");
        let instance_path: PathBuf = match get_instance_dir(&name) {
            Ok(path) => path,
            Err(err) => {
                return Err(Error::InstanceDirError { err });
            },
        };
        if instance_path.exists() {
            debug!("Asking for confirmation...");
            println!("An instance with the name {} already exists. Overwrite?", style(&name).cyan().bold());
            let consent: bool = match Confirm::new().interact() {
                Ok(consent) => consent,
                Err(err) => {
                    return Err(Error::ConfirmationError { err });
                },
            };
            if !consent {
                println!("Not overwriting, aborted.");
                return Ok(());
            }
        }
    }

    // Convert the hostname and ports to Addresses
    // Note we do it a bit impractically, but that's to parse the hostname correctly in case it's an IP address.
    debug!("Parsing hostname...");
    let api: Address = match Address::from_str(&format!("http://{}:{}", hostname.hostname, api_port)) {
        Ok(addr) => addr,
        Err(err) => {
            return Err(Error::AddressParseError { err });
        },
    };
    let drv: Address = match Address::from_str(&format!("grpc://{}:{}", hostname.hostname, drv_port)) {
        Ok(addr) => addr,
        Err(err) => {
            return Err(Error::AddressParseError { err });
        },
    };

    // Warn the user to let them know an alternative is available if it is an IP
    if name == hostname.hostname && api.is_ip() {
        warn!("Your instance name will now be set to an IP-address ({}); use '--name' to choose a simpler name for this instance.", name);
    }

    // Assert at least the API address is responsive (and if not told to omit this check)
    if !unchecked {
        debug!("Checking instance reachability...");

        // Do a simple HTTP call to the health
        let health_addr: String = format!("{api}/health");
        let res: reqwest::Response = match reqwest::get(&health_addr).await {
            Ok(res) => res,
            Err(err) => {
                return Err(Error::RequestError { address: health_addr, err });
            },
        };
        if !res.status().is_success() {
            return Err(Error::InstanceNotAliveError { address: health_addr, code: res.status(), err: res.text().await.ok() });
        }
    }

    // Create a new InstanceInfo
    debug!("Writing InstanceInfo...");
    let info: InstanceInfo = InstanceInfo { api, drv, user };

    // Write it to wherever it wants to be
    info.to_default_path(&name)?;

    // If told to do so, call `select()` to immediately make it active
    println!("Successfully added new instance {}", style(&name).cyan().bold());
    if use_immediately {
        select(name)?;
    }

    // Done
    Ok(())
}

/// Removes a registered instance (or multiple at once).
///
/// # Arguments
/// - `names`: The names of the instances to remove.
/// - `force`: Whether to ask for confirmation before removal (false) or not (true).
///
/// # Errors
/// This function errors if we failed to generate any files, or if some check failed for this instance.
pub fn remove(names: Vec<String>, force: bool) -> Result<(), Error> {
    info!("Removing instance(s) '{:?}'...", names);

    // Do nothing if no names are given
    if names.is_empty() {
        println!("No instances given to remove.");
        return Ok(());
    }

    // Ask first (to avoid asking for every instance)
    if !force {
        debug!("Asking for confirmation...");
        println!(
            "Are you sure you want to remove instance{} {}?",
            if names.len() > 1 { "s" } else { "" },
            PrettyListFormatter::new(names.iter().map(|n| style(n).bold().cyan()), "and")
        );
        match Confirm::new().interact() {
            Ok(consent) => {
                if !consent {
                    println!("Aborted.");
                    return Ok(());
                }
            },
            Err(err) => {
                return Err(Error::ConfirmationError { err });
            },
        };
    }

    // Now loop through the names to remove them
    for name in names {
        debug!("Removing instance '{}'...", name);

        // Find the folder for this name
        let dir: PathBuf = match get_instance_dir(&name) {
            Ok(dir) => dir,
            Err(_) => {
                warn!("Cannot get directory for instance '{}' (skipping)", name);
                continue;
            },
        };

        // Attempt to remove it if it exists
        if dir.exists() {
            if let Err(err) = fs::remove_dir_all(&dir) {
                warn!("Failed to remove directory '{}': {} (skipping)", dir.display(), err);
                continue;
            }
        } else {
            println!("Instance {} does not exist (skipping)", style(name).yellow().bold());
            continue;
        }

        // If it's the active link, then de-active it
        if InstanceInfo::active_instance_exists()? {
            // Read the name in the link to find if it is us
            debug!("Removing active link to instance '{}'...", name);
            let active_name: String = read_active_instance_link()?;
            if name == active_name {
                // Remove the active file
                let active_path: PathBuf = InstanceInfo::get_default_path(&name)?;
                if let Err(err) = fs::remove_file(&active_path) {
                    return Err(Error::ActiveInstanceRemoveError { path: active_path, err });
                }
            }
        }

        // Alright done then
        println!("Removed instance {}", style(name).cyan().bold());
    }

    // Done
    Ok(())
}



/// Shows all the currently defined instances.
///
/// # Arguments
/// - `show_status`: If true, then an additional column is shown that shows whether the instance is currently reachable or not.
///
/// # Errors
/// This function errors if we failed to read the instance directory.
pub async fn list(show_status: bool) -> Result<(), Error> {
    info!("Listing instances...");

    // Prepare display table.
    let format = FormatBuilder::new().column_separator('\0').borders('\0').padding(1, 1).build();
    let mut table = Table::new();
    table.set_format(format);
    if show_status {
        table.add_row(row!["NAME", "API", "DRIVER", "USERNAME", "STATUS"]);
    } else {
        table.add_row(row!["NAME", "API", "DRIVER", "USERNAME"]);
    }

    // Fetch the instances directory
    let instances_dir: PathBuf = match ensure_instances_dir(true) {
        Ok(dir) => dir,
        Err(err) => {
            return Err(Error::InstancesDirError { err });
        },
    };

    // Fetch the active link, if any
    let active_name: Option<String> = if InstanceInfo::active_instance_exists()? {
        // Get the name in the link
        Some(read_active_instance_link()?)
    } else {
        // Nothing to get
        None
    };

    // Open up the ol' directory and iterate over its contents
    debug!("Reading '{}'...", instances_dir.display());
    let entries: ReadDir = match fs::read_dir(&instances_dir) {
        Ok(entries) => entries,
        Err(err) => {
            return Err(Error::InstancesDirReadError { path: instances_dir, err });
        },
    };
    for (i, entry) in entries.enumerate() {
        // Unpack the entry
        let entry: DirEntry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                return Err(Error::InstancesDirEntryReadError { path: instances_dir, entry: i, err });
            },
        };

        // Assert it is a directory
        let entry_path: PathBuf = entry.path();
        debug!("Listing entry '{}'...", entry_path.display());
        if !entry_path.is_dir() {
            debug!("Skipping entry '{}' (not a directory)", entry_path.display());
            continue;
        }

        // Deduce its name as the name of the folder
        let name: OsString = entry.file_name();
        let name: Cow<str> = name.to_string_lossy();

        // Read the InstanceInfo for further details
        let (api_addr, drv_addr, user): (String, String, String) = {
            // Open up the file
            let info: InstanceInfo = match InstanceInfo::from_default_path(&name) {
                Ok(info) => info,
                Err(Error::InstanceInfoOpenError { path, err }) => {
                    // Skip silently if not found
                    if err.kind() == std::io::ErrorKind::NotFound {
                        debug!("Skipping entry '{}' (no nested '{}' file)", entry_path.display(), path.display());
                        continue;
                    }
                    // Otherwise, do error
                    return Err(Error::InstanceInfoOpenError { path, err });
                },
                Err(err) => {
                    return Err(err);
                },
            };
            (info.api.to_string(), info.drv.to_string(), info.user.clone())
        };

        // Re-style them if active
        let (name, api, drv, user): (String, String, String, String) = if active_name.is_some() && active_name.as_ref().unwrap() == &name {
            (style(name).bold().to_string(), style(&api_addr).bold().to_string(), style(drv_addr).bold().to_string(), style(user).bold().to_string())
        } else {
            (name.into(), api_addr.clone(), drv_addr, user)
        };

        // Align the properties found so far... properly
        let (name, api, drv, user): (Cow<str>, Cow<str>, Cow<str>, Cow<str>) = (
            pad_str(&name, 25, Alignment::Left, Some("..")),
            pad_str(&api, 30, Alignment::Left, Some("..")),
            pad_str(&drv, 30, Alignment::Left, Some("..")),
            pad_str(&user, 25, Alignment::Left, Some("..")),
        );

        // Either get the reachability and then add the row, or add the row immediately (depending on what the user wants us to do)
        if show_status {
            // Get the status
            let status: String = 'reach: {
                // Do a simple HTTP call to the health and see where we fail
                let health_addr: String = format!("{api_addr}/health");
                let res: reqwest::Response = match reqwest::get(&health_addr).await {
                    Ok(res) => res,
                    Err(_) => {
                        break 'reach style("UNREACHABLE").red().bold().to_string();
                    },
                };
                if !res.status().is_success() {
                    break 'reach style("UNHEALTHY").yellow().bold().to_string();
                }
                style("OK").green().bold().to_string()
            };

            // Pad the status
            let status: Cow<str> = pad_str(&status, 15, Alignment::Left, None);

            // Add the column
            table.add_row(row![name, api, drv, user, status]);
        } else {
            // Add the column
            table.add_row(row![name, api, drv, user]);
        }
    }

    // Done
    table.printstd();
    Ok(())
}

/// Changes the active instance to the current one.
///
/// # Arguments
/// - `name`: The name of the instance to make active.
///
/// # Errors
/// This function will error if we failed to read the directory (including if the instance does not exist), or if we failed to update the active instance file.
pub fn select(name: String) -> Result<(), Error> {
    info!("Selecting instance '{}'...", name);

    // Get the path to the instance directory
    debug!("Asserting instance exists...");
    let dir: PathBuf = match get_instance_dir(&name) {
        Ok(dir) => dir,
        Err(err) => {
            return Err(Error::InstanceDirError { err });
        },
    };

    // Assert it exists (as a directory).
    if !dir.exists() {
        return Err(Error::UnknownInstance { name });
    }
    if !dir.is_dir() {
        return Err(Error::InstanceNotADirError { path: dir });
    }

    // Get the path of the link file
    let link_path: PathBuf = match get_active_instance_link() {
        Ok(path) => path,
        Err(err) => {
            return Err(Error::ActiveInstancePathError { err });
        },
    };

    // Simply write a new link, which overwrites the previous file
    debug!("Generating new active link...");
    if let Err(err) = fs::write(&link_path, &name) {
        return Err(Error::ActiveInstanceCreateError { path: link_path, target: name, err });
    }

    // Done
    println!("Successfully switched to {}", style(name).bold().cyan());
    Ok(())
}



/// Edits an existing instance to change its properties.
///
/// # Arguments
/// - `name`: The name of the instance to edit. If omitted, should use the active instance instead.
/// - `hostname`: Whether to change the hostname of the instance and, if so, what to change it to.
/// - `api_port`: Whether to change the API service port of the instance and, if so, what to change it to.
/// - `drv_port`: Whether to change the driver service port of the instance and, if so, what to change it to.
/// - `user`: Whether to change the user name which the user presents as receiver of the final result.
///
/// # Errors
/// This function errors if we failed to find the instance or failed to update its file.
pub fn edit(
    name: Option<String>,
    hostname: Option<Hostname>,
    api_port: Option<u16>,
    drv_port: Option<u16>,
    user: Option<String>,
) -> Result<(), Error> {
    info!("Editing instance {}...", name.as_ref().map(|n| format!("'{n}'")).unwrap_or("<active>".into()));

    // Get the instance's directory
    debug!("Resolving instance directory...");
    let instance_path: PathBuf = name
        .as_ref()
        .map(|n| {
            // We fetch the directory based on the name
            match get_instance_dir(n) {
                Ok(path) => Ok(path.join("info.yml")),
                Err(err) => Err(Error::InstanceDirError { err }),
            }
        })
        .unwrap_or_else(|| {
            // Error if there is no active link
            if !InstanceInfo::active_instance_exists()? {
                return Err(Error::NoActiveInstance);
            }
            // Read the active link
            let active_name: String = read_active_instance_link()?;
            // Return the default path of that name
            InstanceInfo::get_default_path(active_name)
        })?;

    // With the path confirmed, load the info.yml
    debug!("Loading instance file...");
    let mut info: InstanceInfo = InstanceInfo::from_path(instance_path.as_path())?;

    // Adapt whatever is necessary
    debug!("Updating information...");
    if let Some(hostname) = hostname {
        // We replace the addresses. Any new ports will be handled in subsequent if let's
        println!("Updating hostname to {}...", style(&hostname.hostname).cyan().bold());
        info.api = Address::Hostname(format!("http://{}", hostname.hostname), info.api.port());
        info.drv = Address::Hostname(format!("grpc://{}", hostname.hostname), info.drv.port());
    }
    if let Some(port) = api_port {
        println!("Updating API service port to {}...", style(port).cyan().bold());
        info.api = Address::Hostname(info.api.domain().into(), port);
    }
    if let Some(port) = drv_port {
        println!("Updating driver service port to {}...", style(port).cyan().bold());
        info.drv = Address::Hostname(info.drv.domain().into(), port);
    }
    if let Some(user) = user {
        println!("Updating username to {}...", style(&user).cyan().bold());
        info.user = user;
    }

    // Write the modified file back
    debug!("Writing instance file back...");
    info.to_path(instance_path)?;

    // Done
    if let Some(name) = name {
        println!("Successfully updated instance {}", style(name).bold().cyan());
    } else {
        println!("Successfully updated {} instance", style("active").bold().cyan());
    }
    Ok(())
}
