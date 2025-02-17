use std::fs;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use bollard::Docker;
use bollard::image::{ImportImageOptions, TagImageOptions};
use bollard::models::BuildInfo;
use brane_dsl::DataType;
use brane_shr::formatters::PrettyListFormatter;
use brane_tsk::docker::{self, DockerOptions};
use chrono::{Local, Utc};
use console::{Alignment, pad_str, style};
use dialoguer::Confirm;
use fs_extra::dir;
use futures_util::stream::TryStreamExt;
use indicatif::{DecimalBytes, HumanDuration};
use prettytable::Table;
use prettytable::format::FormatBuilder;
use specifications::container::Image;
use specifications::package::PackageInfo;
use specifications::version::Version;
use tokio::fs::File as TFile;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};

use crate::errors::PackageError;
use crate::utils::{ensure_package_dir, ensure_packages_dir};


/***** HELPER FUNCTIONS *****/
/// Inserts a PackageInfo in a list of PackageInfos such that it tries to only have the latest version of each package.
///
/// **Arguments**
///  * `infos`: The list of PackageInfos to insert into.
///  * `name`: The name of the package to add.
///  * `info`: The PackageInfo of the package to add.
fn insert_package_in_list(infos: &mut Vec<PackageInfo>, info: PackageInfo) {
    // Go through the list
    for pkg in infos.iter_mut() {
        // Check if its this package
        debug!("Package '{}' vs '{}'", &info.name, &pkg.name);
        if info.name.eq(&pkg.name) {
            // Only add if the new version is higher
            debug!(" > Version '{}' vs '{}'", info.version, pkg.version.to_string());
            if info.version > pkg.version {
                *pkg = info;
            }
            // Always stop tho
            return;
        }
    }

    // Simply add to the list
    infos.push(info);
}
/*******/





/***** SUBCOMMANDS *****/
/// Inspects the given package, pretty-printing its details.
///
/// # Arguments
/// - `name`: The name of the package to inspect.
/// - `version`: The version of the package to inspect.
/// - `syntax`: The mode of syntax to use for classes & functions. Can be 'bscript', 'bakery' or 'custom'.
///
/// # Returns
/// Nothing
pub fn inspect(name: String, version: Version, syntax: String) -> Result<()> {
    let package_dir = ensure_package_dir(&name, Some(&version), false)?;
    let package_file = package_dir.join("package.yml");

    if let Ok(info) = PackageInfo::from_path(package_file) {
        // _Neatly_ print it
        println!();
        println!(
            "Package {} ({} package, version {})",
            style(&info.name).bold().cyan(),
            style(format!("{}", info.kind)).bold(),
            style(format!("{}", info.version)).bold()
        );
        println!(
            "Created {} ({} ago)",
            style(format!("{}", info.created.with_timezone(&Local))).bold().cyan(),
            HumanDuration(Duration::from_secs((Local::now().time() - info.created.time()).num_seconds() as u64))
        );
        println!();

        // Print the description and owner(s)
        println!(
            "Owners: {}",
            if !info.owners.is_empty() {
                format!("{}", PrettyListFormatter::new(info.owners.iter().map(|o| format!("{}", style(&o).bold())), "and"))
            } else {
                "<unspecified>".into()
            }
        );
        println!("{}", if !info.description.trim().is_empty() { &info.description } else { "<no description>" });
        println!();

        // Now print the types
        println!("Classes provided by this package:");
        let mut types: Vec<&String> = info.types.keys().collect();
        types.sort_by_key(|t| t.to_lowercase());
        for name in types {
            let info = info.types.get(name).unwrap();
            match syntax.as_str() {
                "bscript" => {
                    println!("  - class {} {{", style(&name).bold().cyan());
                    for p in &info.properties {
                        println!("        {}: {};", style(&p.name).bold(), DataType::from(&p.data_type));
                    }
                    println!("    }}");
                },

                "bakery" => {
                    return Err(anyhow!("Bakery syntax is not yet implemented"));
                },

                "custom" => {
                    println!("  - Class {}", style(&name).bold().cyan());
                    for p in &info.properties {
                        println!("        {} {};", DataType::from(&p.data_type), style(&p.name).bold());
                    }
                },

                _ => {
                    return Err(anyhow!("Given syntax '{}' is unknown", syntax));
                },
            }
        }
        if info.types.is_empty() {
            println!("    <none>");
        }
        println!();

        // Now print the list of functions
        println!("Functions provided by this package:");
        let mut funcs: Vec<&String> = info.functions.keys().collect();
        funcs.sort_by_key(|t| t.to_lowercase());
        for name in funcs {
            let func = info.functions.get(name).unwrap();
            match syntax.as_str() {
                "bscript" => {
                    println!(
                        "  - func {}({}) -> {}",
                        style(&name).bold().cyan(),
                        func.parameters
                            .iter()
                            .map(|p| format!("{}: {}", style(&p.name).bold(), DataType::from(&p.data_type)))
                            .collect::<Vec<String>>()
                            .join(", "),
                        DataType::from(&func.return_type)
                    );
                },

                "bakery" => {
                    return Err(anyhow!("Bakery syntax is not yet implemented"));
                },

                "custom" => {
                    println!("  - Function {}", style(&name).bold().cyan());
                    println!("      - Arguments:");
                    for p in &func.parameters {
                        println!("          - {} {}", DataType::from(&p.data_type), style(&p.name).bold());
                    }
                    println!("      - Returns: {}", DataType::from(&func.return_type));
                },

                _ => {
                    return Err(anyhow!("Given syntax '{}' is unknown", syntax));
                },
            }
        }
        if info.functions.is_empty() {
            println!("    <none>");
        }
        println!();
    } else {
        return Err(anyhow!("Failed to read package information."));
    }

    Ok(())
}



/* TIM */
/// **Edited: updated to deal with get_packages_dir() returning ExecutorErrors. Also added option to only show latest packages and also standard packages.**
///
/// Lists the packages locally build and available.
/// use console::style;
/// **Arguments**
///  * `latest`: If set to true, only shows latest version of each package.
///
/// **Returns**  
/// Nothing other than prints on stdout if successfull, or an ExecutorError otherwise.
pub fn list(latest: bool) -> Result<(), PackageError> {
    // Get the directory with the packages
    let packages_dir = match ensure_packages_dir(false) {
        Ok(dir) => dir,
        Err(_) => {
            println!("No packages found.");
            return Ok(());
        },
    };

    // Prepare display table.
    let format = FormatBuilder::new().column_separator('\0').borders('\0').padding(1, 1).build();
    let mut table = Table::new();
    table.set_format(format);
    table.add_row(row!["ID", "NAME", "VERSION", "KIND", "CREATED", "SIZE"]);

    // Get the local PackageIndex
    let index = match brane_tsk::local::get_package_index(&packages_dir) {
        Ok(idx) => idx,
        Err(err) => {
            return Err(PackageError::IndexError { err });
        },
    };

    // Collect a list of PackageInfos to show
    let mut infos: Vec<PackageInfo> = Vec::with_capacity(index.packages.len());
    // Then to the normal packages
    for (_, info) in index.packages {
        // Decide if we want to show all or just the latest version
        if latest {
            // Insert using the common code
            insert_package_in_list(&mut infos, info);
        } else {
            // Just append
            infos.push(info);
        }
    }

    // With the list constructed, add each entry
    let now = Utc::now().timestamp();
    for entry in infos {
        // Derive the pathname for this package
        let package_path = packages_dir.join(&entry.name).join(entry.version.to_string());
        let sversion = entry.version.to_string();

        // Collect the package information in the proper formats
        let uuid = format!("{}", &entry.id);
        let id = pad_str(&uuid[..8], 10, Alignment::Left, Some(".."));
        let name = pad_str(&entry.name, 20, Alignment::Left, Some(".."));
        let version = pad_str(&sversion, 10, Alignment::Left, Some(".."));
        let skind = format!("{}", entry.kind);
        let kind = pad_str(&skind, 10, Alignment::Left, Some(".."));
        let elapsed = Duration::from_secs((now - entry.created.timestamp()) as u64);
        let created = format!("{} ago", HumanDuration(elapsed));
        let created = pad_str(&created, 15, Alignment::Left, None);
        let size = DecimalBytes(dir::get_size(package_path).unwrap());

        // Add the row
        table.add_row(row![id, name, version, kind, created, size]);
    }

    // Write to stdout and done!
    table.printstd();
    Ok(())
}
/*******/



/// **Edited: now working with new versions.**
///
/// Loads the given package to the local Docker daemon.
///
/// **Arguments**
///  * `name`: The name of the package to load.
///  * `version`: The Version of the package to load. Might be an unresolved 'latest'.
///
/// **Returns**  
/// Nothing on success, or else an error.
pub async fn load(name: String, version: Version) -> Result<()> {
    debug!("Loading package '{}' (version {})", name, &version);

    let package_dir = ensure_package_dir(&name, Some(&version), false)?;
    if !package_dir.exists() {
        return Err(anyhow!("Package not found."));
    }

    let package_info = PackageInfo::from_path(package_dir.join("package.yml"))?;
    let image = format!("{}:{}", package_info.name, package_info.version);
    let image_file = package_dir.join("image.tar");

    let docker = Docker::connect_with_local_defaults()?;

    // Abort, if image is already loaded
    if docker.inspect_image(&image).await.is_ok() {
        println!("Image already exists in local Docker deamon.");
        return Ok(());
    }

    println!("Image doesn't exist in Docker deamon: importing...");
    let options = ImportImageOptions { quiet: true };

    /* TIM */
    let file_handle = TFile::open(&image_file).await;
    if let Err(reason) = file_handle {
        let code = reason.raw_os_error().unwrap_or(-1);
        eprintln!("Could not open image file '{}': {}.", image_file.to_string_lossy(), reason);
        std::process::exit(code);
    }
    // let file = TFile::open(image_file).await?;
    let file = file_handle.ok().unwrap();
    /*******/
    let byte_stream = FramedRead::new(file, BytesCodec::new()).map(|r| r.unwrap().freeze());

    let result = docker.import_image_stream(options, byte_stream, None).try_collect::<Vec<_>>().await?;
    if let Some(BuildInfo { stream: Some(stream), .. }) = result.first() {
        debug!("{}", stream);

        let (_, image_hash) = stream.trim().split_once("sha256:").unwrap_or_default();

        // Manually add tag to image, if not specified.
        if !image_hash.is_empty() {
            debug!("Imported image: {}", image_hash);

            let options = TagImageOptions { repo: &package_info.name, tag: &package_info.version.to_string() };

            docker.tag_image(image_hash, Some(options)).await?;
        }
    }

    Ok(())
}



/// **Edited: now working with new versions.**
///
/// Removes the given list of packages from the local repository.
///
/// # Arguments
///  - `force`: Whether or not to force removal (remove the image from the Docker daemon even if there are still containers using it).
///  - `packages`: The list of (name, Version) pairs to remove.
///  - `docker_opts`: Configuration for how to connect to the local Docker daemon.
///
/// # Returns  
/// Nothing on success, or else an error.
pub async fn remove(force: bool, packages: Vec<(String, Version)>, docker_opts: DockerOptions) -> Result<(), PackageError> {
    // Iterate over the packages
    for (name, version) in packages {
        // Remove without confirmation if explicity stated package version.
        if !version.is_latest() {
            // Try to resolve the directory for this pair
            let package_dir = match ensure_package_dir(&name, Some(&version), false) {
                Ok(dir) => dir,
                Err(err) => {
                    return Err(PackageError::PackageVersionError { name, version, err });
                },
            };

            // Ask for permission if needed
            if !force {
                println!("Are you sure you want to remove package {} version {}?", style(&name).bold().cyan(), style(&version).bold().cyan());
                println!();
                let consent: bool = match Confirm::new().interact() {
                    Ok(consent) => consent,
                    Err(err) => {
                        return Err(PackageError::ConsentError { err });
                    },
                };
                if !consent {
                    return Ok(());
                }
            }

            // If we got permission, get the digest of this version
            let package_info_path = package_dir.join("package.yml");
            let package_info = match PackageInfo::from_path(package_info_path.clone()) {
                Ok(info) => info,
                Err(err) => {
                    return Err(PackageError::PackageInfoError { path: package_info_path, err });
                },
            };
            let digest = match package_info.digest {
                Some(digest) => digest,
                None => {
                    return Err(PackageError::PackageInfoNoDigest { path: package_info_path });
                },
            };

            // Remove that image from the Docker daemon
            let image: Image = Image::new(&package_info.name, Some(format!("{}", package_info.version)), Some(digest));
            if let Err(err) = docker::remove_image(&docker_opts, &image).await {
                return Err(PackageError::DockerRemoveError { image: Box::new(image), err });
            }

            // Also remove the package files
            if let Err(err) = fs::remove_dir_all(&package_dir) {
                return Err(PackageError::PackageRemoveError { name, version, dir: package_dir, err });
            }

            // If there are now no more packages left, remove the package directory itself as well
            let package_dir = match ensure_package_dir(&name, None, false) {
                Ok(dir) => dir,
                Err(err) => {
                    return Err(PackageError::PackageError { name, err });
                },
            };
            match fs::read_dir(&package_dir) {
                Ok(versions) => {
                    if versions.count() == 0 {
                        // Attempt to remove the main dir
                        if let Err(err) = fs::remove_dir_all(&package_dir) {
                            return Err(PackageError::PackageRemoveError { name, version, dir: package_dir, err });
                        }
                    }
                },
                Err(err) => {
                    return Err(PackageError::VersionsError { name, dir: package_dir, err });
                },
            };

            // Donelet versions =
            println!("Successfully removed version {} of package {}", style(&version).bold().cyan(), style(&name).bold().cyan());
            return Ok(());
        }

        // Otherwise, resolve the package directory only
        let package_dir = match ensure_package_dir(&name, None, false) {
            Ok(dir) => dir,
            Err(err) => {
                return Err(PackageError::PackageError { name, err });
            },
        };

        // Look for packages.
        let versions: Vec<Version> = match fs::read_dir(&package_dir) {
            Ok(versions) => {
                // Parse them all
                let mut result = Vec::with_capacity(3);
                for version in versions {
                    // Resolve the entry
                    let version = match version {
                        Ok(version) => version,
                        Err(err) => {
                            return Err(PackageError::VersionsError { name, dir: package_dir, err });
                        },
                    };

                    // Parse the path as a Version
                    let version = String::from(version.file_name().to_string_lossy());
                    let version = match Version::from_str(&version) {
                        Ok(version) => version,
                        Err(err) => {
                            return Err(PackageError::VersionParseError { name, raw: version, err });
                        },
                    };

                    // Add it to the list
                    result.push(version);
                }

                // Done
                result
            },
            Err(err) => {
                return Err(PackageError::VersionsError { name, dir: package_dir, err });
            },
        };

        // Ask for permission, if --force is not provided
        if !force {
            println!("Are you sure you want to remove the following version(s) of package {}?", style(&name).bold().cyan());
            for version in &versions {
                println!("- {}", style(&version).bold().cyan());
            }
            println!();
            let consent: bool = match Confirm::new().interact() {
                Ok(consent) => consent,
                Err(err) => {
                    return Err(PackageError::ConsentError { err });
                },
            };
            if !consent {
                continue;
            }
        }

        // Check if image is locally loaded in Docker and if so, remove it there first
        for version in &versions {
            // Get the digest of this version
            let package_info_path = package_dir.join(version.to_string()).join("package.yml");
            let package_info = match PackageInfo::from_path(package_info_path.clone()) {
                Ok(info) => info,
                Err(err) => {
                    return Err(PackageError::PackageInfoError { path: package_info_path, err });
                },
            };
            let digest = match package_info.digest {
                Some(digest) => digest,
                None => {
                    return Err(PackageError::PackageInfoNoDigest { path: package_info_path });
                },
            };

            // Remove that image from the Docker daemon
            let image: Image = Image::new(&package_info.name, Some(format!("{}", package_info.version)), Some(digest));
            if let Err(err) = docker::remove_image(&docker_opts, &image).await {
                return Err(PackageError::DockerRemoveError { image: Box::new(image), err });
            }
        }

        // Remove the package files
        if let Err(err) = fs::remove_dir_all(&package_dir) {
            return Err(PackageError::PackageRemoveError { name, version, dir: package_dir, err });
        }

        // Done
        println!("Successfully removed package {}", style(&name).bold().cyan());
    }

    // Done!
    Ok(())
}
