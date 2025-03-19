//  MAIN.rs
//    by Lut99
//
//  Created:
//    21 Sep 2022, 14:34:28
//  Last edited:
//    08 Feb 2024, 17:15:18
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the CLI binary.
//

#[macro_use]
extern crate human_panic;

use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use anyhow::Result;
use brane_cli::errors::{CliError, ImportError};
use brane_cli::{build_ecu, certs, check, data, instance, packages, registry, repl, run, test, upgrade, verify, version};
use brane_dsl::Language;
use brane_shr::fs::DownloadSecurity;
use brane_tsk::docker::DockerOptions;
use clap::Parser;
use dotenvy::dotenv;
use error_trace::ErrorTrace as _;
use humanlog::{DebugMode, HumanLogger};
// use git2::Repository;
use log::{error, info};
use specifications::arch::Arch;
use specifications::package::PackageKind;
use specifications::version::Version as SemVersion;
use tempfile::TempDir;


mod cli;
use cli::*;

/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() -> Result<()> {
    // Parse the CLI arguments
    dotenv().ok();
    let options = Cli::parse();

    // Prepare the logger
    if let Err(err) = HumanLogger::terminal(if options.debug { DebugMode::Debug } else { DebugMode::HumanFriendly }).init() {
        eprintln!("WARNING: Failed to setup logger: {err} (no logging for this session)");
    }
    info!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));

    // Also setup humanpanic
    if !options.debug {
        setup_panic!();
    }

    // Check dependencies if not withheld from doing so
    if !options.skip_check {
        match brane_cli::utils::check_dependencies().await {
            Ok(Ok(())) => {},
            Ok(Err(err)) => {
                eprintln!("Dependencies not met: {err}");
                process::exit(1);
            },
            Err(err) => {
                eprintln!("Could not check for dependencies: {err}");
                process::exit(1);
            },
        }
    }

    // Run the subcommand given
    match run(options).await {
        Ok(_) => process::exit(0),
        Err(err) => {
            error!("{}", err.trace());
            process::exit(1);
        },
    }
}

/// Runs one of the subcommand as given on the Cli.
///
/// **Arguments**
///  * `options`: The struct with (parsed) Cli-options and subcommands.
///
/// **Returns**  
/// Nothing if the subcommand executed successfully (they are self-contained), or a CliError otherwise.
async fn run(options: Cli) -> Result<(), CliError> {
    use SubCommand::*;
    match options.sub_command {
        Certs { subcommand } => {
            use CertsSubcommand::*;
            match subcommand {
                Add { paths, domain, instance, force } => {
                    if let Err(err) = certs::add(instance, paths, domain, force) {
                        return Err(CliError::CertsError { err });
                    }
                },
                Remove { domains, instance, force } => {
                    if let Err(err) = certs::remove(domains, instance, force) {
                        return Err(CliError::CertsError { err });
                    }
                },

                List { instance, all } => {
                    if let Err(err) = certs::list(instance, all) {
                        return Err(CliError::CertsError { err });
                    }
                },
            }
        },
        Data { subcommand } => {
            // Match again
            use DataSubcommand::*;
            match subcommand {
                Build { file, workdir, keep_files, no_links } => {
                    if let Err(err) = data::build(
                        &file,
                        workdir.unwrap_or_else(|| file.parent().map(|p| p.into()).unwrap_or_else(|| PathBuf::from("./"))),
                        keep_files,
                        no_links,
                    )
                    .await
                    {
                        return Err(CliError::DataError { err });
                    }
                },
                Download { names, locs, proxy_addr, force } => {
                    if let Err(err) = data::download(names, locs, &proxy_addr, force).await {
                        return Err(CliError::DataError { err });
                    }
                },

                List {} => {
                    if let Err(err) = data::list() {
                        return Err(CliError::DataError { err });
                    }
                },
                Search {} => {
                    eprintln!("search is not yet implemented.");
                    std::process::exit(1);
                },
                Path { names } => {
                    if let Err(err) = data::path(names) {
                        return Err(CliError::DataError { err });
                    }
                },

                Remove { names, force } => {
                    if let Err(err) = data::remove(names, force) {
                        return Err(CliError::DataError { err });
                    }
                },
            }
        },
        Instance { subcommand } => {
            // Switch on the subcommand
            use InstanceSubcommand::*;
            match subcommand {
                Add { hostname, api_port, drv_port, user, name, use_immediately, unchecked, force } => {
                    if let Err(err) = instance::add(
                        name.unwrap_or_else(|| hostname.hostname.clone()),
                        hostname,
                        api_port,
                        drv_port,
                        user.unwrap_or_else(|| names::three::lowercase::rand().into()),
                        use_immediately,
                        unchecked,
                        force,
                    )
                    .await
                    {
                        return Err(CliError::InstanceError { err });
                    }
                },
                Remove { names, force } => {
                    if let Err(err) = instance::remove(names, force) {
                        return Err(CliError::InstanceError { err });
                    }
                },

                List { show_status } => {
                    if let Err(err) = instance::list(show_status).await {
                        return Err(CliError::InstanceError { err });
                    }
                },
                Select { name } => {
                    if let Err(err) = instance::select(name) {
                        return Err(CliError::InstanceError { err });
                    }
                },

                Edit { name, hostname, api_port, drv_port, user } => {
                    if let Err(err) = instance::edit(name, hostname, api_port, drv_port, user) {
                        return Err(CliError::InstanceError { err });
                    }
                },
            }
        },

        Package { subcommand } => {
            match subcommand {
                PackageSubcommand::Build { arch, workdir, file, kind, init, keep_files, crlf_ok } => {
                    // Resolve the working directory
                    let workdir = match workdir {
                        Some(workdir) => workdir,
                        None => match std::fs::canonicalize(&file) {
                            Ok(file) => file.parent().unwrap().to_path_buf(),
                            Err(err) => {
                                return Err(CliError::PackageFileCanonicalizeError { path: file, err });
                            },
                        },
                    };
                    let workdir = match std::fs::canonicalize(workdir) {
                        Ok(workdir) => workdir,
                        Err(err) => {
                            return Err(CliError::WorkdirCanonicalizeError { path: file, err });
                        },
                    };

                    // Resolve the kind of the file
                    let kind = if let Some(kind) = kind {
                        match PackageKind::from_str(&kind) {
                            Ok(kind) => kind,
                            Err(err) => {
                                return Err(CliError::IllegalPackageKind { kind, err });
                            },
                        }
                    } else {
                        match brane_cli::utils::determine_kind(&file) {
                            Ok(kind) => kind,
                            Err(err) => {
                                return Err(CliError::UtilError { err });
                            },
                        }
                    };

                    // Build a new package with it
                    match kind {
                        PackageKind::Ecu => build_ecu::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, keep_files, crlf_ok)
                            .await
                            .map_err(|err| CliError::BuildError { err })?,
                        _ => eprintln!("Unsupported package kind: {kind}"),
                    }
                },
                PackageSubcommand::Import { arch, repo, branch, workdir, file, kind, init, crlf_ok } => {
                    // Prepare the input URL and output directory
                    let url = format!("https://api.github.com/repos/{repo}/tarball/{branch}");
                    let dir = match TempDir::new() {
                        Ok(dir) => dir,
                        Err(err) => {
                            return Err(CliError::ImportError { err: ImportError::TempDirError { err } });
                        },
                    };

                    // Download the file
                    let tar_path: PathBuf = dir.path().join("repo.tar.gz");
                    let dir_path: PathBuf = dir.path().join("repo");
                    if let Err(err) =
                        brane_shr::fs::download_file_async(&url, &tar_path, DownloadSecurity { checksum: None, https: true }, None).await
                    {
                        return Err(CliError::ImportError { err: ImportError::RepoCloneError { repo: url, target: dir_path, err } });
                    }
                    if let Err(err) = brane_shr::fs::unarchive_async(&tar_path, &dir_path).await {
                        return Err(CliError::ImportError { err: ImportError::RepoCloneError { repo: url, target: dir_path, err } });
                    }
                    // Resolve that one weird folder in there
                    let dir_path: PathBuf = match brane_shr::fs::recurse_in_only_child_async(&dir_path).await {
                        Ok(path) => path,
                        Err(err) => {
                            return Err(CliError::ImportError { err: ImportError::RepoCloneError { repo: url, target: dir_path, err } });
                        },
                    };

                    // Try to get which file we need to use as package file
                    let file = match file {
                        Some(file) => dir_path.join(file),
                        None => dir_path.join(brane_cli::utils::determine_file(&dir_path).map_err(|err| CliError::UtilError { err })?),
                    };
                    let file = match std::fs::canonicalize(&file) {
                        Ok(file) => file,
                        Err(err) => {
                            return Err(CliError::PackageFileCanonicalizeError { path: file, err });
                        },
                    };
                    if !file.starts_with(&dir_path) {
                        return Err(CliError::ImportError { err: ImportError::RepoEscapeError { path: file } });
                    }

                    // Try to resolve the working directory relative to the repository
                    let workdir = match workdir {
                        Some(workdir) => dir.path().join(workdir),
                        None => file.parent().unwrap().to_path_buf(),
                    };
                    let workdir = match std::fs::canonicalize(workdir) {
                        Ok(workdir) => workdir,
                        Err(err) => {
                            return Err(CliError::WorkdirCanonicalizeError { path: file, err });
                        },
                    };
                    if !workdir.starts_with(&dir_path) {
                        return Err(CliError::ImportError { err: ImportError::RepoEscapeError { path: file } });
                    }

                    // Resolve the kind of the file
                    let kind = if let Some(kind) = kind {
                        match PackageKind::from_str(&kind) {
                            Ok(kind) => kind,
                            Err(err) => {
                                return Err(CliError::IllegalPackageKind { kind, err });
                            },
                        }
                    } else {
                        match brane_cli::utils::determine_kind(&file) {
                            Ok(kind) => kind,
                            Err(err) => {
                                return Err(CliError::UtilError { err });
                            },
                        }
                    };

                    // Build a new package with it
                    match kind {
                        PackageKind::Ecu => build_ecu::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, false, crlf_ok)
                            .await
                            .map_err(|err| CliError::BuildError { err })?,
                        _ => eprintln!("Unsupported package kind: {kind}"),
                    }
                },
                PackageSubcommand::Inspect { name, version, syntax } => {
                    if let Err(err) = packages::inspect(name, version, syntax) {
                        return Err(CliError::OtherError { err });
                    };
                },
                PackageSubcommand::List { latest } => {
                    if let Err(err) = packages::list(latest) {
                        return Err(CliError::OtherError { err: anyhow::anyhow!(err) });
                    };
                },
                PackageSubcommand::Load { name, version } => {
                    if let Err(err) = packages::load(name, version).await {
                        return Err(CliError::OtherError { err });
                    };
                },
                PackageSubcommand::Pull { packages } => {
                    // Parse the NAME:VERSION pairs into a name and a version
                    if packages.is_empty() {
                        println!("Nothing to do.");
                        return Ok(());
                    }
                    let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
                    for package in &packages {
                        parsed.push(match SemVersion::from_package_pair(package) {
                            Ok(pair) => pair,
                            Err(err) => {
                                return Err(CliError::PackagePairParseError { raw: package.into(), err });
                            },
                        })
                    }

                    // Now delegate the parsed pairs to the actual pull() function
                    if let Err(err) = registry::pull(parsed).await {
                        return Err(CliError::RegistryError { err });
                    };
                },
                PackageSubcommand::Push { packages } => {
                    // Parse the NAME:VERSION pairs into a name and a version
                    if packages.is_empty() {
                        println!("Nothing to do.");
                        return Ok(());
                    }
                    let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
                    for package in packages {
                        parsed.push(match SemVersion::from_package_pair(&package) {
                            Ok(pair) => pair,
                            Err(err) => {
                                return Err(CliError::PackagePairParseError { raw: package, err });
                            },
                        })
                    }

                    // Now delegate the parsed pairs to the actual push() function
                    if let Err(err) = registry::push(parsed).await {
                        return Err(CliError::RegistryError { err });
                    };
                },
                PackageSubcommand::Remove { force, packages, docker_socket, client_version } => {
                    // Parse the NAME:VERSION pairs into a name and a version
                    if packages.is_empty() {
                        println!("Nothing to do.");
                        return Ok(());
                    }
                    let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
                    for package in packages {
                        parsed.push(match SemVersion::from_package_pair(&package) {
                            Ok(pair) => pair,
                            Err(err) => {
                                return Err(CliError::PackagePairParseError { raw: package, err });
                            },
                        })
                    }

                    // Now delegate the parsed pairs to the actual remove() function
                    if let Err(err) = packages::remove(force, parsed, DockerOptions { socket: docker_socket, version: client_version }).await {
                        return Err(CliError::PackageError { err });
                    };
                },
                PackageSubcommand::Test { name, version, show_result, docker_socket, client_version, keep_containers } => {
                    if let Err(err) =
                        test::handle(name, version, show_result, DockerOptions { socket: docker_socket, version: client_version }, keep_containers)
                            .await
                    {
                        return Err(CliError::TestError { err });
                    };
                },
                PackageSubcommand::Search { term } => {
                    if let Err(err) = registry::search(term).await {
                        return Err(CliError::OtherError { err });
                    };
                },
                PackageSubcommand::Unpublish { name, version, force } => {
                    if let Err(err) = registry::unpublish(name, version, force).await {
                        return Err(CliError::OtherError { err });
                    };
                },
            }
        },
        Upgrade { subcommand } => {
            // Match the subcommand in question
            use UpgradeSubcommand::*;
            match subcommand {
                Data { path, dry_run, overwrite, version } => {
                    // Upgrade the file
                    if let Err(err) = upgrade::data(path, dry_run, overwrite, version) {
                        return Err(CliError::UpgradeError { err });
                    }
                },
            }
        },
        Verify { subcommand } => {
            // Match the subcommand in question
            use VerifySubcommand::*;
            match subcommand {
                Config { infra } => {
                    // Verify the configuration
                    if let Err(err) = verify::config(infra) {
                        return Err(CliError::VerifyError { err });
                    }
                    println!("OK");
                },
            }
        },
        Version { arch, local, remote } => {
            if local || remote {
                // If any of local or remote is given, do those
                if arch {
                    if local {
                        if let Err(err) = version::handle_local_arch() {
                            return Err(CliError::VersionError { err });
                        }
                    }
                    if remote {
                        if let Err(err) = version::handle_remote_arch().await {
                            return Err(CliError::VersionError { err });
                        }
                    }
                } else {
                    if local {
                        if let Err(err) = version::handle_local_version() {
                            return Err(CliError::VersionError { err });
                        }
                    }
                    if remote {
                        if let Err(err) = version::handle_remote_version().await {
                            return Err(CliError::VersionError { err });
                        }
                    }
                }
            } else {
                // Print neatly
                if let Err(err) = version::handle().await {
                    return Err(CliError::VersionError { err });
                }
            }
        },
        Workflow { subcommand } => match subcommand {
            WorkflowSubcommand::Check { file, bakery, user, profile } => {
                if let Err(err) = check::handle(file, if bakery { Language::Bakery } else { Language::BraneScript }, user, profile).await {
                    return Err(CliError::CheckError { err });
                };
            },
            WorkflowSubcommand::Repl { proxy_addr, bakery, clear, remote, attach, profile, docker_socket, client_version, keep_containers } => {
                if let Err(err) = repl::start(
                    proxy_addr,
                    remote,
                    attach,
                    if bakery { Language::Bakery } else { Language::BraneScript },
                    clear,
                    profile,
                    DockerOptions { socket: docker_socket, version: client_version },
                    keep_containers,
                )
                .await
                {
                    return Err(CliError::ReplError { err });
                };
            },
            WorkflowSubcommand::Run { proxy_addr, bakery, file, dry_run, remote, profile, docker_socket, client_version, keep_containers } => {
                if let Err(err) = run::handle(
                    proxy_addr,
                    if bakery { Language::Bakery } else { Language::BraneScript },
                    file,
                    dry_run,
                    remote,
                    profile,
                    DockerOptions { socket: docker_socket, version: client_version },
                    keep_containers,
                )
                .await
                {
                    return Err(CliError::RunError { err });
                };
            },
        },
    }

    Ok(())
}
