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

mod cli;

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
use cli::*;
use dotenvy::dotenv;
use error_trace::ErrorTrace as _;
use specifications::arch::Arch;
use specifications::package::PackageKind;
use specifications::version::Version as SemVersion;
use tempfile::TempDir;
use tracing::level_filters::LevelFilter;
// use git2::Repository;
use tracing::{error, info};


// Constants
/// The default log level for tracing_subscriber. Levels higher than this will be discarded.
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::INFO;
/// Tracing log filter used by brane-cli
const LOG_LEVEL_ENV_VAR: &str = "BRANE_CLI_LOG";


/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() -> Result<()> {
    // Parse the CLI arguments
    dotenv().ok();
    let options = cli::Cli::parse();

    let cli_log_level = options.logging.log_level(DEFAULT_LOG_LEVEL);
    specifications::tracing::setup_subscriber(LOG_LEVEL_ENV_VAR, cli_log_level);

    info!("{} - v{}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));

    // Also setup humanpanic
    if !options.logging.debug {
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

/// **Edited: now returning CliErrors.**
///
/// Runs one of the subcommand as given on the Cli.
///
/// # Arguments
/// * `options`: The struct with (parsed) Cli-options and subcommands.
///
/// # Returns
/// Nothing if the subcommand executed successfully (they are self-contained), or a CliError otherwise.
async fn run(options: Cli) -> Result<(), CliError> {
    use SubCommand::*;
    match options.sub_command {
        Certs { subcommand } => {
            use CertsSubcommand::*;
            match subcommand {
                Add { paths, domain, instance, force } => {
                    certs::add(instance, paths, domain, force).map_err(|source| CliError::CertsError { source })?;
                },
                Remove { domains, instance, force } => {
                    certs::remove(domains, instance, force).map_err(|source| CliError::CertsError { source })?;
                },

                List { instance, all } => {
                    certs::list(instance, all).map_err(|source| CliError::CertsError { source })?;
                },
            }
        },
        Data { subcommand } => {
            // Match again
            use DataSubcommand::*;
            match subcommand {
                Build { file, workdir, keep_files, no_links } => {
                    data::build(
                        &file,
                        workdir.unwrap_or_else(|| file.parent().map(|p| p.into()).unwrap_or_else(|| PathBuf::from("./"))),
                        keep_files,
                        no_links,
                    )
                    .await
                    .map_err(|source| CliError::DataError { source })?;
                },
                Download { names, locs, use_case, user, proxy_addr, force } => {
                    let user = user.unwrap_or_else(|| {
                        std::env::var("USER").expect("Currently we require the user to be set. This should default to the logged in user")
                    });

                    data::download(names, locs, use_case, user, &proxy_addr, force).await.map_err(|source| CliError::DataError { source })?;
                },

                List {} => {
                    data::list().map_err(|source| CliError::DataError { source })?;
                },
                Search {} => {
                    eprintln!("search is not yet implemented.");
                    std::process::exit(1);
                },
                Path { names } => {
                    data::path(names).map_err(|source| CliError::DataError { source })?;
                },

                Remove { names, force } => {
                    data::remove(names, force).map_err(|source| CliError::DataError { source })?;
                },
            }
        },
        Instance { subcommand } => {
            // Switch on the subcommand
            use InstanceSubcommand::*;
            match subcommand {
                Add { hostname, api_port, drv_port, user, name, use_immediately, unchecked, force } => {
                    instance::add(
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
                    .map_err(|source| CliError::InstanceError { source })?;
                },
                Remove { names, force } => {
                    instance::remove(names, force).map_err(|source| CliError::InstanceError { source })?;
                },

                List { show_status } => {
                    instance::list(show_status).await.map_err(|source| CliError::InstanceError { source })?;
                },
                Select { name } => {
                    instance::select(name).map_err(|source| CliError::InstanceError { source })?;
                },

                Edit { name, hostname, api_port, drv_port, user } => {
                    instance::edit(name, hostname, api_port, drv_port, user).map_err(|source| CliError::InstanceError { source })?;
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
                            Err(source) => {
                                return Err(CliError::PackageFileCanonicalizeError { path: file, source });
                            },
                        },
                    };
                    let workdir =
                        std::fs::canonicalize(workdir).map_err(|source| CliError::WorkdirCanonicalizeError { path: file.clone(), source })?;

                    // Resolve the kind of the file
                    let kind = if let Some(kind) = kind {
                        PackageKind::from_str(&kind).map_err(|source| CliError::IllegalPackageKind { kind, source })?
                    } else {
                        brane_cli::utils::determine_kind(&file).map_err(|source| CliError::UtilError { source })?
                    };

                    // Build a new package with it
                    match kind {
                        PackageKind::Ecu => build_ecu::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, keep_files, crlf_ok)
                            .await
                            .map_err(|source| CliError::BuildError { source })?,
                        _ => eprintln!("Unsupported package kind: {kind}"),
                    }
                },
                PackageSubcommand::Import { arch, repo, branch, workdir, file, kind, init, crlf_ok } => {
                    // Prepare the input URL and output directory
                    let url = format!("https://api.github.com/repos/{repo}/tarball/{branch}");
                    let dir = TempDir::new().map_err(|source| CliError::ImportError { source: ImportError::TempDirError { source } })?;

                    // Download the file
                    let tar_path: PathBuf = dir.path().join("repo.tar.gz");
                    let dir_path: PathBuf = dir.path().join("repo");
                    brane_shr::fs::download_file_async(&url, &tar_path, DownloadSecurity { checksum: None, https: true }, None).await.map_err(
                        |source| CliError::ImportError {
                            source: ImportError::RepoCloneError { repo: url.clone(), target: dir_path.clone(), source },
                        },
                    )?;
                    brane_shr::fs::unarchive_async(&tar_path, &dir_path).await.map_err(|source| CliError::ImportError {
                        source: ImportError::RepoCloneError { repo: url.clone(), target: dir_path.clone(), source },
                    })?;

                    // Resolve that one weird folder in there
                    let dir_path: PathBuf = brane_shr::fs::recurse_in_only_child_async(&dir_path)
                        .await
                        .map_err(|source| CliError::ImportError { source: ImportError::RepoCloneError { repo: url, target: dir_path, source } })?;

                    // Try to get which file we need to use as package file
                    let file = match file {
                        Some(file) => dir_path.join(file),
                        None => dir_path.join(brane_cli::utils::determine_file(&dir_path).map_err(|source| CliError::UtilError { source })?),
                    };
                    let file =
                        std::fs::canonicalize(&file).map_err(|source| CliError::PackageFileCanonicalizeError { path: file.clone(), source })?;
                    if !file.starts_with(&dir_path) {
                        return Err(CliError::ImportError { source: ImportError::RepoEscapeError { path: file } });
                    }

                    // Try to resolve the working directory relative to the repository
                    let workdir = match workdir {
                        Some(workdir) => dir.path().join(workdir),
                        None => file.parent().unwrap().to_path_buf(),
                    };
                    let workdir =
                        std::fs::canonicalize(workdir).map_err(|source| CliError::WorkdirCanonicalizeError { path: file.clone(), source })?;
                    if !workdir.starts_with(&dir_path) {
                        return Err(CliError::ImportError { source: ImportError::RepoEscapeError { path: file } });
                    }

                    // Resolve the kind of the file
                    let kind = if let Some(kind) = kind {
                        PackageKind::from_str(&kind).map_err(|source| CliError::IllegalPackageKind { kind, source })?
                    } else {
                        brane_cli::utils::determine_kind(&file).map_err(|source| CliError::UtilError { source })?
                    };

                    // Build a new package with it
                    match kind {
                        PackageKind::Ecu => build_ecu::handle(arch.unwrap_or(Arch::HOST), workdir, file, init, false, crlf_ok)
                            .await
                            .map_err(|source| CliError::BuildError { source })?,
                        _ => eprintln!("Unsupported package kind: {kind}"),
                    }
                },
                PackageSubcommand::Inspect { name, version, syntax } => {
                    packages::inspect(name, version, syntax).map_err(|source| CliError::OtherError { source })?;
                },
                PackageSubcommand::List { latest } => {
                    packages::list(latest).map_err(|source| CliError::OtherError { source: anyhow::anyhow!(source) })?;
                },
                PackageSubcommand::Load { name, version } => {
                    packages::load(name, version).await.map_err(|source| CliError::OtherError { source })?;
                },
                PackageSubcommand::Pull { packages } => {
                    // Parse the NAME:VERSION pairs into a name and a version
                    if packages.is_empty() {
                        println!("Nothing to do.");
                        return Ok(());
                    }
                    let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
                    for package in &packages {
                        parsed.push(
                            SemVersion::from_package_pair(package)
                                .map_err(|source| CliError::PackagePairParseError { raw: package.into(), source })?,
                        );
                    }

                    // Now delegate the parsed pairs to the actual pull() function
                    registry::pull(parsed).await.map_err(|source| CliError::RegistryError { source })?;
                },
                PackageSubcommand::Push { packages } => {
                    // Parse the NAME:VERSION pairs into a name and a version
                    if packages.is_empty() {
                        println!("Nothing to do.");
                        return Ok(());
                    }
                    let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
                    for package in packages {
                        parsed.push(
                            SemVersion::from_package_pair(&package).map_err(|source| CliError::PackagePairParseError { raw: package, source })?,
                        );
                    }

                    // Now delegate the parsed pairs to the actual push() function
                    registry::push(parsed).await.map_err(|source| CliError::RegistryError { source })?;
                },
                PackageSubcommand::Remove { force, packages, docker_socket, client_version } => {
                    // Parse the NAME:VERSION pairs into a name and a version
                    if packages.is_empty() {
                        println!("Nothing to do.");
                        return Ok(());
                    }
                    let mut parsed: Vec<(String, SemVersion)> = Vec::with_capacity(packages.len());
                    for package in packages {
                        parsed.push(
                            SemVersion::from_package_pair(&package).map_err(|source| CliError::PackagePairParseError { raw: package, source })?,
                        );
                    }

                    // Now delegate the parsed pairs to the actual remove() function
                    packages::remove(force, parsed, DockerOptions { socket: docker_socket, version: client_version })
                        .await
                        .map_err(|source| CliError::PackageError { source })?;
                },
                PackageSubcommand::Test { name, version, show_result, docker_socket, client_version, keep_containers } => {
                    test::handle(name, version, show_result, DockerOptions { socket: docker_socket, version: client_version }, keep_containers)
                        .await
                        .map_err(|source| CliError::TestError { source })?;
                },
                PackageSubcommand::Search { term } => {
                    registry::search(term).await.map_err(|source| CliError::OtherError { source })?;
                },
                PackageSubcommand::Unpublish { name, version, force } => {
                    registry::unpublish(name, version, force).await.map_err(|source| CliError::OtherError { source })?;
                },
            }
        },
        Upgrade { subcommand } => {
            // Match the subcommand in question
            use UpgradeSubcommand::*;
            match subcommand {
                Data { path, dry_run, overwrite, version } => {
                    // Upgrade the file
                    upgrade::data(path, dry_run, overwrite, version).map_err(|source| CliError::UpgradeError { source })?;
                },
            }
        },
        Verify { subcommand } => {
            // Match the subcommand in question
            use VerifySubcommand::*;
            match subcommand {
                Config { infra } => {
                    // Verify the configuration
                    verify::config(infra).map_err(|source| CliError::VerifyError { source })?;
                    println!("OK");
                },
            }
        },
        Version { arch, local, remote } => {
            if local || remote {
                // If any of local or remote is given, do those
                if arch {
                    if local {
                        version::handle_local_arch().map_err(|source| CliError::VersionError { source })?;
                    }
                    if remote {
                        version::handle_remote_arch().await.map_err(|source| CliError::VersionError { source })?;
                    }
                } else {
                    if local {
                        version::handle_local_version().map_err(|source| CliError::VersionError { source })?;
                    }
                    if remote {
                        version::handle_remote_version().await.map_err(|source| CliError::VersionError { source })?;
                    }
                }
            } else {
                // Print neatly
                version::handle().await.map_err(|source| CliError::VersionError { source })?;
            }
        },
        Workflow { subcommand } => match subcommand {
            WorkflowSubcommand::Check { file, bakery, user, profile } => {
                check::handle(file, if bakery { Language::Bakery } else { Language::BraneScript }, user, profile)
                    .await
                    .map_err(|source| CliError::CheckError { source })?;
            },
            WorkflowSubcommand::Repl {
                proxy_addr,
                use_case,
                bakery,
                clear,
                remote,
                attach,
                profile,
                docker_socket,
                client_version,
                keep_containers,
            } => {
                repl::start(
                    proxy_addr,
                    remote,
                    use_case,
                    attach,
                    if bakery { Language::Bakery } else { Language::BraneScript },
                    clear,
                    profile,
                    DockerOptions { socket: docker_socket, version: client_version },
                    keep_containers,
                )
                .await
                .map_err(|source| CliError::ReplError { source })?;
            },
            WorkflowSubcommand::Run {
                proxy_addr,
                use_case,
                bakery,
                file,
                dry_run,
                remote,
                profile,
                docker_socket,
                client_version,
                keep_containers,
            } => {
                run::handle(
                    proxy_addr,
                    if bakery { Language::Bakery } else { Language::BraneScript },
                    use_case,
                    file,
                    dry_run,
                    remote,
                    profile,
                    DockerOptions { socket: docker_socket, version: client_version },
                    keep_containers,
                )
                .await
                .map_err(|source| CliError::RunError { source })?;
            },
        },
    }

    Ok(())
}
