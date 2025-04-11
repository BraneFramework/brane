use std::process::Stdio;

use anyhow::Context as _;
use tracing::warn;

/// Sets the version of the current project to the provided version.
///
/// The supports the full semver version format.
///
/// # Arguments:
/// - semver: If provided updates the semver x.y.z portion of the version
/// - prerelease: If provided updates the prerelease portion of the version
/// - metadata: If provided udpates the metadata portion of the version
pub fn set_version(
    semver: Option<semver::Version>,
    prerelease: Option<semver::Prerelease>,
    metadata: Option<SpecialBuildMetadata>,
) -> anyhow::Result<()> {
    warn!("set_version can restructure your Cargo.toml. Handle with care.");
    let mut table = std::fs::read_to_string("Cargo.toml").context("Could not read Cargo.toml")?.parse::<toml::Table>()?;
    let version = table
        .get_mut("workspace")
        .context("Could not find field 'workspace' in Cargo.toml")?
        .get_mut("package")
        .context("Could not find field 'workspace.package' in Cargo.toml")?
        .get_mut("version")
        .context("Could not find field 'version' in workspace.package")?;
    let version_str = version.as_str().context("Could not convert package version to str")?;

    let metadata = metadata.map(|x| x.0);
    let new_version = rewrite_version(version_str, semver, prerelease, metadata)?;
    *version = new_version.to_string().into();

    std::fs::write("Cargo.toml", table.to_string()).context("Could not write to Cargo.toml")?;

    Ok(())
}

/// Gets the git hash of the project in the current directory
fn get_git_hash() -> anyhow::Result<String> {
    let bytes = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("Could not get latest git commit hash")?
        .stdout;

    String::from_utf8(bytes).context("Could not convert git hash to unicode string")
}

/// Checks if the current working tree is dirty or contains staged changes.
fn get_git_dirty() -> anyhow::Result<bool> {
    Ok(!std::process::Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("Could not determine whether working tree is dirty")?
        .status
        .success())
}

/// Alters the provided sections of the version string,
/// If a section is not provided it is not altered, if it is given an empty string, it will omit
/// the section entirely.
fn rewrite_version(
    version_str: &str,
    semver: Option<semver::Version>,
    prerelease: Option<semver::Prerelease>,
    metadata: Option<semver::BuildMetadata>,
) -> anyhow::Result<semver::Version> {
    let old_version = semver::Version::parse(version_str).context("Could not parse Cargo.toml version as semver")?;

    let mut new_version = semver::Version::new(old_version.major, old_version.minor, old_version.patch);

    if let Some(new_semver) = semver {
        if new_semver.pre != semver::Prerelease::EMPTY || new_semver.build != semver::BuildMetadata::EMPTY {
            anyhow::bail!("semver parameter may not contain prerelease or metadata");
        }
        new_version.major = new_semver.major;
        new_version.minor = new_semver.minor;
        new_version.patch = new_semver.patch;
    }

    new_version.pre = prerelease.unwrap_or(old_version.pre);
    new_version.build = metadata.unwrap_or(old_version.build);

    Ok(new_version)
}

#[derive(Clone, Debug)]
pub(crate) struct SpecialBuildMetadata(semver::BuildMetadata);

impl std::str::FromStr for SpecialBuildMetadata {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let replaced_version = s.replace("$git_hash", &get_git_hash()?[..8]).replace("$git_dirty", if get_git_dirty()? { ".dirty" } else { "" });
        Ok(Self(semver::BuildMetadata::new(&replaced_version)?))
    }
}
