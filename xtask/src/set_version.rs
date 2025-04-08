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
// TODO: Maybe use the semver crate to ensure that the pre-release and metadata are well formatted
// This is not currently checked
pub fn set_version(semver: Option<String>, prerelease: Option<String>, metadata: Option<String>) -> anyhow::Result<()> {
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

    let metadata = match metadata {
        Some(m) => Some(m.replace("$git_hash", &get_git_hash()?[..8]).replace("$git_dirty", if get_git_dirty()? { ".dirty" } else { "" })),
        None => None,
    };

    let new_version = rewrite_version(version_str, semver.as_deref(), prerelease.as_deref(), metadata.as_deref());
    *version = new_version.into();

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

/// A rudimentary parser for the three semver sections
// TODO: Maybe this can be handled by the semver crate as well
fn parse_version(version_str: &str) -> (&str, Option<&str>, Option<&str>) {
    if let Some((semver, remainder)) = version_str.split_once('-') {
        if let Some((prerelease, metadata)) = remainder.split_once('+') {
            (semver, Some(prerelease), Some(metadata))
        } else {
            (semver, Some(remainder), None)
        }
    } else if let Some((semver, metadata)) = version_str.split_once('+') {
        (semver, None, Some(metadata))
    } else {
        (version_str, None, None)
    }
}

/// Alters the provided sections of the version string,
/// If a section is not provided it is not altered, if it is given an empty string, it will omit
/// the section entirely.
fn rewrite_version(version_str: &str, semver: Option<&str>, prerelease: Option<&str>, metadata: Option<&str>) -> String {
    let (semver_old, prerelease_old, metadata_old) = parse_version(version_str);

    let mut new_version = semver.unwrap_or(semver_old).to_owned();

    if let Some(prerelease) = prerelease.or(prerelease_old) {
        if !prerelease.is_empty() {
            new_version.push('-');
            new_version.push_str(prerelease);
        }
    }
    if let Some(metadata) = metadata.or(metadata_old) {
        if !metadata.is_empty() {
            new_version.push('+');
            new_version.push_str(metadata);
        }
    }

    new_version
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), ("1.2.3", None, None));
        assert_eq!(parse_version("1.2.3-nightly"), ("1.2.3", Some("nightly"), None));
        assert_eq!(parse_version("1.2.3-nightly+abcdef"), ("1.2.3", Some("nightly"), Some("abcdef")));
        assert_eq!(parse_version("1.2.3+abcdef"), ("1.2.3", None, Some("abcdef")));
        assert_eq!(parse_version("1.2.3-nightly-release"), ("1.2.3", Some("nightly-release"), None));
    }

    #[test]
    fn test_rewrite_version() {
        assert_eq!(rewrite_version("1.2.3", None, Some("nightly"), None), String::from("1.2.3-nightly"));
        assert_eq!(rewrite_version("1.2.3-nightly", None, Some("rc.1"), None), String::from("1.2.3-rc.1"));
        assert_eq!(rewrite_version("1.2.3-nightly+abcdef", None, Some("rc.1"), None), String::from("1.2.3-rc.1+abcdef"));
        assert_eq!(rewrite_version("1.2.3-nightly+abcdef", None, None, Some("123456")), String::from("1.2.3-nightly+123456"));
        assert_eq!(rewrite_version("1.2.3-nightly+abcdef", None, Some("rc.1"), Some("123456")), String::from("1.2.3-rc.1+123456"));
        assert_eq!(rewrite_version("1.2.3-nightly+abcdef", Some("2.0.0"), Some(""), Some("")), String::from("2.0.0"));
    }
}
