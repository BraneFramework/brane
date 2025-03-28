use std::hash::Hash;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::utilities::create_dir_with_cachetag;

pub static REGISTRY: OnceLock<Registry> = OnceLock::new();

pub type BuildFunc = dyn Fn(BuildFuncInfo) -> anyhow::Result<()> + Sync + Send;

pub struct BuildFuncInfo {
    pub out_dir:     PathBuf,
    pub target_arch: String,
}

#[derive(Clone)]
pub struct Target {
    pub package_name: String,
    pub output_name:  String,

    pub platforms: Vec<(String, String)>,
    pub groups:    Vec<String>,

    pub build_command: Arc<BuildFunc>,
}

impl Hash for Target {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.package_name.hash(state);
        self.output_name.hash(state);
        self.platforms.hash(state);
        self.groups.hash(state);
    }
}

impl PartialEq for Target {
    // Implemented by hand to ignore build_command
    fn eq(&self, other: &Self) -> bool {
        self.package_name == other.package_name
            && self.output_name == other.output_name
            && self.platforms == other.platforms
            && self.groups == other.groups
    }
}

impl Eq for Target {}

impl Target {
    pub fn new(name: &str, output_name: &str, groups: &[&str], platforms: &[(&str, &str)], build_command: Arc<BuildFunc>) -> Self {
        Self {
            package_name: name.to_owned(),
            output_name: output_name.to_owned(),
            platforms: platforms.iter().map(|(x, y)| (x.to_string(), y.to_string())).collect(),
            groups: groups.iter().map(|x| x.to_string()).collect(),
            build_command,
        }
    }
}

pub struct Registry {
    targets: Vec<Target>,
}

impl Registry {
    pub fn new() -> Self { Self { targets: Default::default() } }

    pub fn register(&mut self, target: Target) { self.targets.push(target) }

    pub fn search(&self, name: impl Into<String>) -> impl Iterator<Item = Target> + '_ {
        let name = name.into();
        self.targets.iter().filter(move |target| target.package_name == name || target.groups.iter().any(|group| group == &name)).cloned()
    }

    pub fn search_for_system(&self, name: impl Into<String>, os: impl Into<String>, arch: impl Into<String>) -> impl Iterator<Item = Target> + '_ {
        let os = os.into();
        let arch = arch.into();
        self.search(name).filter(move |target| target.platforms.iter().any(|(a_os, a_arch)| a_os == &os && a_arch == &arch))
    }
}

pub fn build_registry() -> Registry {
    let mut registry = Registry::new();

    registry.register(Target::new(
        "brane-cc",
        "branec",
        &["all", "binaries"],
        &[("linux", "x86_64"), ("linux", "aarch64"), ("macos", "x86_64"), ("macos", "aarch64")],
        build_binary_builder("brane-cc"),
    ));

    registry.register(Target::new(
        "brane-cli",
        "brane",
        &["all", "binaries"],
        &[("linux", "x86_64"), ("linux", "aarch64"), ("macos", "aarch64"), ("macos", "x86_64"), ("windows", "x86_64")],
        build_binary_builder("brane-cli"),
    ));
    registry.register(Target::new(
        "brane-ctl",
        "branectl",
        &["all", "binaries"],
        &[("linux", "x86_64"), ("linux", "aarch64"), ("macos", "x86_64"), ("macos", "aarch64")],
        build_binary_builder("brane-ctl"),
    ));
    registry.register(Target::new(
        "brane-let",
        "branelet",
        &["all", "binaries"],
        &[("linux", "x86_64"), ("linux", "aarch64")],
        build_binary_builder("brane-let"),
    ));

    registry.register(Target::new(
        "brane-api",
        "brane-api.tar",
        &["all", "images", "central"],
        &[("linux", "x86_64")],
        build_image_builder("brane-api"),
    ));
    registry.register(Target::new(
        "brane-drv",
        "brane-drv.tar",
        &["all", "images", "central"],
        &[("linux", "x86_64")],
        build_image_builder("brane-drv"),
    ));
    registry.register(Target::new(
        "brane-plr",
        "brane-plr.tar",
        &["all", "images", "central"],
        &[("linux", "x86_64")],
        build_image_builder("brane-plr"),
    ));
    registry.register(Target::new(
        "brane-chk",
        "brane-chk.tar",
        &["all", "images", "worker"],
        &[("linux", "x86_64")],
        build_image_builder("brane-chk"),
    ));
    registry.register(Target::new(
        "brane-job",
        "brane-job.tar",
        &["all", "images", "worker"],
        &[("linux", "x86_64")],
        build_image_builder("brane-job"),
    ));
    registry.register(Target::new(
        "brane-reg",
        "brane-reg.tar",
        &["all", "images", "worker"],
        &[("linux", "x86_64")],
        build_image_builder("brane-reg"),
    ));
    registry.register(Target::new(
        "brane-prx",
        "brane-prx.tar",
        &["all", "images", "worker", "central"],
        &[("linux", "x86_64")],
        build_image_builder("brane-prx"),
    ));

    registry.register(Target::new(
        "brane-cli-c",
        "brane_cli",
        &["all", "library"],
        &[("linux", "x86_64"), ("macos", "x86_64"), ("macos", "aarch64"), ("windows", "x86_64")],
        build_binary_builder("brane-cli-c"),
    ));

    registry
}

pub fn build_image_builder(package: &str) -> Arc<BuildFunc> {
    let package = package.to_owned();

    Arc::new(move |info: BuildFuncInfo| {
        let image_dir = "./target/release";

        // Since this is not handled by cargo and we are "borrowing" its target directory, we need to
        // set it up ourselves
        let absolute_dir = info.out_dir;
        create_dir_with_cachetag(absolute_dir)?;

        let mut cmd = std::process::Command::new("docker");

        let x = cmd.args([
            "buildx",
            "build",
            "--output",
            &format!(r#"type=docker,dest={image_dir}/{package}.tar"#),
            "--file",
            "Dockerfile.rls",
            "--target",
            &package,
            ".",
        ]);

        println!("{x:?}");

        if !cmd.spawn()?.wait_with_output()?.status.success() {
            anyhow::bail!("{package} compilation process failed")
        }
        Ok(())
    })
}

pub fn build_binary_builder(package: &str) -> Arc<BuildFunc> {
    let package = package.to_owned();

    Arc::new(move |_info: BuildFuncInfo| {
        if !std::process::Command::new("cargo").args(["build", "--package", &package, "--release"]).spawn()?.wait_with_output()?.status.success() {
            anyhow::bail!("{package} compilation process failed")
        }

        Ok(())
    })
}
