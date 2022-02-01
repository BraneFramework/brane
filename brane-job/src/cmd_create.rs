use crate::interface::{Command, Event, EventKind};
use anyhow::{Context, Result};
use bollard::container::{Config, CreateContainerOptions, StartContainerOptions};
use bollard::image::CreateImageOptions;
use bollard::models::HostConfig;
use bollard::Docker;
use brane_cfg::infrastructure::{Location, LocationCredentials};
use brane_cfg::{Infrastructure, Secrets};
use dashmap::lock::RwLock;
use dashmap::DashMap;
use futures_util::stream::TryStreamExt;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client as KubeClient, Config as KubeConfig};
use rand::distributions::Alphanumeric;
use rand::{self, Rng};
use serde_json::{json, Value as JValue};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::iter;
use std::sync::Arc;
use xenon::compute::{JobDescription, Scheduler};
use xenon::credentials::{CertificateCredential, Credential};
use xenon::storage::{FileSystem, FileSystemPath};

// Names of environment variables.
const BRANE_APPLICATION_ID: &str = "BRANE_APPLICATION_ID";
const BRANE_LOCATION_ID: &str = "BRANE_LOCATION_ID";
const BRANE_JOB_ID: &str = "BRANE_JOB_ID";
const BRANE_CALLBACK_TO: &str = "BRANE_CALLBACK_TO";
const BRANE_PROXY_ADDRESS: &str = "BRANE_PROXY_ADDRESS";
const BRANE_MOUNT_DFS: &str = "BRANE_MOUNT_DFS";

///
///
///
pub async fn handle(
    key: &str,
    mut command: Command,
    infra: Infrastructure,
    secrets: Secrets,
    xenon_endpoint: String,
    xenon_schedulers: Arc<DashMap<String, Arc<RwLock<Scheduler>>>>,
) -> Result<Vec<(String, Event)>> {
    let context = || format!("CREATE command failed or is invalid (key: {}).", key);

    debug!("Validating CREATE command...");
    validate_command(&command).with_context(context)?;
    let application = command.application.clone().unwrap();
    let correlation_id = command.identifier.clone().unwrap();
    let image = command.image.clone().unwrap();

    // Retreive location metadata and credentials.
    debug!("Retrieving location data...");
    let location_id = command.location.clone().unwrap();
    let location = infra.get_location_metadata(&location_id).with_context(context)?;

    /* TIM */
    // command.image = Some(format!("{}/library/{}", location.get_registry(), &image));
    command.image = Some(format!("{}", &image));
    /*******/

    // Generate job identifier.
    let job_id = format!("{}-{}", correlation_id, get_random_identifier());

    // Branch into specific handlers based on the location kind.
    match location {
        Location::Kube {
            address,
            callback_to,
            namespace,
            credentials,
            proxy_address,
            mount_dfs,
            ..
        } => {
            debug!("Executing command in Kubernetes environment...");
            let environment = construct_environment(
                &application,
                &location_id,
                &job_id,
                &callback_to,
                &proxy_address,
                &mount_dfs,
            )?;
            let credentials = credentials.resolve_secrets(&secrets);

            handle_k8s(command, &job_id, environment, address, namespace, credentials).await?
        }
        Location::Local {
            callback_to,
            network,
            proxy_address,
            mount_dfs,
            ..
        } => {
            debug!("Executing command locally with network '{}'...", network);
            let environment = construct_environment(
                &application,
                &location_id,
                &job_id,
                &callback_to,
                &proxy_address,
                &mount_dfs,
            )?;
            handle_local(command, &correlation_id, environment, network).await?
        }
        Location::Slurm {
            address,
            callback_to,
            runtime,
            credentials,
            proxy_address,
            mount_dfs,
            ..
        } => {
            debug!("Executing command using slurm...");
            let environment = construct_environment(
                &application,
                &location_id,
                &job_id,
                &callback_to,
                &proxy_address,
                &mount_dfs,
            )?;
            let credentials = credentials.resolve_secrets(&secrets);

            handle_slurm(
                command,
                &job_id,
                environment,
                address,
                runtime,
                credentials,
                xenon_endpoint,
                xenon_schedulers,
            )
            .await?
        }
        Location::Vm {
            address,
            callback_to,
            runtime,
            credentials,
            proxy_address,
            mount_dfs,
            ..
        } => {
            debug!("Executing command on Brane VM...");
            let environment = construct_environment(
                &application,
                &location_id,
                &job_id,
                &callback_to,
                &proxy_address,
                &mount_dfs,
            )?;
            let credentials = credentials.resolve_secrets(&secrets);

            handle_vm(
                command,
                &job_id,
                environment,
                address,
                runtime,
                credentials,
                xenon_endpoint,
                xenon_schedulers,
            )
            .await?
        }
    };

    info!(
        "Created job '{}' at location '{}' as part of application '{}'.",
        job_id, location_id, application
    );

    let order = 0; // A CREATE event is always the first, thus order=0.
    let key = format!("{}#{}", job_id, order);
    let category = String::from("job");
    let payload = image.into_bytes();
    let event = Event::new(
        EventKind::Created,
        job_id,
        application,
        location_id,
        category,
        order,
        Some(payload),
        None,
    );

    Ok(vec![(key, event)])
}

///
///
///
fn validate_command(command: &Command) -> Result<()> {
    ensure!(command.identifier.is_some(), "Identifier is not specified");
    ensure!(command.application.is_some(), "Application is not specified");
    ensure!(command.location.is_some(), "Location is not specified");
    ensure!(command.image.is_some(), "Image is not specified");

    Ok(())
}

///
///
///
fn construct_environment<S: Into<String>>(
    application_id: S,
    location_id: S,
    job_id: S,
    callback_to: S,
    proxy_address: &Option<String>,
    mount_dfs: &Option<String>,
) -> Result<HashMap<String, String>> {
    let mut environment = hashmap! {
        BRANE_APPLICATION_ID.to_string() => application_id.into(),
        BRANE_LOCATION_ID.to_string() => location_id.into(),
        BRANE_JOB_ID.to_string() => job_id.into(),
        BRANE_CALLBACK_TO.to_string() => callback_to.into(),
    };

    if let Some(proxy_address) = proxy_address {
        environment.insert(BRANE_PROXY_ADDRESS.to_string(), proxy_address.clone());
    }

    if let Some(mount_dfs) = mount_dfs {
        environment.insert(BRANE_MOUNT_DFS.to_string(), mount_dfs.clone());
    }

    Ok(environment)
}

///
///
///
async fn handle_k8s(
    command: Command,
    job_id: &str,
    environment: HashMap<String, String>,
    _address: String,
    namespace: String,
    credentials: LocationCredentials,
) -> Result<()> {
    // Create Kubernetes client based on config credentials
    let client = if let LocationCredentials::Config { file } = credentials {
        let config = construct_k8s_config(file).await?;
        KubeClient::try_from(config)?
    } else {
        bail!("Cannot create KubeClient from non-config credentials.");
    };

    let job_description = create_k8s_job_description(job_id, &command, environment)?;

    let jobs: Api<Job> = Api::namespaced(client.clone(), &namespace);
    let result = jobs.create(&PostParams::default(), &job_description).await;

    // Try again if job creation failed because of missing namespace.
    if let Err(error) = result {
        match error {
            kube::Error::Api(error) => {
                if error.message.starts_with("namespaces") && error.reason.as_str() == "NotFound" {
                    warn!(
                        "Failed to create k8s job because namespace '{}' didn't exist.",
                        namespace
                    );

                    // First create namespace
                    let namespaces: Api<Namespace> = Api::all(client.clone());
                    let new_namespace = create_k8s_namespace(&namespace)?;
                    let result = namespaces.create(&PostParams::default(), &new_namespace).await;

                    // Only try again if namespace creation succeeded.
                    if result.is_ok() {
                        info!("Created k8s namespace '{}'. Trying again to create k8s job.", namespace);
                        jobs.create(&PostParams::default(), &job_description).await?;
                    }
                }
            }
            _ => bail!(error),
        }
    }

    Ok(())
}

///
///
///
async fn construct_k8s_config(config_file: String) -> Result<KubeConfig> {
    let base64_symbols = ['+', '/', '='];

    // Remove any whitespace and/or newlines.
    let config_file: String = config_file
        .chars()
        .filter(|c| c.is_alphanumeric() || base64_symbols.contains(c))
        .collect();

    // Decode and parse as YAML.
    let config_file = String::from_utf8(base64::decode(config_file)?)?;
    let config_file: Kubeconfig = serde_yaml::from_str(&config_file)?;

    KubeConfig::from_custom_kubeconfig(config_file, &KubeConfigOptions::default())
        .await
        .context("Failed to construct Kubernetes configuration object.")
}

///
///
///
fn create_k8s_job_description(
    job_id: &str,
    command: &Command,
    environment: HashMap<String, String>,
) -> Result<Job> {
    let command = command.clone();
    let environment: Vec<JValue> = environment
        .iter()
        .map(|(k, v)| json!({ "name": k, "value": v }))
        .collect();

    // Kubernetes jobs require lowercase names
    let job_id = job_id.to_lowercase();

    let job_description = serde_json::from_value(json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_id,
        },
        "spec": {
            "backoffLimit": 3,
            "ttlSecondsAfterFinished": 120,
            "template": {
                "spec": {
                    "containers": [{
                        "name": job_id,
                        "image": command.image.expect("unreachable!"),
                        "args": command.command,
                        "env": environment,
                        "securityContext": {
                            "capabilities": {
                                "drop": ["all"],
                                "add": ["NET_BIND_SERVICE", "NET_ADMIN", "SYS_ADMIN"]
                            },
                            "privileged": true // Quickfix, needs to be dynamic based on capabilities/devices used.
                        }
                    }],
                    "restartPolicy": "Never",
                }
            }
        }
    }))?;

    Ok(job_description)
}

///
///
///
fn create_k8s_namespace(namespace: &str) -> Result<Namespace> {
    let namespace = serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": namespace,
        }
    }))?;

    Ok(namespace)
}

///
///
///
async fn handle_local(
    command: Command,
    job_id: &str,
    environment: HashMap<String, String>,
    network: String,
) -> Result<()> {
    let docker = Docker::connect_with_local_defaults()?;

    debug!("Ensuring docker image...");
    let image = command.image.expect("Empty `image` field on CREATE command.");
    ensure_image(&docker, &image).await?;

    debug!("Generating docker configuration...");
    let create_options = CreateContainerOptions { name: job_id };

    let host_config = HostConfig {
        auto_remove: Some(true),
        // NOTE: Enable when the job container is doing funky
        // auto_remove: Some(false),
        network_mode: Some(network),
        privileged: Some(true),
        ..Default::default()
    };

    let environment = environment
        .iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect();

    let create_config = Config {
        cmd: Some(command.command),
        env: Some(environment),
        host_config: Some(host_config),
        image: Some(image),
        ..Default::default()
    };

    // Create and start container
    debug!("Creating docker container...");
    docker.create_container(Some(create_options), create_config).await.context("Could not create docker container.")?;

    debug!("Starting docker container...");
    docker.start_container(job_id, None::<StartContainerOptions<String>>).await.context("Could not start docker container.")?;

    Ok(())
}

///
///
///
async fn ensure_image(
    docker: &Docker,
    image: &str,
) -> Result<()> {
    // Abort, if image is already loaded
    debug!("Checking if image '{}' already exists...", image);
    if docker.inspect_image(image).await.is_ok() {
        debug!("Image already exists in Docker deamon.");
        return Ok(());
    }

    debug!("Creating image options...");
    let options = Some(CreateImageOptions {
        from_image: image,
        ..Default::default()
    });

    debug!("Creating image with options '{:?}'...", options);
    docker.create_image(options, None, None).try_collect::<Vec<_>>().await.context("Could not create docker image.")?;

    Ok(())
}

///
///
///
#[allow(clippy::too_many_arguments)]
async fn handle_slurm(
    command: Command,
    job_id: &str,
    environment: HashMap<String, String>,
    address: String,
    runtime: String,
    credentials: LocationCredentials,
    xenon_endpoint: String,
    xenon_schedulers: Arc<DashMap<String, Arc<RwLock<Scheduler>>>>,
) -> Result<()> {
    let credentials = match credentials {
        LocationCredentials::SshCertificate {
            username,
            certificate,
            passphrase,
        } => Credential::new_certificate(certificate, username, passphrase.unwrap_or_default()),
        LocationCredentials::SshPassword { username, password } => Credential::new_password(username, password),
        LocationCredentials::Config { .. } => unreachable!(),
    };

    let location_id = environment
        .get(BRANE_LOCATION_ID)
        .expect("Expected 'location_id' as environment variable.");
    let scheduler = create_xenon_scheduler(
        location_id,
        "slurm",
        address,
        credentials,
        xenon_endpoint,
        xenon_schedulers,
    )
    .await?;
    handle_xenon(command, job_id, environment, runtime, scheduler).await
}

///
///
///
#[allow(clippy::too_many_arguments)]
async fn handle_vm(
    command: Command,
    job_id: &str,
    environment: HashMap<String, String>,
    address: String,
    runtime: String,
    credentials: LocationCredentials,
    xenon_endpoint: String,
    xenon_schedulers: Arc<DashMap<String, Arc<RwLock<Scheduler>>>>,
) -> Result<()> {
    debug!("Handling incoming VM job '{}'...", job_id);
    let credentials = match credentials {
        LocationCredentials::SshCertificate {
            username,
            certificate,
            passphrase,
        } => Credential::new_certificate(certificate, username, passphrase.unwrap_or_default()),
        LocationCredentials::SshPassword { username, password } => Credential::new_password(username, password),
        LocationCredentials::Config { .. } => unreachable!(),
    };

    let location_id = environment
        .get(BRANE_LOCATION_ID)
        .expect("Expected 'location_id' as environment variable.");
    let scheduler = create_xenon_scheduler(
        location_id,
        "ssh",
        address,
        credentials,
        xenon_endpoint,
        xenon_schedulers,
    )
    .await?;
    handle_xenon(command, job_id, environment, runtime, scheduler).await
}

///
///
///
async fn handle_xenon(
    command: Command,
    job_id: &str,
    environment: HashMap<String, String>,
    runtime: String,
    scheduler: Arc<RwLock<Scheduler>>,
) -> Result<()> {
    debug!("Handling incoming Xenon job '{}'...", job_id);
    let job_description = match runtime.to_lowercase().as_str() {
        "singularity" => create_singularity_job_description(&command, job_id, environment)?,
        "docker" => create_docker_job_description(&command, job_id, environment, None)?,
        _ => unreachable!(),
    };

    debug!("Scheduling job '{}' on Xenon...", job_id);
    let _job = scheduler.write().submit_batch_job(job_description).await?;
    debug!("Job complete.");

    Ok(())
}

///
///
///
async fn create_xenon_scheduler<S1, S2, S3>(
    location_id: &str,
    adaptor: S2,
    location: S1,
    credential: Credential,
    xenon_endpoint: S3,
    xenon_schedulers: Arc<DashMap<String, Arc<RwLock<Scheduler>>>>,
) -> Result<Arc<RwLock<Scheduler>>>
where
    S1: Into<String>,
    S2: Into<String>,
    S3: Into<String>,
{
    debug!("Creating Xenon scheduler...");
    if xenon_schedulers.contains_key(location_id) {
        let scheduler = xenon_schedulers.get(location_id).unwrap();
        let scheduler = scheduler.value();

        if scheduler.write().is_open().await? {
            return Ok(scheduler.clone());
        } else {
            xenon_schedulers.remove(location_id);
        }
    }

    let adaptor = adaptor.into();
    let location = location.into();
    let xenon_endpoint = xenon_endpoint.into();

    let properties = hashmap! {
        String::from("xenon.adaptors.schedulers.ssh.strictHostKeyChecking") => String::from("false")
    };

    // A SLURM scheduler requires the protocol scheme in the address.
    let location = if adaptor == *"slurm" {
        format!("ssh://{}", location)
    } else {
        location
    };

    let credential = if let Credential::Certificate(CertificateCredential {
        username,
        certificate,
        passphrase,
    }) = credential
    {
        let certificate = base64::decode(certificate.replace("\n", ""))?;

        let mut local = FileSystem::create_local(xenon_endpoint.clone()).await?;
        let certificate_file = format!("/keys/{}", get_random_identifier());

        let path = FileSystemPath::new(&certificate_file);
        local.write_to_file(certificate, &path).await?;

        Credential::new_certificate(certificate_file, username, passphrase)
    } else {
        credential
    };

    let scheduler = Scheduler::create(adaptor, location, credential, xenon_endpoint, Some(properties)).await?;
    xenon_schedulers.insert(location_id.to_string(), Arc::new(RwLock::new(scheduler)));

    let scheduler = xenon_schedulers.get(location_id).unwrap();
    let scheduler = scheduler.value().clone();

    Ok(scheduler)
}

///
///
///
fn create_docker_job_description(
    command: &Command,
    job_id: &str,
    environment: HashMap<String, String>,
    network: Option<String>,
) -> Result<JobDescription> {
    let command = command.clone();

    // Format: docker run [-v /source:/target] {image} {arguments}
    let executable = String::from("docker");
    let mut arguments = vec![
        String::from("run"),
        String::from("--rm"),
        String::from("--name"),
        job_id.to_string(),
        String::from("--privileged"),
        // String::from("ALL"),
        // String::from("--cap-add"),
        // String::from("NET_ADMIN"),
        // String::from("--cap-add"),
        // String::from("NET_BIND_SERVICE"),
        // String::from("--cap-add"),
        // String::from("NET_RAW"),
    ];

    // if environment.contains_key(BRANE_MOUNT_DFS) {
    //     arguments.push(String::from("--cap-add"));
    //     arguments.push(String::from("SYS_ADMIN"));
    //     arguments.push(String::from("--device"));
    //     arguments.push(String::from("/dev/fuse"));
    //     arguments.push(String::from("--security-opt"));
    //     arguments.push(String::from("apparmor:unconfined"));
    // }

    arguments.push(String::from("--network"));
    if let Some(network) = network {
        arguments.push(network);
        arguments.push(String::from("--hostname"));
        arguments.push(job_id.to_string());
    } else {
        arguments.push(String::from("host"));
    }

    // Add environment variables
    for (name, value) in environment {
        arguments.push(String::from("--env"));
        arguments.push(format!("{}={}", name, value));
    }

    // Add mount bindings
    for mount in command.mounts {
        arguments.push(String::from("-v"));
        arguments.push(format!("{}:{}", mount.source, mount.destination));
    }

    // Add image
    arguments.push(command.image.expect("unreachable!"));

    // Add command
    arguments.push(String::from("--debug"));
    arguments.extend(command.command);

    debug!("[job {}] arguments: {}", job_id, arguments.join(" "));
    debug!("[job {}] executable: {}", job_id, executable);

    let job_description = JobDescription {
        queue: Some(String::from("unlimited")),
        arguments: Some(arguments),
        executable: Some(executable),
        stdout: Some(format!("stdout-{}.txt", job_id)),
        stderr: Some(format!("stderr-{}.txt", job_id)),
        ..Default::default()
    };

    Ok(job_description)
}

///
///
///
fn create_singularity_job_description(
    command: &Command,
    job_id: &str,
    environment: HashMap<String, String>,
) -> Result<JobDescription> {
    let command = command.clone();

    // TODO: don't require sudo
    let executable = String::from("sudo");
    let mut arguments = vec![
        String::from("singularity"),
        String::from("run"),
        String::from("--nohttps"),
    ];

    if !environment.contains_key(BRANE_MOUNT_DFS) {
        arguments.push(String::from("--drop-caps"));
        arguments.push(String::from("ALL"));
        arguments.push(String::from("--add-caps"));
        arguments.push(String::from("CAP_NET_ADMIN,CAP_NET_BIND_SERVICE,CAP_NET_RAW"));
    }

    // Add environment variables
    for (name, value) in environment {
        arguments.push(String::from("--env"));
        arguments.push(format!("{}={}", name, value));
    }

    // Add mount bindings
    for mount in command.mounts {
        arguments.push(String::from("-B"));
        arguments.push(format!("{}:{}", mount.source, mount.destination));
    }

    // Add image
    arguments.push(format!("docker://{}", command.image.expect("unreachable!")));

    // Add command
    arguments.extend(command.command);

    let job_description = JobDescription {
        arguments: Some(arguments),
        executable: Some(executable),
        stdout: Some(format!("stdout-{}.txt", job_id)),
        stderr: Some(format!("stderr-{}.txt", job_id)),
        ..Default::default()
    };

    Ok(job_description)
}

///
///
///
fn get_random_identifier() -> String {
    let mut rng = rand::thread_rng();

    let identifier: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(10)
        .collect();

    identifier.to_lowercase()
}
