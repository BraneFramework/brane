//! Constants
//!
//! This file is a collection of constants that may be used throughout the Brane codebase
//! Using this file we can change defaults on various parts of the infrastructure without modifying
//! a whole bunch of files and inevitably missing one. Some examples of things that should be
//! stored in here are URLs to the documentation. These can change easily and it would be
//! unforunate if it would require more changes than one.

pub const BRANE_CENTRAL_PRX_PORT: u16 = 50050;
pub const BRANE_CENTRAL_API_PORT: u16 = 50051;
pub const BRANE_CENTRAL_PLR_PORT: u16 = 50052;
pub const BRANE_CENTRAL_DRV_PORT: u16 = 50053;

pub const BRANE_WORKER_PRX_PORT: u16 = 50150;
pub const BRANE_WORKER_REG_PORT: u16 = 50151;
pub const BRANE_WORKER_JOB_PORT: u16 = 50152;
pub const BRANE_WORKER_CHK_PORT: u16 = 50153;

pub const SCYLLA_PORT: u16 = 9042;

pub const BRANE_CENTRAL_PRX_NAME: &str = "brane-prx";
pub const BRANE_CENTRAL_API_NAME: &str = "brane-api";
pub const BRANE_CENTRAL_PLR_NAME: &str = "brane-plr";
pub const BRANE_CENTRAL_DRV_NAME: &str = "brane-drv";

// The only way this can be static path is using something lazy lock or lazy cell.
pub const CERTIFICATE_PATH: &str = "certs";
pub const PACKAGE_PATH: &str = "packages";

pub const NODE_HEADER: &str = indoc::indoc!("
    # This file defines the environment of the local node.
    # Edit this file to change service properties. Some require a restart
    # of the service (typically any 'ports' or 'topics' related setting), but most
    # will be reloaded dynamically by the services themselves.
");

pub const PROXY_HEADER: &str = indoc::indoc!("
    # This file defines the settings for the proxy service on this node.
    # This file is loaded eagerly, so changing it requires a restart of the proxy
    # service itself.
");

pub const INFRA_HEADER: &str = indoc::indoc!("
    # This file defines the nodes part of this Brane instance.
    # Edit this file to change the location of nodes and relevant services.
    # This file is loaded lazily, so changing it typically does not require a
    # restart.
");

pub const INFRA_CONFIG_URL: &str = "https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/infra.html";
pub const PROXY_CONFIG_URL: &str = "https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/proxy.html";
pub const CENTRAL_NODE_CONFIG_URL: &str = "https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/node.html";
pub const WORKER_NODE_CONFIG_URL: &str = "https://wiki.enablingpersonalizedinterventions.nl/user-guide/system-admins/docs/config/node.html";
