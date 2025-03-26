use std::env::VarError;

use strum::EnumIter;
use tracing::{debug, warn};

#[derive(Copy, Clone)]
pub enum ServiceKind {
    Central(CentralKind),
    Worker(WorkerKind),
}

static BRANE_LOG_VAR: &str = "BRANE_LOG";

impl ServiceKind {
    #[inline]
    pub fn to_service_name(&self) -> &'static str {
        match self {
            Self::Central(central_kind) => central_kind.to_service_name(),
            Self::Worker(worker_kind) => worker_kind.to_service_name(),
        }
    }

    #[inline]
    pub fn to_env_var(&self) -> &'static str {
        match self {
            Self::Central(central_kind) => central_kind.to_env_var(),
            Self::Worker(worker_kind) => worker_kind.to_env_var(),
        }
    }

    #[inline]
    pub fn log_env_var(&self) -> String { format!("{}_LOG", self.to_env_var()) }

    pub fn get_tracing_env_filter(&self) -> Option<String> {
        let log_var = self.log_env_var();

        match std::env::var(&log_var) {
            Ok(val) => return Some(val),
            Err(VarError::NotPresent) => debug!("Container specific log level was not set via {log_var}, checking `{BRANE_LOG_VAR}`"),
            Err(VarError::NotUnicode(_)) => warn!("Malformed log level set via `{log_var}`. Falling back to using `{BRANE_LOG_VAR}`"),
        };

        match std::env::var(BRANE_LOG_VAR) {
            Ok(val) => return Some(val),
            Err(VarError::NotPresent) => debug!("`{BRANE_LOG_VAR}` was not set, Continuing with default logging"),
            Err(VarError::NotUnicode(_)) => warn!("Malformed log level set using environment variable `{BRANE_LOG_VAR}`."),
        };

        None
    }
}

#[derive(EnumIter, Copy, Clone, Debug)]
pub enum CentralKind {
    Api,
    Drv,
    Plr,
    Prx,
}

impl CentralKind {
    #[inline]
    pub fn to_service_name(&self) -> &'static str {
        match self {
            Self::Api => "brane-api",
            Self::Drv => "brane-drv",
            Self::Plr => "brane-plr",
            Self::Prx => "brane-prx",
        }
    }

    #[inline]
    pub fn to_env_var(&self) -> &'static str {
        match self {
            Self::Api => "BRANE_API",
            Self::Drv => "BRANE_DRV",
            Self::Plr => "BRANE_PLR",
            Self::Prx => "BRANE_PRX",
        }
    }
}

#[derive(EnumIter, Copy, Clone, Debug)]
pub enum WorkerKind {
    Reg,
    Job,
    Chk,
    Prx,
}

impl WorkerKind {
    #[inline]
    pub fn to_service_name(&self) -> &'static str {
        match self {
            Self::Reg => "brane-reg",
            Self::Job => "brane-job",
            Self::Chk => "brane-chk",
            Self::Prx => "brane-prx",
        }
    }

    #[inline]
    pub fn to_env_var(&self) -> &'static str {
        match self {
            Self::Reg => "BRANE_REG",
            Self::Job => "BRANE_JOB",
            Self::Chk => "BRANE_CHK",
            Self::Prx => "BRANE_PRX",
        }
    }
}
