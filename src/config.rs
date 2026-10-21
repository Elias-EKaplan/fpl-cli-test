//! On-disk config for fpl-cli. Stores only non-secret preferences (the default
//! FPL username, optionally a default account number, and passkey-login browser
//! settings) so day-to-day commands don't need `--username`/`--account` every
//! time. The password itself
//! never lands here — it lives in the OS keychain (see [`crate::secrets`]).
//! Storage and pathing come from `pk-cli-config`
//! (`${XDG_CONFIG_HOME:-~/.config}/fpl-cli/config.json`).

use pk_cli_config::ConfigStore;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// Existing installs keep their config dir name.
const APP_DIR: &str = "fpl-cli";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Default FPL login (email). Not a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Default FPL account number, if the user pinned one. Not a secret, but
    /// account-scoped, so we only write it when explicitly set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Persistent browser profile for `fpl auth login --passkey` (holds the
    /// browser's own state plus the saved FPL session). Default:
    /// `browser-profile/` beside this file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_profile_dir: Option<String>,
    /// Chrome/Chromium/Edge executable for passkey login (default: auto-detect).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_path: Option<String>,
    /// Seconds to wait for the passkey login to complete (default: 180).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_timeout: Option<u64>,
}

fn store() -> ConfigStore {
    ConfigStore::new(APP_DIR)
}

impl Config {
    pub fn load() -> Result<Config, AppError> {
        store().load()
    }

    /// The resolved config file path (for `fpl config path`).
    pub fn path() -> Result<std::path::PathBuf, AppError> {
        store().path()
    }

    pub fn save(&self) -> Result<(), AppError> {
        store().save(self)
    }

    /// Remove the config file entirely (used by `auth logout --forget`).
    pub fn clear() -> Result<bool, AppError> {
        store().clear()
    }
}
