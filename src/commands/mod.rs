//! Command handlers, one module per resource group. Shared session/account
//! resolution and prompt helpers live here on [`Ctx`].

pub mod accounts;
pub mod alerts;
pub mod api;
pub mod auth;
pub mod bills;
pub mod config;
pub mod documents;
pub mod history;
pub mod init;
pub mod lookup;
pub mod meter;
pub mod outages;
pub mod passkey;
pub mod payments;
pub mod profile;
pub mod set_credential;
pub mod summary;
pub mod update;
pub mod usage;

use std::io::{IsTerminal, Write};

use serde_json::Value;

use crate::cli::Cli;
use crate::client::Fpl;
use crate::config::Config;
use crate::error::AppError;
use crate::secrets::CredentialStore;
use crate::session;

/// Family keychain service name (SPEC v1: `piekstra.<bin>`).
pub const SERVICE: &str = "piekstra.fpl";
/// Pre-cli-common service name; entries are migrated on first read.
const LEGACY_SERVICE: &str = "fpl-cli";

/// Read a stored password, transparently migrating a legacy-service entry to
/// the family service name on first use.
pub fn get_credential_migrating(
    username: &str,
) -> Result<Option<crate::secrets::Secret>, AppError> {
    let store = CredentialStore::new(SERVICE);
    if let Some(s) = store.get(username)? {
        return Ok(Some(s));
    }
    let legacy = CredentialStore::new(LEGACY_SERVICE);
    if let Some(s) = legacy.get(username)? {
        store.set(username, &s)?;
        let _ = legacy.delete(username);
        return Ok(Some(s));
    }
    Ok(None)
}

/// Delete a stored password from both the family and legacy service names.
pub fn delete_credential(username: &str) -> Result<bool, AppError> {
    let a = CredentialStore::new(SERVICE).delete(username)?;
    let b = CredentialStore::new(LEGACY_SERVICE).delete(username)?;
    Ok(a || b)
}

/// `fpl info` — cli-info/v1 capability discovery.
pub fn info(_ctx: &Ctx) -> Result<(), AppError> {
    use pk_cli_core::info::{AuthInfo, CliInfo};
    let info = CliInfo::new(
        "fpl",
        env!("CARGO_PKG_VERSION"),
        "https://github.com/piekstra/fpl-cli",
        AuthInfo {
            required: true,
            method: "password".into(),
            login_hint: Some("fpl auth login".into()),
        },
        &[
            "summary",
            "accounts",
            "bills",
            "documents",
            "payments",
            "usage",
            "history",
            "outages",
            "lookup",
            "config",
            "api",
        ],
    )
    .with_profiles(&[pk_cli_utility::PROFILE, pk_cli_documents::PROFILE]);
    crate::output::json(&serde_json::to_value(&info).unwrap_or_default());
    Ok(())
}

/// Per-invocation context threaded to every command handler.
pub struct Ctx<'a> {
    pub cli: &'a Cli,
    pub cfg: &'a Config,
}

impl Ctx<'_> {
    pub fn resolve_username(&self) -> Result<String, AppError> {
        if let Some(u) = self.cli.username.clone().filter(|s| !s.is_empty()) {
            return Ok(u);
        }
        if let Some(u) = self.cfg.username.clone().filter(|s| !s.is_empty()) {
            return Ok(u);
        }
        Err(AppError::Auth(
            "no FPL username configured — run `fpl init` (or pass --username / set $FPL_USERNAME)"
                .into(),
        ))
    }

    fn debug(&self, msg: &str) {
        if self.cli.verbose && !self.cli.quiet {
            eprintln!("{msg}");
        }
    }

    /// Open an authenticated session. A saved passkey session (from `fpl auth
    /// login --passkey`) is reused when present; otherwise the password comes
    /// only from the keychain — `fpl init` / `fpl set-credential` put it there.
    pub fn connect(&self) -> Result<Fpl, AppError> {
        let username = self.resolve_username()?;
        let profile_dir = session::resolve_profile_dir(None, self.cfg)?;
        let password = match session::load(&profile_dir, &username) {
            Some(saved) => {
                // A keychain hiccup mustn't block a usable passkey session.
                let password = get_credential_migrating(&username).unwrap_or(None);
                if let Some(fpl) = self.resume(&saved, &username, password.is_some())? {
                    return Ok(fpl);
                }
                password
            }
            None => get_credential_migrating(&username)?,
        };
        let secret = password.ok_or_else(|| {
            AppError::Auth(format!(
                "no stored password or passkey session for {username:?} — run \
                 `fpl auth login --passkey`, `fpl init`, or `fpl set-credential --stdin`"
            ))
        })?;
        self.debug(&format!("logging in to FPL as {username}"));
        Fpl::login(&username, &secret)
    }

    /// Try a saved passkey session. With a password to fall back on, the
    /// session is probed first so a lapsed one quietly yields to the password
    /// login (`Ok(None)`); without one, the session is used as-is.
    fn resume(
        &self,
        saved: &session::SavedSession,
        username: &str,
        can_fall_back: bool,
    ) -> Result<Option<Fpl>, AppError> {
        if saved.is_expired(session::now_unix()) {
            if can_fall_back {
                self.debug("saved passkey session has expired; using the stored password");
                return Ok(None);
            }
            return Err(AppError::Auth(format!(
                "the saved passkey session for {username:?} has expired — run \
                 `fpl auth login --passkey`"
            )));
        }
        let fpl = Fpl::from_session(saved)?;
        if can_fall_back {
            match fpl.header() {
                Ok(_) => {}
                Err(AppError::Auth(_)) => {
                    self.debug("saved passkey session was rejected; using the stored password");
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
        self.debug(&format!("using the saved passkey session for {username}"));
        Ok(Some(fpl))
    }

    /// Resolve the account to act on: explicit positional, then global
    /// `--account`, then the active account in config, then the first account.
    pub fn resolve_account(&self, positional: Option<&str>, fpl: &Fpl) -> Result<String, AppError> {
        if let Some(a) = positional.filter(|s| !s.is_empty()) {
            return Ok(a.to_string());
        }
        if let Some(a) = self.cli.account.clone().filter(|s| !s.is_empty()) {
            return Ok(a);
        }
        if let Some(a) = self.cfg.account.clone().filter(|s| !s.is_empty()) {
            return Ok(a);
        }
        let list = fpl.accounts()?;
        list.into_iter()
            .next()
            .map(|a| a.account_number)
            .ok_or_else(|| {
                AppError::NotFound(
                    "no account found on this login — pass an account id or --account".into(),
                )
            })
    }
}

/// Premise, meter, and last-billed date (`MMDDYYYY`) from account detail —
/// needed by the usage and projected-bill endpoints.
pub struct AcctCtx {
    pub premise: String,
    pub meter: String,
    pub last_billed: String,
}

pub fn account_ctx(fpl: &Fpl, account: &str) -> Result<AcctCtx, AppError> {
    let detail = fpl.account_detail(account)?;
    let premise = Fpl::premise_of(&detail).ok_or_else(|| {
        AppError::NotFound("could not read the premise number from account detail".into())
    })?;
    let meter = detail_str(&detail, "meterNo").unwrap_or_default();
    let last_billed = detail_str(&detail, "currentBillDate")
        .and_then(|raw| mmddyyyy_from_raw(&raw))
        .ok_or_else(|| {
            AppError::NotFound("could not read the current bill date from account detail".into())
        })?;
    Ok(AcctCtx {
        premise,
        meter,
        last_billed,
    })
}

pub fn detail_str(detail: &Value, key: &str) -> Option<String> {
    let v = detail.pointer(&format!("/data/{key}"))?;
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// FPL bill dates arrive as `YYYY-MM-DD…` or `YYYYMMDD`; the usage and
/// projected-bill endpoints want `MMDDYYYY`.
pub fn mmddyyyy_from_raw(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 8 {
        return None;
    }
    let ymd = &digits[..8];
    Some(format!("{}{}{}", &ymd[4..6], &ymd[6..8], &ymd[0..4]))
}

/// Prompt for one line on a TTY (non-secret input, e.g. a username).
pub fn prompt_line(label: &str) -> Result<String, AppError> {
    if !stdin_is_tty() {
        return Err(AppError::Usage(format!(
            "{label} is required (run interactively or pass it as a flag)"
        )));
    }
    eprint!("{label}: ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| AppError::Other(format!("reading input: {e}")))?;
    let s = s.trim().to_string();
    if s.is_empty() {
        return Err(AppError::Usage(format!("{label} cannot be empty")));
    }
    Ok(s)
}

/// One-shot `y/N` safety confirmation. Reads from stdin.
pub fn confirm(prompt: &str) -> Result<bool, AppError> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| AppError::Other(format!("reading input: {e}")))?;
    Ok(matches!(s.trim().to_lowercase().as_str(), "y" | "yes"))
}

pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mmddyyyy_reformats() {
        assert_eq!(
            mmddyyyy_from_raw("2024-06-15T00:00:00").as_deref(),
            Some("06152024")
        );
        assert_eq!(mmddyyyy_from_raw("20240615").as_deref(), Some("06152024"));
        assert_eq!(mmddyyyy_from_raw("2024").as_deref(), None);
    }

    #[test]
    fn detail_reads_nested_fields() {
        let d = json!({ "data": { "meterNo": "ABC123", "premiseNumber": 42 } });
        assert_eq!(detail_str(&d, "meterNo").as_deref(), Some("ABC123"));
        assert_eq!(detail_str(&d, "premiseNumber").as_deref(), Some("42"));
        assert_eq!(detail_str(&d, "missing"), None);
    }
}
