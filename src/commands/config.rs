//! `fpl config` — the piekstra-cli/1 standard `config path|show|set|unset`
//! surface over the non-secret settings (`username`, `account`, and the
//! passkey-login `browser_profile_dir` / `browser_path` / `browser_timeout`). The password
//! is deliberately not a config key — it lives in the OS keychain
//! (`fpl set-credential`).

use crate::cli::ConfigCommand;
use crate::commands::Ctx;
use crate::config::Config;
use crate::error::AppError;
use crate::output;

pub fn run(ctx: &Ctx, cmd: &ConfigCommand) -> Result<(), AppError> {
    match cmd {
        ConfigCommand::Path => {
            println!("{}", Config::path()?.display());
            Ok(())
        }
        ConfigCommand::Show => {
            let v = serde_json::to_value(Config::load()?).unwrap_or_default();
            output::emit(ctx.cli.json, &v, output::render);
            Ok(())
        }
        ConfigCommand::Set { key, value } => set(key, Some(value)),
        ConfigCommand::Unset { key } => set(key, None),
    }
}

/// Set (or, with `value: None`, clear) one config key and persist the file.
/// Loads the on-disk config so transient CLI overrides aren't written back.
fn set(key: &str, value: Option<&str>) -> Result<(), AppError> {
    let mut cfg = Config::load()?;
    apply_key(&mut cfg, key, value)?;
    cfg.save()
}

/// Apply one key/value to a [`Config`] in memory, validating the key. Pure
/// (no IO) so it's unit-testable.
fn apply_key(cfg: &mut Config, key: &str, value: Option<&str>) -> Result<(), AppError> {
    match key {
        "username" => cfg.username = value.map(String::from),
        "account" => cfg.account = value.map(String::from),
        "browser_profile_dir" => cfg.browser_profile_dir = value.map(String::from),
        "browser_path" => cfg.browser_path = value.map(String::from),
        "browser_timeout" => {
            cfg.browser_timeout = value
                .map(|v| match v.trim().parse::<u64>() {
                    Ok(n) if n > 0 => Ok(n),
                    _ => Err(AppError::Usage(format!(
                        "browser_timeout must be a positive number of seconds, got {v:?}"
                    ))),
                })
                .transpose()?
        }
        other => {
            return Err(AppError::Usage(format!(
                "unknown config key {other:?} (settable: username, account, \
                 browser_profile_dir, browser_path, browser_timeout)"
            )))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_key_sets_clears_and_validates() {
        let mut cfg = Config::default();

        apply_key(&mut cfg, "username", Some("me@example.com")).unwrap();
        assert_eq!(cfg.username.as_deref(), Some("me@example.com"));
        apply_key(&mut cfg, "username", None).unwrap();
        assert_eq!(cfg.username, None);

        apply_key(&mut cfg, "account", Some("1234567890")).unwrap();
        assert_eq!(cfg.account.as_deref(), Some("1234567890"));
        apply_key(&mut cfg, "account", None).unwrap();
        assert_eq!(cfg.account, None);

        apply_key(&mut cfg, "browser_profile_dir", Some("/tmp/fpl-profile")).unwrap();
        assert_eq!(cfg.browser_profile_dir.as_deref(), Some("/tmp/fpl-profile"));
        apply_key(&mut cfg, "browser_path", Some("/usr/bin/chromium")).unwrap();
        assert_eq!(cfg.browser_path.as_deref(), Some("/usr/bin/chromium"));
        apply_key(&mut cfg, "browser_timeout", Some("300")).unwrap();
        assert_eq!(cfg.browser_timeout, Some(300));
        assert!(apply_key(&mut cfg, "browser_timeout", Some("0")).is_err());
        assert!(apply_key(&mut cfg, "browser_timeout", Some("soon")).is_err());
        assert_eq!(cfg.browser_timeout, Some(300));
        apply_key(&mut cfg, "browser_timeout", None).unwrap();
        assert_eq!(cfg.browser_timeout, None);

        // Unknown keys — and the password in particular — are usage errors.
        assert!(apply_key(&mut cfg, "password", Some("x")).is_err());
        assert!(apply_key(&mut cfg, "nope", Some("x")).is_err());
    }
}
