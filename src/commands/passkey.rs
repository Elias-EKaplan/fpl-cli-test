//! Browser sign-in: `fpl auth login --passkey` and `fpl init --mfa` /
//! `fpl auth login --mfa`.
//!
//! The browser does the login (see [`crate::browser`]): the WebAuthn ceremony
//! for a passkey, or the password form plus a one-time code the user enters
//! for MFA. This handler resolves the options, verifies the captured session
//! over plain HTTP, saves it (see [`crate::session`]), and records the username
//! and a default account like `fpl init` does. No password is stored: MFA reads
//! one (prompt, `--password-stdin`, or `--password-from-env`) only to type it
//! into FPL's login page.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use crate::browser::{self, LoginMethod, LoginOptions};
use crate::cli::{InitArgs, PasskeyArgs};
use crate::client::Fpl;
use crate::commands::{prompt_line, stdin_is_tty, Ctx};
use crate::config::Config;
use crate::error::AppError;
use crate::output;
use crate::session;

/// Effective login wait: flag, then config `browser_timeout`, then the
/// per-method default (longer for MFA).
fn resolve_timeout(flag: Option<u64>, configured: Option<u64>, mfa: bool) -> Duration {
    let default = if mfa {
        browser::DEFAULT_MFA_TIMEOUT_SECS
    } else {
        browser::DEFAULT_TIMEOUT_SECS
    };
    Duration::from_secs(flag.or(configured).filter(|s| *s > 0).unwrap_or(default))
}

/// The login page to open; only http(s) URLs are accepted.
fn resolve_login_url(flag: Option<&str>) -> Result<String, AppError> {
    match flag.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(browser::LOGIN_URL.to_string()),
        Some(u) if u.starts_with("https://") || u.starts_with("http://") => Ok(u.to_string()),
        Some(u) => Err(AppError::Usage(format!(
            "--login-url must be an http(s) URL, got {u:?}"
        ))),
    }
}

/// Run a browser login. `init.mfa` selects password + one-time code; otherwise
/// passkey. `p` carries the browser knobs (defaults for `fpl init --mfa`).
pub fn run(ctx: &Ctx, init: &InitArgs, p: &PasskeyArgs) -> Result<(), AppError> {
    let interactive = !init.non_interactive && stdin_is_tty();
    let username = match ctx
        .cli
        .username
        .clone()
        .or_else(|| ctx.cfg.username.clone())
    {
        Some(u) if !u.is_empty() => u,
        _ if interactive => prompt_line("FPL username (email)")?,
        _ => {
            return Err(AppError::Usage(
                "no username: pass --username or set $FPL_USERNAME".into(),
            ))
        }
    };

    let method = if init.mfa {
        let password = crate::commands::init::ingest_password(init, &username, interactive)?;
        if password.is_empty() {
            return Err(AppError::Usage(
                "empty password — nothing to sign in with".into(),
            ));
        }
        LoginMethod::Mfa(password)
    } else {
        LoginMethod::Passkey
    };
    let label = if init.mfa {
        "password + one-time code"
    } else {
        "a passkey"
    };

    let profile_dir = session::resolve_profile_dir(p.profile_dir.as_deref(), ctx.cfg)?;
    if p.reset_session && session::delete(&profile_dir)? && !ctx.cli.quiet {
        eprintln!("discarded the saved browser session");
    }
    let opts = LoginOptions {
        username: username.clone(),
        method,
        profile_dir: profile_dir.clone(),
        browser_path: p
            .browser_path
            .clone()
            .or_else(|| ctx.cfg.browser_path.clone())
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from),
        headless: p.headless,
        timeout: resolve_timeout(p.timeout, ctx.cfg.browser_timeout, init.mfa),
        reset: p.reset_session,
        login_url: resolve_login_url(p.login_url.as_deref())?,
        verbose: ctx.cli.verbose,
        quiet: ctx.cli.quiet,
    };

    let captured = browser::login(&opts)?;
    drop(opts);

    // Prove the captured session works over plain HTTP before keeping it.
    let fpl = Fpl::from_session(&captured)?;
    fpl.header().map_err(|e| {
        AppError::Auth(format!(
            "the browser sign-in finished, but FPL didn't accept the captured session ({e}) \
             — retry with --verbose, or --reset-session for a fresh sign-in"
        ))
    })?;
    session::save(&profile_dir, &captured)?;

    let mut cfg = Config::load()?;
    cfg.username = Some(username.clone());
    if cfg.account.is_none() {
        if let Ok(list) = fpl.accounts() {
            cfg.account = list.first().map(|a| a.account_number.clone());
        }
    }
    cfg.save()?;

    let session_path = session::session_path(&profile_dir);
    let expires_at = captured.expires_at();
    if !ctx.cli.quiet {
        eprintln!(
            "signed in as {username} with {label}; session saved to {}{}{}",
            session_path.display(),
            expires_at
                .as_deref()
                .map(|e| format!(" (expires {e})"))
                .unwrap_or_default(),
            cfg.account
                .as_deref()
                .map(|a| format!("; active account {a}"))
                .unwrap_or_default(),
        );
    }
    if init.json || ctx.cli.json {
        output::json(&json!({
            "status": "ok",
            "method": if init.mfa { "mfa" } else { "passkey" },
            "username": username,
            "account": cfg.account,
            "verified": true,
            "session_path": session_path,
            "expires_at": expires_at,
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_precedence() {
        assert_eq!(
            resolve_timeout(Some(30), Some(90), false),
            Duration::from_secs(30)
        );
        assert_eq!(
            resolve_timeout(None, Some(90), true),
            Duration::from_secs(90)
        );
        assert_eq!(resolve_timeout(None, None, false), Duration::from_secs(180));
        assert_eq!(
            resolve_timeout(None, Some(0), false),
            Duration::from_secs(180)
        );
        assert_eq!(resolve_timeout(None, None, true), Duration::from_secs(300));
        assert_eq!(
            resolve_timeout(Some(60), None, true),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn login_url_defaults_and_validates() {
        assert_eq!(resolve_login_url(None).unwrap(), browser::LOGIN_URL);
        assert_eq!(resolve_login_url(Some(" ")).unwrap(), browser::LOGIN_URL);
        assert_eq!(
            resolve_login_url(Some("http://127.0.0.1:8080/login")).unwrap(),
            "http://127.0.0.1:8080/login"
        );
        assert!(resolve_login_url(Some("javascript:alert(1)")).is_err());
        assert!(resolve_login_url(Some("file:///etc/passwd")).is_err());
    }
}
