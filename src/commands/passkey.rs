//! `fpl auth login --passkey` — semi-automatic passkey sign-in.
//!
//! The browser does the WebAuthn ceremony (see [`crate::browser`]); this
//! handler resolves the options, verifies the captured session over plain
//! HTTP, saves it (see [`crate::session`]), and records the username and a
//! default account like `fpl init` does. No password is read or stored.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use crate::browser::{self, LoginOptions};
use crate::cli::AuthLoginArgs;
use crate::client::Fpl;
use crate::commands::{prompt_line, stdin_is_tty, Ctx};
use crate::config::Config;
use crate::error::AppError;
use crate::output;
use crate::session;

/// Effective login wait: flag, then config `browser_timeout`, then default.
fn resolve_timeout(flag: Option<u64>, configured: Option<u64>) -> Duration {
    Duration::from_secs(
        flag.or(configured)
            .filter(|s| *s > 0)
            .unwrap_or(browser::DEFAULT_TIMEOUT_SECS),
    )
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

pub fn run(ctx: &Ctx, args: &AuthLoginArgs) -> Result<(), AppError> {
    let p = &args.passkey;
    let interactive = !args.init.non_interactive && stdin_is_tty();
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

    let profile_dir = session::resolve_profile_dir(p.profile_dir.as_deref(), ctx.cfg)?;
    if p.reset_session && session::delete(&profile_dir)? && !ctx.cli.quiet {
        eprintln!("discarded the saved passkey session");
    }
    let opts = LoginOptions {
        username: username.clone(),
        profile_dir: profile_dir.clone(),
        browser_path: p
            .browser_path
            .clone()
            .or_else(|| ctx.cfg.browser_path.clone())
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from),
        headless: p.headless,
        timeout: resolve_timeout(p.timeout, ctx.cfg.browser_timeout),
        reset: p.reset_session,
        login_url: resolve_login_url(p.login_url.as_deref())?,
        verbose: ctx.cli.verbose,
        quiet: ctx.cli.quiet,
    };

    let captured = browser::login(&opts)?;

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
            "signed in as {username} with a passkey; session saved to {}{}{}",
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
    if args.init.json || ctx.cli.json {
        output::json(&json!({
            "status": "ok",
            "method": "passkey",
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
        assert_eq!(resolve_timeout(Some(30), Some(90)), Duration::from_secs(30));
        assert_eq!(resolve_timeout(None, Some(90)), Duration::from_secs(90));
        assert_eq!(
            resolve_timeout(None, None),
            Duration::from_secs(browser::DEFAULT_TIMEOUT_SECS)
        );
        assert_eq!(
            resolve_timeout(None, Some(0)),
            Duration::from_secs(browser::DEFAULT_TIMEOUT_SECS)
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
