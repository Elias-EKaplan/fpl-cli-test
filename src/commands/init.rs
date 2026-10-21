//! `fpl init` — flag-driven first-time setup. Verifies credentials and stores
//! the password in the keychain. Fully scriptable: the password enters via
//! `--password-stdin` or `--password-from-env`, never a flag value.

use serde_json::json;

use crate::cli::{AuthLoginArgs, InitArgs};
use crate::client::Fpl;
use crate::commands::{prompt_line, stdin_is_tty, Ctx, SERVICE};
use crate::config::Config;
use crate::error::AppError;
use crate::output;
use crate::secrets::{self, CredentialStore, Secret};

pub fn run_auth(ctx: &Ctx, args: &AuthLoginArgs) -> Result<(), AppError> {
    if args.passkey.passkey {
        return crate::commands::passkey::run(ctx, args);
    }
    if args.browser {
        open_fpl_login_page()?;
        if !ctx.cli.quiet {
            eprintln!(
                "opened FPL account login page in the default browser; browser session is not transferred to the CLI"
            );
        }
    }
    run(ctx, &args.init)
}

pub fn run(ctx: &Ctx, args: &InitArgs) -> Result<(), AppError> {
    let interactive = !args.non_interactive && stdin_is_tty();

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

    let password = ingest_password(args, &username, interactive)?;
    if password.is_empty() {
        return Err(AppError::Usage("empty password — nothing stored".into()));
    }

    if !args.overwrite && crate::commands::get_credential_migrating(&username)?.is_some() {
        return Err(AppError::Usage(format!(
            "a password for {username:?} is already stored — pass --overwrite to replace it"
        )));
    }
    let password_length = password.expose().chars().count();
    CredentialStore::new(SERVICE).set(&username, &password)?;

    let mut cfg = Config::load()?;
    cfg.username = Some(username.clone());
    cfg.save()?;

    let mut verified = false;
    if !args.no_verify {
        let fpl = Fpl::login(&username, &password)?;
        verified = true;
        if cfg.account.is_none() {
            if let Ok(list) = fpl.accounts() {
                if let Some(first) = list.first() {
                    cfg.account = Some(first.account_number.clone());
                }
            }
        }
    }
    if verified {
        cfg.save()?;
    }

    if !ctx.cli.quiet {
        match &cfg.account {
            Some(a) => eprintln!(
                "stored credentials for {username}; active account {a}; password length: {password_length} characters"
            ),
            None => eprintln!(
                "stored credentials for {username}; password length: {password_length} characters"
            ),
        }
    }
    if args.json || ctx.cli.json {
        output::json(&json!({
            "status": "ok",
            "username": username,
            "account": cfg.account,
            "verified": verified,
            "credential_length_chars": password_length,
        }));
    }
    Ok(())
}

fn open_fpl_login_page() -> Result<(), AppError> {
    const LOGIN_PAGE: &str = "https://www.fpl.com/my-account.html";

    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg(LOGIN_PAGE).status();

    #[cfg(all(unix, not(target_os = "macos")))]
    let status = std::process::Command::new("xdg-open")
        .arg(LOGIN_PAGE)
        .status();

    #[cfg(windows)]
    let status = std::process::Command::new("cmd")
        .args(["/C", "start", "", LOGIN_PAGE])
        .status();

    #[cfg(not(any(unix, windows)))]
    return Err(AppError::Other(
        "opening a browser is not supported on this platform".into(),
    ));

    let status = status
        .map_err(|error| AppError::Other(format!("could not open the FPL login page: {error}")))?;
    if !status.success() {
        return Err(AppError::Other(format!(
            "could not open the FPL login page (browser launcher exited with {status})"
        )));
    }
    Ok(())
}

fn ingest_password(args: &InitArgs, username: &str, interactive: bool) -> Result<Secret, AppError> {
    match (args.password_stdin, &args.password_from_env) {
        (true, Some(_)) => Err(AppError::Usage(
            "--password-stdin and --password-from-env are mutually exclusive".into(),
        )),
        (true, None) => secrets::read_stdin(),
        (false, Some(var)) => secrets::read_from_env(var),
        (false, None) if interactive => Secret::prompt(&format!("FPL password for {username}")),
        (false, None) => Err(AppError::Usage(
            "no password: pass --password-stdin or --password-from-env <VAR>".into(),
        )),
    }
}
