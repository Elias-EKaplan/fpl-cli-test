//! `fpl init` — flag-driven first-time setup. Verifies credentials and stores
//! the password in the keychain. Fully scriptable: the password enters via
//! `--password-stdin` or `--password-from-env`, never a flag value. With
//! `--mfa` it hands off to the browser login instead (see `passkey.rs`).

use serde_json::json;

use crate::cli::{AuthLoginArgs, InitArgs, PasskeyArgs};
use crate::client::Fpl;
use crate::commands::{prompt_line, stdin_is_tty, Ctx, SERVICE};
use crate::config::Config;
use crate::error::AppError;
use crate::output;
use crate::secrets::{self, CredentialStore, Secret};

pub fn run_auth(ctx: &Ctx, args: &AuthLoginArgs) -> Result<(), AppError> {
    if args.passkey.passkey || args.init.mfa {
        return crate::commands::passkey::run(ctx, &args.init, &args.passkey);
    }
    run(ctx, &args.init)
}

pub fn run(ctx: &Ctx, args: &InitArgs) -> Result<(), AppError> {
    if args.mfa {
        return crate::commands::passkey::run(ctx, args, &PasskeyArgs::default());
    }
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

pub(crate) fn ingest_password(
    args: &InitArgs,
    username: &str,
    interactive: bool,
) -> Result<Secret, AppError> {
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
