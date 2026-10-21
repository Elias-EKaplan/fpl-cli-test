//! `fpl auth` — session and credential status.

use pk_cli_auth::{AuthMethod, AuthStatus};

use crate::cli::AuthCommand;
use crate::commands::Ctx;
use crate::config::Config;
use crate::error::AppError;
use crate::session;

pub fn run(ctx: &Ctx, cmd: &AuthCommand) -> Result<(), AppError> {
    match cmd {
        AuthCommand::Login(args) => crate::commands::init::run_auth(ctx, args),
        AuthCommand::SetCredential(args) => crate::commands::set_credential::run(ctx, args),
        AuthCommand::Status { json } => status(ctx, *json || ctx.cli.json),
        AuthCommand::Logout { forget } => logout(ctx, *forget),
    }
}

fn status(ctx: &Ctx, json_flag: bool) -> Result<(), AppError> {
    let username = ctx
        .cli
        .username
        .clone()
        .or_else(|| ctx.cfg.username.clone());
    let profile_dir = session::resolve_profile_dir(None, ctx.cfg)?;
    let saved = username
        .as_deref()
        .and_then(|u| session::load(&profile_dir, u));
    let password_length = match &username {
        // A keychain error mustn't hide a usable passkey session.
        Some(u) => match crate::commands::get_credential_migrating(u) {
            Ok(secret) => secret.map(|secret| secret.expose().chars().count()),
            Err(_) if saved.is_some() => None,
            Err(e) => return Err(e),
        },
        None => None,
    };
    let has_password = password_length.is_some();
    let account = ctx.cli.account.clone().or_else(|| ctx.cfg.account.clone());
    let session_valid = saved.as_ref().map(|s| !s.is_expired(session::now_unix()));

    let (authenticated, method) = match session_valid {
        Some(true) => (true, AuthMethod::BrowserSession),
        Some(false) if !has_password => (false, AuthMethod::BrowserSession),
        _ => (has_password, AuthMethod::Password),
    };
    let mut st = AuthStatus::new(true, authenticated, method);
    st.username = username;
    st.account = account;
    st.credential_in_keychain = Some(has_password);
    st.session_valid = session_valid;
    st.expires_at = saved.as_ref().and_then(|s| s.expires_at());
    st.emit(json_flag);
    if saved.is_some() && !json_flag {
        println!(
            "Passkey session: {}",
            session::session_path(&profile_dir).display()
        );
    }
    match (json_flag, password_length) {
        (false, Some(length)) => println!("Credential length: {length} characters"),
        (false, None) => println!("Credential length: unavailable"),
        (true, Some(length)) => {
            eprintln!("credential length: {length} characters (value not displayed)")
        }
        (true, None) => eprintln!("credential length: unavailable"),
    }
    Ok(())
}

fn logout(ctx: &Ctx, forget: bool) -> Result<(), AppError> {
    // Forgetting local credentials must work even when they are invalid.
    // Server-side logout is only useful when retaining the configured identity.
    if !forget {
        if let Ok(fpl) = ctx.connect() {
            let _ = fpl.logout();
        }
    }

    let profile_dir = session::resolve_profile_dir(None, ctx.cfg)?;
    let removed_session = session::delete(&profile_dir)?;

    let mut removed = false;
    if let Some(u) = ctx
        .cli
        .username
        .clone()
        .or_else(|| ctx.cfg.username.clone())
    {
        removed = crate::commands::delete_credential(&u)?;
    }
    if forget {
        Config::clear()?;
    }
    if !ctx.cli.quiet {
        let cleared: Vec<&str> = [
            (removed, "stored password"),
            (removed_session, "saved passkey session"),
        ]
        .iter()
        .filter(|(done, _)| *done)
        .map(|(_, what)| *what)
        .collect();
        if cleared.is_empty() {
            eprintln!("logged out");
        } else {
            eprintln!("logged out and cleared {}", cleared.join(" and "));
        }
    }
    Ok(())
}
