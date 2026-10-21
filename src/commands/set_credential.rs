//! `fpl set-credential` — low-level single-secret keyring write for rotation
//! and headless provisioning. Secret enters via `--stdin` or `--from-env`
//! (exactly one); an existing entry is replaced only with `--overwrite`.

use serde_json::json;

use crate::cli::SetCredentialArgs;
use crate::commands::{Ctx, SERVICE};
use crate::config::Config;
use crate::error::AppError;
use crate::output;
use crate::secrets::{self, CredentialStore};

pub fn run(ctx: &Ctx, args: &SetCredentialArgs) -> Result<(), AppError> {
    let username = ctx.resolve_username()?;

    let secret = match (args.stdin, &args.from_env) {
        (true, Some(_)) => {
            return Err(AppError::Usage(
                "--stdin and --from-env are mutually exclusive".into(),
            ))
        }
        (true, None) => secrets::read_stdin()?,
        (false, Some(var)) => secrets::read_from_env(var)?,
        (false, None) => {
            return Err(AppError::Usage(
                "provide the secret via --stdin or --from-env <VAR>".into(),
            ))
        }
    };
    if secret.is_empty() {
        return Err(AppError::Usage("empty secret — nothing stored".into()));
    }

    let existed = crate::commands::get_credential_migrating(&username)?.is_some();
    if existed && !args.overwrite {
        return Err(AppError::Usage(format!(
            "a credential for {username:?} already exists — pass --overwrite to replace it"
        )));
    }
    let password_length = secret.expose().chars().count();
    CredentialStore::new(SERVICE).set(&username, &secret)?;

    // Remember the username so later commands default to it.
    if ctx.cfg.username.as_deref() != Some(username.as_str()) {
        let mut cfg = Config::load()?;
        cfg.username = Some(username.clone());
        cfg.save()?;
    }

    if !ctx.cli.quiet {
        eprintln!("stored password for {username} in the keychain ({password_length} characters)");
    }
    if args.json || ctx.cli.json {
        output::json(&json!({
            "status": "stored",
            "key": "password",
            "username": username,
            "overwritten": existed,
            "credential_length_chars": password_length,
        }));
    }
    Ok(())
}
