//! The saved browser session from `fpl auth login --passkey`.
//!
//! A passkey login happens in a real browser (see [`crate::browser`]); what the
//! CLI keeps afterwards is the resulting FPL session — the `jwttoken` and the
//! `fpl.com` cookies — so ordinary commands can reuse it over plain HTTP
//! without launching a browser or prompting for a passkey again.
//!
//! The session lives in `fpl-session.json` inside the browser profile
//! directory. That directory already holds the same cookies in the browser's
//! own store, so keeping the session beside it doesn't widen what's on disk;
//! both are created owner-only (`0700` dir / `0600` file on Unix). This is a
//! short-lived session, not the password — the password stays keychain-only.
//! `SavedSession` deliberately has no `Debug` impl so it can't be logged.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pk_cli_auth::token;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::AppError;

/// File name of the saved session inside the profile directory.
pub const SESSION_FILE: &str = "fpl-session.json";
/// Default profile directory name, next to `config.json`.
const PROFILE_DIR_NAME: &str = "browser-profile";
/// Env override for the profile directory (also honored by every command).
pub const PROFILE_ENV: &str = "FPL_BROWSER_PROFILE";
const SESSION_VERSION: u32 = 1;

/// One `fpl.com` cookie captured from the browser.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    #[serde(default = "root_path")]
    pub path: String,
    #[serde(default)]
    pub secure: bool,
}

fn root_path() -> String {
    "/".into()
}

/// An authenticated FPL session captured from a browser login.
#[derive(Clone, Serialize, Deserialize)]
pub struct SavedSession {
    pub version: u32,
    /// The FPL login this session belongs to (not a secret).
    pub username: String,
    /// Unix seconds when the session was captured.
    pub saved_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<String>,
    #[serde(default)]
    pub cookies: Vec<SessionCookie>,
}

impl SavedSession {
    pub fn new(username: &str, jwt: Option<String>, cookies: Vec<SessionCookie>) -> Self {
        SavedSession {
            version: SESSION_VERSION,
            username: username.to_string(),
            saved_at: now_unix(),
            jwt: jwt.filter(|t| !t.is_empty()),
            cookies: cookies
                .into_iter()
                .filter(|c| is_fpl_domain(&c.domain) && !c.name.is_empty())
                .collect(),
        }
    }

    /// Whether the session's JWT says it has lapsed (with a minute of skew).
    /// A session without a readable expiry defers to the server.
    pub fn is_expired(&self, now: u64) -> bool {
        self.jwt
            .as_deref()
            .is_some_and(|t| token::is_expired(t, now, token::DEFAULT_SKEW_SECS))
    }

    /// RFC 3339 expiry from the JWT, when known.
    pub fn expires_at(&self) -> Option<String> {
        self.jwt.as_deref().and_then(token::expires_at)
    }

    /// Whether this session belongs to `username` (emails are case-insensitive).
    pub fn belongs_to(&self, username: &str) -> bool {
        self.username.eq_ignore_ascii_case(username)
    }

    /// A reqwest cookie jar pre-loaded with the captured cookies.
    pub fn jar(&self) -> Arc<reqwest::cookie::Jar> {
        let jar = reqwest::cookie::Jar::default();
        for c in &self.cookies {
            if let Ok(url) = cookie_url(c).parse::<reqwest::Url>() {
                jar.add_cookie_str(&set_cookie_str(c), &url);
            }
        }
        Arc::new(jar)
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `fpl.com` or any subdomain — never a lookalike such as `notfpl.com`.
pub fn is_fpl_domain(domain: &str) -> bool {
    let d = domain.trim_start_matches('.').to_ascii_lowercase();
    d == "fpl.com" || d.ends_with(".fpl.com")
}

/// The URL a cookie applies to, for seeding a jar.
fn cookie_url(c: &SessionCookie) -> String {
    let host = c.domain.trim_start_matches('.');
    let path = if c.path.starts_with('/') {
        c.path.as_str()
    } else {
        "/"
    };
    format!("https://{host}{path}")
}

/// Render a captured cookie as a `Set-Cookie` value. Host-only cookies (no
/// leading dot) keep their exact host by omitting `Domain`.
fn set_cookie_str(c: &SessionCookie) -> String {
    let mut s = format!("{}={}; Path={}", c.name, c.value, c.path);
    if c.domain.starts_with('.') {
        s.push_str(&format!("; Domain={}", c.domain.trim_start_matches('.')));
    }
    if c.secure {
        s.push_str("; Secure");
    }
    s
}

/// Expand a leading `~/` to the home directory.
fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

/// Pick the profile directory: explicit (flag / `$FPL_BROWSER_PROFILE`), then
/// config `browser_profile_dir`, then the default beside `config.json`.
pub fn pick_profile_dir(
    explicit: Option<&str>,
    configured: Option<&str>,
    default: PathBuf,
) -> PathBuf {
    explicit
        .filter(|s| !s.trim().is_empty())
        .or(configured.filter(|s| !s.trim().is_empty()))
        .map(|s| expand_home(s.trim()))
        .unwrap_or(default)
}

/// Resolve the profile directory for this invocation. `explicit` is the
/// `--profile-dir` value; when `None`, `$FPL_BROWSER_PROFILE` is consulted.
pub fn resolve_profile_dir(explicit: Option<&str>, cfg: &Config) -> Result<PathBuf, AppError> {
    let env = std::env::var(PROFILE_ENV).ok();
    let explicit = explicit.or(env.as_deref());
    let default = Config::path()?
        .parent()
        .map(|p| p.join(PROFILE_DIR_NAME))
        .ok_or_else(|| AppError::Other("could not resolve the config directory".into()))?;
    Ok(pick_profile_dir(
        explicit,
        cfg.browser_profile_dir.as_deref(),
        default,
    ))
}

pub fn session_path(profile_dir: &Path) -> PathBuf {
    profile_dir.join(SESSION_FILE)
}

/// Create the profile directory owner-only.
pub fn ensure_private_dir(dir: &Path) -> Result<(), AppError> {
    fs::create_dir_all(dir)
        .map_err(|e| AppError::Other(format!("creating {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Load the saved session for `username`, if there is a readable one. A
/// missing, unreadable, or other-user session is `None`.
pub fn load(profile_dir: &Path, username: &str) -> Option<SavedSession> {
    let text = fs::read_to_string(session_path(profile_dir)).ok()?;
    let s: SavedSession = serde_json::from_str(&text).ok()?;
    (s.version == SESSION_VERSION && s.belongs_to(username)).then_some(s)
}

/// Persist the session owner-only, replacing any previous one atomically.
pub fn save(profile_dir: &Path, session: &SavedSession) -> Result<(), AppError> {
    ensure_private_dir(profile_dir)?;
    let path = session_path(profile_dir);
    let tmp = profile_dir.join(format!("{SESSION_FILE}.tmp"));
    let body = serde_json::to_vec_pretty(session)
        .map_err(|e| AppError::Other(format!("serializing session: {e}")))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let write = |p: &Path| -> std::io::Result<()> {
        let mut f = opts.open(p)?;
        f.write_all(&body)?;
        f.sync_all()
    };
    write(&tmp)
        .and_then(|_| fs::rename(&tmp, &path))
        .map_err(|e| AppError::Other(format!("saving session to {}: {e}", path.display())))
}

/// Remove the saved session. Returns whether one existed.
pub fn delete(profile_dir: &Path) -> Result<bool, AppError> {
    let path = session_path(profile_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AppError::Other(format!("removing {}: {e}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(name: &str, domain: &str) -> SessionCookie {
        SessionCookie {
            name: name.into(),
            value: "v".into(),
            domain: domain.into(),
            path: "/".into(),
            secure: true,
        }
    }

    /// Unsigned JWT with the given claims JSON (signature is never checked).
    fn jwt(claims: &str) -> String {
        use base64::Engine;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims);
        format!("h.{b}.s")
    }

    #[test]
    fn fpl_domain_matching_rejects_lookalikes() {
        assert!(is_fpl_domain("fpl.com"));
        assert!(is_fpl_domain(".fpl.com"));
        assert!(is_fpl_domain("www.FPL.com"));
        assert!(!is_fpl_domain("notfpl.com"));
        assert!(!is_fpl_domain("fplmaps.com"));
        assert!(!is_fpl_domain("fpl.com.evil.example"));
    }

    #[test]
    fn new_session_keeps_only_fpl_cookies() {
        let s = SavedSession::new(
            "me@example.com",
            Some(String::new()),
            vec![
                cookie("a", ".fpl.com"),
                cookie("b", "tracker.example"),
                cookie("", "www.fpl.com"),
            ],
        );
        assert_eq!(s.cookies.len(), 1);
        assert_eq!(s.cookies[0].name, "a");
        // An empty JWT is treated as absent.
        assert!(s.jwt.is_none());
    }

    #[test]
    fn set_cookie_str_handles_host_only_and_domain_cookies() {
        let host_only = cookie("sid", "www.fpl.com");
        assert_eq!(set_cookie_str(&host_only), "sid=v; Path=/; Secure");
        assert_eq!(cookie_url(&host_only), "https://www.fpl.com/");
        let domain = cookie("sid", ".fpl.com");
        assert_eq!(
            set_cookie_str(&domain),
            "sid=v; Path=/; Domain=fpl.com; Secure"
        );
        assert_eq!(cookie_url(&domain), "https://fpl.com/");
    }

    #[test]
    fn jar_sends_cookies_to_fpl() {
        use reqwest::cookie::CookieStore;
        let s = SavedSession::new(
            "me@example.com",
            None,
            vec![cookie("a", ".fpl.com"), cookie("b", "www.fpl.com")],
        );
        let url: reqwest::Url = "https://www.fpl.com/cs/customer/v1/resources/header"
            .parse()
            .unwrap();
        let header = s.jar().cookies(&url).unwrap();
        let h = header.to_str().unwrap();
        assert!(h.contains("a=v") && h.contains("b=v"), "{h}");
    }

    #[test]
    fn expiry_reads_jwt_and_defers_when_unknown() {
        let mut s = SavedSession::new("me@example.com", None, vec![]);
        assert!(!s.is_expired(u64::MAX / 2));
        s.jwt = Some(jwt(r#"{"exp":1000000}"#));
        assert!(s.is_expired(1_000_000));
        assert!(!s.is_expired(900_000));
        assert_eq!(s.expires_at().as_deref(), Some("1970-01-12T13:46:40Z"));
    }

    #[test]
    fn profile_dir_precedence() {
        let d = PathBuf::from("/default");
        assert_eq!(
            pick_profile_dir(Some("/flag"), Some("/cfg"), d.clone()),
            PathBuf::from("/flag")
        );
        assert_eq!(
            pick_profile_dir(None, Some("/cfg"), d.clone()),
            PathBuf::from("/cfg")
        );
        assert_eq!(pick_profile_dir(Some("  "), None, d.clone()), d);
        assert_eq!(pick_profile_dir(None, None, d.clone()), d);
    }

    #[test]
    fn save_load_delete_roundtrip_is_private_and_user_scoped() {
        let dir = std::env::temp_dir().join(format!(
            "fpl-session-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let s = SavedSession::new(
            "Me@Example.com",
            Some("t".into()),
            vec![cookie("a", ".fpl.com")],
        );
        save(&dir, &s).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(session_path(&dir))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let loaded = load(&dir, "me@example.com").expect("same user, any case");
        assert_eq!(loaded.jwt.as_deref(), Some("t"));
        assert_eq!(loaded.cookies.len(), 1);
        assert!(load(&dir, "other@example.com").is_none());
        assert!(delete(&dir).unwrap());
        assert!(!delete(&dir).unwrap());
        assert!(load(&dir, "me@example.com").is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
