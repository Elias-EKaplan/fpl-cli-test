//! Semi-automatic passkey login through a real browser.
//!
//! FPL's passkey login is WebAuthn: the server's challenge must be signed by an
//! authenticator the user controls (Touch ID, Windows Hello, a security key, or
//! a phone), so it can't be replayed or forged over plain HTTP — and this
//! module doesn't try. Instead it drives the user's own Chromium-family browser
//! (Chrome, Edge, Brave, Chromium) over the DevTools protocol:
//!
//! 1. Launch the browser with a **persistent profile** (`--user-data-dir`), so
//!    cookies, device trust, and any passkeys saved in that profile survive
//!    between runs.
//! 2. Open FPL's login page, fill the username, click "Continue", then "Log in
//!    with passkey" (backing out of any passkey *setup* screen). The browser
//!    shows its native passkey prompt; the user approves.
//!    If the page can't be automated, the user finishes signing in by hand.
//! 3. Watch for success: the `login.success` response from FPL's login API,
//!    or the tab landing on a `/my-account/…` page with an authenticated API
//!    call in flight.
//! 4. Capture the session (`jwttoken` + `fpl.com` cookies) and close the
//!    browser cleanly so the profile is flushed to disk.
//!
//! Nothing secret is ever logged: verbose network logging prints only the
//! method, status, and the URL with its query string removed. Header values,
//! cookies, response bodies, and WebAuthn payloads never reach stderr.

use std::collections::{HashSet, VecDeque};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tungstenite::{Message, WebSocket};

use crate::error::AppError;
use crate::session::{self, SavedSession, SessionCookie};

/// FPL's account login page (offers passkey, or email/password + one-time code).
pub const LOGIN_URL: &str = "https://www.fpl.com/my-account/login.html";
/// Default time allowed for the user to approve the passkey prompt.
pub const DEFAULT_TIMEOUT_SECS: u64 = 180;

const LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a success signal may stand without a captured JWT before the
/// session is taken as cookie-only.
const SETTLE_GRACE: Duration = Duration::from_secs(8);
const POLL_INTERVAL: Duration = Duration::from_millis(750);
/// After this long with no passkey button found, ask the user to finish by hand.
const MANUAL_HINT_AFTER: Duration = Duration::from_secs(15);
/// Minimum gap before repeating a Continue/Back click that didn't advance.
const STEP_RETRY: Duration = Duration::from_secs(4);
/// Cap on Continue and on Back clicks, so a page that loops can't trap us.
const MAX_STEP_CLICKS: u8 = 3;
const JWT_HEADER: &str = "jwttoken";

/// Inputs for one browser login.
pub struct LoginOptions {
    pub username: String,
    pub profile_dir: PathBuf,
    pub browser_path: Option<PathBuf>,
    pub headless: bool,
    pub timeout: Duration,
    /// Clear FPL cookies/storage in the profile first, forcing a fresh login.
    pub reset: bool,
    pub login_url: String,
    pub verbose: bool,
    pub quiet: bool,
}

impl LoginOptions {
    fn note(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{msg}");
        }
    }

    fn debug(&self, msg: &str) {
        if self.verbose && !self.quiet {
            eprintln!("[browser] {msg}");
        }
    }
}

/// Run the semi-automatic browser login and return the captured session.
pub fn login(opts: &LoginOptions) -> Result<SavedSession, AppError> {
    let exe = find_browser(opts.browser_path.as_deref())?;
    session::ensure_private_dir(&opts.profile_dir)?;
    opts.debug(&format!("launching {}", exe.display()));
    opts.debug(&format!("profile {}", opts.profile_dir.display()));
    if opts.headless {
        opts.note(
            "headless mode: passkey prompts can't be shown, so this only succeeds \
             when the browser profile is still signed in to FPL",
        );
    }

    let mut browser = Browser::launch(&exe, &opts.profile_dir, opts.headless)?;
    let result = (|| {
        let mut cdp = Cdp::connect(&browser.page_ws_url()?)?;
        cdp.call("Network.enable", json!({}))?;
        cdp.call("Page.enable", json!({}))?;
        if opts.reset {
            opts.debug("clearing FPL cookies and site data in the profile");
            let _ = cdp.call("Network.clearBrowserCookies", json!({}));
            for origin in ["https://www.fpl.com", "https://fpl.com"] {
                let _ = cdp.call(
                    "Storage.clearDataForOrigin",
                    json!({ "origin": origin, "storageTypes": "all" }),
                );
            }
        }
        cdp.call("Page.navigate", json!({ "url": opts.login_url }))?;
        opts.note("opened the FPL login page in the browser window");
        let jwt = wait_for_login(&mut cdp, opts)?;
        let cookies = parse_cookies(&cdp.call(
            "Network.getCookies",
            json!({ "urls": ["https://www.fpl.com/", "https://fpl.com/"] }),
        )?);
        let jwt = jwt.or_else(|| jwt_from_cookies(&cookies));
        opts.debug(&format!(
            "captured {} cookie(s){}",
            cookies.len(),
            if jwt.is_some() {
                " and a session token"
            } else {
                ""
            }
        ));
        Ok(SavedSession::new(&opts.username, jwt, cookies))
    })();
    browser.close();
    result
}

// ---- Success detection (pure; unit-tested) ---------------------------------

/// Split an absolute http(s) URL into lowercase host and path (no query or
/// fragment).
fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest[..host_end].to_ascii_lowercase();
    let after = &rest[host_end..];
    let path_end = after.find(['?', '#']).unwrap_or(after.len());
    let path = match &after[..path_end] {
        "" => "/".to_string(),
        p => p.to_string(),
    };
    Some((host, path))
}

fn is_fpl_host(host: &str) -> bool {
    session::is_fpl_domain(host.split(':').next().unwrap_or(host))
}

/// Whether the tab is on a signed-in FPL account page (`/my-account/…`, not
/// the login, registration, or recovery pages).
pub fn is_account_url(url: &str) -> bool {
    let Some((host, path)) = split_url(url) else {
        return false;
    };
    let path = path.to_ascii_lowercase();
    is_fpl_host(&host)
        && path.starts_with("/my-account/")
        && !["login", "logout", "register", "forgot", "reset", "passkey"]
            .iter()
            .any(|w| path.contains(w))
}

/// Whether a request URL is one of FPL's login API calls (passkey challenge /
/// assertion, password login, …) whose response can carry `login.success`.
fn is_login_api(url: &str) -> bool {
    let Some((host, path)) = split_url(url) else {
        return false;
    };
    let path = path.to_ascii_lowercase();
    is_fpl_host(&host)
        && path.starts_with("/cs/")
        && path.contains("login")
        && !path.contains("logout")
}

/// Whether a login API response body reports success
/// (`{"message":{"code":"login.success",…}}` in the passkey flow).
pub fn is_login_success_body(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    [
        "/message/code",
        "/code",
        "/messageCode",
        "/data/message/code",
    ]
    .iter()
    .filter_map(|p| v.pointer(p).and_then(|c| c.as_str()))
    .any(|c| c.eq_ignore_ascii_case("login.success"))
}

/// A URL safe to print: scheme, host, and path only — the query string and
/// fragment (which can carry tokens or codes) are dropped.
pub fn redact_url(url: &str) -> String {
    match split_url(url) {
        Some((host, path)) => {
            let scheme = if url.starts_with("http://") {
                "http"
            } else {
                "https"
            };
            let q = if url[scheme.len() + 3..].contains(['?', '#']) {
                "?…"
            } else {
                ""
            };
            format!("{scheme}://{host}{path}{q}")
        }
        None => "<non-http url>".into(),
    }
}

/// Case-insensitive header lookup on a DevTools headers object.
fn header_value<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
    headers
        .as_object()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_str())
}

/// Shape check only (three non-empty base64url segments) — never verified.
fn looks_like_jwt(t: &str) -> bool {
    let parts: Vec<&str> = t.split('.').collect();
    t.len() > 20
        && parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=' | b'+' | b'/')
                })
        })
}

/// The session JWT from a captured `jwttoken` cookie, if FPL set one.
fn jwt_from_cookies(cookies: &[SessionCookie]) -> Option<String> {
    cookies
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(JWT_HEADER) && looks_like_jwt(&c.value))
        .map(|c| c.value.clone())
}

/// DevTools `Network.getCookies` result → session cookies (FPL domains only).
fn parse_cookies(result: &Value) -> Vec<SessionCookie> {
    result
        .get("cookies")
        .and_then(|c| c.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|c| {
                    Some(SessionCookie {
                        name: c.get("name")?.as_str()?.to_string(),
                        value: c.get("value")?.as_str()?.to_string(),
                        domain: c.get("domain")?.as_str()?.to_string(),
                        path: c
                            .get("path")
                            .and_then(|p| p.as_str())
                            .unwrap_or("/")
                            .to_string(),
                        secure: c.get("secure").and_then(|s| s.as_bool()).unwrap_or(false),
                    })
                })
                .filter(|c| session::is_fpl_domain(&c.domain))
                .collect()
        })
        .unwrap_or_default()
}

/// Folds DevTools events into the login signals.
#[derive(Default)]
struct LoginTracker {
    jwt: Option<String>,
    /// Request ids of login API calls.
    login_requests: HashSet<String>,
    /// Login API calls with a 2xx response, waiting for their body.
    awaiting_body: HashSet<String>,
    /// Finished 2xx login responses whose body should be checked.
    pending_bodies: Vec<String>,
    success_at: Option<Instant>,
    url: String,
    account_url_since: Option<Instant>,
    /// A login API call FPL rejected (status only), for a user hint.
    rejected_status: Option<u64>,
}

impl LoginTracker {
    fn capture_jwt(&mut self, headers: Option<&Value>) {
        if let Some(t) = headers.and_then(|h| header_value(h, JWT_HEADER)) {
            if looks_like_jwt(t) {
                self.jwt = Some(t.to_string());
            }
        }
    }

    fn set_url(&mut self, url: &str, now: Instant) {
        if url == self.url {
            return;
        }
        self.url = url.to_string();
        self.account_url_since = is_account_url(url).then_some(now);
    }

    fn mark_success(&mut self, now: Instant) {
        self.success_at.get_or_insert(now);
    }

    /// Apply one DevTools event. `log` receives redacted one-line summaries.
    fn on_event(&mut self, ev: &Value, now: Instant, log: &mut dyn FnMut(String)) {
        let method = ev.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let p = ev.get("params").cloned().unwrap_or(Value::Null);
        let id = p
            .get("requestId")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        match method {
            "Network.requestWillBeSent" => {
                let req = p.get("request").cloned().unwrap_or(Value::Null);
                let url = req.get("url").and_then(|u| u.as_str()).unwrap_or("");
                self.capture_jwt(req.get("headers"));
                if is_login_api(url) {
                    self.login_requests.insert(id);
                }
                if is_api_url(url) {
                    let m = req.get("method").and_then(|m| m.as_str()).unwrap_or("?");
                    log(format!("→ {m} {}", redact_url(url)));
                }
            }
            "Network.responseReceived" => {
                let resp = p.get("response").cloned().unwrap_or(Value::Null);
                let url = resp.get("url").and_then(|u| u.as_str()).unwrap_or("");
                let status = resp.get("status").and_then(|s| s.as_u64()).unwrap_or(0);
                self.capture_jwt(resp.get("headers"));
                if self.login_requests.contains(&id) {
                    if (200..300).contains(&status) {
                        self.awaiting_body.insert(id);
                    } else if status >= 400 {
                        self.rejected_status = Some(status);
                    }
                }
                if is_api_url(url) {
                    log(format!("← {status} {}", redact_url(url)));
                }
            }
            "Network.responseReceivedExtraInfo" | "Network.requestWillBeSentExtraInfo" => {
                self.capture_jwt(p.get("headers"));
            }
            "Network.loadingFinished" => {
                if self.awaiting_body.remove(&id) {
                    self.pending_bodies.push(id);
                }
            }
            "Network.loadingFailed" => {
                self.awaiting_body.remove(&id);
            }
            "Page.frameNavigated" => {
                let frame = p.get("frame").cloned().unwrap_or(Value::Null);
                if frame.get("parentId").is_none() {
                    if let Some(url) = frame.get("url").and_then(|u| u.as_str()) {
                        self.set_url(url, now);
                    }
                }
            }
            _ => {}
        }
    }

    /// Done when a success signal is backed by a captured JWT, or has stood
    /// long enough that the session is evidently cookie-only.
    fn is_done(&self, now: Instant) -> bool {
        let settled = |t: Option<Instant>| t.is_some_and(|t| now.duration_since(t) >= SETTLE_GRACE);
        let signal = self.success_at.is_some() || self.account_url_since.is_some();
        (signal && self.jwt.is_some())
            || settled(self.success_at)
            || settled(self.account_url_since)
    }
}

/// FPL JSON service calls worth a verbose log line.
fn is_api_url(url: &str) -> bool {
    split_url(url).is_some_and(|(host, path)| is_fpl_host(&host) && path.starts_with("/cs/"))
}

/// Which page actions the in-page helper may take on this poll.
#[derive(Clone, Copy, Debug, Default)]
struct StepPermits {
    /// Click "Log in with passkey" (the final step).
    passkey: bool,
    /// Submit the filled username with "Continue".
    continue_: bool,
    /// Leave a passkey *setup* screen with "Back".
    back: bool,
}

/// The in-page helper. FPL's login is a multi-step flow: enter the username,
/// press **Continue**, then press **Log in with passkey**. Other controls that
/// mention passkeys (the "Use passkey…" link, "Create/Set up passkey") start
/// passkey *registration*, so they are never clicked; if the page lands on a
/// setup screen anyway, the helper presses **Back**, which returns to the
/// passkey sign-in choice.
///
/// Returns a JSON string `{filled, hasField, hasPasskey, onSetup, clicked,
/// continued, wentBack}`. Heuristic on purpose — FPL's markup drifts — and
/// harmless when nothing matches: the user then finishes signing in by hand.
fn automation_script(username: &str, permits: StepPermits) -> String {
    let user = serde_json::to_string(username).unwrap_or_else(|_| "\"\"".into());
    let StepPermits {
        passkey,
        continue_,
        back,
    } = permits;
    format!(
        r#"(() => {{
  const user = {user};
  const allowPasskey = {passkey};
  const allowContinue = {continue_};
  const allowBack = {back};
  const visible = (el) => !!el && !el.disabled && el.getClientRects().length > 0
    && getComputedStyle(el).visibility !== 'hidden';
  const text = (el) => [el.innerText, el.value, el.getAttribute('aria-label'),
    el.getAttribute('title')].filter((x) => typeof x === 'string').join(' ')
    .replace(/\s+/g, ' ').trim();
  const meta = (el) => [el.id, typeof el.className === 'string' ? el.className : '']
    .join(' ');
  const out = {{ filled: false, hasField: false, hasPasskey: false, onSetup: false,
    clicked: false, continued: false, wentBack: false }};
  const controls = Array.from(document.querySelectorAll(
    'button, a, [role="button"], input[type="button"], input[type="submit"]')).filter(visible);
  const setupRe = /(create|set\s*-?\s*up|setting\s+up|register)\b[^.]{{0,20}}pass\s*-?key|pass\s*-?key[\s-]*(setup|registration)/i;

  const field = Array.from(document.querySelectorAll('input')).filter(visible).find((i) => {{
    const t = (i.getAttribute('type') || 'text').toLowerCase();
    if (!['text', 'email'].includes(t)) return false;
    return /user|email|login/i.test([i.name, i.id, i.autocomplete, i.placeholder,
      i.getAttribute('aria-label')].join(' '));
  }});
  if (field) {{
    out.hasField = true;
    if (user && !field.value) {{
      field.focus();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(field, user);
      for (const t of ['input', 'change', 'blur']) field.dispatchEvent(new Event(t, {{ bubbles: true }}));
      out.filled = true;
    }}
  }}

  // A passkey *setup* screen: setup controls or setup copy on show.
  out.onSetup = controls.some((c) => setupRe.test(text(c)))
    || setupRe.test((document.body && document.body.innerText) || '');

  // 1. The sign-in button itself — "Log in / Sign in with passkey" only.
  const passkeyBtn = controls.find((c) =>
    /(log\s*-?\s*in|sign\s*-?\s*in)\s+(with\s+)?(a\s+|your\s+)?pass\s*-?key/i.test(text(c))
    && !setupRe.test(text(c)) && !/setup|regist/i.test(meta(c)));
  if (passkeyBtn) {{
    out.hasPasskey = true;
    if (allowPasskey && !out.filled) {{ passkeyBtn.click(); out.clicked = true; }}
    return JSON.stringify(out);
  }}

  // 2. Landed on passkey setup: go back to the sign-in choice.
  if (out.onSetup) {{
    const backBtn = controls.find((c) => /^(go\s+)?back$/i.test(text(c)));
    if (backBtn && allowBack) {{ backBtn.click(); out.wentBack = true; }}
    return JSON.stringify(out);
  }}

  // 3. Username entered: press "Continue" to reach the passkey step.
  if (field && field.value && !out.filled) {{
    const cont = controls.find((c) => /^continue$/i.test(text(c)));
    if (cont && allowContinue) {{ cont.click(); out.continued = true; }}
  }}
  return JSON.stringify(out);
}})()"#
    )
}

/// Evaluate an expression in the page and return its string value.
fn eval_string(cdp: &mut Cdp, expr: &str) -> Option<String> {
    cdp.call(
        "Runtime.evaluate",
        json!({ "expression": expr, "returnByValue": true, "userGesture": true }),
    )
    .ok()?
    .pointer("/result/value")?
    .as_str()
    .map(String::from)
}

/// Drive the page and wait until a login success signal. Returns the JWT if
/// one was observed.
fn wait_for_login(cdp: &mut Cdp, opts: &LoginOptions) -> Result<Option<String>, AppError> {
    let started = Instant::now();
    let deadline = started + opts.timeout;
    let mut t = LoginTracker::default();
    let mut clicked = false;
    let mut filled_at: Option<Instant> = None;
    let mut stepped_at: Option<Instant> = None;
    let mut continues = 0u8;
    let mut backs = 0u8;
    let mut hinted_setup = false;
    let mut hinted_manual = false;
    let mut hinted_rejected = None;
    let mut last_poll: Option<Instant> = None;
    let mut log = |line: String| opts.debug(&line);

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(AppError::Auth(format!(
                "timed out after {}s waiting for the FPL login to finish — approve the \
                 passkey prompt in the browser window, or raise --timeout",
                opts.timeout.as_secs()
            )));
        }

        // Drain whatever events are ready (bounded so polling still happens).
        let drain_until = Instant::now() + Duration::from_millis(250);
        while Instant::now() < drain_until {
            match cdp.next_event(Duration::from_millis(100))? {
                Some(ev) => t.on_event(&ev, Instant::now(), &mut log),
                None => break,
            }
        }

        for id in std::mem::take(&mut t.pending_bodies) {
            let Ok(r) = cdp.call("Network.getResponseBody", json!({ "requestId": id })) else {
                continue;
            };
            let body = r.get("body").and_then(|b| b.as_str()).unwrap_or("");
            let body = if r.get("base64Encoded").and_then(|b| b.as_bool()) == Some(true) {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default()
            } else {
                body.to_string()
            };
            if is_login_success_body(&body) {
                opts.debug("FPL reported login.success");
                t.mark_success(Instant::now());
            }
        }

        if t.rejected_status.is_some()
            && hinted_rejected != t.rejected_status
            && t.success_at.is_none()
        {
            hinted_rejected = t.rejected_status;
            opts.note(&format!(
                "FPL rejected a login attempt (HTTP {}) — retry in the browser window",
                t.rejected_status.unwrap_or_default()
            ));
        }

        if last_poll.map_or(true, |p| p.elapsed() >= POLL_INTERVAL) {
            last_poll = Some(Instant::now());
            if let Some(href) = eval_string(cdp, "location.href") {
                t.set_url(&href, Instant::now());
            }
            let on_account = t.account_url_since.is_some();
            if !clicked && t.success_at.is_none() && !on_account {
                let since =
                    |at: Option<Instant>, d: Duration| at.map_or(true, |a| a.elapsed() >= d);
                let settled = since(filled_at, Duration::from_secs(1))
                    && since(stepped_at, Duration::from_secs(1));
                let step_ok = settled && since(stepped_at, STEP_RETRY);
                let permits = StepPermits {
                    passkey: settled,
                    continue_: step_ok && continues < MAX_STEP_CLICKS,
                    back: step_ok && backs < MAX_STEP_CLICKS,
                };
                let script = automation_script(&opts.username, permits);
                let state: Value = eval_string(cdp, &script)
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null);
                let flag = |k: &str| state.get(k).and_then(|v| v.as_bool()) == Some(true);
                if flag("filled") {
                    filled_at = Some(Instant::now());
                    opts.debug("filled the username field");
                }
                if flag("continued") {
                    continues += 1;
                    stepped_at = Some(Instant::now());
                    opts.debug("pressed Continue");
                }
                if flag("wentBack") {
                    backs += 1;
                    stepped_at = Some(Instant::now());
                    opts.debug("left the passkey setup screen with Back");
                }
                if flag("onSetup") && !flag("wentBack") && !hinted_setup && backs >= MAX_STEP_CLICKS
                {
                    hinted_setup = true;
                    opts.note(
                        "FPL keeps showing passkey setup — press Back, then \"Log in with \
                         passkey\" in the browser window",
                    );
                }
                if flag("clicked") {
                    clicked = true;
                    opts.note(
                        "requested passkey sign-in — approve the prompt (Touch ID, Windows \
                         Hello, security key, or phone) in the browser window",
                    );
                } else if !hinted_manual && started.elapsed() >= MANUAL_HINT_AFTER {
                    hinted_manual = true;
                    opts.note(
                        "couldn't find a passkey button automatically — finish signing in \
                         in the browser window (passkey, or password + one-time code); \
                         the CLI is watching for success",
                    );
                }
            }
        }

        if t.is_done(Instant::now()) {
            opts.debug(&format!("signed in (now at {})", redact_url(&t.url)));
            return Ok(t.jwt);
        }
    }
}

// ---- Browser process & DevTools transport ----------------------------------

/// Well-known install locations / names of Chromium-family browsers.
fn browser_candidates() -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut v: Vec<PathBuf> = Vec::new();
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        for app in [
            "Google Chrome",
            "Microsoft Edge",
            "Brave Browser",
            "Chromium",
        ] {
            let rel = format!("{app}.app/Contents/MacOS/{app}");
            v.push(Path::new("/Applications").join(&rel));
            if let Some(h) = &home {
                v.push(h.join("Applications").join(&rel));
            }
        }
    }
    #[cfg(windows)]
    {
        for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Some(base) = std::env::var_os(var).map(PathBuf::from) {
                for rel in [
                    r"Google\Chrome\Application\chrome.exe",
                    r"Microsoft\Edge\Application\msedge.exe",
                    r"BraveSoftware\Brave-Browser\Application\brave.exe",
                ] {
                    v.push(base.join(rel));
                }
            }
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        for name in [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "microsoft-edge-stable",
            "brave-browser",
        ] {
            for d in &dirs {
                v.push(d.join(name));
            }
        }
    }
    v
}

/// The browser to drive: an explicit path, else the first installed candidate.
pub fn find_browser(explicit: Option<&Path>) -> Result<PathBuf, AppError> {
    if let Some(p) = explicit {
        return if p.is_file() {
            Ok(p.to_path_buf())
        } else {
            Err(AppError::Usage(format!(
                "browser not found at {} (check --browser-path / $FPL_BROWSER)",
                p.display()
            )))
        };
    }
    browser_candidates()
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            AppError::Other(
                "no Chrome, Edge, Brave, or Chromium found — install one or pass \
                 --browser-path <EXE>"
                    .into(),
            )
        })
}

/// Command-line flags for the browser. The DevTools port is OS-assigned and
/// reported back through `DevToolsActivePort` in the profile directory.
fn launch_args(profile_dir: &Path, headless: bool) -> Vec<String> {
    let mut args = vec![
        format!("--user-data-dir={}", profile_dir.display()),
        "--remote-debugging-port=0".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
    ];
    if headless {
        args.push("--headless=new".to_string());
    }
    args.push("about:blank".to_string());
    args
}

/// `DevToolsActivePort` → (port, browser websocket path).
fn parse_devtools_active_port(contents: &str) -> Option<(u16, String)> {
    let mut lines = contents.lines();
    let port = lines.next()?.trim().parse().ok()?;
    let path = lines.next()?.trim().to_string();
    path.starts_with('/').then_some((port, path))
}

/// The first page target's websocket URL from `/json/list`.
fn pick_page_ws(list: &Value) -> Option<String> {
    list.as_array()?
        .iter()
        .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("page"))?
        .get("webSocketDebuggerUrl")?
        .as_str()
        .map(String::from)
}

struct Browser {
    child: Option<Child>,
    port: u16,
    browser_path: String,
}

impl Browser {
    fn launch(exe: &Path, profile_dir: &Path, headless: bool) -> Result<Browser, AppError> {
        let port_file = profile_dir.join("DevToolsActivePort");
        let _ = std::fs::remove_file(&port_file);
        let mut child = Command::new(exe)
            .args(launch_args(profile_dir, headless))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| AppError::Other(format!("could not start {}: {e}", exe.display())))?;
        let deadline = Instant::now() + LAUNCH_TIMEOUT;
        loop {
            if let Some((port, path)) = std::fs::read_to_string(&port_file)
                .ok()
                .and_then(|c| parse_devtools_active_port(&c))
            {
                return Ok(Browser {
                    child: Some(child),
                    port,
                    browser_path: path,
                });
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(AppError::Other(format!(
                    "the browser exited before it was ready ({status}) — if it's already \
                     open with this profile, close that window and retry"
                )));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AppError::Other(
                    "timed out waiting for the browser to start".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn page_ws_url(&self) -> Result<String, AppError> {
        let http = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| AppError::Other(format!("failed to build HTTP client: {e}")))?;
        let url = format!("http://127.0.0.1:{}/json/list", self.port);
        let deadline = Instant::now() + LAUNCH_TIMEOUT;
        loop {
            if let Some(ws) = http
                .get(&url)
                .send()
                .ok()
                .and_then(|r| r.json::<Value>().ok())
                .and_then(|v| pick_page_ws(&v))
            {
                return Ok(ws);
            }
            if Instant::now() >= deadline {
                return Err(AppError::Other(
                    "the browser didn't expose a page to automate".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Close gracefully (so the profile's cookies are flushed), then make sure
    /// the process is gone. Idempotent.
    fn close(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let ws = format!("ws://127.0.0.1:{}{}", self.port, self.browser_path);
        if let Ok(mut cdp) = Cdp::connect(&ws) {
            let _ = cdp.send("Browser.close", json!({}));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.close();
    }
}

/// A minimal synchronous DevTools-protocol connection to one target.
struct Cdp {
    ws: WebSocket<TcpStream>,
    next_id: u64,
    events: VecDeque<Value>,
}

fn browser_gone() -> AppError {
    AppError::Auth("the browser window was closed before the FPL login finished".into())
}

impl Cdp {
    fn connect(ws_url: &str) -> Result<Cdp, AppError> {
        let host_port = ws_url
            .strip_prefix("ws://")
            .and_then(|r| r.split('/').next())
            .filter(|h| h.starts_with("127.0.0.1:") || h.starts_with("localhost:"))
            .ok_or_else(|| AppError::Other("unexpected DevTools endpoint".into()))?;
        let stream = TcpStream::connect(host_port)
            .map_err(|e| AppError::Other(format!("connecting to the browser: {e}")))?;
        let _ = stream.set_read_timeout(Some(COMMAND_TIMEOUT));
        let (ws, _) = tungstenite::client(ws_url, stream)
            .map_err(|e| AppError::Other(format!("DevTools handshake failed: {e}")))?;
        let _ = ws
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(100)));
        Ok(Cdp {
            ws,
            next_id: 1,
            events: VecDeque::new(),
        })
    }

    fn send(&mut self, method: &str, params: Value) -> Result<u64, AppError> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "id": id, "method": method, "params": params }).to_string();
        self.ws
            .send(Message::text(msg))
            .map_err(|_| browser_gone())?;
        Ok(id)
    }

    /// Read one JSON message, or `None` if nothing arrives before `until`.
    fn read_one(&mut self, until: Instant) -> Result<Option<Value>, AppError> {
        loop {
            match self.ws.read() {
                Ok(Message::Text(t)) => {
                    if let Ok(v) = serde_json::from_str::<Value>(t.as_str()) {
                        return Ok(Some(v));
                    }
                }
                Ok(Message::Close(_)) => return Err(browser_gone()),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= until {
                        return Ok(None);
                    }
                }
                Err(_) => return Err(browser_gone()),
            }
        }
    }

    /// Send a command and wait for its result, queueing events seen meanwhile.
    fn call(&mut self, method: &str, params: Value) -> Result<Value, AppError> {
        let id = self.send(method, params)?;
        let until = Instant::now() + COMMAND_TIMEOUT;
        loop {
            let Some(v) = self.read_one(until)? else {
                return Err(AppError::Other(format!(
                    "the browser didn't answer {method} in time"
                )));
            };
            if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                if let Some(err) = v.get("error") {
                    let msg = err
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("error");
                    return Err(AppError::Other(format!("browser {method} failed: {msg}")));
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
            if v.get("method").is_some() {
                self.events.push_back(v);
            }
        }
    }

    /// The next queued or incoming event, waiting at most `wait`.
    fn next_event(&mut self, wait: Duration) -> Result<Option<Value>, AppError> {
        if let Some(ev) = self.events.pop_front() {
            return Ok(Some(ev));
        }
        let until = Instant::now() + wait;
        while let Some(v) = self.read_one(until)? {
            if v.get("method").is_some() {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JWT-shaped placeholder (not a real token).
    const JWT: &str = "placeholder-header.placeholder-claims.placeholder-sig";

    fn ev(method: &str, params: Value) -> Value {
        json!({ "method": method, "params": params })
    }

    #[test]
    fn account_urls_exclude_login_and_recovery_pages() {
        assert!(is_account_url(
            "https://www.fpl.com/my-account/residential.html"
        ));
        assert!(is_account_url(
            "https://www.fpl.com/my-account/account-landing.html?x=1#top"
        ));
        assert!(!is_account_url("https://www.fpl.com/my-account/login.html"));
        assert!(!is_account_url(
            "https://www.fpl.com/my-account/forgot-password.html"
        ));
        assert!(!is_account_url("https://www.fpl.com/my-account.html"));
        assert!(!is_account_url(
            "https://evil.example/my-account/residential.html"
        ));
        assert!(!is_account_url(
            "https://www.fpl.com.evil.example/my-account/x.html"
        ));
        assert!(!is_account_url("about:blank"));
    }

    #[test]
    fn login_api_matching() {
        assert!(is_login_api(
            "https://www.fpl.com/cs/customer/v3/login/public/passkeys/authentication"
        ));
        assert!(is_login_api(
            "https://www.fpl.com/cs/customer/v1/registration/loginAndUseMigration?view=LoginMini"
        ));
        assert!(!is_login_api(
            "https://www.fpl.com/cs/customer/v1/registration/logout"
        ));
        assert!(!is_login_api("https://www.fpl.com/my-account/login.html"));
        assert!(!is_login_api("https://other.example/cs/login"));
    }

    #[test]
    fn login_success_body_detection() {
        assert!(is_login_success_body(
            r#"{"message":{"code":"login.success","message":"Log in successful"}}"#
        ));
        assert!(is_login_success_body(r#"{"code":"LOGIN.SUCCESS"}"#));
        assert!(!is_login_success_body(
            r#"{"message":{"code":"login.failed"}}"#
        ));
        // A challenge (POST) response is not success, even if it mentions it.
        assert!(!is_login_success_body(r#"{"challenge":"login.success"}"#));
        assert!(!is_login_success_body("login.success"));
        assert!(!is_login_success_body(""));
    }

    #[test]
    fn redact_url_drops_query_and_fragment() {
        assert_eq!(
            redact_url("https://www.fpl.com/cs/x?token=abc#frag"),
            "https://www.fpl.com/cs/x?…"
        );
        assert_eq!(
            redact_url("https://www.fpl.com/cs/x"),
            "https://www.fpl.com/cs/x"
        );
        assert_eq!(redact_url("https://www.fpl.com"), "https://www.fpl.com/");
        assert_eq!(redact_url("data:text/plain,secret"), "<non-http url>");
    }

    #[test]
    fn devtools_port_file_and_target_parsing() {
        assert_eq!(
            parse_devtools_active_port("9222\n/devtools/browser/abc\n"),
            Some((9222, "/devtools/browser/abc".to_string()))
        );
        assert_eq!(parse_devtools_active_port("9222\n"), None);
        assert_eq!(parse_devtools_active_port("nope\n/x"), None);
        let list = json!([
            { "type": "service_worker", "webSocketDebuggerUrl": "ws://127.0.0.1:1/sw" },
            { "type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:1/devtools/page/P" }
        ]);
        assert_eq!(
            pick_page_ws(&list).as_deref(),
            Some("ws://127.0.0.1:1/devtools/page/P")
        );
        assert_eq!(pick_page_ws(&json!([])), None);
    }

    #[test]
    fn launch_args_use_persistent_profile_and_optional_headless() {
        let a = launch_args(Path::new("/tmp/prof"), false);
        assert!(a.contains(&"--user-data-dir=/tmp/prof".to_string()));
        assert!(a.contains(&"--remote-debugging-port=0".to_string()));
        assert!(!a.iter().any(|x| x.starts_with("--headless")));
        assert!(launch_args(Path::new("/tmp/prof"), true).contains(&"--headless=new".to_string()));
    }

    #[test]
    fn explicit_browser_path_must_exist() {
        assert!(matches!(
            find_browser(Some(Path::new("/definitely/not/a/browser"))),
            Err(AppError::Usage(_))
        ));
    }

    #[test]
    fn jwt_shape_and_cookie_fallback() {
        assert!(looks_like_jwt(JWT));
        assert!(!looks_like_jwt("null"));
        assert!(!looks_like_jwt("a.b.c"));
        assert!(!looks_like_jwt("aaaaaaaaaa..bbbbbbbbbbbb"));
        let cookies = parse_cookies(&json!({ "cookies": [
            { "name": "JWTTOKEN", "value": JWT, "domain": ".fpl.com", "path": "/", "secure": true },
            { "name": "other", "value": "x", "domain": "tracker.example" }
        ]}));
        assert_eq!(cookies.len(), 1, "non-FPL cookies are dropped");
        assert_eq!(jwt_from_cookies(&cookies).as_deref(), Some(JWT));
    }

    #[test]
    fn tracker_detects_passkey_login_success_from_network() {
        let mut t = LoginTracker::default();
        let mut lines = Vec::new();
        let mut log = |l: String| lines.push(l);
        let now = Instant::now();
        let url = "https://www.fpl.com/cs/customer/v3/login/public/passkeys/authentication";
        t.on_event(
            &ev(
                "Network.requestWillBeSent",
                json!({ "requestId": "1", "request": { "url": url, "method": "PUT", "headers": {} } }),
            ),
            now,
            &mut log,
        );
        t.on_event(
            &ev(
                "Network.responseReceived",
                json!({ "requestId": "1", "response": { "url": url, "status": 200,
                        "headers": { "JwtToken": JWT } } }),
            ),
            now,
            &mut log,
        );
        assert!(t.pending_bodies.is_empty());
        t.on_event(
            &ev("Network.loadingFinished", json!({ "requestId": "1" })),
            now,
            &mut log,
        );
        assert_eq!(t.pending_bodies, vec!["1".to_string()]);
        assert!(!t.is_done(now));
        t.mark_success(now);
        assert!(t.is_done(now));
        assert_eq!(t.jwt.as_deref(), Some(JWT));
        // Logged lines carry method/status/path only — never the token.
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| !l.contains(JWT)));
    }

    #[test]
    fn tracker_url_signal_needs_jwt_or_settling() {
        let mut t = LoginTracker::default();
        let mut log = |_l: String| {};
        let now = Instant::now();
        t.set_url("https://www.fpl.com/my-account/login.html", now);
        assert!(!t.is_done(now + SETTLE_GRACE * 2));
        t.on_event(
            &ev(
                "Page.frameNavigated",
                json!({ "frame": { "id": "F", "url": "https://www.fpl.com/my-account/residential.html" } }),
            ),
            now,
            &mut log,
        );
        // On the dashboard, but no authenticated call seen yet.
        assert!(!t.is_done(now));
        assert!(t.is_done(now + SETTLE_GRACE));
        // An authenticated API call with a jwttoken header completes it at once.
        t.on_event(
            &ev(
                "Network.requestWillBeSent",
                json!({ "requestId": "2", "request": {
                    "url": "https://www.fpl.com/cs/customer/v1/resources/header",
                    "method": "GET", "headers": { "jwttoken": JWT } } }),
            ),
            now,
            &mut log,
        );
        assert!(t.is_done(now));
        // Child-frame navigations don't move the tracked URL.
        t.on_event(
            &ev(
                "Page.frameNavigated",
                json!({ "frame": { "parentId": "F", "url": "https://www.fpl.com/my-account/login.html" } }),
            ),
            now,
            &mut log,
        );
        assert!(is_account_url(&t.url));
    }

    #[test]
    fn tracker_records_rejected_login_without_success() {
        let mut t = LoginTracker::default();
        let mut log = |_l: String| {};
        let now = Instant::now();
        let url = "https://www.fpl.com/cs/customer/v3/login/public/passkeys/authentication";
        t.on_event(
            &ev(
                "Network.requestWillBeSent",
                json!({ "requestId": "9", "request": { "url": url, "method": "PUT", "headers": {} } }),
            ),
            now,
            &mut log,
        );
        t.on_event(
            &ev(
                "Network.responseReceived",
                json!({ "requestId": "9", "response": { "url": url, "status": 401, "headers": {} } }),
            ),
            now,
            &mut log,
        );
        t.on_event(
            &ev("Network.loadingFinished", json!({ "requestId": "9" })),
            now,
            &mut log,
        );
        assert_eq!(t.rejected_status, Some(401));
        assert!(t.pending_bodies.is_empty());
        assert!(!t.is_done(now + SETTLE_GRACE * 2));
    }

    #[test]
    fn automation_script_embeds_username_and_permits() {
        let all = StepPermits {
            passkey: true,
            continue_: true,
            back: true,
        };
        let s = automation_script("a\"b@example.com", all);
        assert!(s.contains(r#"const user = "a\"b@example.com";"#));
        assert!(s.contains("const allowPasskey = true;"));
        assert!(s.contains("const allowContinue = true;"));
        assert!(s.contains("const allowBack = true;"));
        let none = automation_script("x", StepPermits::default());
        assert!(none.contains("const allowPasskey = false;"));
        assert!(none.contains("const allowContinue = false;"));
        assert!(none.contains("const allowBack = false;"));
    }
}
