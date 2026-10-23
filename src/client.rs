//! FPL customer-portal HTTP client (main region, "FL01").
//!
//! FPL exposes no official public API. Everything here targets the same
//! `www.fpl.com` JSON services the account-management web app and iOS app use.
//! Endpoint paths were mapped from the site's own service registry
//! (`/data/serviceconfparameters.js`) and cross-checked against the community
//! Home Assistant integration. See `docs/api.md`.
//!
//! Auth model: HTTP Basic on the login endpoint returns a `jwttoken` response
//! header plus session cookies. Subsequent calls send that JWT in a `jwttoken`
//! header and reuse the cookie jar. A passkey login (`fpl auth login
//! --passkey`) happens in a browser instead; its captured JWT + cookies seed
//! the same client via [`Fpl::from_session`].
//!
//! Northwest / former-Gulf-Power accounts ("FL02") use a different AWS Cognito
//! login flow and are not supported yet.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::secrets::Secret;
use crate::session::SavedSession;

pub const API_HOST: &str = "https://www.fpl.com";

/// Public, unauthenticated county-level outage feed behind fplmaps.com.
pub const OUTAGE_COUNTY_URL: &str = "https://www.fplmaps.com/customer/outage/CountyOutages.json";

/// A recent desktop Chrome UA. FPL's edge is picky about obviously-bot clients.
const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const LOGIN_PATH: &str =
    "/cs/customer/v1/registration/loginAndUseMigration?migrationToggle=Y&view=LoginMini";
const LOGOUT_PATH: &str = "/cs/customer/v1/registration/logout";

/// A logged-in FPL session.
pub struct Fpl {
    client: reqwest::blocking::Client,
    jwt: String,
}

/// One account as returned by the account-list endpoint.
#[derive(Debug, Serialize)]
pub struct AccountSummary {
    pub account_number: String,
    pub status_category: Option<String>,
    pub address: Option<String>,
    pub balance: Option<String>,
}

fn build_client(
    jar: Option<Arc<reqwest::cookie::Jar>>,
) -> Result<reqwest::blocking::Client, AppError> {
    let builder = reqwest::blocking::Client::builder()
        .user_agent(UA)
        // Total request budget, plus an explicit connect budget so a stalled
        // TCP/TLS handshake (which the overall `.timeout()` doesn't reliably
        // bound) fails fast instead of hanging.
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15));
    match jar {
        Some(jar) => builder.cookie_provider(jar),
        None => builder.cookie_store(true),
    }
    .build()
    .map_err(|e| AppError::Other(format!("failed to build HTTP client: {e}")))
}

/// Pull a short human hint out of an error response body: a `message` /
/// `messageCode` field if the body is JSON, else a trimmed snippet. Returns a
/// leading `" — …"` (or empty) so it slots into an error message.
fn body_hint(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        for key in ["message", "messageCode", "error", "errorMessage"] {
            if let Some(m) = v.get(key).and_then(|x| x.as_str()) {
                if !m.is_empty() {
                    return format!(" — {m}");
                }
            }
        }
        if let Some(m) = v.pointer("/messages/0/message").and_then(|x| x.as_str()) {
            return format!(" — {m}");
        }
    }
    format!(" — {}", trimmed.chars().take(120).collect::<String>())
}

/// Turn a service path into a full URL. Accepts either an absolute URL or a
/// leading-slash path relative to [`API_HOST`].
fn url_for(path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else if let Some(rest) = path.strip_prefix('/') {
        format!("{API_HOST}/{rest}")
    } else {
        format!("{API_HOST}/{path}")
    }
}

impl Fpl {
    /// Authenticate with FPL and capture the session JWT + cookies.
    pub fn login(username: &str, password: &Secret) -> Result<Fpl, AppError> {
        let client = build_client(None)?;
        let resp = client
            .get(url_for(LOGIN_PATH))
            .basic_auth(username, Some(password.expose()))
            .header("Accept", "application/json")
            .send()?;

        let status = resp.status();
        if status.is_success() {
            let jwt = resp
                .headers()
                .get("jwttoken")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            return Ok(Fpl { client, jwt });
        }

        let body = resp.text()?;
        Err(AppError::Auth(format!(
            "FPL login failed (HTTP {}): {body}",
            status.as_u16()
        )))
    }

    /// Resume a session captured by a browser (passkey) login: its cookies
    /// seed the jar and its JWT, when present, rides in the `jwttoken` header.
    pub fn from_session(session: &SavedSession) -> Result<Fpl, AppError> {
        Ok(Fpl {
            client: build_client(Some(session.jar()))?,
            jwt: session.jwt.clone().unwrap_or_default(),
        })
    }

    fn auth_headers(
        &self,
        mut req: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        req = req.header("Accept", "application/json");
        if !self.jwt.is_empty() {
            req = req.header("jwttoken", &self.jwt);
        }
        req
    }

    fn handle(&self, resp: reqwest::blocking::Response, path: &str) -> Result<Value, AppError> {
        let status = resp.status();
        // Read the body once; include a snippet in error messages so a 4xx from
        // FPL explains itself instead of just showing a status code.
        let text = resp.text().unwrap_or_default();
        if matches!(status.as_u16(), 401 | 403) {
            return Err(AppError::Auth(format!(
                "FPL returned {} for {path} — session expired. Run `fpl init` again \
                 (or `fpl auth login --passkey` / `fpl init --mfa` for a browser login).",
                status.as_u16()
            )));
        }
        if status.as_u16() == 404 {
            return Err(AppError::NotFound(format!("{path} (HTTP 404)")));
        }
        if !status.is_success() {
            return Err(AppError::Upstream(format!(
                "FPL HTTP {} for {path}{}",
                status.as_u16(),
                body_hint(&text)
            )));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| {
            AppError::Other(format!(
                "FPL returned a non-JSON response for {path} (first bytes: {:?})",
                text.chars().take(60).collect::<String>()
            ))
        })
    }

    pub fn get(&self, path: &str) -> Result<Value, AppError> {
        let resp = self.auth_headers(self.client.get(url_for(path))).send()?;
        self.handle(resp, path)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value, AppError> {
        let resp = self
            .auth_headers(self.client.post(url_for(path)))
            .header("Content-Type", "application/json")
            .json(body)
            .send()?;
        self.handle(resp, path)
    }

    pub fn put(&self, path: &str, body: &Value) -> Result<Value, AppError> {
        let resp = self
            .auth_headers(self.client.put(url_for(path)))
            .header("Content-Type", "application/json")
            .json(body)
            .send()?;
        self.handle(resp, path)
    }

    /// Raw request escape hatch used by `fpl api`. `method` is case-insensitive.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, AppError> {
        let m = method.to_uppercase();
        match m.as_str() {
            "GET" => self.get(path),
            "POST" => self.post(path, body.unwrap_or(&Value::Null)),
            "PUT" => self.put(path, body.unwrap_or(&Value::Null)),
            "DELETE" => {
                let resp = self
                    .auth_headers(self.client.delete(url_for(path)))
                    .send()?;
                self.handle(resp, path)
            }
            other => Err(AppError::Usage(format!(
                "unsupported HTTP method {other:?} (use GET, POST, PUT, or DELETE)"
            ))),
        }
    }

    // ---- Account discovery -------------------------------------------------

    /// The portal header: the signed-in customer plus every account with its
    /// service address, balance, and status.
    pub fn header(&self) -> Result<Value, AppError> {
        self.get("/cs/customer/v1/resources/header")
    }

    /// Parse the header's per-account rows into summaries (address + balance).
    fn header_accounts(&self) -> Result<Vec<AccountSummary>, AppError> {
        let header = self.header()?;
        let rows = header
            .pointer("/data/accounts/data/data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for a in &rows {
            let Some(num) = a.get("accountNumber").and_then(|v| v.as_str()) else {
                continue;
            };
            let address = a.get("serviceAddress").map(|addr| {
                let line1 = addr.get("line1").and_then(|v| v.as_str()).unwrap_or("");
                let city = addr.get("city").and_then(|v| v.as_str()).unwrap_or("");
                [line1, city]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            let balance = a.get("balance").map(|b| match b {
                Value::Number(n) => format!("${:.2}", n.as_f64().unwrap_or(0.0)),
                other => other.to_string(),
            });
            out.push(AccountSummary {
                account_number: num.to_string(),
                status_category: a
                    .get("statusName")
                    .or_else(|| a.get("statusCategory"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                address: address.filter(|s| !s.is_empty()),
                balance,
            });
        }
        Ok(out)
    }

    /// List the caller's accounts. Prefers the header endpoint (one call, with
    /// address + balance), falling back to the paginated list + `loginNew`.
    pub fn accounts(&self) -> Result<Vec<AccountSummary>, AppError> {
        if let Ok(list) = self.header_accounts() {
            if !list.is_empty() {
                return Ok(list);
            }
        }
        let mut out = Vec::new();
        let mut start = 1;
        let page = 10;
        loop {
            let path = format!(
                "/cs/customer/v1/resources/account?sortBy=status&count={page}&start={start}"
            );
            let body = self.get(&path)?;
            let rows = body
                .get("data")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if rows.is_empty() {
                break;
            }
            for a in &rows {
                if let Some(num) = a.get("accountNumber").and_then(|v| v.as_str()) {
                    out.push(AccountSummary {
                        account_number: num.to_string(),
                        status_category: a
                            .get("statusCategory")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        address: a
                            .get("serviceAddress")
                            .or_else(|| a.get("premiseAddress"))
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        balance: None,
                    });
                }
            }
            let has_more = body
                .get("hasMore")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !has_more {
                break;
            }
            let count = body.get("count").and_then(|v| v.as_i64()).unwrap_or(page);
            start += count;
        }
        // Fall back to the app's `loginNew` fan-out if the paginated endpoint
        // returned nothing (some account types only surface there).
        if out.is_empty() {
            if let Ok(list) = self.account_list() {
                if let Some(rows) = list
                    .pointer("/data/AccountList/data")
                    .and_then(|v| v.as_array())
                {
                    for a in rows {
                        if let Some(num) = a.get("accountNumber").and_then(|v| v.as_str()) {
                            out.push(AccountSummary {
                                account_number: num.to_string(),
                                status_category: a
                                    .get("accountStatus")
                                    .or_else(|| a.get("statusCategory"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                address: a
                                    .get("serviceAddress")
                                    .or_else(|| a.get("premiseAddress"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                balance: a
                                    .get("balance")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                            });
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Select an account server-side and return its detail record.
    pub fn account_detail(&self, account: &str) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/accountservices/resources/account/{account}/select?view=account-lander"
        ))
    }

    /// Account list with balances (the app's `loginNew` fan-out).
    pub fn account_list(&self) -> Result<Value, AppError> {
        self.post(
            "/cs/customer/v1/accountservices/resources/loginNew?mediaChannel=IOS",
            &json!({}),
        )
    }

    /// Extract the 9-digit, zero-padded premise number from an account detail.
    pub fn premise_of(detail: &Value) -> Option<String> {
        detail
            .pointer("/data/premiseNumber")
            .and_then(|v| {
                v.as_str()
                    .map(String::from)
                    .or_else(|| v.as_i64().map(|n| n.to_string()))
            })
            .map(|s| format!("{s:0>9}"))
    }

    // ---- Billing -----------------------------------------------------------

    /// Balance and due status for one account. The dedicated `/balance` endpoint
    /// is finicky about pagination params, so we read the balance fields off the
    /// `loginNew` account list, which returns a clean per-account summary.
    pub fn balance(&self, account: &str) -> Result<Value, AppError> {
        let list = self.account_list()?;
        let rows = list
            .pointer("/data/AccountList/data")
            .and_then(|v| v.as_array());
        if let Some(rows) = rows {
            for a in rows {
                if a.get("accountNumber").and_then(|v| v.as_str()) == Some(account) {
                    return Ok(a.clone());
                }
            }
        }
        Err(AppError::NotFound(format!(
            "no balance information for account {account}"
        )))
    }

    pub fn bill_history(&self, account: &str) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/sumbillaccount/resources/account/{account}/bill-history"
        ))
    }

    /// Fetch a bill statement PDF. `date_billed` / `date_print` come from a
    /// `bill-history` row (`YYYY-MM-DD`); FPL wants them dash-stripped. The
    /// response is `{ data: { bytes: "<base64 PDF>", … } }`.
    pub fn download_bill(
        &self,
        account: &str,
        date_billed: &str,
        date_print: &str,
    ) -> Result<Value, AppError> {
        // All values are URL-safe (digits / fixed ASCII tokens).
        let bill_date = date_billed.replace('-', "");
        let print_date = date_print.replace('-', "");
        let query = format!(
            "channel=WEB&jobType=BL&requestedDocType=PDF&billAccountNumber={account}\
             &billDate={bill_date}&printDate={print_date}&fileName=billPdf-{print_date}.pdf\
             &docPathEncryptDecryptRequired=true&requestFor=ViewBillPdfRequest"
        );
        self.get(&format!(
            "/cs/customer/v1/documentretrieval/resources/account/{account}/download?{query}"
        ))
    }

    pub fn projected_bill(
        &self,
        account: &str,
        premise: &str,
        last_billed_mmddyyyy: &str,
    ) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/accountservices/resources/account/{account}/projectedBill?premiseNumber={premise}&lastBilledDate={last_billed_mmddyyyy}"
        ))
    }

    pub fn budget_billing(&self, account: &str) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/budgetbillingapi/resources/account/{account}/budgetBillingGraph"
        ))
    }

    // ---- Payments ----------------------------------------------------------

    pub fn payment_options(&self, account: &str) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/paymentservices/resources/account/{account}/payment-option"
        ))
    }

    /// Submit a payment. FPL's payment service creates via HTTP **PUT** (its
    /// `ServiceInvoker._create` uses PUT, not POST — a POST here 404s).
    pub fn make_payment(&self, account: &str, body: &Value) -> Result<Value, AppError> {
        self.put(
            &format!("/cs/customer/v1/paymentservices/resources/account/{account}/payment"),
            body,
        )
    }

    // ---- History -----------------------------------------------------------

    pub fn account_history(&self, account: &str) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/accounthistory/resources/account/{account}/account-history?count=25&start=1&sortBy=date"
        ))
    }

    pub fn deposit_history(&self, account: &str) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/accounthistory/resources/account/{account}/deposit-history?count=25&start=1&sortBy=date"
        ))
    }

    // ---- Usage -------------------------------------------------------------

    /// Current-period energy summary (projected kWh, daily average, bill-to-date).
    pub fn energy_usage(
        &self,
        account: &str,
        premise: &str,
        last_billed_mmddyyyy: &str,
        meter_no: &str,
    ) -> Result<Value, AppError> {
        let body = json!({
            "status": "2",
            "accountType": "RESIDENTIAL",
            "premiseNumber": premise,
            "lastBilledDate": last_billed_mmddyyyy,
            "amrFlag": "Y",
            "revCode": "1",
            "meterNo": meter_no,
        });
        self.post(
            &format!("/cs/customer/v1/energydashboard/resources/energy-usage/account/{account}/mobile-energy-service"),
            &body,
        )
    }

    /// Hourly usage for a single day (`MM-DD-YYYY`).
    pub fn hourly_usage(
        &self,
        account: &str,
        premise: &str,
        date_mmddyyyy: &str,
    ) -> Result<Value, AppError> {
        let body = json!({ "premiseNumber": premise, "startDate": date_mmddyyyy });
        self.post(
            &format!("/cs/customer/v1/energydashboard/resources/energy-usage/account/{account}/mobile-hourly-usage"),
            &body,
        )
    }

    /// Appliance-level disaggregated usage for the latest bill period.
    pub fn appliance_usage(&self, account: &str, premise: &str) -> Result<Value, AppError> {
        let body = json!({ "premiseId": premise, "accountNumber": account });
        self.post(
            &format!("/cs/customer/v1/energyanalyzer/resources/{account}/getDisaggResp"),
            &body,
        )
    }

    // ---- Diagnostics & notifications ---------------------------------------

    /// Smart-meter (AMI) status: whether the meter is reporting, breaker state,
    /// and the ping window. What the outage-status page uses to check a meter.
    pub fn meter_status(&self, account: &str) -> Result<Value, AppError> {
        self.post(
            "/cs/customer/v1/wors/public/amiping",
            &json!({ "accountNumber": account }),
        )
    }

    /// Account alert/banner state (balance alerts, collection thresholds, flags).
    pub fn alerts(&self, account: &str) -> Result<Value, AppError> {
        self.get(&format!(
            "/cs/customer/v1/profileservices/resources/account/{account}/alert-notification"
        ))
    }

    // ---- Public reference data ---------------------------------------------

    /// FPL-served Florida cities.
    pub fn cities(&self) -> Result<Value, AppError> {
        self.get("/cs/customer/v1/connect-journey/public/city")
    }

    /// FPL-served Florida ZIP codes.
    pub fn zips(&self) -> Result<Value, AppError> {
        self.get("/cs/customer/v1/connect-journey/public/zip")
    }

    // ---- Session -----------------------------------------------------------

    pub fn logout(&self) -> Result<(), AppError> {
        // Best-effort; ignore the body.
        let _ = self
            .auth_headers(self.client.get(url_for(LOGOUT_PATH)))
            .send();
        Ok(())
    }
}

/// Fetch the public county outage feed (no auth required).
pub fn county_outages() -> Result<Value, AppError> {
    let client = build_client(None)?;
    let resp = client.get(OUTAGE_COUNTY_URL).send()?;
    if !resp.status().is_success() {
        return Err(AppError::Upstream(format!(
            "outage feed HTTP {}",
            resp.status().as_u16()
        )));
    }
    Ok(resp.json::<Value>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn url_for_handles_paths_and_absolutes() {
        assert_eq!(url_for("/cs/x"), "https://www.fpl.com/cs/x");
        assert_eq!(url_for("cs/x"), "https://www.fpl.com/cs/x");
        assert_eq!(url_for("https://other/y"), "https://other/y");
    }

    #[test]
    fn premise_zero_pads_to_nine() {
        let d = json!({ "data": { "premiseNumber": 12345 } });
        assert_eq!(Fpl::premise_of(&d).as_deref(), Some("000012345"));
        let s = json!({ "data": { "premiseNumber": "987654321" } });
        assert_eq!(Fpl::premise_of(&s).as_deref(), Some("987654321"));
        assert_eq!(Fpl::premise_of(&json!({})), None);
    }

    #[test]
    fn body_hint_empty_is_blank() {
        assert_eq!(body_hint(""), "");
        assert_eq!(body_hint("   \n"), "");
    }

    #[test]
    fn body_hint_prefers_json_message_fields() {
        // Real FPL 400s carry the explanation in a `message` field.
        assert_eq!(
            body_hint(r#"{"message":"Required Integer parameter 'count' is not present"}"#),
            " — Required Integer parameter 'count' is not present"
        );
        // Falls through the key priority to messageCode / error.
        assert_eq!(
            body_hint(r#"{"messageCode":"FAILEDPASSWORD"}"#),
            " — FAILEDPASSWORD"
        );
        assert_eq!(body_hint(r#"{"error":"boom"}"#), " — boom");
        // Nested messages[].message array.
        assert_eq!(
            body_hint(r#"{"messages":[{"message":"Unable to retrieve premise"}]}"#),
            " — Unable to retrieve premise"
        );
    }

    #[test]
    fn body_hint_falls_back_to_snippet() {
        // A plain-text body (e.g. the 555 "No file path available in DB").
        assert_eq!(
            body_hint("No file path available in DB"),
            " — No file path available in DB"
        );
        // JSON without a recognized key is shown as its raw (truncated) text.
        assert_eq!(body_hint(r#"{"foo":"bar"}"#), r#" — {"foo":"bar"}"#);
        // Long bodies are truncated to 120 chars.
        let long = "x".repeat(200);
        assert_eq!(body_hint(&long).chars().count(), 120 + 3); // " — " + 120
    }
}
