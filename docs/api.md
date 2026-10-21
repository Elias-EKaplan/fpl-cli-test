# FPL API notes

FPL has no official public API. This documents the undocumented `www.fpl.com`
JSON services that `fpl-cli` talks to, so the mapping is auditable and the next
person doesn't have to re-derive it.

## How this was mapped

- FPL's account-management web app is an AMD/Dojo bundle. Its **service
  registry** lives at `https://www.fpl.com/data/serviceconfparameters.js` — a
  plain object of `{ name: { url, target } }` entries. That file is the source of
  truth for most paths below.
- The `serviceconfig` module composes account-scoped URLs as
  roughly `{url}/account/{account}{target}`.
- Auth flow and a few request bodies were cross-checked against the community
  Home Assistant integration ([`dotKrad/hass-fpl`](https://github.com/dotKrad/hass-fpl)).
- Reachability was confirmed by probing each path unauthenticated: a `401`
  (rather than `404`) means the route exists and requires a session.

Nothing here is guaranteed stable. FPL can change these at any time.

## Authentication (main region / "FL01")

1. **Login** — `GET /cs/customer/v1/registration/loginAndUseMigration?migrationToggle=Y&view=LoginMini`
   with HTTP **Basic** auth (`username:password`). On success (`200`), the
   response carries a **`jwttoken`** header and sets session cookies. Login
   failures include the HTTP status and full response body in the CLI error;
   the body may contain a `messageCode`, such as `NOTVALIDUSER` or
   `FAILEDPASSWORD`.
2. **Authenticated calls** — send the `jwttoken` header and reuse the cookie jar.
3. **Logout** — `GET /cs/customer/v1/registration/logout`.

`fpl auth login --browser` opens FPL's account login page in the system browser
as a helper, then follows the same CLI credential/API login flow. It does not
transfer browser cookies or an authenticated browser session to the CLI.

### Passkey login (browser-driven)

The web login page (`/my-account/login.html`) offers a passkey sign-in. It is
two calls to the same path, distinguished by verb:

1. `POST /cs/customer/v3/login/public/passkeys/authentication` with
   `{"userName": …, "flow": "WEB"}` returns WebAuthn request options
   (`challenge`, `rpId: "fpl.com"`, `allowCredentials`,
   `userVerification: "required"`) plus an opaque server `session`.
2. The page calls `navigator.credentials.get(…)`; the authenticator signs.
3. `PUT` to the same path with the assertion (`id`, `rawId`, `type`,
   `clientDataJSON`, `authenticatorData`, `signature`, `userHandle`) and the
   echoed `session` / `userName`. Success is
   `{"message":{"code":"login.success","message":"Log in successful"}}` with a
   `jwttoken` response header and session cookies.

Step 2 needs a real authenticator bound to `fpl.com`, so `fpl auth login
--passkey` does **not** reimplement this over HTTP. It drives a Chromium-family
browser over the DevTools protocol (`src/browser.rs`) with a persistent profile,
lets native WebAuthn run, and treats either the `login.success` body on a `/cs/…
login…` response or the tab reaching `/my-account/…` (with an authenticated API
call carrying `jwttoken`) as success. It then captures the `jwttoken` and the
`fpl.com` cookies, verifies them with `GET /cs/customer/v1/resources/header`,
and saves them (`src/session.rs`) for `Fpl::from_session`. Response bodies are
read only to check the result code and are never logged or stored.

Email/password + one-time-code MFA in the browser is supported the same way:
the user completes it in the window, and the URL signal detects success. MFA
over the plain API login is not implemented because that challenge/response
format is not documented here.

Former **Gulf Power** accounts (Northwest Florida, "FL02") use an AWS Cognito
SRP login against `cognito-idp.us-east-1.amazonaws.com` instead, and a separate
`/cs/gulf/ssp/…` service tree. Not implemented here.

## Endpoints used by fpl-cli

All paths are under `https://www.fpl.com` and require the session unless noted.
`{account}` is the FPL account number; `{premise}` is the 9-digit zero-padded
premise number from account detail.

| Command | Method | Path |
|---------|--------|------|
| `accounts list` | GET | `/cs/customer/v1/resources/account?sortBy=status&count=10&start=1` |
| `accounts list` (fallback) | POST | `/cs/customer/v1/accountservices/resources/loginNew?mediaChannel=IOS` |
| `accounts list` / `profile` | GET | `/cs/customer/v1/resources/header` (customer + all accounts with address/balance/status) |
| `accounts get` | GET | `/cs/customer/v1/accountservices/resources/account/{account}/select?view=account-lander` |
| `meter` | POST | `/cs/customer/v1/wors/public/amiping` (body `{accountNumber}`) |
| `alerts` | GET | `/cs/customer/v1/profileservices/resources/account/{account}/alert-notification` |
| `lookup cities` | GET | `/cs/customer/v1/connect-journey/public/city` |
| `lookup zips` | GET | `/cs/customer/v1/connect-journey/public/zip` |
| `accounts balance` | POST | `/cs/customer/v1/accountservices/resources/loginNew?mediaChannel=IOS` (balance fields per account) |
| `bills list` | GET | `/cs/customer/v1/sumbillaccount/resources/account/{account}/bill-history` |
| `bills projected` | GET | `/cs/customer/v1/accountservices/resources/account/{account}/projectedBill?premiseNumber={premise}&lastBilledDate={MMDDYYYY}` |
| `bills budget` | GET | `/cs/customer/v1/budgetbillingapi/resources/account/{account}/budgetBillingGraph` |
| `bills download` | GET | `/cs/customer/v1/documentretrieval/resources/account/{account}/download?…` (bill PDF, base64 in `data.bytes`) |
| `bills get` / `usage get` | POST | `/cs/customer/v1/energydashboard/resources/energy-usage/account/{account}/mobile-energy-service` |
| `usage hourly` | POST | `/cs/customer/v1/energydashboard/resources/energy-usage/account/{account}/mobile-hourly-usage` |
| `usage appliances` | POST | `/cs/customer/v1/energyanalyzer/resources/{account}/getDisaggResp` |
| `payments methods` | GET | `/cs/customer/v1/paymentservices/resources/account/{account}/payment-option` |
| `payments create` | **PUT** | `/cs/customer/v1/paymentservices/resources/account/{account}/payment` |
| `payments list` / `history list --type account` | GET | `/cs/customer/v1/accounthistory/resources/account/{account}/account-history?count=25&start=1&sortBy=date` |
| `history list --type deposit` | GET | `/cs/customer/v1/accounthistory/resources/account/{account}/deposit-history?count=25&start=1&sortBy=date` |
| `outages list` | GET | `https://www.fplmaps.com/customer/outage/CountyOutages.json` *(public, no auth)* |

The `account-history` / `deposit-history` endpoints require the `count`, `start`,
and `sortBy` query parameters together — omit any and they return `400`. The
dedicated `/balance` endpoint has similar pagination requirements and is
inconsistent, so `accounts balance` reads the per-account balance fields
(`balance`, `actualBalance`, `dueDateVal`) off the `loginNew` list instead.
**Bill-PDF retrieval (`bills download`) is mapped and verified.** It's a single
authenticated GET — no document-history call needed for bills. `bills download`
reads the target bill's `dateBilled` / `datePrint` from `bill-history`, strips
the dashes, and calls the download endpoint with the query the web `viewbill`
app builds:

```
GET /cs/customer/v1/documentretrieval/resources/account/{account}/download
      ?channel=WEB&jobType=BL&requestedDocType=PDF&billAccountNumber={account}
      &billDate={YYYYMMDD}&printDate={YYYYMMDD}&fileName=billPdf-{YYYYMMDD}.pdf
      &docPathEncryptDecryptRequired=true&requestFor=ViewBillPdfRequest
```

The response is JSON: `{ data: { bytes: "<base64 PDF>", documentPath, patternMatchFound, … } }`.
Base64-decode `data.bytes` to get the PDF. The earlier `555 "No file path
available in DB"` was simply the download called without the `requestedDocType`,
`requestFor`, and `fileName` params. The separate **`document-history`** service
(a *`PUT`* to `/documentretrieval/resources/account/{account}/document-history/{account}`
— note the account appears twice — with a `billHistorys` body) lists all
downloadable documents including final notices; it's not needed for plain bill
PDFs, so it isn't wrapped.

### Request-body notes

- **`mobile-energy-service`**: `{ status: "2", accountType: "RESIDENTIAL",
  premiseNumber, lastBilledDate: "MMDDYYYY", amrFlag: "Y", revCode: "1",
  meterNo }`. `status` `"2"` = active account. `lastBilledDate` and `meterNo`
  come from account detail (`currentBillDate`, `meterNo`).
- **`mobile-hourly-usage`**: `{ premiseNumber, startDate: "MM-DD-YYYY" }` (note
  the dashed date here, versus the undashed `MMDDYYYY` elsewhere).
- **`getDisaggResp`**: `{ premiseId, accountNumber }`.
- **`payment`** (verified against live submissions): issued as an HTTP **`PUT`**
  (FPL's `ServiceInvoker._create` uses PUT — a `POST` to this URL `404`s). Body
  is `{ amount, paymentDate: "YYYY-MM-DD", donations: [] }`, drawing the bank
  account on file (from `payment-option`). The draw account, `requestedBy`, and
  channel are **not** sent — the web app wraps the payload in a `transactionData`
  envelope for its `/api/resources` gateway, but the direct backend rejects that
  envelope (`For input string: ""`, an empty-int parse) and wants the bare body.

  **⚠️ The endpoint commits the payment and *then* may return an HTTP `4xx`** (a
  post-commit confirmation step; response is `{"messages":[{"messageType":"ERROR"}]}`
  with no text). **Money moves even on a 400** — the HTTP status is not a success
  signal. `payments create` therefore reads `currentAccountBalance` before and
  after and reports success from the balance delta, not the response. FPL also
  rejects a second payment for the same amount the same day (a business-logic
  409-style guard returned as a 400 with a "payment for this amount was already
  made today" message).

  **Follow-up (not yet done):** find the request that returns a clean `200` with
  a `confirmationNumber` (the web success handler reads `{data:{confirmationNumber,
  emailAddress}}`). Every real attempt is a live charge, so this needs a batch of
  small test payments at distinct amounts (the same amount can't be retried same
  day). Until then the balance-delta verification is the reliable success signal.

## Other known endpoints (not wrapped)

The service registry (`/data/serviceconfparameters.js`) lists ~120 endpoints.
`fpl-cli` wraps the account/billing/usage/history/diagnostics **read** surface.
The rest fall into a few buckets, reachable via `fpl api <METHOD> <PATH>`:

- **Mutations we deliberately don't wrap:** enrollment flows — automatic bill
  pay (`/api/automaticbillpayment/resources/program`), paperless/eBill
  (`/programenrollment/resources/ebill`), Budget Billing enrollment
  (`/budgetbillingapi/resources/programEnrollment`) — plus start/stop/transfer
  service (`/connect-journey/…`, `/serviceorder/…`, `/transfer/…`) and trouble
  reporting (street light, vegetation, wire-down, flicker submit-ticket).
- **Probed but not viable on a standard residential account:** `multiaccount`
  (`getMultiAccounts` is a contact-*edit* endpoint expecting a body, not a read;
  the read variants `400`/`401` without a linked multi-account setup); Solar
  Together (`/solartogether-api/…` returns `401` unless enrolled); the pay-agent
  locator (`api-dee.fpl.com/cs/v1/payagentlocator`, `400` for every param
  combination tried); high-bill report and per-account contact endpoints
  (`email-address`/`phone-number`/`ccin`, all `404` at the registry-implied
  paths — contact info is available via `fpl profile` instead).
- **Northwest / former-Gulf-Power region (`/cs/gulf/ssp/…`):** a separate service
  tree behind AWS Cognito login; unsupported.

## Adding a first-class command

New endpoints go in `src/client.rs` as a method returning `serde_json::Value`,
wired to a verb in `src/cli.rs` and a handler in `src/commands/<group>.rs`. Reads
render through `output::render` (text); don't add `--json` to a read — `fpl api`
is the raw-JSON path. Once you can confirm a response shape from a real
(redacted) payload, add a purpose-built renderer in `src/output.rs`.
