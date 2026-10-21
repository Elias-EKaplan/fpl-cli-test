# AGENTS.md — fpl-cli

Canonical agent entrypoint for this repo. `CLAUDE.md` is a one-line pointer here.

## What this is

A single-binary CLI (`fpl`) over Florida Power & Light's **undocumented**
`www.fpl.com` JSON services — account info, billing, usage, payments, outages.
No official API exists. Design ergonomics: a verb command surface, keychain-only
runtime secrets with stdin/env ingress, text-primary output, and stable exit
codes.

The endpoint map and auth flow are in [`docs/api.md`](docs/api.md) — read it
before touching `src/client.rs`.

## Local map

| Path | Responsibility |
|------|----------------|
| `src/main.rs` | thin entrypoint; parses args, dispatches |
| `src/cli.rs` | `clap` command tree (verbs + args) |
| `src/commands/*.rs` | one handler module per resource group (accounts, bills, payments, usage, history, profile, meter, alerts, lookup, outages, …) |
| `src/client.rs` | `Fpl` HTTP client: login, session, endpoints, raw `request` |
| `src/secrets.rs` | `Secret` (redacting/zeroizing) + `CredentialStore` + ingress |
| `src/browser.rs` | passkey login: minimal DevTools-protocol driver over a persistent browser profile, success detection |
| `src/session.rs` | saved browser session (JWT + `fpl.com` cookies, `0600`) reused by `Ctx::connect` |
| `src/config.rs` | `~/.config/fpl-cli/config.json` (non-secret prefs) |
| `src/output.rs` | text rendering + control-plane JSON |
| `src/error.rs` | `AppError` + exit codes |
| `src/commands/update.rs` | `fpl update`: self-update from GitHub Releases |
| `src/commands/config.rs` | `fpl config path\|show\|set\|unset`: non-secret settings via `pk-cli-config` |
| `src/dates.rs` | minimal date math (no calendar crate) |
| `build.rs` | bakes the target triple into `FPL_TARGET` for `update` |

## Durable conventions (do not drift)

- **Verb language.** Resource groups take fixed verbs: `list`, `get`, `use`,
  `create`. Domain reads that name a precise FPL concept are allowed
  (`bills projected`, `accounts balance`). Don't coin a verb where a table verb
  fits; don't collapse `accounts list` to bare `accounts`.
- **Secrets: keychain-only at runtime.** The password is read only from the OS
  keychain. It gets there via `fpl init` / `fpl set-credential`, which ingest
  from `--stdin` or `--from-env <VAR>` — **never a `--value`/`--password` flag**
  (leaks to `ps`, history, transcripts). Credential replacement uses
  `--overwrite`. Wrap secrets in `secrets::Secret`; never log or serialize one.
  The one on-disk exception is the short-lived session captured by
  `auth login --passkey` (`fpl-session.json`, `0600`, in the browser profile
  dir) — never log its JWT/cookies, and never forge WebAuthn over HTTP.
- **Mutation safety.** `payments create` moves money — confirm by default, skip
  with `--force` (NOT `--yes`). A non-TTY run without `--force` fails with a hint.
- **Output: text is primary.** Resource reads render `Key: value` blocks and
  pipe-delimited (`ALL_CAPS`) tables. `--json` on the utility/v1 profile
  commands (`summary`, `accounts balance`, `bills list`, `payments list`,
  `history list`) emits the canonical DTOs from `pk-cli-utility`, mapped in
  `src/output.rs` at the emission layer only — handlers keep passing raw
  provider JSON. Elsewhere `--json` is the raw FPL payload or a control-plane
  DTO (`init`/`set-credential` results, `auth status`, `info`, `api`). Data →
  stdout, diagnostics/confirmations → stderr. Never reword the text labels
  `Balance:` / `Due:` — drivers parse them.
- **Exit codes are a contract:** `0` ok, `1` other/keychain, `2` usage, `3`
  auth, `4` not found, `5` network. See `error.rs`.
- **Best-effort parsing.** FPL shapes vary by account type and drift. Never
  `unwrap()` on a response field; `output::render` flattens unknown shapes.

## This repo is public

Never commit personal data — no real account number, service address, email,
cookie, JWT, or password, in code, tests, fixtures, comments, or commit
messages. Use the placeholder account `1234567890`. CI runs `gitleaks`.

## Local checks (must pass before pushing)

```sh
make verify        # fmt-check + clippy -D warnings + test + smoke
make audit         # cargo-deny (licenses/advisories), matches CI
```

`make smoke` and `fpl outages list` need no login and exercise the binary
end-to-end. Authenticated paths can't run in CI; keep their logic covered by
unit tests on the pure helpers and verify manually with `fpl api`.

## The CLI family & cli-common

This CLI conforms to **piekstra-cli/1** — the shared surface spec in
[piekstra/cli-common](https://github.com/piekstra/cli-common) (`DESIGN.md`):
standard `auth` / `config` / `self-update` / `completions` / `info` commands,
global `--json`, canonical DTOs (`auth-status/v1`, `self-update/v1`,
`cli-info/v1`), and frozen exit codes 0–6. It also declares the **utility/v1
domain profile** (SPEC v1.1 §1.8, crate `pk-cli-utility`) via `fpl info`:
`summary`/`accounts balance` emit `utility-summary/v1`, and the profile list
commands emit `Paged` `<record>-list/v1` envelopes with `--limit`/`--since`/
`--until` range flags.

- **Don't fork shared behavior.** Error/exit-code handling, output rendering,
  keychain secrets, config storage, and self-update come from the `pk-cli-*`
  crates (tag-pinned git deps on cli-common). If you need a change there — or
  you're writing anything reusable across the family CLIs (fpl, xfin, lrfl,
  tojfl, …) — add it to cli-common, cut a tag, and bump the pin here. Never
  copy shared code into this repo.
- **Surface changes are spec changes.** A new standard command, flag, DTO
  field, or exit code belongs in cli-common's `DESIGN.md` first; update
  `conformance.md` alongside.
- **macOS dev signing.** Every plain `cargo build` — and every `cargo install`
  — gets a fresh ad-hoc code signature, so keychain "Always Allow" grants don't
  stick and every rebuild or reinstall re-prompts. One-time: run cli-common's
  `scripts/setup-dev-signing.sh`. After that, both `make dev` and `make install`
  re-sign with the stable `pk-cli-codesign` identity, so a single grant holds
  across every future build and install.
