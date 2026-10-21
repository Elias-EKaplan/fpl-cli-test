# fpl-cli

Manage your **Florida Power & Light** account from the command line: check your
balance, view and download bills, inspect energy usage, make a payment, and
watch outages — from a terminal, with stable exit codes and text output a person
*or* an agent can parse.

FPL publishes no official public API. This is a polite client over the same
`www.fpl.com` JSON services that FPL's own website and mobile app call. It
follows a small set of ergonomics: a fixed **verb** command surface,
**keychain-only** runtime secrets with stdin/env ingress, **text-first** output,
and a stable exit-code contract. Endpoint mapping is in
[`docs/api.md`](docs/api.md); component architecture and command flow are in
[`docs/architecture.md`](docs/architecture.md).

> **Status: work in progress.** The public **outage** feed needs no login and is
> fully verified. Authenticated commands target real, confirmed-reachable
> endpoints, but FPL's response *shapes* vary by account type and aren't all
> pinned down yet — reads render a best-effort flattened view of whatever comes
> back. For the raw payload (and to help map a shape), use `fpl api`.

## Install

Install the stable Rust toolchain first; it includes Cargo. On macOS or Linux,
use [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

On Windows, download and run `rustup-init.exe` from
[rustup.rs](https://rustup.rs/). After installation, open a new terminal (or
follow rustup's instructions to add Cargo to your `PATH`).

Then, from the repository:

```sh
make install          # cargo install --path . → the `fpl` binary on your PATH
# or
cargo build --release # binary at ./target/release/fpl
```

The crate/repo is `fpl-cli`; the binary is **`fpl`**. macOS, Windows, and
Linux are supported (each uses its native secret store).

## Getting started

Set up once. Your password is read from stdin or an env var and stored only in
the OS keychain — there is deliberately no password flag.

The `op read` examples require the [1Password CLI (`op`)](https://developer.1password.com/docs/cli/get-started/)
to be installed and signed in. If you don't use 1Password, run `fpl init`
interactively instead; it prompts for your password without echoing it.

```sh
# Interactive first-time setup (prompts, no echo):
$ fpl init --username you@example.com
FPL password for you@example.com: ********
stored credentials for you@example.com; active account 1234567890

# Or fully scriptable (headless / CI / 1Password):
$ op read 'op://Private/FPL/password' | fpl init --username you@example.com --password-stdin
$ FPL_PW=... fpl init --username you@example.com --password-from-env FPL_PW

# What's configured? (never prints the password)
$ fpl auth status
username: you@example.com
account:  1234567890
password: stored in keychain

# Optionally open FPL's account login page as a browser helper:
$ fpl auth login --browser
```

`--browser` does not transfer the browser session or its MFA state to the CLI;
credential verification still uses the documented API login.

To reset the stored account and password in the OS key-chain use:
```sh
fpl auth logout --forget
```

Setup and credential-rotation confirmations report the entered password's
character count, never its value. `fpl auth status` reports the stored
credential's character count (on stderr with `--json`, preserving the
`auth-status/v1` JSON schema).

Rotate a stored password without re-running full setup:

```sh
op read 'op://Private/FPL/password' | fpl set-credential --stdin --overwrite
```

## Commands

The surface is resource groups + fixed verbs (`list`, `get`, `use`, `create`).
Most commands take an optional `[account-id]`; omit it to use the active account
(set with `accounts use`, or the first account on your login).

### At a glance

```sh
$ fpl summary
Account 4265842247  ·  RESIDENTIAL  ·  Jupiter
Balance         $0.00
Cycle           2026-06-26 → 2026-07-28   (day 15 of 32)
Projected bill  $204.43   ·  bill-to-date $90.94   ·  ~$6.06/day
Projected use   1389 kWh  ·  651 kWh so far        ·  ~43 kWh/day
```

`fpl summary [account-id]` is the daily-driver dashboard — balance, bill cycle,
and projected bill/usage in one call. `--json` emits the canonical
`utility-summary/v1` card (see [Output & scripting](#output--scripting)).

### Accounts & profile

```sh
fpl accounts list                 # all accounts with status, balance, and address
fpl accounts get [account-id]     # service address, meter, bill cycle, programs
fpl accounts use <account-id>     # set the active account for later commands
fpl accounts balance [account-id] # current balance and due date
fpl profile [account-id]          # account holder: name, email, phone, mailing address
```

### Config

```sh
fpl config show                   # effective non-secret settings
fpl config set account 1234567890 # keys: username, account
fpl config unset account
fpl config path                   # where the config file lives
```

The config file holds only non-secret preferences — the password lives in the
OS keychain (`fpl init` / `fpl set-credential`).

### Bills

```sh
fpl bills get [account-id]        # this period: projected bill, bill-to-date, daily avg
fpl bills projected [account-id]  # projected end-of-cycle bill
fpl bills list [account-id]       # prior bills (--limit/--since/--until to narrow)
fpl bills budget [account-id]     # Budget Billing plan status + monthly graph
fpl bills download [account-id]   # save a bill statement PDF (latest, or --date)
```

`fpl bills download` fetches a bill statement as a PDF. It defaults to the most
recent bill; pass `--date YYYY-MM-DD` (a date from `bills list`) for an older
one. The PDF is written to `./fpl-bill-<account>-<date>.pdf` by default, or use
`-o <path>` (`-o -` streams it to stdout, e.g. `fpl bills download -o - | open -f -a Preview`).

### Payments

```sh
fpl payments list [account-id]    # payments from the ledger (--limit/--since/--until)
fpl payments methods [account-id] # saved payment methods / options (bank on file)
fpl payments create --amount 123.45              # make a payment (asks to confirm)
fpl payments create --amount 123.45 --date 2026-08-01 --force
```

A payment draws from the bank account on file (see `payments methods`); the
date defaults to today. `payments create` **will not submit without
confirmation** — it prompts `[y/N]`, or requires `--force` in a non-interactive
shell. Money movement is hard to reverse, so `--force` is the explicit go-ahead.

**On success reporting:** FPL's payment endpoint commits the payment and *then*
sometimes returns an HTTP error (a post-commit confirmation step), so the HTTP
status is not a reliable signal — a 400 does **not** mean the charge didn't
happen. `create` therefore reads your account balance before and after
submitting and reports success from the balance change, not the response. If the
balance drops by the amount, it reports the payment as posted (even if FPL
returned an error); if it doesn't, it reports the payment did not post. FPL also
rejects a second payment for the same amount on the same day.

### Usage

```sh
fpl usage get [account-id]                 # current-period kWh, projected cost, daily avg
fpl usage hourly [account-id] --date 07-04-2026   # hourly kWh (default: yesterday)
fpl usage appliances [account-id]          # appliance-level (disaggregated) breakdown
```

### History

```sh
fpl history list [account-id]                 # account ledger (default --type account)
fpl history list [account-id] --type deposit  # deposit history
fpl history list --since 2026-01-01 --limit 5 # range flags work on any ledger
fpl history types                             # valid --type values
```

### Meter & alerts

```sh
fpl meter [account-id]    # smart-meter (AMI) status: reporting, breaker state, ping window
fpl alerts [account-id]   # account alert/banner state (balance alerts, collection thresholds)
```

### Reference data (no login required for the data itself)

```sh
fpl lookup cities   # Florida cities in FPL's service territory
fpl lookup zips     # Florida ZIP codes in FPL's service territory
```

### Outages (no login required)

```sh
$ fpl outages list --name broward
COUNTY | OUT | SERVED
Broward | 70 | 853,654
TOTAL OUT | 70

fpl outages list                  # all counties FPL serves
```

### Raw API escape hatch

Anything not yet wrapped in a subcommand — or the raw JSON of one — with your
session:

```sh
fpl api GET /cs/customer/v1/resources/header
fpl api POST /cs/customer/v1/accountservices/resources/loginNew?mediaChannel=IOS --data '{}'
```

Paths are relative to `https://www.fpl.com` (or pass a full URL). Output is
always JSON.

### Updating

```sh
fpl self-update --check    # is a newer release available?
fpl self-update            # download the latest release for your platform and replace the binary
```

`fpl self-update` pulls the matching `fpl-<target>.tar.gz` from this repo's
GitHub Releases and swaps the running binary in place. (`fpl update` still works
as an alias. If you installed with `cargo install`, `git pull && make install`
also works.)

### Shell completions & discovery

```sh
fpl completions zsh > ~/.zfunc/_fpl   # bash | zsh | fish | powershell | elvish
fpl info                             # machine-readable capabilities (cli-info/v1 JSON)
```

`fpl info` reports the command surface, auth method, and version as JSON — handy
for agents and tooling that introspect the CLI before driving it.

## Output & scripting

**Text is the default.** Resource reads render `Key: value` blocks and
pipe-delimited tables (`ALL_CAPS` headers) — token-dense and parseable without
JSON. `--json` switches the profile commands to the shared **utility/v1** DTOs
from [cli-common](https://github.com/piekstra/cli-common): `summary` and
`accounts balance` emit a `utility-summary/v1` card, and `bills list`,
`payments list`, and `history list` emit `<record>-list/v1` envelopes with the
rows under `items` (narrow them with `--limit`/`--since`/`--until`). Elsewhere
`--json` is the raw FPL payload or a control-plane DTO (`auth status`, `info`,
and `fpl api`, which is always JSON). For the raw structure of a resource
read, pipe it through `fpl api`.

Data goes to stdout; diagnostics and confirmations go to stderr.

```sh
# Total customers out across all FPL counties:
fpl api GET https://www.fplmaps.com/customer/outage/CountyOutages.json \
  | jq '[.outages[] | (.["Customers Out"] | gsub(",";"") | tonumber)] | add'
```

### Global flags

| Flag | Meaning |
|------|---------|
| `-a, --account <number>` | Account to act on (else active account → first account) |
| `--username <email>` | Login (else config → `$FPL_USERNAME`) |
| `-v, --verbose` | Extra diagnostics on stderr (never secrets) |
| `-q, --quiet` | Suppress non-error stderr output |

### Environment variables

| Var | Purpose |
|-----|---------|
| `FPL_USERNAME` | Default login email |
| `FPL_ACCOUNT` | Default account number |

Secrets never enter through an env var the CLI reads at runtime — pass them to
`init`/`set-credential` via `--password-from-env` / `--from-env` at setup time.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Unexpected / keychain error |
| `2` | Usage error (bad input, unconfirmed payment) |
| `3` | Authentication required or rejected |
| `4` | Not found (unknown account, empty result) |
| `5` | Network / upstream error |

## Regional support

Works for standard FPL (**"main region"**) accounts. Former **Gulf Power**
accounts in Northwest Florida use a different AWS Cognito login flow and aren't
supported yet — contributions welcome.

## Disclaimer

Unofficial and not affiliated with, endorsed by, or supported by Florida Power &
Light. It uses undocumented endpoints that can change or break at any time. Use
it with your own account, at personal scale, and within FPL's Terms of Service.
No warranty — see the license.

## License

Dual-licensed under **MIT OR Apache-2.0**. See [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE).
