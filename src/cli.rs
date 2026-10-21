use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
pub use pk_cli_selfupdate::SelfUpdateArgs;
pub use pk_cli_utility::RangeArgs;

/// Manage your Florida Power & Light (FPL) account from the command line.
///
/// FPL publishes no official API; this talks to the same www.fpl.com JSON
/// services the website and mobile app use. Your password lives only in the OS
/// keychain — set it up with `fpl init` (or `fpl set-credential`), which read
/// the secret from stdin or an env var, never a flag.
///
/// Output is human- and agent-friendly text by default; resource reads render
/// key/value blocks and pipe-delimited tables. For a raw JSON payload (handy
/// while FPL's response shapes are still being mapped), use `fpl api`.
#[derive(Parser, Debug)]
#[command(name = "fpl", version, about, long_about = None)]
pub struct Cli {
    /// Emit machine-readable JSON on stdout (diagnostics go to stderr).
    #[arg(long, global = true)]
    pub json: bool,

    /// Account number to act on. Overrides the active account and $FPL_ACCOUNT.
    #[arg(short = 'a', long, global = true, env = "FPL_ACCOUNT")]
    pub account: Option<String>,

    /// FPL login (email). Falls back to config, then $FPL_USERNAME.
    #[arg(long, global = true, env = "FPL_USERNAME")]
    pub username: Option<String>,

    /// Extra diagnostics on stderr (never secrets).
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress non-error stderr output.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Disable ANSI color (reserved; output is currently plain).
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// First-time setup: verify credentials and store them in the keychain.
    ///
    /// Flag-driven and fully scriptable. Supply the password via
    /// `--password-stdin` or `--password-from-env`; there is no password flag.
    Init(InitArgs),

    /// Write a single credential to the keychain (rotation / headless setup).
    ///
    /// Reads the secret from `--stdin` or `--from-env <VAR>` (exactly one).
    /// Refuses to replace an existing entry unless `--overwrite` is given.
    SetCredential(SetCredentialArgs),

    /// Session and credential status.
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Non-secret settings: default username and active account.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// At-a-glance dashboard: balance, bill cycle, projected bill and usage.
    Summary {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },

    /// Accounts on your login: list, detail, active-account selection, balance.
    #[command(subcommand)]
    Accounts(AccountsCommand),

    /// Billing: current/projected bill, history, budget billing, PDF download.
    #[command(subcommand)]
    Bills(BillsCommand),

    /// Statement documents: list and download bill PDFs (documents/v1 profile).
    #[command(subcommand)]
    Documents(DocumentsCommand),

    /// Payments: history, saved methods, and making a payment.
    #[command(subcommand)]
    Payments(PaymentsCommand),

    /// Energy usage: current summary, hourly detail, appliance breakdown.
    #[command(subcommand)]
    Usage(UsageCommand),

    /// Account ledgers: transaction and deposit history.
    #[command(subcommand)]
    History(HistoryCommand),

    /// Account holder's contact profile (name, email, phone, mailing address).
    Profile {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },

    /// Smart-meter (AMI) status: reporting, breaker state, ping window.
    Meter {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },

    /// Account alert/banner state (balance alerts, collection thresholds).
    Alerts {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },

    /// Public FPL reference data (no login required).
    #[command(subcommand)]
    Lookup(LookupCommand),

    /// Public power-outage counts (no login required).
    #[command(subcommand)]
    Outages(OutagesCommand),

    /// Raw authenticated request to any FPL endpoint (returns JSON).
    ///
    /// Example: `fpl api GET /cs/customer/v1/resources/header`
    Api(ApiArgs),

    /// Update `fpl` to the latest release from GitHub.
    #[command(name = "self-update", alias = "update")]
    SelfUpdate(SelfUpdateArgs),

    /// Print a shell completion script (e.g. `fpl completions zsh`).
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Machine-readable capability discovery (cli-info/v1).
    Info,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Read the password from stdin (one line).
    #[arg(long)]
    pub password_stdin: bool,
    /// Read the password from a named environment variable.
    #[arg(long, value_name = "VAR")]
    pub password_from_env: Option<String>,
    /// Store the credentials without a live login check.
    #[arg(long)]
    pub no_verify: bool,
    /// Replace an existing stored password instead of failing.
    #[arg(long)]
    pub overwrite: bool,
    /// Never prompt; fail if a required input is missing.
    #[arg(long)]
    pub non_interactive: bool,
    /// Emit the result as JSON on stdout (confirmation still goes to stderr).
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SetCredentialArgs {
    /// Read the secret from stdin (one line).
    #[arg(long)]
    pub stdin: bool,
    /// Read the secret from a named environment variable.
    #[arg(long, value_name = "VAR")]
    pub from_env: Option<String>,
    /// Replace an existing entry instead of failing.
    #[arg(long)]
    pub overwrite: bool,
    /// Emit the result as JSON on stdout (confirmation still goes to stderr).
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Verify credentials and store them in the keychain (same as `fpl init`),
    /// or sign in with a passkey in a browser window (`--passkey`).
    Login(AuthLoginArgs),
    /// Write a single credential to the keychain (rotation / headless setup).
    SetCredential(SetCredentialArgs),
    /// Show configured username, active account, and keychain state.
    Status {
        /// Emit as JSON.
        #[arg(long)]
        json: bool,
    },
    /// End the FPL session and remove the stored password and saved passkey
    /// session.
    Logout {
        /// Clear saved username/account and remove the credential without logging in to FPL.
        #[arg(long)]
        forget: bool,
    },
}

#[derive(Args, Debug)]
pub struct AuthLoginArgs {
    #[command(flatten)]
    pub init: InitArgs,
    #[command(flatten)]
    pub passkey: PasskeyArgs,
}

/// Semi-automatic passkey login through a real browser window.
#[derive(Args, Debug, Default)]
pub struct PasskeyArgs {
    /// Sign in with a passkey in a browser window (Chrome, Edge, Brave, or
    /// Chromium), then reuse that session for later commands.
    ///
    /// The CLI opens FPL's login page with a persistent browser profile, fills
    /// your username, and clicks "sign in with passkey"; you approve the
    /// prompt (Touch ID, Windows Hello, security key, or phone). No password is
    /// stored. Later commands reuse the saved session until it expires.
    #[arg(
        long,
        conflicts_with_all = ["password_stdin", "password_from_env", "no_verify", "overwrite"]
    )]
    pub passkey: bool,
    /// Persistent browser profile directory (default: `browser-profile/`
    /// beside the config file; also $FPL_BROWSER_PROFILE or config
    /// `browser_profile_dir`).
    #[arg(long, value_name = "DIR")]
    pub profile_dir: Option<String>,
    /// Browser executable to drive (default: auto-detect; also config
    /// `browser_path`).
    #[arg(long, value_name = "EXE", env = "FPL_BROWSER")]
    pub browser_path: Option<String>,
    /// Run the browser without a window. Passkey prompts can't appear, so this
    /// only works while the profile is still signed in to FPL.
    #[arg(long, requires = "passkey")]
    pub headless: bool,
    /// Seconds to wait for the login to finish (default: 180, or config
    /// `browser_timeout`).
    #[arg(long, value_name = "SECS", requires = "passkey",
          value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: Option<u64>,
    /// Discard the saved session and clear FPL cookies in the profile first,
    /// forcing a fresh passkey sign-in.
    #[arg(long, requires = "passkey")]
    pub reset_session: bool,
    /// Override the FPL login page URL (troubleshooting, if FPL moves it).
    #[arg(long, value_name = "URL", requires = "passkey")]
    pub login_url: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print the resolved config file path.
    Path,
    /// Show the effective configuration.
    Show,
    /// Set a config key: `username`, `account`, `browser_profile_dir`,
    /// `browser_path`, or `browser_timeout`.
    Set { key: String, value: String },
    /// Remove a config key.
    Unset { key: String },
}

#[derive(Subcommand, Debug)]
pub enum AccountsCommand {
    /// List the accounts on your login.
    #[command(alias = "ls")]
    List,
    /// Show details for one account (defaults to the active account).
    Get {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
    /// Select the active account for subsequent commands.
    Use {
        /// Account number to make active.
        account_id: String,
    },
    /// Show the current balance and due date.
    Balance {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum BillsCommand {
    /// Prior bills (amounts, due dates, usage).
    #[command(alias = "ls")]
    List {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Current period: projected bill, bill-to-date, daily average.
    Get {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
    /// Projected end-of-cycle bill for the current period.
    Projected {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
    /// Budget Billing plan status and monthly graph.
    Budget {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
    /// Download a bill statement PDF.
    Download {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
        /// Bill date to download as YYYY-MM-DD (default: the most recent bill).
        #[arg(long)]
        date: Option<String>,
        /// Write the PDF here (default: ./fpl-bill-<account>-<date>.pdf; `-` for stdout).
        #[arg(long, short)]
        output: Option<String>,
    },
}

/// Statement documents (documents/v1). FPL addresses statements by bill date,
/// so a document's id is its ISO bill date — `documents download 2026-03-15`
/// is the same statement as `bills download --date 2026-03-15`.
#[derive(Subcommand, Debug)]
pub enum DocumentsCommand {
    /// List statement documents, newest first (document-list/v1).
    #[command(alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Download a statement PDF by id (its bill date), or every one with --all.
    #[command(alias = "get")]
    Download {
        /// Document id from `documents list` — the bill date, `YYYY-MM-DD`.
        /// Omit to take the most recent; use `--all` for every statement.
        id: Option<String>,
        /// Download every statement (write to a directory with `-o`).
        #[arg(long, conflicts_with = "id")]
        all: bool,
        /// Write here: a file or `-` for stdout (single id), or a directory
        /// (with `--all`). Default: `./fpl-bill-<account>-<date>.pdf`.
        #[arg(long, short)]
        output: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PaymentsCommand {
    /// Payment history (from the account ledger).
    #[command(alias = "ls")]
    List {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// List saved payment methods / options.
    Methods {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
    /// Make a payment. Prompts for confirmation unless `--force` is given.
    Create {
        /// Amount in dollars, e.g. 123.45.
        #[arg(long)]
        amount: String,
        /// Payment date as YYYY-MM-DD (default: today). Draws from the
        /// bank account on file (see `payments methods`).
        #[arg(long)]
        date: Option<String>,
        /// Account number (defaults to active / --account).
        #[arg(long)]
        account_id: Option<String>,
        /// Skip the confirmation prompt (submits the payment).
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum UsageCommand {
    /// Current-period energy summary (projected kWh, daily average, cost).
    Get {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
    /// Hourly usage for a single day.
    Hourly {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
        /// Day as MM-DD-YYYY (default: yesterday).
        #[arg(long)]
        date: Option<String>,
    },
    /// Appliance-level (disaggregated) usage for the latest bill period.
    Appliances {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum HistoryCommand {
    /// List ledger entries of a given kind.
    #[command(alias = "ls")]
    List {
        /// Account number (defaults to active / --account).
        account_id: Option<String>,
        /// Which ledger: account or deposit.
        #[arg(long, default_value = "account")]
        r#type: String,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// List the valid `--type` values for `history list`.
    Types,
}

#[cfg(test)]
mod tests {
    use super::{AuthCommand, Cli, Command};
    use clap::Parser;

    #[test]
    fn browser_helper_flag_is_not_available() {
        assert!(Cli::try_parse_from(["fpl", "auth", "login", "--browser"]).is_err());
        assert!(Cli::try_parse_from(["fpl", "init", "--browser"]).is_err());
    }

    #[test]
    fn passkey_login_options_parse() {
        let cli = Cli::try_parse_from([
            "fpl",
            "auth",
            "login",
            "--passkey",
            "--profile-dir",
            "/tmp/fpl-profile",
            "--browser-path",
            "/usr/bin/chromium",
            "--headless",
            "--timeout",
            "60",
            "--reset-session",
        ])
        .unwrap();
        let Command::Auth(AuthCommand::Login(args)) = cli.command else {
            panic!("expected auth login");
        };
        let p = args.passkey;
        assert!(p.passkey && p.headless && p.reset_session);
        assert_eq!(p.profile_dir.as_deref(), Some("/tmp/fpl-profile"));
        assert_eq!(p.browser_path.as_deref(), Some("/usr/bin/chromium"));
        assert_eq!(p.timeout, Some(60));
    }

    #[test]
    fn passkey_login_rejects_password_and_orphan_flags() {
        for argv in [
            &["fpl", "auth", "login", "--passkey", "--password-stdin"][..],
            &["fpl", "auth", "login", "--passkey", "--browser"],
            &["fpl", "auth", "login", "--passkey", "--timeout", "0"],
            // Browser-only knobs need --passkey.
            &["fpl", "auth", "login", "--headless"],
            &["fpl", "auth", "login", "--reset-session"],
            &["fpl", "init", "--passkey"],
        ] {
            assert!(Cli::try_parse_from(argv).is_err(), "{argv:?} should fail");
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum LookupCommand {
    /// Florida cities in FPL's service territory.
    Cities,
    /// Florida ZIP codes in FPL's service territory.
    Zips,
}

#[derive(Subcommand, Debug)]
pub enum OutagesCommand {
    /// County-level outage counts.
    #[command(alias = "ls")]
    List {
        /// Filter to counties whose name contains this text (case-insensitive).
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Args, Debug)]
pub struct ApiArgs {
    /// HTTP method: GET, POST, PUT, or DELETE.
    pub method: String,
    /// Path (leading slash, relative to https://www.fpl.com) or full URL.
    pub path: String,
    /// Request body as a JSON string (for POST/PUT).
    #[arg(long)]
    pub data: Option<String>,
}
