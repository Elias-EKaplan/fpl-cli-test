mod browser;
mod cli;
mod client;
mod commands;
mod config;
mod dates;
mod error;
mod output;
mod secrets;
mod session;

use clap::Parser;

use cli::{Cli, Command};
use commands::Ctx;
use config::Config;
use error::AppError;

fn main() {
    let cli = Cli::parse();
    let json_mode = cli.json;
    if let Err(e) = run(cli) {
        std::process::exit(output::fail(&e, json_mode));
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    let cfg = Config::load()?;
    let ctx = Ctx {
        cli: &cli,
        cfg: &cfg,
    };
    match &cli.command {
        Command::Init(args) => commands::init::run(&ctx, args),
        Command::SetCredential(args) => commands::set_credential::run(&ctx, args),
        Command::Auth(cmd) => commands::auth::run(&ctx, cmd),
        Command::Config(cmd) => commands::config::run(&ctx, cmd),
        Command::Summary { account_id } => commands::summary::run(&ctx, account_id.as_deref()),
        Command::Accounts(cmd) => commands::accounts::run(&ctx, cmd),
        Command::Bills(cmd) => commands::bills::run(&ctx, cmd),
        Command::Documents(cmd) => commands::documents::run(&ctx, cmd),
        Command::Payments(cmd) => commands::payments::run(&ctx, cmd),
        Command::Usage(cmd) => commands::usage::run(&ctx, cmd),
        Command::History(cmd) => commands::history::run(&ctx, cmd),
        Command::Profile { account_id } => commands::profile::run(&ctx, account_id.as_deref()),
        Command::Meter { account_id } => commands::meter::run(&ctx, account_id.as_deref()),
        Command::Alerts { account_id } => commands::alerts::run(&ctx, account_id.as_deref()),
        Command::Lookup(cmd) => commands::lookup::run(&ctx, cmd),
        Command::Outages(cmd) => commands::outages::run(&ctx, cmd),
        Command::Api(args) => commands::api::run(&ctx, args),
        Command::SelfUpdate(args) => commands::update::run(&ctx, args),
        Command::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(*shell, &mut Cli::command(), "fpl", &mut std::io::stdout());
            Ok(())
        }
        Command::Info => commands::info(&ctx),
    }
}
