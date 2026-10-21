# Architecture and command flow

`fpl` is a single-binary CLI. Command handlers use shared CLI-family crates for
common behavior, while `client.rs` owns the FPL HTTP session and endpoint
operations. The diagrams below show the main runtime components and the
decision path for a command.

## Architecture

```mermaid
flowchart LR
    User["User / shell"]
    Binary["fpl binary<br/>main.rs"]
    Cli["CLI parser<br/>cli.rs · clap"]
    Dispatch["Command dispatcher<br/>main.rs"]
    Handlers["Command handlers<br/>commands/*.rs"]
    Context["Shared invocation context<br/>commands::Ctx"]
    Config["Preferences<br/>config.json"]
    Secrets["Credential store<br/>OS keychain"]
    Shared["Shared CLI behavior<br/>pk-cli-* crates"]
    Client["FPL HTTP client<br/>client.rs"]
    Portal["FPL JSON services<br/>www.fpl.com"]
    Outages["Public outage feed<br/>fplmaps.com"]
    Output["Output rendering<br/>output.rs"]
    Terminal["stdout / stderr<br/>exit status"]

    User --> Binary --> Cli --> Dispatch --> Handlers
    Dispatch --> Context
    Context --> Config
    Handlers --> Context
    Handlers --> Client
    Handlers --> Outages
    Context --> Secrets
    Context --> Client
    Client --> Portal
    Outages --> Output
    Portal --> Client --> Handlers
    Handlers --> Output
    Shared -. "config, keychain, errors,<br/>self-update, DTOs" .-> Config
    Shared -.-> Secrets
    Shared -.-> Output
    Shared -.-> Dispatch
    Output --> Terminal
    Dispatch -->|"errors"| Output
```

Resource handlers keep domain-specific orchestration. `Ctx` resolves the
username, opens authenticated sessions, and chooses the account; the client
handles login, cookies, JWT headers, and HTTP responses. `output.rs` renders
text or JSON, while errors are reported with the CLI's stable exit-code
contract.

## Command flow

```mermaid
flowchart TD
    Start([Run fpl command]) --> Parse["Parse args and global options"]
    Parse --> Load["Load non-secret config"]
    Load --> Route{"Which command?"}

    Route -->|init / auth login| Ingress["Read password from prompt,<br/>stdin, or environment"]
    Ingress --> Store["Store password in OS keychain"]
    Store --> Verify{"Verify requested?"}
    Verify -->|yes| Login["Login to FPL"]
    Verify -->|no| SaveSetup["Save non-secret preferences"]
    Login --> HasAccount{"Default account configured?"}
    HasAccount -->|yes| SaveSetup
    HasAccount -->|no| Discover["List accounts and select<br/>the first, when available"]
    Discover --> SaveSetup
    SaveSetup --> SetupOutput["Emit setup result"]

    Route -->|set-credential / auth set-credential| CredentialIngress["Read secret from stdin<br/>or environment"]
    CredentialIngress --> CredentialStore["Store password in OS keychain"]
    CredentialStore --> SetupOutput

    Route -->|config / auth status / auth logout / info / completions / self-update| Control["Run local or shared control command"]
    Control --> ControlOutput["Emit result"]

    Route -->|outages| Public["Fetch public outage data<br/>(no login)"]
    Public --> Render["Render text or JSON"]

    Route -->|account, lookup, and other authenticated commands| Username["Resolve username<br/>CLI/env, then config"]
    Username --> Keychain["Read password from OS keychain"]
    Keychain --> LoginSession["Login; retain JWT and cookies"]
    LoginSession --> Account{"Needs an account?"}
    Account -->|yes| ResolveAccount["Resolve account<br/>positional, --account/env,<br/>config, then first account"]
    Account -->|no| Request
    ResolveAccount --> Request["Handler calls FPL endpoint"]
    Request --> ParseResponse["Handle HTTP status<br/>and parse JSON"]
    ParseResponse --> Render

    SetupOutput --> Done([Exit])
    ControlOutput --> Done
    Render --> Done
    Username -. "missing username/credential" .-> Error["Report error and stable exit code"]
    Keychain -.-> Error
    LoginSession -. "auth/network failure" .-> Error
    Request -. "HTTP/network failure" .-> Error
    ParseResponse -. "invalid response" .-> Error
    Error --> Done
```

The exact FPL login endpoints, session behavior, and resource mappings are
documented in [api.md](./api.md).

`lookup cities` and `lookup zips` use public FPL reference endpoints but still
open a session through the current command handler. `auth logout` makes a
best-effort server-side logout when a session can be opened; with `--forget`, it
skips provider login and clears the local credential and config directly.
