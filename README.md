# agent-keychain

Project-scoped credential and browser-session isolation for local AI agent workflows on macOS.

[![CI](https://github.com/brynary/agent-keychain/actions/workflows/ci.yml/badge.svg)](https://github.com/brynary/agent-keychain/actions/workflows/ci.yml)

`agent-keychain` is a Swift command-line tool for storing agent credentials in a project-specific security boundary. It manages small secrets, encrypted APFS sparsebundle volumes, Chrome profile directories inside those volumes, role-based policy, and a project-local audit log.

The tool is intentionally local-first. It does not provide remote secret management, a brokered API gateway, or complete protection against malware running as the current macOS user.

## Requirements

- macOS 14 or newer
- Google Chrome for managed browser profile launches
- Touch ID or another macOS user-presence method for sensitive production flows
- Swift Package Manager for source builds, `--HEAD` installs, and development

## Install

Install from Homebrew:

```sh
brew tap brynary/agent-keychain ssh://git@github.com/brynary/agent-keychain.git
brew install brynary/agent-keychain/agent-keychain
```

Stable release tags update the Homebrew formula with prebuilt macOS release assets automatically after the GitHub Release workflow succeeds.

Build from source:

```sh
swift build -c release --product agent-keychain
```

Run the built executable:

```sh
.build/release/agent-keychain status
```

During development, use:

```sh
swift run agent-keychain -- status
```

## Quick Start

Initialize a project:

```sh
agent-keychain init --project-name my-project
```

Create the role or roles your project needs:

```sh
agent-keychain role create regular \
  --reason "Create regular role for day-to-day agent work" \
  --description "Day-to-day lower-risk work"
```

Add a secret for regular agent work:

```sh
agent-keychain secret set github-readonly \
  --role regular \
  --reason "Add GitHub token for regular agent work"
```

Run an agent command with that secret injected:

```sh
agent-keychain run \
  --role regular \
  --secret GITHUB_TOKEN=github-readonly \
  -- agent-command
```

Create an encrypted browser volume and profile:

```sh
agent-keychain volume create RegularBrowser \
  --role regular \
  --size 20g \
  --reason "Create encrypted browser volume for regular sessions"
```

```sh
agent-keychain browser create GitHub \
  --role regular \
  --volume RegularBrowser \
  --reason "Create GitHub browser profile for regular work"
```

Open the isolated browser profile with the low-level passthrough command:

```sh
agent-keychain browser open GitHub
```

Use the managed headed-to-headless workflow when a human needs to authenticate first and an agent then needs the same encrypted Chrome profile through local CDP:

```sh
agent-keychain browser headed GitHub \
  --url https://github.com \
  --cdp-port 9222 \
  --reason "Authenticate GitHub in the managed browser profile"
```

After login, stop the visible browser:

```sh
agent-keychain browser stop GitHub
```

Start the same profile headlessly for local automation:

```sh
agent-keychain browser headless GitHub \
  --url about:blank \
  --cdp-port 9222 \
  --reason "Reuse authenticated GitHub profile for approved automation"
```

Inspect CDP attach details or human-readable session status:

```sh
agent-keychain browser cdp GitHub
agent-keychain browser session GitHub
```

Stop Chrome and lock the backing volume:

```sh
agent-keychain browser stop GitHub --lock-volume
```

Print the managed Chrome profile path for another launcher:

```sh
agent-keychain browser path GitHub
```

Pass additional guarded Chrome arguments after `--`:

```sh
agent-keychain browser open GitHub -- \
  --remote-debugging-port=9222 \
  https://github.com
```

## Project State

Each project stores local state under `.agent-keychain/`:

```text
.agent-keychain/
  config.json
  config.integrity.json
  audit.jsonl
  locks/
  keychains/
    roles/
  sessions/
  volumes/
```

The repository ignores local keychains, volumes, locks, the audit log, and the integrity file. Treat `.agent-keychain/config.json` as local config unless your project deliberately commits it.

## Roles

`agent-keychain` does not create roles by default. Define role names and policy explicitly for each project.

Example roles:

- `regular`: day-to-day lower-risk work.
- `workspace-admin`: identity and workspace administration.
- `finance`: money movement and billing workflows.

Roles own their own secrets, volumes, and browser profiles. Commands that use one configured resource infer the owning role from trusted config. Commands that create ownership, delete resources, update project policy, or run a child process require an explicit role and/or reason as shown below.

## Commands

Project commands:

```sh
agent-keychain init [--project-name NAME]
agent-keychain status
agent-keychain config path
agent-keychain config trust-current --reason TEXT
```

Role commands:

```sh
agent-keychain role create NAME --reason TEXT [options]
agent-keychain role list
agent-keychain role show NAME
agent-keychain role unlock NAME [--reason TEXT]
agent-keychain role lock NAME
agent-keychain role update NAME --reason TEXT --description TEXT
agent-keychain role delete NAME --reason TEXT
```

Secret commands:

```sh
agent-keychain secret set NAME --role ROLE --reason TEXT
agent-keychain secret get NAME [--reason TEXT]
agent-keychain secret list [--role ROLE]
agent-keychain secret delete NAME --role ROLE --reason TEXT
```

Volume commands:

```sh
agent-keychain volume create NAME --role ROLE --size SIZE --reason TEXT [--path PATH]
agent-keychain volume unlock NAME [--reason TEXT]
agent-keychain volume lock NAME
agent-keychain volume status [NAME]
agent-keychain volume delete NAME --role ROLE --reason TEXT
```

Browser commands:

```sh
agent-keychain browser create NAME --role ROLE --volume VOLUME --reason TEXT
agent-keychain browser open NAME [--reason TEXT] [-- CHROME_ARG...]
agent-keychain browser headed NAME --url URL --cdp-port PORT [--reason TEXT]
agent-keychain browser headless NAME --url URL --cdp-port PORT [--reason TEXT]
agent-keychain browser stop NAME [--lock-volume]
agent-keychain browser cdp NAME
agent-keychain browser session NAME
agent-keychain browser path NAME [--reason TEXT]
agent-keychain browser list [--role ROLE]
agent-keychain browser delete NAME --role ROLE --reason TEXT
```

Run command:

```sh
agent-keychain run \
  --role ROLE \
  [--reason TEXT] \
  --secret ENV_NAME=SECRET_NAME \
  [--secret ENV_NAME=SECRET_NAME]... \
  -- COMMAND [ARGS...]
```

`run` injects one or more same-role secrets into the child process environment.
Use `volume unlock`, `volume lock`, `browser open`, and the managed browser lifecycle commands explicitly for encrypted volume and browser workflows.

## Security Model

See [docs/security-model.md](docs/security-model.md) for the detailed threat model, role keychain storage, APFS volume rules, audit guarantees, and limitations.

The short version:

- Secret values never live in `config.json`.
- Disk-image passwords never live in `config.json`.
- Role-owned secrets and disk-image passwords live in per-role keychains.
- Role keychain passwords are stored in the login keychain behind user presence; each role unlock has a 5-minute TTL.
- Passwords are passed to `hdiutil` through standard input, not arguments.
- Chrome launches with `--user-data-dir` inside a managed encrypted volume.
- Chrome passthrough arguments cannot override the managed profile path, and remote debugging addresses are restricted to loopback.
- Managed headed/headless browser commands keep browser auth state in the encrypted Chrome profile and do not export cookies, storage state, tokens, page text, or site data.
- The project audit log records policy decisions and sensitive operations.
- Mounted volumes and injected environment variables are available to user-level processes.

## Testing

See [docs/testing.md](docs/testing.md) for details.

Run the full local verification set:

```sh
swift build
swift run agent-keychain-test-runner
swift build --product agent-keychain
swift run agent-keychain-black-box-test-runner
```

GitHub Actions runs the same build and test layers on `main` and pull requests.

## License

MIT. See [LICENSE](LICENSE).
