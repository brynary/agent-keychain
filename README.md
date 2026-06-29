# agent-keychain

Project-scoped credential and browser-session isolation for local AI agent workflows on macOS.

[![CI](https://github.com/brynary/agent-keychain/actions/workflows/ci.yml/badge.svg)](https://github.com/brynary/agent-keychain/actions/workflows/ci.yml)

`agent-keychain` is a Swift command-line tool for storing agent credentials in a project-specific security boundary. It manages small secrets, encrypted APFS sparsebundle volumes, Chrome profile directories inside those volumes, role-based policy, and a project-local audit log.

The tool is intentionally local-first. It does not provide remote secret management, a brokered API gateway, or complete protection against malware running as the current macOS user.

## Requirements

- macOS 14 or newer
- Swift Package Manager
- Google Chrome for managed browser profile launches
- Touch ID or another macOS user-presence method for sensitive production flows

## Install

Install from Homebrew:

```sh
brew tap brynary/agent-keychain ssh://git@github.com/brynary/agent-keychain.git
brew install --HEAD brynary/agent-keychain/agent-keychain
```

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

Open the isolated browser profile:

```sh
agent-keychain browser open GitHub --role regular
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
  volumes/
```

The repository ignores local keychains, volumes, locks, the audit log, and the integrity file. Treat `.agent-keychain/config.json` as local config unless your project deliberately commits it.

## Roles

`agent-keychain` does not create roles by default. Define role names and policy explicitly for each project.

Example roles:

- `regular`: day-to-day lower-risk work, with secret export allowed.
- `workspace-admin`: identity and workspace administration, with reasons required and secret export denied.
- `finance`: money movement and billing workflows, with reasons required and secret export denied.

Roles own their own secrets, volumes, and browser profiles. A command running under one role cannot use another role's resources.

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
agent-keychain role update NAME --reason TEXT [options]
agent-keychain role delete NAME --reason TEXT
```

Secret commands:

```sh
agent-keychain secret set NAME --role ROLE --reason TEXT
agent-keychain secret get NAME --role ROLE [--reason TEXT] [--allow-raw-secret]
agent-keychain secret list [--role ROLE]
agent-keychain secret delete NAME --role ROLE --reason TEXT
```

Volume commands:

```sh
agent-keychain volume create NAME --role ROLE --size SIZE --reason TEXT [--path PATH]
agent-keychain volume unlock NAME --role ROLE [--reason TEXT]
agent-keychain volume lock NAME --role ROLE
agent-keychain volume status [NAME]
agent-keychain volume delete NAME --role ROLE --reason TEXT
```

Browser commands:

```sh
agent-keychain browser create NAME --role ROLE --volume VOLUME --reason TEXT
agent-keychain browser open NAME --role ROLE [--reason TEXT] [--detach-on-exit]
agent-keychain browser list [--role ROLE]
agent-keychain browser delete NAME --role ROLE --reason TEXT
```

Run command:

```sh
agent-keychain run \
  --role ROLE \
  [--reason TEXT] \
  [--secret ENV_NAME=SECRET_NAME]... \
  [--allow-privileged-env] \
  [--volume VOLUME]... \
  [--browser BROWSER]... \
  [--detach-on-exit] \
  -- COMMAND [ARGS...]
```

## Security Model

See [docs/security-model.md](docs/security-model.md) for the detailed threat model, project keychain storage, APFS volume rules, audit guarantees, and limitations.

The short version:

- Secret values never live in `config.json`.
- Disk-image passwords never live in `config.json`.
- Passwords are passed to `hdiutil` through standard input, not arguments.
- Chrome launches with `--user-data-dir` inside a managed encrypted volume.
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

No license has been added yet.
