# Testing

This project uses two executable test runners.

## Core Command Tests

Run:

```sh
swift run agent-keychain-test-runner
```

This runner calls `AgentKeychainCLI` directly with fake dependencies. It exercises policy, config, audit, keychain, volume, browser, and run behavior without touching real Keychain, APFS images, Chrome, or child processes.

Use this runner for focused behavioral coverage and regression tests.

## Black-Box Integration Tests

Run:

```sh
swift build --product agent-keychain
swift run agent-keychain-black-box-test-runner
```

This runner launches the built `agent-keychain` executable as a child process. It verifies real process-boundary behavior:

- Argument parsing.
- Working-directory project discovery.
- `--project` override handling.
- Stdout and stderr.
- Filesystem side effects.
- Config and audit files.
- Command lifecycle events.
- Role, secret, volume, browser, and run workflows.

The black-box runner uses a debug-only backend selected by environment variables. That backend persists fake Keychain, APFS, browser, child-command, and user-presence state in a JSON file.

The debug backend is guarded by `#if DEBUG` and is not available in release builds.

## Full Local Verification

Run:

```sh
swift build
swift run agent-keychain-test-runner
swift build --product agent-keychain
swift run agent-keychain-black-box-test-runner
```

## GitHub Actions

CI runs on `main` and pull requests.

The workflow is:

```text
.github/workflows/ci.yml
```

It runs:

- `swift build`
- `swift run agent-keychain-test-runner`
- `swift build --product agent-keychain`
- `swift run agent-keychain-black-box-test-runner`

## Manual Production Checks

Avoid running production `init`, volume, or browser flows in automated tests. Those commands may create real local keychain state, APFS sparsebundles, Touch ID prompts, or Chrome processes.

Use manual production checks only when intentionally validating macOS integration on a local machine.
