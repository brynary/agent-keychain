# Agent Keychain v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v0.1 macOS Swift CLI described by `SPEC.md` with project-local config, policy enforcement, keychain-backed secrets, encrypted volume commands, browser profile launch, run command support, and audit logging.

**Architecture:** Use a SwiftPM package with a small executable target and a testable `AgentKeychainCore` library. Core workflows depend on protocols for keychain, disk image, browser, process execution, prompts, and filesystem-sensitive operations so unit tests exercise policy and command behavior without touching real Touch ID, Keychain, APFS images, or Chrome. Production adapters implement the macOS behavior with Security/LocalAuthentication APIs and `Process`.

**Tech Stack:** Swift 6.2, Swift Package Manager, Swift executable test runner, Foundation, Security, LocalAuthentication, CryptoKit.

---

## File Structure

- Create `Package.swift`: SwiftPM manifest for `AgentKeychainCore`, `agent-keychain`, and `AgentKeychainTestRunner`.
- Create `Sources/agent-keychain/main.swift`: executable entrypoint that wires production dependencies.
- Create `Sources/AgentKeychainCore/Models.swift`: codable project config, roles, secrets, volumes, browser profiles, and validation.
- Create `Sources/AgentKeychainCore/Errors.swift`: typed user-facing errors and exit-code mapping.
- Create `Sources/AgentKeychainCore/Support.swift`: clock, random generator, SHA-256 helpers, atomic file helpers, command parsing helpers.
- Create `Sources/AgentKeychainCore/ProjectLocator.swift`: project discovery and `--project` override handling.
- Create `Sources/AgentKeychainCore/ConfigStore.swift`: canonical JSON, integrity file, tamper detection, atomic writes, config mutation helper.
- Create `Sources/AgentKeychainCore/AuditLog.swift`: JSONL audit writer with run IDs and hash chaining.
- Create `Sources/AgentKeychainCore/PolicyEngine.swift`: role/resource ownership, reason, raw secret exposure, privileged env, and mutation policy checks.
- Create `Sources/AgentKeychainCore/KeychainStores.swift`: protocols plus production login/project keychain implementations.
- Create `Sources/AgentKeychainCore/DiskImageStore.swift`: protocols plus production `hdiutil` create/attach/detach/status/lock behavior.
- Create `Sources/AgentKeychainCore/BrowserLauncher.swift`: protocol plus production Chrome process launcher.
- Create `Sources/AgentKeychainCore/CommandRunner.swift`: protocol plus production child process runner.
- Create `Sources/AgentKeychainCore/CLI.swift`: parser and command dispatch for all v0.1 commands.
- Create `Sources/AgentKeychainTestRunner/main.swift`: end-to-end command tests with fakes.

## Task 1: SwiftPM Skeleton

**Files:**
- Create: `Package.swift`
- Create: `Sources/agent-keychain/main.swift`
- Create: `Sources/AgentKeychainCore/Models.swift`
- Create: `Sources/AgentKeychainTestRunner/main.swift`

- [ ] **Step 1: Write the failing build/test baseline**

Add a test that imports `AgentKeychainCore` and calls a placeholder `AgentKeychainCLI`.

- [ ] **Step 2: Run test to verify it fails**

Run: `swift run agent-keychain-test-runner`

Expected: FAIL because `Package.swift` or `AgentKeychainCLI` does not exist.

- [ ] **Step 3: Add minimal package skeleton**

Create the SwiftPM manifest, executable entrypoint, empty core type, and compiling test target.

- [ ] **Step 4: Run test to verify it passes**

Run: `swift run agent-keychain-test-runner`

Expected: PASS.

## Task 2: Init, Config, Integrity, and Audit

**Files:**
- Create/Modify: `Sources/AgentKeychainCore/Models.swift`
- Create: `Sources/AgentKeychainCore/Support.swift`
- Create: `Sources/AgentKeychainCore/ConfigStore.swift`
- Create: `Sources/AgentKeychainCore/AuditLog.swift`
- Modify: `Sources/AgentKeychainCore/CLI.swift`
- Modify: `Sources/AgentKeychainTestRunner/main.swift`

- [ ] **Step 1: Write failing tests**

Cover `init --project-name demo`, explicit example roles, `.agent-keychain` layout, canonical config hash, integrity file, and audit events that never include secret values.

- [ ] **Step 2: Run tests to verify failure**

Run: `swift run agent-keychain-test-runner`

Expected: FAIL because init/config/audit behavior is missing.

- [ ] **Step 3: Implement minimal behavior**

Implement models, canonical JSON/hash helpers, atomic config/integrity writes, project initialization, and audit JSONL appends.

- [ ] **Step 4: Run tests to verify pass**

Run: `swift run agent-keychain-test-runner`

Expected: PASS.

## Task 3: Roles and Policy Enforcement

**Files:**
- Create: `Sources/AgentKeychainCore/Errors.swift`
- Create: `Sources/AgentKeychainCore/PolicyEngine.swift`
- Modify: `Sources/AgentKeychainCore/CLI.swift`
- Modify: `Sources/AgentKeychainTestRunner/main.swift`

- [ ] **Step 1: Write failing tests**

Cover `role create/list/show`, required mutation reasons, config tamper rejection for sensitive commands, role reason enforcement, and cross-role secret/browser/volume rejection messages.

- [ ] **Step 2: Run tests to verify failure**

Run: `swift run agent-keychain-test-runner`

Expected: FAIL because policy commands are missing.

- [ ] **Step 3: Implement minimal behavior**

Implement role commands and policy checks that run before touching keychain, disk images, browser profiles, or child processes.

- [ ] **Step 4: Run tests to verify pass**

Run: `swift run agent-keychain-test-runner`

Expected: PASS.

## Task 4: Secrets

**Files:**
- Create: `Sources/AgentKeychainCore/KeychainStores.swift`
- Modify: `Sources/AgentKeychainCore/CLI.swift`
- Modify: `Sources/AgentKeychainTestRunner/main.swift`

- [ ] **Step 1: Write failing tests**

Cover `secret set/get/list/delete`, no secret values in config or audit, no raw secret stdout for roles with `allowEnvInjection: false` unless `--allow-raw-secret --reason TEXT` is supplied, and fallback service names scoped by project.

- [ ] **Step 2: Run tests to verify failure**

Run: `swift run agent-keychain-test-runner`

Expected: FAIL because secret workflows are missing.

- [ ] **Step 3: Implement minimal behavior**

Implement keychain protocols, fake-friendly storage orchestration, metadata updates, raw secret policy, and production login/project keychain adapters.

- [ ] **Step 4: Run tests to verify pass**

Run: `swift run agent-keychain-test-runner`

Expected: PASS.

## Task 5: Volumes and Browsers

**Files:**
- Create: `Sources/AgentKeychainCore/DiskImageStore.swift`
- Create: `Sources/AgentKeychainCore/BrowserLauncher.swift`
- Modify: `Sources/AgentKeychainCore/CLI.swift`
- Modify: `Sources/AgentKeychainTestRunner/main.swift`

- [ ] **Step 1: Write failing tests**

Cover `volume create/unlock/lock/status`, `browser create/open/list`, generated volume passwords stored only in keychain, role-owned volume/profile enforcement, `hdiutil attach -stdinpass`, explicit mountpoints, and Chrome `--user-data-dir` under the mounted volume.

- [ ] **Step 2: Run tests to verify failure**

Run: `swift run agent-keychain-test-runner`

Expected: FAIL because volume/browser workflows are missing.

- [ ] **Step 3: Implement minimal behavior**

Implement disk image and browser protocols, production process adapters, metadata writes, profile directory creation, and detach-on-exit hooks for supervised commands.

- [ ] **Step 4: Run tests to verify pass**

Run: `swift run agent-keychain-test-runner`

Expected: PASS.

## Task 6: Run Command and Status

**Files:**
- Create: `Sources/AgentKeychainCore/CommandRunner.swift`
- Create/Modify: `Sources/AgentKeychainCore/ProjectLocator.swift`
- Modify: `Sources/AgentKeychainCore/CLI.swift`
- Modify: `Sources/AgentKeychainTestRunner/main.swift`

- [ ] **Step 1: Write failing tests**

Cover `status`, `config path`, `config trust-current`, `run --role ... --secret ENV=NAME -- COMMAND`, privileged env override rejection/allowance, explicit `--project`, missing project discovery, and command-start/completed/failed audit events.

- [ ] **Step 2: Run tests to verify failure**

Run: `swift run agent-keychain-test-runner`

Expected: FAIL because run/status/project behavior is missing.

- [ ] **Step 3: Implement minimal behavior**

Implement project location, status rendering, config trust, child process execution with injected environment, and supervised volume/browser setup for run.

- [ ] **Step 4: Run tests to verify pass**

Run: `swift run agent-keychain-test-runner`

Expected: PASS.

## Task 7: Verification Against SPEC.md

**Files:**
- Modify as needed after audit.

- [ ] **Step 1: Run full tests**

Run: `swift run agent-keychain-test-runner`

Expected: PASS with no unexpected warnings that indicate broken behavior.

- [ ] **Step 2: Build executable**

Run: `swift build`

Expected: PASS.

- [ ] **Step 3: Exercise safe local CLI flows**

Run init/status/role/list/config-path commands in a temporary directory. Do not create real APFS images or request Touch ID in automated verification.

- [ ] **Step 4: Audit SPEC.md coverage**

Map each v0.1 requirement to implementation, test evidence, or an explicit deferred non-goal. Fix any missing v0.1 requirement before completion.
