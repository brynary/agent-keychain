import AgentKeychainCore
import Foundation

struct TestFailure: Error, CustomStringConvertible {
    let description: String
}

struct ProcessResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

final class TemporaryDirectory {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agent-keychain-black-box-tests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }
}

func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw TestFailure(description: message)
    }
}

func expectEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String) throws {
    if actual != expected {
        throw TestFailure(description: "\(message): expected \(expected), got \(actual)")
    }
}

func expectContains(_ text: String, _ expected: String, _ message: String) throws {
    try expect(text.contains(expected), "\(message): expected to contain \(expected), got \(text)")
}

func expectNotContains(_ text: String, _ unexpected: String, _ message: String) throws {
    try expect(!text.contains(unexpected), "\(message): should not contain \(unexpected)")
}

func occurrenceCount(in text: String, of needle: String) -> Int {
    text.components(separatedBy: needle).count - 1
}

func agentKeychainExecutable() throws -> URL {
    if let path = ProcessInfo.processInfo.environment["AGENT_KEYCHAIN_EXECUTABLE"] {
        return URL(fileURLWithPath: path)
    }
    let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        .appendingPathComponent(".build/debug/agent-keychain")
    guard FileManager.default.isExecutableFile(atPath: url.path) else {
        throw TestFailure(description: "missing executable at \(url.path); run swift build --product agent-keychain first")
    }
    return url
}

func runAgentKeychain(
    _ arguments: [String],
    workingDirectory: URL,
    stateURL: URL,
    secret: String? = nil
) throws -> ProcessResult {
    let process = Process()
    process.executableURL = try agentKeychainExecutable()
    process.arguments = arguments
    process.currentDirectoryURL = workingDirectory

    var environment = ProcessInfo.processInfo.environment
    environment["AGENT_KEYCHAIN_BLACK_BOX_STATE"] = stateURL.path
    if let secret {
        environment["AGENT_KEYCHAIN_BLACK_BOX_SECRET"] = secret
    } else {
        environment.removeValue(forKey: "AGENT_KEYCHAIN_BLACK_BOX_SECRET")
    }
    process.environment = environment

    let stdout = Pipe()
    let stderr = Pipe()
    process.standardOutput = stdout
    process.standardError = stderr

    try process.run()
    process.waitUntilExit()

    return ProcessResult(
        exitCode: process.terminationStatus,
        stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
        stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    )
}

func configURL(projectRoot: URL) -> URL {
    projectRoot.appendingPathComponent(".agent-keychain/config.json")
}

func auditURL(projectRoot: URL) -> URL {
    projectRoot.appendingPathComponent(".agent-keychain/audit.jsonl")
}

func readConfig(projectRoot: URL) throws -> ProjectConfig {
    try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL(projectRoot: projectRoot)))
}

func writeConfig(_ config: ProjectConfig, projectRoot: URL) throws {
    try config.canonicalData().write(to: configURL(projectRoot: projectRoot))
}

func readAudit(projectRoot: URL) throws -> String {
    try String(contentsOf: auditURL(projectRoot: projectRoot), encoding: .utf8)
}

func readState(_ stateURL: URL) throws -> BlackBoxTestState {
    try BlackBoxTestState.load(from: stateURL)
}

func writeState(_ state: BlackBoxTestState, to stateURL: URL) throws {
    try state.save(to: stateURL)
}

func createExampleRolesFixture(projectRoot: URL, stateURL: URL) throws {
    let regular = try runAgentKeychain([
        "role", "create", "regular",
        "--reason", "Create regular example role",
        "--description", "Day-to-day low-risk agent work",
    ], workingDirectory: projectRoot, stateURL: stateURL)
    try expectEqual(regular.exitCode, 0, "regular role fixture")

    let workspaceAdmin = try runAgentKeychain([
        "role", "create", "workspace-admin",
        "--reason", "Create workspace admin example role",
        "--description", "Identity and workspace administration",
    ], workingDirectory: projectRoot, stateURL: stateURL)
    try expectEqual(workspaceAdmin.exitCode, 0, "workspace-admin role fixture")

    let finance = try runAgentKeychain([
        "role", "create", "finance",
        "--reason", "Create finance example role",
        "--description", "Money movement and financial administration",
    ], workingDirectory: projectRoot, stateURL: stateURL)
    try expectEqual(finance.exitCode, 0, "finance role fixture")
}

func initializeProject(_ temp: TemporaryDirectory, stateURL: URL, name: String = "demo", createExampleRoles: Bool = true) throws {
    let result = try runAgentKeychain(["init", "--project-name", name], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(result.exitCode, 0, "init exit code")
    if createExampleRoles {
        try createExampleRolesFixture(projectRoot: temp.url, stateURL: stateURL)
    }
}

func trustEditedConfig(projectRoot: URL, stateURL: URL, reason: String) throws {
    let result = try runAgentKeychain(
        ["config", "trust-current", "--reason", reason],
        workingDirectory: projectRoot,
        stateURL: stateURL
    )
    try expectEqual(result.exitCode, 0, "trust-current exit code")
}

func setVolumeMountpoint(projectRoot: URL, stateURL: URL, volumeName: String, mountpoint: String) throws {
    var config = try readConfig(projectRoot: projectRoot)
    guard config.volumes[volumeName] != nil else {
        throw TestFailure(description: "missing volume \(volumeName)")
    }
    config.volumes[volumeName]?.mountpoint = mountpoint
    try writeConfig(config, projectRoot: projectRoot)
    try trustEditedConfig(projectRoot: projectRoot, stateURL: stateURL, reason: "Trust black-box mountpoint edit")
}

func testBlackBoxBackendHealthcheck() throws {
    let temp = try TemporaryDirectory()
    let stateURL = temp.url.appendingPathComponent("state.json")

    let result = try runAgentKeychain(
        ["__test-backend-healthcheck"],
        workingDirectory: temp.url,
        stateURL: stateURL
    )

    try expectEqual(result.exitCode, 0, "test backend healthcheck exit code")
    try expectContains(result.stdout, "agent-keychain black-box backend ready", "healthcheck stdout")
}

func testProjectLifecycle() throws {
    let physical = try TemporaryDirectory()
    let physicalStateURL = physical.url.appendingPathComponent("state.json")

    try initializeProject(physical, stateURL: physicalStateURL, createExampleRoles: false)

    let projectDir = physical.url.appendingPathComponent(".agent-keychain")
    try expect(FileManager.default.fileExists(atPath: projectDir.path), "init should create .agent-keychain")
    try expect(FileManager.default.fileExists(atPath: projectDir.appendingPathComponent("locks").path), "init should create locks")
    try expect(FileManager.default.fileExists(atPath: projectDir.appendingPathComponent("config.integrity.json").path), "init should create integrity")
    let config = try readConfig(projectRoot: physical.url)

    let state = try readState(physicalStateURL)
    try expectEqual(state.roleKeychainCreations.count, 0, "init should not create role keychains before roles exist")
    try expectEqual(state.rolePasswords.count, 0, "init should not store role keychain passwords before roles exist")

    let status = try runAgentKeychain(["status"], workingDirectory: physical.url, stateURL: physicalStateURL)
    try expectEqual(status.exitCode, 0, "status exit code")
    try expectNotContains(status.stdout, "Project keychain:", "status should not report legacy project keychain")

    let path = try runAgentKeychain(["config", "path"], workingDirectory: physical.url, stateURL: physicalStateURL)
    try expectEqual(path.stdout, configURL(projectRoot: physical.url).path + "\n", "config path stdout")

    let nested = physical.url.appendingPathComponent("nested/worktree", isDirectory: true)
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    let discoveredStatus = try runAgentKeychain(["status"], workingDirectory: nested, stateURL: physicalStateURL)
    try expectEqual(discoveredStatus.exitCode, 0, "discovered status exit code")
    try expectContains(discoveredStatus.stdout, "Root: \(config.project.root)", "upward project discovery")

    let outside = try TemporaryDirectory()
    let explicitPath = try runAgentKeychain([
        "--project", physical.url.path,
        "config", "path"
    ], workingDirectory: outside.url, stateURL: physicalStateURL)
    try expectEqual(explicitPath.stdout, configURL(projectRoot: physical.url).path + "\n", "explicit project config path")

    let audit = try readAudit(projectRoot: physical.url)
    try expectContains(audit, "\"event\":\"project_initialized\"", "init audit")
    try expectNotContains(audit, "black-box-generated-password", "audit should not contain generated password")
}

func testConfigTrustAndCommandLifecycle() throws {
    let temp = try TemporaryDirectory()
    let stateURL = temp.url.appendingPathComponent("state.json")
    try initializeProject(temp, stateURL: stateURL)

    let set = try runAgentKeychain([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token for integrity check",
    ], workingDirectory: temp.url, stateURL: stateURL, secret: "ghp_black_box_integrity")
    try expectEqual(set.exitCode, 0, "integrity run fixture secret")

    var config = try readConfig(projectRoot: temp.url)
    config.roles["regular"]?.description = "Trusted black-box manual edit"
    try writeConfig(config, projectRoot: temp.url)

    let rejected = try runAgentKeychain(
        [
            "run",
            "--role", "regular",
            "--secret", "GITHUB_TOKEN=github-readonly",
            "--", "agent-command"
        ],
        workingDirectory: temp.url,
        stateURL: stateURL
    )
    try expectEqual(rejected.exitCode, 1, "tampered run exit code")
    try expectContains(rejected.stderr, "Config integrity check failed", "tamper rejection")

    try trustEditedConfig(projectRoot: temp.url, stateURL: stateURL, reason: "Accept black-box manual edit")
    let accepted = try runAgentKeychain(
        [
            "run",
            "--role", "regular",
            "--secret", "GITHUB_TOKEN=github-readonly",
            "--", "agent-command"
        ],
        workingDirectory: temp.url,
        stateURL: stateURL
    )
    try expectEqual(accepted.exitCode, 0, "trusted run exit code")
    try expectEqual(accepted.stdout, "child stdout\n", "trusted run stdout")

    let lockURL = temp.url.appendingPathComponent(".agent-keychain/locks/config.lock")
    FileManager.default.createFile(atPath: lockURL.path, contents: Data("held".utf8))
    let lockedMutation = try runAgentKeychain([
        "role", "create", "ops",
        "--reason", "Add ops role",
        "--description", "Operations"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(lockedMutation.exitCode, 1, "locked mutation exit code")
    try expectContains(lockedMutation.stderr, "Config is locked by another agent-keychain process", "locked mutation stderr")
    try FileManager.default.removeItem(at: lockURL)

    let audit = try readAudit(projectRoot: temp.url)
    try expectContains(audit, "\"event\":\"config_tamper_detected\"", "tamper audit")
    try expectContains(audit, "\"event\":\"config_trust_baseline_updated\"", "trust audit")
    try expectContains(audit, "\"event\":\"config_mutation_failed\"", "config mutation failure audit")
    try expect(occurrenceCount(in: audit, of: "\"event\":\"command_started\"") >= 2, "audit should include command_started")
    try expect(occurrenceCount(in: audit, of: "\"event\":\"command_completed\"") >= 2, "audit should include command_completed")
}

func testRoleManagementCommands() throws {
    let temp = try TemporaryDirectory()
    let stateURL = temp.url.appendingPathComponent("state.json")
    try initializeProject(temp, stateURL: stateURL, createExampleRoles: false)

    let create = try runAgentKeychain([
        "role", "create", "analyst",
        "--reason", "Create analyst role",
        "--description", "Analysis work",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(create.exitCode, 0, "role create exit code")

    let list = try runAgentKeychain(["role", "list"], workingDirectory: temp.url, stateURL: stateURL)
    try expectContains(list.stdout, "analyst\n", "role list")

    let show = try runAgentKeychain(["role", "show", "analyst"], workingDirectory: temp.url, stateURL: stateURL)
    try expectContains(show.stdout, "\"description\":\"Analysis work\"", "role show")
    try expectNotContains(show.stdout, "requireReason", "role show should not include removed reason policy")
    try expectNotContains(show.stdout, "allowSecretExport", "role show should not include removed secret export policy")

    let update = try runAgentKeychain([
        "role", "update", "analyst",
        "--reason", "Update analyst description",
        "--description", "Analysis work updated",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(update.exitCode, 0, "role update exit code")

    let updated = try runAgentKeychain(["role", "show", "analyst"], workingDirectory: temp.url, stateURL: stateURL)
    try expectContains(updated.stdout, "\"description\":\"Analysis work updated\"", "updated role description")
    try expectNotContains(updated.stdout, "requireReason", "updated role should not include removed reason policy")
    try expectNotContains(updated.stdout, "allowSecretExport", "updated role should not include removed secret export policy")

    let missingDescription = try runAgentKeychain([
        "role", "update", "analyst",
        "--reason", "No-op role update",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(missingDescription.exitCode, 2, "role update without description exit code")
    try expectContains(missingDescription.stderr, "role update requires --description", "role update without description error")

    let removedRequireReasonFlag = try runAgentKeychain([
        "role", "update", "analyst",
        "--reason", "Try removed require reason flag",
        "--require-reason",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(removedRequireReasonFlag.exitCode, 2, "removed role update require reason flag exit code")

    let removedCreateFlag = try runAgentKeychain([
        "role", "create", "auditor",
        "--reason", "Create auditor role",
        "--deny-secret-export",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(removedCreateFlag.exitCode, 2, "removed role create export flag exit code")

    let removedUpdateFlag = try runAgentKeychain([
        "role", "update", "analyst",
        "--reason", "Try removed export flag",
        "--allow-secret-export",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(removedUpdateFlag.exitCode, 2, "removed role update export flag exit code")

    let delete = try runAgentKeychain([
        "role", "delete", "analyst",
        "--reason", "Remove analyst role"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(delete.exitCode, 0, "role delete exit code")

    let audit = try readAudit(projectRoot: temp.url)
    try expectContains(audit, "\"event\":\"role_created\"", "role created audit")
    try expectContains(audit, "\"event\":\"role_updated\"", "role updated audit")
    try expectContains(audit, "\"event\":\"role_deleted\"", "role deleted audit")

    let state = try readState(stateURL)
    try expect(state.authorizations.contains("Create analyst role"), "role create should authorize")
    try expect(state.authorizations.contains("Update analyst description"), "role update should authorize")
    try expect(state.authorizations.contains("Remove analyst role"), "role delete should authorize")
}

func testSecretCommandsAndPolicies() throws {
    let temp = try TemporaryDirectory()
    let stateURL = temp.url.appendingPathComponent("state.json")
    try initializeProject(temp, stateURL: stateURL)

    let setRegular = try runAgentKeychain([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
    ], workingDirectory: temp.url, stateURL: stateURL, secret: "ghp_black_box")
    try expectEqual(setRegular.exitCode, 0, "regular secret set")

    let list = try runAgentKeychain(["secret", "list", "--role", "regular"], workingDirectory: temp.url, stateURL: stateURL)
    try expectContains(list.stdout, "github-readonly\n", "secret list")

    let getRegular = try runAgentKeychain([
        "secret", "get", "github-readonly"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(getRegular.stdout, "ghp_black_box\n", "regular secret get")

    let setFinance = try runAgentKeychain([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key",
    ], workingDirectory: temp.url, stateURL: stateURL, secret: "mercury_black_box")
    try expectEqual(setFinance.exitCode, 0, "finance secret set")

    let rejectedRole = try runAgentKeychain([
        "secret", "get", "mercury-api-key",
        "--role", "regular"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(rejectedRole.exitCode, 2, "explicit role secret get exit code")
    try expectContains(rejectedRole.stderr, "secret get infers the role from secret ownership; omit --role", "explicit role secret stderr")

    let financeGet = try runAgentKeychain([
        "secret", "get", "mercury-api-key",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(financeGet.exitCode, 0, "finance secret get exit code")
    try expectEqual(financeGet.stdout, "mercury_black_box\n", "finance secret get stdout")

    let removedFlag = try runAgentKeychain([
        "secret", "get", "mercury-api-key",
        "--reason", "Review approved invoices",
        "--allow-raw-secret"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(removedFlag.exitCode, 2, "removed raw secret flag exit code")

    let delete = try runAgentKeychain([
        "secret", "delete", "github-readonly",
        "--role", "regular",
        "--reason", "Remove GitHub token"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(delete.exitCode, 0, "secret delete")

    let state = try readState(stateURL)
    try expectEqual(state.keychainItems["agent-keychain.role.finance.secret.mercury-api-key"], "mercury_black_box", "stored finance secret")
    try expect(state.deletedServices.contains("agent-keychain.role.regular.secret.github-readonly"), "deleted secret service")

    let audit = try readAudit(projectRoot: temp.url)
    try expectContains(audit, "\"event\":\"secret_set\"", "secret set audit")
    try expectContains(audit, "\"event\":\"secret_read\"", "secret read audit")
    try expectContains(audit, "\"event\":\"secret_delete\"", "secret delete audit")
    try expectNotContains(audit, "\"event\":\"raw_secret_stdout_override\"", "raw override audit should be removed")
    try expectNotContains(audit, "ghp_black_box", "audit should not contain regular secret")
    try expectNotContains(audit, "mercury_black_box", "audit should not contain finance secret")
}

func testVolumeCommandsAndPolicies() throws {
    let temp = try TemporaryDirectory()
    let stateURL = temp.url.appendingPathComponent("state.json")
    try initializeProject(temp, stateURL: stateURL)

    let create = try runAgentKeychain([
        "volume", "create", "RegularBrowser",
        "--role", "regular",
        "--size", "20g",
        "--reason", "Create regular browser volume",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(create.exitCode, 0, "volume create")

    let mountpoint = temp.url.appendingPathComponent("mounts/RegularBrowser").path
    try setVolumeMountpoint(projectRoot: temp.url, stateURL: stateURL, volumeName: "RegularBrowser", mountpoint: mountpoint)

    let statusBefore = try runAgentKeychain(["volume", "status", "RegularBrowser"], workingDirectory: temp.url, stateURL: stateURL)
    try expectContains(statusBefore.stdout, "RegularBrowser unmounted", "volume status before unlock")

    let unlock = try runAgentKeychain([
        "volume", "unlock", "RegularBrowser"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(unlock.exitCode, 0, "volume unlock")

    let statusAfter = try runAgentKeychain(["volume", "status", "RegularBrowser"], workingDirectory: temp.url, stateURL: stateURL)
    try expectContains(statusAfter.stdout, "RegularBrowser mounted", "volume status after unlock")

    var state = try readState(stateURL)
    state.busyMountpoints.append(mountpoint)
    try writeState(state, to: stateURL)

    let busyLock = try runAgentKeychain([
        "volume", "lock", "RegularBrowser"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(busyLock.exitCode, 0, "busy volume lock")
    try expectContains(busyLock.stdout, "Skipped locking volume RegularBrowser because mountpoint is busy", "busy lock stdout")

    state = try readState(stateURL)
    state.busyMountpoints.removeAll()
    try writeState(state, to: stateURL)

    let lock = try runAgentKeychain([
        "volume", "lock", "RegularBrowser"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(lock.exitCode, 0, "volume lock")

    let rejectedRole = try runAgentKeychain([
        "volume", "unlock", "RegularBrowser",
        "--role", "finance",
        "--reason", "Try wrong role"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(rejectedRole.exitCode, 2, "explicit role volume")
    try expectContains(rejectedRole.stderr, "volume unlock infers the role from resource ownership; omit --role", "explicit role volume stderr")

    let delete = try runAgentKeychain([
        "volume", "delete", "RegularBrowser",
        "--role", "regular",
        "--reason", "Remove regular browser volume"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(delete.exitCode, 0, "volume delete")

    state = try readState(stateURL)
    try expectEqual(state.createdImages.count, 1, "created image count")
    try expectEqual(state.attachedImages.count, 1, "attached image count")
    try expect(state.detachedMountpoints.contains(mountpoint), "detached mountpoint")
    try expect(state.deletedImages.contains { $0.hasSuffix(".agent-keychain/volumes/RegularBrowser.sparsebundle") }, "deleted image")

    let audit = try readAudit(projectRoot: temp.url)
    try expectContains(audit, "\"event\":\"volume_created\"", "volume created audit")
    try expectContains(audit, "\"event\":\"volume_unlock_succeeded\"", "volume unlock audit")
    try expectContains(audit, "\"event\":\"volume_lock_skipped_because_busy\"", "busy lock audit")
    try expectContains(audit, "\"event\":\"volume_lock_succeeded\"", "volume lock audit")
    try expectContains(audit, "\"event\":\"volume_deleted\"", "volume deleted audit")
}

func testBrowserCommandsAndIsolatedProfileLaunch() throws {
    let temp = try TemporaryDirectory()
    let stateURL = temp.url.appendingPathComponent("state.json")
    try initializeProject(temp, stateURL: stateURL)

    let createVolume = try runAgentKeychain([
        "volume", "create", "RegularBrowser",
        "--role", "regular",
        "--size", "20g",
        "--reason", "Create regular browser volume",
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(createVolume.exitCode, 0, "browser fixture volume")
    let mountpoint = temp.url.appendingPathComponent("mounts/RegularBrowser").path
    try setVolumeMountpoint(projectRoot: temp.url, stateURL: stateURL, volumeName: "RegularBrowser", mountpoint: mountpoint)

    let createBrowser = try runAgentKeychain([
        "browser", "create", "GitHub",
        "--role", "regular",
        "--volume", "RegularBrowser",
        "--reason", "Create GitHub browser profile"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(createBrowser.exitCode, 0, "browser create")

    let list = try runAgentKeychain(["browser", "list", "--role", "regular"], workingDirectory: temp.url, stateURL: stateURL)
    try expectContains(list.stdout, "GitHub\n", "browser list")

    let expectedUserData = mountpoint + "/ChromeProfiles/GitHub"
    let path = try runAgentKeychain([
        "browser", "path", "GitHub"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(path.exitCode, 0, "browser path")
    try expectEqual(path.stdout, expectedUserData + "\n", "browser path stdout")
    try expect(FileManager.default.fileExists(atPath: expectedUserData), "browser path should create profile directory")

    let rejectedRole = try runAgentKeychain([
        "browser", "open", "GitHub",
        "--role", "finance",
        "--reason", "Try wrong role"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(rejectedRole.exitCode, 2, "explicit role browser")
    try expectContains(rejectedRole.stderr, "browser open infers the role from resource ownership; omit --role", "explicit role browser stderr")

    let oldDetachFlag = try runAgentKeychain([
        "browser", "open", "GitHub",
        "--detach-on-exit",
        "--",
        "--headless=new",
        "--remote-debugging-port=9222",
        "about:blank"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(oldDetachFlag.exitCode, 2, "browser open detach-on-exit exit code")
    try expectContains(oldDetachFlag.stderr, "browser open no longer accepts --detach-on-exit", "browser open detach-on-exit stderr")

    let headed = try runAgentKeychain([
        "browser", "open", "GitHub",
        "--",
        "https://github.com"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(headed.exitCode, 0, "browser headed open")

    let open = try runAgentKeychain([
        "browser", "open", "GitHub",
        "--",
        "--headless=new",
        "--remote-debugging-port=9222",
        "about:blank"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(open.exitCode, 0, "browser open")

    let state = try readState(stateURL)
    try expectEqual(state.browserLaunches.map(\.userDataDir), [expectedUserData, expectedUserData], "browser launch profile")
    try expectEqual(state.browserLaunches.map(\.additionalArguments), [[
        "https://github.com"
    ], [
        "--headless=new",
        "--remote-debugging-port=9222",
        "about:blank",
        "--remote-debugging-address=127.0.0.1"
    ]], "browser launch arguments")
    try expect(!state.detachedMountpoints.contains(mountpoint), "browser open should leave volume mounted")

    let delete = try runAgentKeychain([
        "browser", "delete", "GitHub",
        "--role", "regular",
        "--reason", "Remove GitHub browser"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(delete.exitCode, 0, "browser delete")

    let audit = try readAudit(projectRoot: temp.url)
    try expectContains(audit, "\"event\":\"browser_created\"", "browser created audit")
    try expectContains(audit, "\"event\":\"browser_path_resolved\"", "browser path audit")
    try expectContains(audit, "\"event\":\"browser_opened\"", "browser opened audit")
    try expectNotContains(audit, "\"event\":\"browser_exited\"", "browser open should not audit unobserved exit")
    try expectContains(audit, "\"event\":\"browser_deleted\"", "browser deleted audit")
    try expectNotContains(audit, "--headless=new", "audit should not contain raw Chrome args")
    try expectNotContains(audit, "about:blank", "audit should not contain raw Chrome URL args")
}

func testRunCommandSecretInjectionAndRemovedResourceOptions() throws {
    let temp = try TemporaryDirectory()
    let stateURL = temp.url.appendingPathComponent("state.json")
    try initializeProject(temp, stateURL: stateURL)

    let setRegular = try runAgentKeychain([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
    ], workingDirectory: temp.url, stateURL: stateURL, secret: "ghp_run_secret")
    try expectEqual(setRegular.exitCode, 0, "run fixture regular secret")

    let runRegular = try runAgentKeychain([
        "run",
        "--role", "regular",
        "--secret", "GITHUB_TOKEN=github-readonly",
        "--", "agent-command", "--flag"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(runRegular.exitCode, 0, "regular run")
    try expectEqual(runRegular.stdout, "child stdout\n", "regular run stdout")

    var state = try readState(stateURL)
    try expectEqual(state.commandInvocations.last?.command, ["agent-command", "--flag"], "regular child command")
    try expectEqual(state.commandInvocations.last?.environment["GITHUB_TOKEN"], "ghp_run_secret", "regular child environment")

    let setFinance = try runAgentKeychain([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key",
    ], workingDirectory: temp.url, stateURL: stateURL, secret: "mercury_run_secret")
    try expectEqual(setFinance.exitCode, 0, "run fixture finance secret")

    let financeRun = try runAgentKeychain([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(financeRun.exitCode, 0, "finance env run")
    state = try readState(stateURL)
    let commandCountBeforeInvalidRuns = state.commandInvocations.count

    let removedFlag = try runAgentKeychain([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--allow-privileged-env",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(removedFlag.exitCode, 2, "removed privileged env flag")

    let volumeFlag = try runAgentKeychain([
        "run",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--", "agent-command"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(volumeFlag.exitCode, 2, "removed run volume flag")
    try expectContains(volumeFlag.stderr, "Unexpected run argument: --volume", "removed run volume stderr")

    let browserFlag = try runAgentKeychain([
        "run",
        "--role", "finance",
        "--browser", "Mercury",
        "--", "agent-command"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(browserFlag.exitCode, 2, "removed run browser flag")
    try expectContains(browserFlag.stderr, "Unexpected run argument: --browser", "removed run browser stderr")

    let detachFlag = try runAgentKeychain([
        "run",
        "--role", "finance",
        "--detach-on-exit",
        "--", "agent-command"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(detachFlag.exitCode, 2, "removed run detach flag")
    try expectContains(detachFlag.stderr, "Unexpected run argument: --detach-on-exit", "removed run detach stderr")

    let zeroSecret = try runAgentKeychain([
        "run",
        "--role", "finance",
        "--", "agent-command"
    ], workingDirectory: temp.url, stateURL: stateURL)
    try expectEqual(zeroSecret.exitCode, 2, "run zero secret")
    try expectContains(zeroSecret.stderr, "run requires at least one --secret", "run zero secret stderr")

    state = try readState(stateURL)
    try expectEqual(state.commandInvocations.count, commandCountBeforeInvalidRuns, "invalid run options must not invoke commands")
    try expectEqual(state.browserLaunches.count, 0, "run must not launch browsers")
    try expectEqual(state.attachedImages.count, 0, "run must not attach volumes")

    let audit = try readAudit(projectRoot: temp.url)
    try expectNotContains(audit, "\"event\":\"privileged_secret_export_override\"", "privileged secret export audit should be removed")
    try expectContains(audit, "\"event\":\"command_started\"", "run command started audit")
    try expectContains(audit, "\"event\":\"command_completed\"", "run command completed audit")
    try expectNotContains(audit, "ghp_run_secret", "audit should not contain regular run secret")
    try expectNotContains(audit, "mercury_run_secret", "audit should not contain finance run secret")
}

let tests: [(String, () throws -> Void)] = [
    ("testBlackBoxBackendHealthcheck", testBlackBoxBackendHealthcheck),
    ("testProjectLifecycle", testProjectLifecycle),
    ("testConfigTrustAndCommandLifecycle", testConfigTrustAndCommandLifecycle),
    ("testRoleManagementCommands", testRoleManagementCommands),
    ("testSecretCommandsAndPolicies", testSecretCommandsAndPolicies),
    ("testVolumeCommandsAndPolicies", testVolumeCommandsAndPolicies),
    ("testBrowserCommandsAndIsolatedProfileLaunch", testBrowserCommandsAndIsolatedProfileLaunch),
    ("testRunCommandSecretInjectionAndRemovedResourceOptions", testRunCommandSecretInjectionAndRemovedResourceOptions)
]

var failures = 0
for (name, test) in tests {
    do {
        try test()
        print("PASS \(name)")
    } catch {
        failures += 1
        print("FAIL \(name): \(error)")
    }
}

if failures > 0 {
    exit(1)
}

print("PASS \(tests.count) black-box tests")
