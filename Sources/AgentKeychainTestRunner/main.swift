import AgentKeychainCore
import Foundation
import CryptoKit

struct TestFailure: Error, CustomStringConvertible {
    let description: String
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

func occurrenceCount(in text: String, of needle: String) -> Int {
    text.components(separatedBy: needle).count - 1
}

final class TemporaryDirectory {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agent-keychain-tests")
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }
}

final class RecordingKeychainStore: KeychainStoring {
    struct ProjectPassword {
        let service: String
        let password: String
    }

    var projectPasswords: [ProjectPassword] = []
    var secrets: [String: String] = [:]
    var deletedServices: [String] = []
    var failingReadServices: Set<String> = []

    func storeProjectKeychainPassword(service: String, password: String) throws {
        projectPasswords.append(ProjectPassword(service: service, password: password))
    }

    func storeGenericPassword(service: String, value: String) throws {
        secrets[service] = value
    }

    func readGenericPassword(service: String) throws -> String {
        if failingReadServices.contains(service) {
            throw AgentKeychainError.filesystem("simulated keychain read failure")
        }
        guard let value = secrets[service] else {
            throw TestFailure(description: "missing keychain value for \(service)")
        }
        return value
    }

    func deleteGenericPassword(service: String) throws {
        deletedServices.append(service)
        secrets.removeValue(forKey: service)
    }
}

final class FailingPhysicalKeychainStore: KeychainStoring, ProjectKeychainPreparing {
    var projectPasswords: [String] = []
    var secrets: [String: String] = [:]

    func createProjectKeychain(path: String, password: String) throws {
        throw AgentKeychainError.filesystem("physical keychain unavailable in test")
    }

    func storeProjectKeychainPassword(service: String, password: String) throws {
        projectPasswords.append(password)
    }

    func storeGenericPassword(service: String, value: String) throws {
        secrets[service] = value
    }

    func readGenericPassword(service: String) throws -> String {
        secrets[service] ?? ""
    }

    func deleteGenericPassword(service: String) throws {
        secrets.removeValue(forKey: service)
    }
}

final class QueueSecretPrompt: SecretPrompting {
    var values: [String]

    init(_ values: [String]) {
        self.values = values
    }

    func readSecret(prompt: String) throws -> String {
        guard !values.isEmpty else {
            throw TestFailure(description: "missing prompted secret for \(prompt)")
        }
        return values.removeFirst()
    }
}

final class RecordingDiskImageStore: DiskImageManaging {
    struct Created: Equatable {
        let imagePath: String
        let size: String
        let volumeName: String
        let password: String
    }

    struct Attached: Equatable {
        let imagePath: String
        let mountpoint: String
        let password: String
    }

    var created: [Created] = []
    var attached: [Attached] = []
    var detached: [String] = []
    var deletedImages: [String] = []
    var mounted: Set<String> = []
    var busyMountpoints: Set<String> = []
    var attachShouldLeaveUnmounted = false
    var detachShouldFail = false

    func createEncryptedSparsebundle(imagePath: String, size: String, volumeName: String, password: String) throws {
        created.append(Created(imagePath: imagePath, size: size, volumeName: volumeName, password: password))
    }

    func attach(imagePath: String, mountpoint: String, password: String) throws {
        attached.append(Attached(imagePath: imagePath, mountpoint: mountpoint, password: password))
        if !attachShouldLeaveUnmounted {
            mounted.insert(mountpoint)
        }
    }

    func detach(mountpoint: String) throws {
        if detachShouldFail {
            throw AgentKeychainError.filesystem("simulated detach failure")
        }
        detached.append(mountpoint)
        mounted.remove(mountpoint)
    }

    func isMounted(imagePath: String, mountpoint: String) throws -> Bool {
        mounted.contains(mountpoint)
    }

    func isBusy(mountpoint: String) throws -> Bool {
        busyMountpoints.contains(mountpoint)
    }

    func deleteImage(imagePath: String) throws {
        deletedImages.append(imagePath)
    }
}

final class RecordingBrowserLauncher: BrowserLaunching {
    struct Launch: Equatable {
        let userDataDir: String
    }

    var launches: [Launch] = []

    func launchChrome(userDataDir: String) throws {
        launches.append(Launch(userDataDir: userDataDir))
    }
}

final class RecordingCommandRunner: CommandRunning {
    struct Invocation: Equatable {
        let command: [String]
        let environment: [String: String]
    }

    var invocations: [Invocation] = []
    var result = ChildProcessResult(exitCode: 0, stdout: "child stdout\n", stderr: "")

    func run(command: [String], environment: [String: String]) throws -> ChildProcessResult {
        invocations.append(Invocation(command: command, environment: environment))
        return result
    }
}

final class RecordingUserPresenceAuthorizer: UserPresenceAuthorizing {
    var reasons: [String] = []

    func authorize(reason: String) throws {
        reasons.append(reason)
    }
}

func createExampleRolesFixture(cli: AgentKeychainCLI, workingDirectory: URL) throws {
    let regular = cli.run([
        "role", "create", "regular",
        "--reason", "Create regular example role",
        "--description", "Day-to-day low-risk agent work",
        "--require-touch-id",
        "--allow-env-injection",
        "--audit", "normal",
        "--default-idle-timeout", "900"
    ], workingDirectory: workingDirectory)
    try expectEqual(regular.exitCode, 0, "regular role fixture")

    let workspaceAdmin = cli.run([
        "role", "create", "workspace-admin",
        "--reason", "Create workspace admin example role",
        "--description", "Identity and workspace administration",
        "--require-touch-id",
        "--require-reason",
        "--deny-env-injection",
        "--audit", "verbose",
        "--default-idle-timeout", "300"
    ], workingDirectory: workingDirectory)
    try expectEqual(workspaceAdmin.exitCode, 0, "workspace-admin role fixture")

    let finance = cli.run([
        "role", "create", "finance",
        "--reason", "Create finance example role",
        "--description", "Money movement and financial administration",
        "--require-touch-id",
        "--require-reason",
        "--deny-env-injection",
        "--audit", "verbose",
        "--default-idle-timeout", "180"
    ], workingDirectory: workingDirectory)
    try expectEqual(finance.exitCode, 0, "finance role fixture")
}

func makeInitializedCLI(
    at root: URL,
    keychain: RecordingKeychainStore = RecordingKeychainStore(),
    prompt: SecretPrompting = QueueSecretPrompt([]),
    disk: DiskImageManaging = RecordingDiskImageStore(),
    browser: BrowserLaunching = RecordingBrowserLauncher(),
    commandRunner: CommandRunning = RecordingCommandRunner(),
    authorizer: UserPresenceAuthorizing = RecordingUserPresenceAuthorizer(),
    createExampleRoles: Bool = true
) throws -> AgentKeychainCLI {
    let cli = AgentKeychainCLI(dependencies: .testing(
        keychainStore: keychain,
        secretPrompt: prompt,
        diskImageStore: disk,
        browserLauncher: browser,
        commandRunner: commandRunner,
        userPresenceAuthorizer: authorizer,
        randomPassword: "generated-project-keychain-password",
        now: ISO8601DateFormatter().date(from: "2026-06-28T16:40:11Z")!
    ))
    let result = cli.run(["init", "--project-name", "demo"], workingDirectory: root)
    try expectEqual(result.exitCode, 0, "init fixture exit code")
    if createExampleRoles {
        try createExampleRolesFixture(cli: cli, workingDirectory: root)
    }
    return cli
}

func testCLITypeExists() throws {
    try expect(AgentKeychainCLI.name == "agent-keychain", "expected CLI name to be agent-keychain")
}

func testInitCreatesProjectLayoutConfigIntegrityAndAudit() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let cli = AgentKeychainCLI(dependencies: .testing(
        keychainStore: keychain,
        secretPrompt: QueueSecretPrompt([]),
        diskImageStore: RecordingDiskImageStore(),
        browserLauncher: RecordingBrowserLauncher(),
        commandRunner: RecordingCommandRunner(),
        userPresenceAuthorizer: RecordingUserPresenceAuthorizer(),
        randomPassword: "generated-project-keychain-password",
        now: ISO8601DateFormatter().date(from: "2026-06-28T16:40:11Z")!
    ))

    let result = cli.run(["init", "--project-name", "demo"], workingDirectory: temp.url)

    try expectEqual(result.exitCode, 0, "init exit code")
    try expect(result.stderr.isEmpty, "init should not write stderr: \(result.stderr)")
    let projectDir = temp.url.appendingPathComponent(".agent-keychain")
    try expect(FileManager.default.fileExists(atPath: projectDir.path), "expected .agent-keychain directory")
    try expect(FileManager.default.fileExists(atPath: projectDir.appendingPathComponent("locks").path), "expected locks directory")
    try expect(FileManager.default.fileExists(atPath: projectDir.appendingPathComponent("keychains").path), "expected keychains directory")
    try expect(FileManager.default.fileExists(atPath: projectDir.appendingPathComponent("volumes").path), "expected volumes directory")
    try expect(FileManager.default.fileExists(atPath: projectDir.appendingPathComponent("audit.jsonl").path), "expected audit log")

    let configURL = projectDir.appendingPathComponent("config.json")
    let configData = try Data(contentsOf: configURL)
    let configText = String(decoding: configData, as: UTF8.self)
    try expect(!configText.contains("generated-project-keychain-password"), "config must not contain generated project keychain password")

    let config = try JSONDecoder().decode(ProjectConfig.self, from: configData)
    try expectEqual(config.project.name, "demo", "project name")
    try expectEqual(config.project.keychainMode, .physical, "keychain mode")
    try expectEqual(config.project.keychainPath, ".agent-keychain/keychains/project.keychain-db", "keychain path")
    try expectEqual(config.project.keychainPasswordService, "agent-keychain.project.demo.keychain-password", "keychain password service")

    try expectEqual(keychain.projectPasswords.count, 1, "stored project keychain password count")
    try expectEqual(keychain.projectPasswords[0].service, "agent-keychain.project.demo.keychain-password", "stored project password service")
    try expectEqual(keychain.projectPasswords[0].password, "generated-project-keychain-password", "stored generated project password")

    let integrityURL = projectDir.appendingPathComponent("config.integrity.json")
    let integrity = try JSONDecoder().decode(ConfigIntegrity.self, from: Data(contentsOf: integrityURL))
    try expectEqual(integrity.configHash, try config.canonicalHash(), "integrity hash should match canonical config")

    let auditText = try String(contentsOf: projectDir.appendingPathComponent("audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"command_started\""), "audit should include command_started for init")
    try expect(auditText.contains("\"event\":\"command_completed\""), "audit should include command_completed for init")
    try expect(auditText.contains("\"event\":\"project_initialized\""), "audit should include project_initialized")
    try expect(auditText.contains("\"event\":\"config_mutation_succeeded\""), "audit should include config mutation success")
    try expect(!auditText.contains("generated-project-keychain-password"), "audit must not contain generated project keychain password")
    try expect(auditText.contains("\"previous_hash\""), "audit should include hash chain previous hash")
    try expect(auditText.contains("\"entry_hash\""), "audit should include hash chain entry hash")
}

func testInitFallsBackWhenPhysicalProjectKeychainUnavailable() throws {
    let temp = try TemporaryDirectory()
    let keychain = FailingPhysicalKeychainStore()
    let cli = AgentKeychainCLI(dependencies: .testing(
        keychainStore: keychain,
        secretPrompt: QueueSecretPrompt([]),
        diskImageStore: RecordingDiskImageStore(),
        browserLauncher: RecordingBrowserLauncher(),
        commandRunner: RecordingCommandRunner(),
        userPresenceAuthorizer: RecordingUserPresenceAuthorizer(),
        randomPassword: "unused-project-password",
        now: ISO8601DateFormatter().date(from: "2026-06-28T16:40:11Z")!
    ))

    let result = cli.run(["init", "--project-name", "demo"], workingDirectory: temp.url)

    try expectEqual(result.exitCode, 0, "fallback init exit code")
    let config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: temp.url.appendingPathComponent(".agent-keychain/config.json")))
    try expectEqual(config.project.keychainMode, .fallback, "fallback keychain mode")
    try expect(keychain.projectPasswords.isEmpty, "fallback mode must not store a project keychain password")
    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"fallback_keychain_mode_selected\""), "audit should record fallback decision")

    let status = cli.run(["status"], workingDirectory: temp.url)
    try expectEqual(status.exitCode, 0, "fallback status exit code")
    try expect(status.stdout.contains("Physical project-keychain separation: unavailable"), "fallback status should explain unavailable physical separation: \(status.stdout)")
}

func testRoleCreateListShowAndReasonRequirement() throws {
    let temp = try TemporaryDirectory()
    let cli = try makeInitializedCLI(at: temp.url, createExampleRoles: false)

    let missingReason = cli.run(["role", "create", "analyst"], workingDirectory: temp.url)
    try expectEqual(missingReason.exitCode, 2, "missing reason exit code")
    try expect(missingReason.stderr.contains("Policy mutations require --reason"), "missing reason message: \(missingReason.stderr)")

    let created = cli.run([
        "role", "create", "analyst",
        "--reason", "Create analyst role for reporting workflows",
        "--description", "Reporting and read-only analytics",
        "--require-touch-id",
        "--require-reason",
        "--deny-env-injection",
        "--audit", "verbose",
        "--default-idle-timeout", "120"
    ], workingDirectory: temp.url)

    try expectEqual(created.exitCode, 0, "role create exit code")
    try expect(created.stderr.isEmpty, "role create stderr: \(created.stderr)")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    let config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    let analyst = try expectUnwrapped(config.roles["analyst"], "expected analyst role in config")
    try expectEqual(analyst.description, "Reporting and read-only analytics", "analyst description")
    try expectEqual(analyst.requireTouchId, true, "analyst touch id")
    try expectEqual(analyst.requireReason, true, "analyst reason")
    try expectEqual(analyst.allowEnvInjection, false, "analyst env injection")
    try expectEqual(analyst.auditLevel, .verbose, "analyst audit")
    try expectEqual(analyst.defaultIdleTimeoutSeconds, 120, "analyst idle timeout")

    let list = cli.run(["role", "list"], workingDirectory: temp.url)
    try expectEqual(list.exitCode, 0, "role list exit code")
    try expect(list.stdout.contains("analyst\n"), "role list should include analyst: \(list.stdout)")

    let show = cli.run(["role", "show", "analyst"], workingDirectory: temp.url)
    try expectEqual(show.exitCode, 0, "role show exit code")
    try expect(show.stdout.contains("\"description\":\"Reporting and read-only analytics\""), "role show description: \(show.stdout)")
    try expect(show.stdout.contains("\"auditLevel\":\"verbose\""), "role show audit level: \(show.stdout)")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"command_started\""), "audit should include command_started")
    try expect(auditText.contains("\"event\":\"command_completed\""), "audit should include command_completed")
    try expect(auditText.contains("\"event\":\"role_created\""), "audit should include role_created")
    try expect(auditText.contains("Create analyst role for reporting workflows"), "audit should include mutation reason")
}

func testRoleUpdateAndDeleteMutatePolicyWithAudit() throws {
    let temp = try TemporaryDirectory()
    let authorizer = RecordingUserPresenceAuthorizer()
    let prompt = QueueSecretPrompt(["analyst_secret"])
    let cli = try makeInitializedCLI(at: temp.url, prompt: prompt, authorizer: authorizer)

    let create = cli.run([
        "role", "create", "analyst",
        "--reason", "Create analyst role",
        "--description", "Initial analyst role"
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "role update fixture create")

    let update = cli.run([
        "role", "update", "analyst",
        "--reason", "Tighten analyst role policy",
        "--description", "Read-only reporting",
        "--require-touch-id",
        "--require-reason",
        "--deny-env-injection",
        "--audit", "verbose",
        "--default-idle-timeout", "240"
    ], workingDirectory: temp.url)
    try expectEqual(update.exitCode, 0, "role update exit code")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    var config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    let analyst = try expectUnwrapped(config.roles["analyst"], "expected analyst role after update")
    try expectEqual(analyst.description, "Read-only reporting", "updated role description")
    try expectEqual(analyst.requireTouchId, true, "updated require touch id")
    try expectEqual(analyst.requireReason, true, "updated require reason")
    try expectEqual(analyst.allowEnvInjection, false, "updated deny env injection")
    try expectEqual(analyst.auditLevel, .verbose, "updated audit level")
    try expectEqual(analyst.defaultIdleTimeoutSeconds, 240, "updated idle timeout")

    let setSecret = cli.run([
        "secret", "set", "analyst-token",
        "--role", "analyst",
        "--reason", "Add analyst token",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(setSecret.exitCode, 0, "role delete fixture secret")

    let deleteWithResource = cli.run([
        "role", "delete", "analyst",
        "--reason", "Try deleting role with owned resources"
    ], workingDirectory: temp.url)
    try expectEqual(deleteWithResource.exitCode, 1, "role delete with resource exit code")
    try expect(deleteWithResource.stderr.contains("Refusing to delete role analyst because it still owns resources"), "delete role with resource message: \(deleteWithResource.stderr)")

    let deleteSecret = cli.run([
        "secret", "delete", "analyst-token",
        "--role", "analyst",
        "--reason", "Remove analyst token"
    ], workingDirectory: temp.url)
    try expectEqual(deleteSecret.exitCode, 0, "role delete fixture secret delete")

    let delete = cli.run([
        "role", "delete", "analyst",
        "--reason", "Remove unused analyst role"
    ], workingDirectory: temp.url)
    try expectEqual(delete.exitCode, 0, "role delete exit code")
    config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    try expect(config.roles["analyst"] == nil, "deleted role should be removed")
    try expect(authorizer.reasons.contains("Tighten analyst role policy"), "role update should require user presence")
    try expect(authorizer.reasons.contains("Remove unused analyst role"), "role delete should require user presence")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"role_updated\""), "audit should include role_updated")
    try expect(auditText.contains("\"event\":\"role_deleted\""), "audit should include role_deleted")
}

func testConfigTamperRejectsPolicyMutationUntilTrusted() throws {
    let temp = try TemporaryDirectory()
    let cli = try makeInitializedCLI(at: temp.url)
    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    let original = try String(contentsOf: configURL, encoding: .utf8)
    let tampered = original.replacingOccurrences(
        of: "Day-to-day low-risk agent work",
        with: "Tampered regular role"
    )
    try tampered.write(to: configURL, atomically: false, encoding: .utf8)

    let result = cli.run([
        "role", "create", "ops",
        "--reason", "Add operations role after manual edit",
        "--description", "Operations"
    ], workingDirectory: temp.url)

    try expectEqual(result.exitCode, 1, "tamper rejection exit code")
    try expect(result.stderr.contains("Config integrity check failed"), "tamper rejection message: \(result.stderr)")
    let currentConfig = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    try expect(currentConfig.roles["ops"] == nil, "tampered config should not be mutated")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"config_tamper_detected\""), "audit should include tamper detection")
}

func testHeldConfigLockBlocksPolicyMutation() throws {
    let temp = try TemporaryDirectory()
    let cli = try makeInitializedCLI(at: temp.url)
    let lockURL = temp.url.appendingPathComponent(".agent-keychain/locks/config.lock")
    FileManager.default.createFile(atPath: lockURL.path, contents: Data("held".utf8))

    let result = cli.run([
        "role", "create", "ops",
        "--reason", "Add operations role",
        "--description", "Operations"
    ], workingDirectory: temp.url)

    try expectEqual(result.exitCode, 1, "held config lock exit code")
    try expect(result.stderr.contains("Config is locked by another agent-keychain process"), "held config lock message: \(result.stderr)")
    let config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: temp.url.appendingPathComponent(".agent-keychain/config.json")))
    try expect(config.roles["ops"] == nil, "held config lock should block mutation")
    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"config_mutation_failed\""), "held config lock should audit mutation failure")
}

func testHeldConfigLockAuditsSecretSetMutationFailure() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)
    let lockURL = temp.url.appendingPathComponent(".agent-keychain/locks/config.lock")
    FileManager.default.createFile(atPath: lockURL.path, contents: Data("held".utf8))
    defer { try? FileManager.default.removeItem(at: lockURL) }

    let result = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
        "--touch-id"
    ], workingDirectory: temp.url)

    try expectEqual(result.exitCode, 1, "locked secret set exit code")
    try expect(result.stderr.contains("Config is locked by another agent-keychain process"), "locked secret set stderr: \(result.stderr)")
    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"config_mutation_failed\""), "locked secret set should audit mutation failure")
}

func testSecretSetGetListDeleteDoesNotLeakValues() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token for regular agent work",
        "--touch-id"
    ], workingDirectory: temp.url)

    try expectEqual(set.exitCode, 0, "secret set exit code")
    let service = "agent-keychain.role.regular.secret.github-readonly"
    try expectEqual(keychain.secrets[service], "ghp_regular_secret", "stored secret value")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    let configText = try String(contentsOf: configURL, encoding: .utf8)
    try expect(configText.contains(service), "config should contain keychain service metadata")
    try expect(!configText.contains("ghp_regular_secret"), "config must not contain secret value")

    let list = cli.run(["secret", "list", "--role", "regular"], workingDirectory: temp.url)
    try expectEqual(list.exitCode, 0, "secret list exit code")
    try expect(list.stdout.contains("github-readonly\n"), "secret list should include name: \(list.stdout)")
    try expect(!list.stdout.contains("ghp_regular_secret"), "secret list must not print value")

    let get = cli.run(["secret", "get", "github-readonly", "--role", "regular"], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 0, "secret get exit code")
    try expectEqual(get.stdout, "ghp_regular_secret\n", "secret get stdout")

    let delete = cli.run([
        "secret", "delete", "github-readonly",
        "--role", "regular",
        "--reason", "Remove old GitHub token"
    ], workingDirectory: temp.url)
    try expectEqual(delete.exitCode, 0, "secret delete exit code")
    try expect(keychain.deletedServices.contains(service), "secret delete should delete keychain item")
    let configAfterDelete = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    try expect(configAfterDelete.secrets["github-readonly"] == nil, "deleted secret should be removed from config")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.components(separatedBy: "\"event\":\"command_started\"").count - 1 >= 2, "audit should include command_started for init and secret get")
    try expect(auditText.components(separatedBy: "\"event\":\"command_completed\"").count - 1 >= 2, "audit should include command_completed for init and secret get")
    try expect(auditText.contains("\"event\":\"secret_set\""), "audit should include secret_set")
    try expect(auditText.contains("\"event\":\"secret_read\""), "audit should include secret_read")
    try expect(auditText.contains("\"event\":\"secret_delete\""), "audit should include secret_delete")
    try expect(!auditText.contains("ghp_regular_secret"), "audit must not contain secret value")
}

func testSecretPoliciesRejectCrossRoleAndPrivilegedRawOutput() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["mercury_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key for finance workflows",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "finance secret set exit code")

    let crossRole = cli.run([
        "secret", "get", "mercury-api-key",
        "--role", "regular"
    ], workingDirectory: temp.url)
    try expectEqual(crossRole.exitCode, 1, "cross-role secret exit code")
    try expect(
        crossRole.stderr.contains("Refusing to use secret mercury-api-key from role finance in role regular."),
        "cross-role rejection message: \(crossRole.stderr)"
    )

    let missingReason = cli.run([
        "secret", "get", "mercury-api-key",
        "--role", "finance",
        "--allow-raw-secret"
    ], workingDirectory: temp.url)
    try expectEqual(missingReason.exitCode, 2, "missing privileged reason exit code")
    try expect(missingReason.stderr.contains("Role finance requires --reason"), "missing reason message: \(missingReason.stderr)")

    let rawDenied = cli.run([
        "secret", "get", "mercury-api-key",
        "--role", "finance",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)
    try expectEqual(rawDenied.exitCode, 1, "raw denied exit code")
    try expect(rawDenied.stderr.contains("Role finance disallows raw secret output"), "raw denied message: \(rawDenied.stderr)")

    let allowed = cli.run([
        "secret", "get", "mercury-api-key",
        "--role", "finance",
        "--reason", "Review approved contractor invoices",
        "--allow-raw-secret"
    ], workingDirectory: temp.url)
    try expectEqual(allowed.exitCode, 0, "privileged raw secret exit code")
    try expectEqual(allowed.stdout, "mercury_secret\n", "privileged raw secret stdout")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"policy_rejection\""), "audit should include policy rejection")
    try expect(auditText.contains("\"event\":\"command_failed\""), "audit should include command_failed for rejected secret get")
    try expect(auditText.contains("\"event\":\"raw_secret_stdout_override\""), "audit should include raw secret override")
    try expect(!auditText.contains("mercury_secret"), "audit must not contain privileged secret value")
}

func testPhysicalSecretReadAuditsProjectKeychainUnlockLifecycle() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "project keychain audit fixture secret set")

    let get = cli.run([
        "secret", "get", "github-readonly",
        "--role", "regular"
    ], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 0, "project keychain audit secret get")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"project_keychain_unlock_requested\""), "audit should include project keychain unlock request")
    try expect(auditText.contains("\"event\":\"project_keychain_unlock_succeeded\""), "audit should include project keychain unlock success")
    try expect(auditText.contains("\"event\":\"project_keychain_locked\""), "audit should include project keychain locked")
}

func testPhysicalSecretReadAuditsProjectKeychainUnlockFailureAndCommandFailure() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "project keychain failure fixture secret set")

    keychain.failingReadServices.insert("agent-keychain.role.regular.secret.github-readonly")
    let get = cli.run([
        "secret", "get", "github-readonly",
        "--role", "regular"
    ], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 1, "project keychain audit failed secret get")
    try expect(get.stderr.contains("simulated keychain read failure"), "failed keychain read message: \(get.stderr)")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"project_keychain_unlock_requested\""), "audit should include failed unlock request")
    try expect(auditText.contains("\"event\":\"project_keychain_unlock_failed\""), "audit should include unlock failure")
    try expect(auditText.contains("\"event\":\"command_failed\""), "audit should include command_failed for keychain failure")
}

func testPhysicalSecretSetAndDeleteAuditProjectKeychainUnlockLifecycle() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "project keychain write fixture secret set")

    let delete = cli.run([
        "secret", "delete", "github-readonly",
        "--role", "regular",
        "--reason", "Remove GitHub token"
    ], workingDirectory: temp.url)
    try expectEqual(delete.exitCode, 0, "project keychain delete fixture secret delete")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.components(separatedBy: "\"event\":\"project_keychain_unlock_requested\"").count - 1 >= 2, "set and delete should each request project keychain unlock")
    try expect(auditText.components(separatedBy: "\"event\":\"project_keychain_unlock_succeeded\"").count - 1 >= 2, "set and delete should each succeed project keychain unlock")
    try expect(auditText.components(separatedBy: "\"event\":\"project_keychain_locked\"").count - 1 >= 2, "set and delete should each lock project keychain")
}

func testVolumeCreateUnlockLockStatusAndRolePolicy() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let create = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)

    try expectEqual(create.exitCode, 0, "volume create exit code")
    let service = "agent-keychain.role.finance.volume.FinanceBrowser.password"
    try expectEqual(keychain.secrets[service], "generated-project-keychain-password", "stored volume password")
    try expectEqual(disk.created.count, 1, "created disk image count")
    try expect(disk.created[0].imagePath.hasSuffix(".agent-keychain/volumes/FinanceBrowser.sparsebundle"), "volume image path: \(disk.created[0].imagePath)")
    try expectEqual(disk.created[0].size, "20g", "volume size")
    try expectEqual(disk.created[0].volumeName, "AgentKeychain-FinanceBrowser", "volume name")
    try expectEqual(disk.created[0].password, "generated-project-keychain-password", "volume create password")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    let config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    let volume = try expectUnwrapped(config.volumes["FinanceBrowser"], "expected FinanceBrowser volume")
    try expectEqual(volume.role, "finance", "volume role")
    try expectEqual(volume.image, ".agent-keychain/volumes/FinanceBrowser.sparsebundle", "volume image metadata")
    try expectEqual(volume.mountpoint, "/Volumes/AgentKeychain-demo-FinanceBrowser", "volume mountpoint")
    try expectEqual(volume.keychainService, service, "volume service metadata")

    let crossRole = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "regular"
    ], workingDirectory: temp.url)
    try expectEqual(crossRole.exitCode, 1, "cross-role volume exit code")
    try expect(crossRole.stderr.contains("Volume FinanceBrowser belongs to role finance, not regular."), "cross-role volume message: \(crossRole.stderr)")
    try expectEqual(disk.attached.count, 0, "cross-role unlock must not attach")

    let auditBeforeMissingReason = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    let policyRejectionsBeforeMissingReason = occurrenceCount(in: auditBeforeMissingReason, of: "\"event\":\"policy_rejection\"")
    let missingReason = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "finance"
    ], workingDirectory: temp.url)
    try expectEqual(missingReason.exitCode, 2, "finance volume missing reason exit code")
    try expect(missingReason.stderr.contains("Role finance requires --reason"), "volume missing reason message: \(missingReason.stderr)")
    let auditAfterMissingReason = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expectEqual(
        occurrenceCount(in: auditAfterMissingReason, of: "\"event\":\"policy_rejection\""),
        policyRejectionsBeforeMissingReason + 1,
        "missing required reason should audit policy rejection"
    )

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)
    try expectEqual(unlock.exitCode, 0, "volume unlock exit code")
    try expectEqual(disk.attached.count, 1, "volume attach count")
    try expectEqual(disk.attached[0].mountpoint, "/Volumes/AgentKeychain-demo-FinanceBrowser", "attach mountpoint")
    try expectEqual(disk.attached[0].password, "generated-project-keychain-password", "attach password")

    let status = cli.run(["volume", "status", "FinanceBrowser"], workingDirectory: temp.url)
    try expectEqual(status.exitCode, 0, "volume status exit code")
    try expect(status.stdout.contains("FinanceBrowser mounted"), "volume status stdout: \(status.stdout)")

    let lock = cli.run([
        "volume", "lock", "FinanceBrowser",
        "--role", "finance"
    ], workingDirectory: temp.url)
    try expectEqual(lock.exitCode, 0, "volume lock exit code")
    try expectEqual(disk.detached, ["/Volumes/AgentKeychain-demo-FinanceBrowser"], "detached mountpoints")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"volume_created\""), "audit should include volume_created")
    try expect(auditText.contains("\"event\":\"volume_unlock_requested\""), "audit should include volume_unlock_requested")
    try expect(auditText.contains("\"event\":\"volume_unlock_succeeded\""), "audit should include volume_unlock_succeeded")
    try expect(auditText.contains("\"event\":\"volume_lock_succeeded\""), "audit should include volume_lock_succeeded")
    try expect(!auditText.contains("generated-project-keychain-password"), "audit must not contain volume password")
}

func testVolumeLockSkipsDetachWhenMountpointBusy() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let create = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "busy fixture volume create")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)
    try expectEqual(unlock.exitCode, 0, "busy fixture volume unlock")

    disk.busyMountpoints.insert("/Volumes/AgentKeychain-demo-FinanceBrowser")
    let lock = cli.run([
        "volume", "lock", "FinanceBrowser",
        "--role", "finance"
    ], workingDirectory: temp.url)

    try expectEqual(lock.exitCode, 0, "busy volume lock exit code")
    try expect(lock.stdout.contains("Skipped locking volume FinanceBrowser because mountpoint is busy"), "busy lock stdout: \(lock.stdout)")
    try expectEqual(disk.detached, [], "busy volume must not detach")
    try expect(disk.mounted.contains("/Volumes/AgentKeychain-demo-FinanceBrowser"), "busy volume should remain mounted")
    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"volume_lock_skipped_because_busy\""), "audit should include busy lock skip")
}

func testVolumeLockAuditsDetachFailure() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let create = cli.run([
        "volume", "create", "RegularBrowser",
        "--role", "regular",
        "--size", "20g",
        "--reason", "Create regular browser volume",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "detach failure fixture volume")

    disk.detachShouldFail = true
    let lock = cli.run([
        "volume", "lock", "RegularBrowser",
        "--role", "regular"
    ], workingDirectory: temp.url)

    try expectEqual(lock.exitCode, 1, "detach failure exit code")
    try expect(lock.stderr.contains("simulated detach failure"), "detach failure message: \(lock.stderr)")
    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"volume_lock_failed\""), "audit should include volume_lock_failed")
}

func testBrowserOpenUsesManagedVolumeLockFile() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let browser = RecordingBrowserLauncher()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk, browser: browser)

    let createVolume = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "lock fixture volume create")
    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile for finance workflows"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "lock fixture browser create")

    let lockURL = temp.url.appendingPathComponent(".agent-keychain/locks/FinanceBrowser.lock")
    FileManager.default.createFile(atPath: lockURL.path, contents: Data("held".utf8))
    let blocked = cli.run([
        "browser", "open", "Mercury",
        "--role", "finance",
        "--reason", "Review payment status for approved invoices",
        "--detach-on-exit"
    ], workingDirectory: temp.url)
    try expectEqual(blocked.exitCode, 1, "held lock browser exit code")
    try expect(blocked.stderr.contains("Managed volume FinanceBrowser is already in use"), "held lock message: \(blocked.stderr)")
    try expectEqual(browser.launches.count, 0, "held lock browser should not launch")

    try FileManager.default.removeItem(at: lockURL)
    let opened = cli.run([
        "browser", "open", "Mercury",
        "--role", "finance",
        "--reason", "Review payment status for approved invoices",
        "--detach-on-exit"
    ], workingDirectory: temp.url)
    try expectEqual(opened.exitCode, 0, "unheld lock browser exit code")
    try expect(!FileManager.default.fileExists(atPath: lockURL.path), "managed lock file should be released after browser exits")
}

func testVolumeUnlockFailsClosedWhenAttachDoesNotVerifyMountedImage() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    disk.attachShouldLeaveUnmounted = true
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let create = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "verify fixture volume create")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)

    try expectEqual(unlock.exitCode, 1, "unverified attach exit code")
    try expect(unlock.stderr.contains("Mounted image verification failed"), "unverified attach message: \(unlock.stderr)")
    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"volume_unlock_failed\""), "audit should include unlock failure")
}

func testVolumeUnlockRejectsExistingMountpointThatIsNotExpectedImage() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let create = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "existing mountpoint fixture volume create")

    let occupiedMountpoint = temp.url.appendingPathComponent("occupied-mount", isDirectory: true)
    try FileManager.default.createDirectory(at: occupiedMountpoint, withIntermediateDirectories: true)
    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    var config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    config.volumes["FinanceBrowser"]?.mountpoint = occupiedMountpoint.path
    try config.canonicalData().write(to: configURL)
    let trust = cli.run([
        "config", "trust-current",
        "--reason", "Trust test mountpoint edit"
    ], workingDirectory: temp.url)
    try expectEqual(trust.exitCode, 0, "trust edited mountpoint")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)

    try expectEqual(unlock.exitCode, 1, "existing non-agent mountpoint unlock exit code")
    try expect(unlock.stderr.contains("Refusing to use existing mountpoint"), "existing mountpoint message: \(unlock.stderr)")
    try expectEqual(disk.attached.count, 0, "existing non-agent mountpoint should not attach")
}

func testVolumeUnlockRejectsSymlinkMountpoint() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let create = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "symlink mountpoint fixture volume create")

    let target = temp.url.appendingPathComponent("symlink-target", isDirectory: true)
    try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
    let symlink = temp.url.appendingPathComponent("symlink-mountpoint")
    try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: target)

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    var config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    config.volumes["FinanceBrowser"]?.mountpoint = symlink.path
    try config.canonicalData().write(to: configURL)
    let trust = cli.run([
        "config", "trust-current",
        "--reason", "Trust symlink mountpoint test edit"
    ], workingDirectory: temp.url)
    try expectEqual(trust.exitCode, 0, "trust symlink mountpoint edit")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)

    try expectEqual(unlock.exitCode, 1, "symlink mountpoint unlock exit code")
    try expect(unlock.stderr.contains("Refusing to use symlink mountpoint"), "symlink mountpoint message: \(unlock.stderr)")
    try expectEqual(disk.attached.count, 0, "symlink mountpoint should not attach")
}

func testBrowserCreateOpenListAndRolePolicy() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let browser = RecordingBrowserLauncher()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk, browser: browser)

    let createVolume = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "browser fixture volume create")

    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile for finance workflows"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "browser create exit code")

    let list = cli.run(["browser", "list", "--role", "finance"], workingDirectory: temp.url)
    try expectEqual(list.exitCode, 0, "browser list exit code")
    try expect(list.stdout.contains("Mercury\n"), "browser list should include Mercury: \(list.stdout)")

    let crossRole = cli.run([
        "browser", "open", "Mercury",
        "--role", "workspace-admin",
        "--reason", "Try wrong role"
    ], workingDirectory: temp.url)
    try expectEqual(crossRole.exitCode, 1, "cross-role browser exit code")
    try expect(crossRole.stderr.contains("Browser profile Mercury belongs to role finance, not workspace-admin."), "cross-role browser message: \(crossRole.stderr)")
    try expectEqual(browser.launches.count, 0, "cross-role browser must not launch")

    let missingReason = cli.run([
        "browser", "open", "Mercury",
        "--role", "finance"
    ], workingDirectory: temp.url)
    try expectEqual(missingReason.exitCode, 2, "browser missing reason exit code")
    try expect(missingReason.stderr.contains("Role finance requires --reason"), "browser missing reason message: \(missingReason.stderr)")

    let open = cli.run([
        "browser", "open", "Mercury",
        "--role", "finance",
        "--reason", "Review payment status for approved invoices",
        "--detach-on-exit"
    ], workingDirectory: temp.url)
    try expectEqual(open.exitCode, 0, "browser open exit code")
    try expectEqual(disk.attached.count, 1, "browser should attach volume once")
    try expectEqual(browser.launches, [
        RecordingBrowserLauncher.Launch(userDataDir: "/Volumes/AgentKeychain-demo-FinanceBrowser/ChromeProfiles/Mercury")
    ], "browser launches")
    try expectEqual(disk.detached, ["/Volumes/AgentKeychain-demo-FinanceBrowser"], "browser detach-on-exit")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"browser_created\""), "audit should include browser_created")
    try expect(auditText.contains("\"event\":\"browser_opened\""), "audit should include browser_opened")
    try expect(auditText.contains("\"event\":\"browser_exited\""), "audit should include browser_exited")
}

func testBrowserOpenRejectsProfilePathTraversal() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let browser = RecordingBrowserLauncher()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk, browser: browser)

    let createVolume = cli.run([
        "volume", "create", "RegularBrowser",
        "--role", "regular",
        "--size", "20g",
        "--reason", "Create regular browser volume",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "profile traversal fixture volume")

    let createBrowser = cli.run([
        "browser", "create", "GitHub",
        "--role", "regular",
        "--volume", "RegularBrowser",
        "--reason", "Create GitHub browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "profile traversal fixture browser")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    var config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    config.browsers["GitHub"]?.profilePath = "../../Library/Application Support/Google/Chrome"
    try config.canonicalData().write(to: configURL)
    let trust = cli.run([
        "config", "trust-current",
        "--reason", "Trust test browser profile edit"
    ], workingDirectory: temp.url)
    try expectEqual(trust.exitCode, 0, "trust unsafe browser profile edit")

    let open = cli.run([
        "browser", "open", "GitHub",
        "--role", "regular"
    ], workingDirectory: temp.url)

    try expectEqual(open.exitCode, 1, "unsafe browser profile open exit code")
    try expect(open.stderr.contains("Refusing to use unsafe browser profile path"), "unsafe profile message: \(open.stderr)")
    try expectEqual(disk.attached.count, 0, "unsafe profile path should fail before attaching volume")
    try expectEqual(browser.launches.count, 0, "unsafe profile path should not launch Chrome")
}

func testPrivilegedBrowserAndRunDefaultToDetachOnExit() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let browser = RecordingBrowserLauncher()
    let runner = RecordingCommandRunner()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk, browser: browser, commandRunner: runner)

    let createVolume = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "privileged detach fixture volume")

    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "privileged detach fixture browser")

    let open = cli.run([
        "browser", "open", "Mercury",
        "--role", "finance",
        "--reason", "Review payment status for approved invoices"
    ], workingDirectory: temp.url)
    try expectEqual(open.exitCode, 0, "privileged browser default detach exit code")
    try expectEqual(disk.detached, ["/Volumes/AgentKeychain-demo-FinanceBrowser"], "privileged browser should detach without explicit flag")

    disk.detached.removeAll()
    disk.mounted.removeAll()
    let run = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--browser", "Mercury",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(run.exitCode, 0, "privileged run default detach exit code")
    try expectEqual(disk.detached, ["/Volumes/AgentKeychain-demo-FinanceBrowser"], "privileged run should detach without explicit flag")
}

func testBrowserDeleteAndVolumeDeleteCleanUpMetadataAndStorage() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let authorizer = RecordingUserPresenceAuthorizer()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk, authorizer: authorizer)

    let createVolume = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "delete fixture volume create")

    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile for finance workflows"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "delete fixture browser create")

    let volumeDeleteWithBrowser = cli.run([
        "volume", "delete", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Try deleting volume with browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(volumeDeleteWithBrowser.exitCode, 1, "volume delete with browser exit code")
    try expect(volumeDeleteWithBrowser.stderr.contains("Refusing to delete volume FinanceBrowser because browser profiles still use it"), "volume delete with browser message: \(volumeDeleteWithBrowser.stderr)")

    let browserDelete = cli.run([
        "browser", "delete", "Mercury",
        "--role", "finance",
        "--reason", "Remove Mercury browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(browserDelete.exitCode, 0, "browser delete exit code")
    var config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: temp.url.appendingPathComponent(".agent-keychain/config.json")))
    try expect(config.browsers["Mercury"] == nil, "browser delete should remove metadata")

    let volumeDelete = cli.run([
        "volume", "delete", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Remove finance browser volume"
    ], workingDirectory: temp.url)
    try expectEqual(volumeDelete.exitCode, 0, "volume delete exit code")
    config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: temp.url.appendingPathComponent(".agent-keychain/config.json")))
    try expect(config.volumes["FinanceBrowser"] == nil, "volume delete should remove metadata")
    try expect(keychain.deletedServices.contains("agent-keychain.role.finance.volume.FinanceBrowser.password"), "volume delete should remove volume password")
    try expect(disk.deletedImages.contains { $0.hasSuffix(".agent-keychain/volumes/FinanceBrowser.sparsebundle") }, "volume delete should delete sparsebundle image")
    try expect(authorizer.reasons.contains("Remove Mercury browser profile"), "browser delete should require user presence")
    try expect(authorizer.reasons.contains("Remove finance browser volume"), "volume delete should require user presence")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"browser_deleted\""), "audit should include browser_deleted")
    try expect(auditText.contains("\"event\":\"volume_deleted\""), "audit should include volume_deleted")
}

func testStatusConfigPathProjectDiscoveryAndTrustCurrent() throws {
    let temp = try TemporaryDirectory()
    let cli = try makeInitializedCLI(at: temp.url)

    let status = cli.run(["status"], workingDirectory: temp.url)
    try expectEqual(status.exitCode, 0, "status exit code")
    try expect(status.stdout.contains("Project: demo"), "status project: \(status.stdout)")
    try expect(status.stdout.contains("Keychain mode: physical"), "status keychain mode: \(status.stdout)")
    try expect(status.stdout.contains("Project keychain: configured"), "status keychain state: \(status.stdout)")
    try expect(status.stdout.contains("Roles: finance, regular, workspace-admin"), "status roles: \(status.stdout)")

    let nested = temp.url.appendingPathComponent("a/b/c", isDirectory: true)
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    let discoveredPath = cli.run(["config", "path"], workingDirectory: nested)
    try expectEqual(discoveredPath.exitCode, 0, "config path discovered exit code")
    try expectEqual(discoveredPath.stdout, temp.url.appendingPathComponent(".agent-keychain/config.json").path + "\n", "discovered config path")

    let outside = try TemporaryDirectory()
    let explicitPath = cli.run(["--project", temp.url.path, "config", "path"], workingDirectory: outside.url)
    try expectEqual(explicitPath.exitCode, 0, "explicit project config path exit code")
    try expectEqual(explicitPath.stdout, temp.url.appendingPathComponent(".agent-keychain/config.json").path + "\n", "explicit config path")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    let original = try String(contentsOf: configURL, encoding: .utf8)
    try original.replacingOccurrences(of: "Day-to-day low-risk agent work", with: "Trusted manual edit")
        .write(to: configURL, atomically: false, encoding: .utf8)

    let missingReason = cli.run(["config", "trust-current"], workingDirectory: temp.url)
    try expectEqual(missingReason.exitCode, 2, "trust-current missing reason exit code")
    try expect(missingReason.stderr.contains("Policy mutations require --reason"), "trust missing reason message: \(missingReason.stderr)")

    let trusted = cli.run([
        "config", "trust-current",
        "--reason", "Accept deliberate local role description edit"
    ], workingDirectory: temp.url)
    try expectEqual(trusted.exitCode, 0, "trust-current exit code")
    let config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    let integrity = try JSONDecoder().decode(ConfigIntegrity.self, from: Data(contentsOf: temp.url.appendingPathComponent(".agent-keychain/config.integrity.json")))
    try expectEqual(integrity.configHash, try config.canonicalHash(), "trusted integrity hash")

    let roleAfterTrust = cli.run([
        "role", "create", "ops",
        "--reason", "Add ops after trust",
        "--description", "Operations"
    ], workingDirectory: temp.url)
    try expectEqual(roleAfterTrust.exitCode, 0, "role create after trust exit code")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"config_trust_baseline_updated\""), "audit should include trust baseline update")
}

func testStatusReportsVolumeMountedState() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let create = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "status volume fixture create")

    var status = cli.run(["status"], workingDirectory: temp.url)
    try expectEqual(status.exitCode, 0, "status unmounted exit code")
    try expect(status.stdout.contains("FinanceBrowser: unmounted"), "status should show unmounted volume: \(status.stdout)")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "finance",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)
    try expectEqual(unlock.exitCode, 0, "status volume fixture unlock")

    status = cli.run(["status"], workingDirectory: temp.url)
    try expectEqual(status.exitCode, 0, "status mounted exit code")
    try expect(status.stdout.contains("FinanceBrowser: mounted"), "status should show mounted volume: \(status.stdout)")
}

func testReadOnlyCommandsAuditLifecycle() throws {
    let temp = try TemporaryDirectory()
    let cli = try makeInitializedCLI(at: temp.url)
    let auditURL = temp.url.appendingPathComponent(".agent-keychain/audit.jsonl")
    let before = try String(contentsOf: auditURL, encoding: .utf8)
    let startedBefore = occurrenceCount(in: before, of: "\"event\":\"command_started\"")
    let completedBefore = occurrenceCount(in: before, of: "\"event\":\"command_completed\"")

    let commands = [
        ["status"],
        ["config", "path"],
        ["role", "list"],
        ["secret", "list"],
        ["volume", "status"],
        ["browser", "list"]
    ]

    for command in commands {
        let result = cli.run(command, workingDirectory: temp.url)
        try expectEqual(result.exitCode, 0, "\(command.joined(separator: " ")) exit code")
    }

    let after = try String(contentsOf: auditURL, encoding: .utf8)
    try expectEqual(
        occurrenceCount(in: after, of: "\"event\":\"command_started\""),
        startedBefore + commands.count,
        "read-only commands should audit command_started"
    )
    try expectEqual(
        occurrenceCount(in: after, of: "\"event\":\"command_completed\""),
        completedBefore + commands.count,
        "read-only commands should audit command_completed"
    )
}

func testRunInjectsAllowedSecretAndAuditsCommand() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let runner = RecordingCommandRunner()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt, commandRunner: runner)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "run fixture secret set")

    let run = cli.run([
        "run",
        "--role", "regular",
        "--keychain-timeout", "5m",
        "--secret", "GITHUB_TOKEN=github-readonly",
        "--", "agent-command", "--flag"
    ], workingDirectory: temp.url)
    try expectEqual(run.exitCode, 0, "run exit code")
    try expectEqual(run.stdout, "child stdout\n", "run stdout")
    try expectEqual(runner.invocations.count, 1, "child invocation count")
    try expectEqual(runner.invocations[0].command, ["agent-command", "--flag"], "child command")
    try expectEqual(runner.invocations[0].environment["GITHUB_TOKEN"], "ghp_regular_secret", "injected env")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"command_started\""), "audit should include command_started")
    try expect(auditText.contains("\"event\":\"command_completed\""), "audit should include command_completed")
    try expect(!auditText.contains("ghp_regular_secret"), "audit must not contain injected secret")
}

func testRunRejectsCrossRoleAndPrivilegedEnvWithoutOverride() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["mercury_secret"])
    let runner = RecordingCommandRunner()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt, commandRunner: runner)

    let set = cli.run([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "run fixture finance secret set")

    let crossRole = cli.run([
        "run",
        "--role", "regular",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(crossRole.exitCode, 1, "run cross-role exit code")
    try expect(crossRole.stderr.contains("Refusing to use secret mercury-api-key from role finance in role regular."), "run cross-role message: \(crossRole.stderr)")
    try expectEqual(runner.invocations.count, 0, "cross-role run must not invoke command")

    let rawDenied = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(rawDenied.exitCode, 1, "privileged env denied exit code")
    try expect(rawDenied.stderr.contains("Role finance disallows environment-variable secret injection"), "privileged env denied message: \(rawDenied.stderr)")
    try expectEqual(runner.invocations.count, 0, "denied privileged run must not invoke command")

    let allowed = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--allow-privileged-env",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(allowed.exitCode, 0, "privileged env allowed exit code")
    try expectEqual(runner.invocations.count, 1, "allowed privileged run invokes command")
    try expectEqual(runner.invocations[0].environment["MERCURY_API_KEY"], "mercury_secret", "privileged env value")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"privileged_environment_injection_override\""), "audit should include privileged env override")
    try expect(auditText.contains("\"event\":\"policy_rejection\""), "audit should include run policy rejection")
    try expect(!auditText.contains("mercury_secret"), "audit must not contain finance secret")
}

func testPolicyMutationsAndRawOverridesRequireUserPresence() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["mercury_secret"])
    let authorizer = RecordingUserPresenceAuthorizer()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt, authorizer: authorizer)

    let roleCreate = cli.run([
        "role", "create", "analyst",
        "--reason", "Create analyst role",
        "--description", "Analyst"
    ], workingDirectory: temp.url)
    try expectEqual(roleCreate.exitCode, 0, "authorized role create")
    try expect(authorizer.reasons.contains("Create analyst role"), "role create should require user presence")

    let secretSet = cli.run([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(secretSet.exitCode, 0, "authorized secret set")
    try expect(authorizer.reasons.contains("Add Mercury API key"), "secret set should require user presence")

    let rawGet = cli.run([
        "secret", "get", "mercury-api-key",
        "--role", "finance",
        "--reason", "Review approved contractor invoices",
        "--allow-raw-secret"
    ], workingDirectory: temp.url)
    try expectEqual(rawGet.exitCode, 0, "authorized raw secret get")
    try expect(authorizer.reasons.contains("Review approved contractor invoices"), "raw secret override should require user presence")
}

func testRunBrowserLaunchesConfiguredBrowserAndDetaches() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let browser = RecordingBrowserLauncher()
    let runner = RecordingCommandRunner()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk, browser: browser, commandRunner: runner)

    let createVolume = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
        "--touch-id"
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "run browser fixture volume")

    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "run browser fixture browser")

    let run = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--browser", "Mercury",
        "--detach-on-exit",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(run.exitCode, 0, "run browser exit code")
    try expectEqual(browser.launches, [
        RecordingBrowserLauncher.Launch(userDataDir: "/Volumes/AgentKeychain-demo-FinanceBrowser/ChromeProfiles/Mercury")
    ], "run browser launch")
    try expectEqual(runner.invocations.count, 1, "run browser command count")
    try expectEqual(disk.detached, ["/Volumes/AgentKeychain-demo-FinanceBrowser"], "run browser detach-on-exit")
}

func expectUnwrapped<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else {
        throw TestFailure(description: message)
    }
    return value
}

let tests: [(String, () throws -> Void)] = [
    ("testCLITypeExists", testCLITypeExists),
    ("testInitCreatesProjectLayoutConfigIntegrityAndAudit", testInitCreatesProjectLayoutConfigIntegrityAndAudit),
    ("testInitFallsBackWhenPhysicalProjectKeychainUnavailable", testInitFallsBackWhenPhysicalProjectKeychainUnavailable),
    ("testRoleCreateListShowAndReasonRequirement", testRoleCreateListShowAndReasonRequirement),
    ("testRoleUpdateAndDeleteMutatePolicyWithAudit", testRoleUpdateAndDeleteMutatePolicyWithAudit),
    ("testConfigTamperRejectsPolicyMutationUntilTrusted", testConfigTamperRejectsPolicyMutationUntilTrusted),
    ("testHeldConfigLockBlocksPolicyMutation", testHeldConfigLockBlocksPolicyMutation),
    ("testHeldConfigLockAuditsSecretSetMutationFailure", testHeldConfigLockAuditsSecretSetMutationFailure),
    ("testSecretSetGetListDeleteDoesNotLeakValues", testSecretSetGetListDeleteDoesNotLeakValues),
    ("testSecretPoliciesRejectCrossRoleAndPrivilegedRawOutput", testSecretPoliciesRejectCrossRoleAndPrivilegedRawOutput),
    ("testPhysicalSecretReadAuditsProjectKeychainUnlockLifecycle", testPhysicalSecretReadAuditsProjectKeychainUnlockLifecycle),
    ("testPhysicalSecretReadAuditsProjectKeychainUnlockFailureAndCommandFailure", testPhysicalSecretReadAuditsProjectKeychainUnlockFailureAndCommandFailure),
    ("testPhysicalSecretSetAndDeleteAuditProjectKeychainUnlockLifecycle", testPhysicalSecretSetAndDeleteAuditProjectKeychainUnlockLifecycle),
    ("testVolumeCreateUnlockLockStatusAndRolePolicy", testVolumeCreateUnlockLockStatusAndRolePolicy),
    ("testVolumeLockSkipsDetachWhenMountpointBusy", testVolumeLockSkipsDetachWhenMountpointBusy),
    ("testVolumeLockAuditsDetachFailure", testVolumeLockAuditsDetachFailure),
    ("testBrowserOpenUsesManagedVolumeLockFile", testBrowserOpenUsesManagedVolumeLockFile),
    ("testVolumeUnlockFailsClosedWhenAttachDoesNotVerifyMountedImage", testVolumeUnlockFailsClosedWhenAttachDoesNotVerifyMountedImage),
    ("testVolumeUnlockRejectsExistingMountpointThatIsNotExpectedImage", testVolumeUnlockRejectsExistingMountpointThatIsNotExpectedImage),
    ("testVolumeUnlockRejectsSymlinkMountpoint", testVolumeUnlockRejectsSymlinkMountpoint),
    ("testBrowserCreateOpenListAndRolePolicy", testBrowserCreateOpenListAndRolePolicy),
    ("testBrowserOpenRejectsProfilePathTraversal", testBrowserOpenRejectsProfilePathTraversal),
    ("testPrivilegedBrowserAndRunDefaultToDetachOnExit", testPrivilegedBrowserAndRunDefaultToDetachOnExit),
    ("testBrowserDeleteAndVolumeDeleteCleanUpMetadataAndStorage", testBrowserDeleteAndVolumeDeleteCleanUpMetadataAndStorage),
    ("testStatusConfigPathProjectDiscoveryAndTrustCurrent", testStatusConfigPathProjectDiscoveryAndTrustCurrent),
    ("testStatusReportsVolumeMountedState", testStatusReportsVolumeMountedState),
    ("testReadOnlyCommandsAuditLifecycle", testReadOnlyCommandsAuditLifecycle),
    ("testRunInjectsAllowedSecretAndAuditsCommand", testRunInjectsAllowedSecretAndAuditsCommand),
    ("testRunRejectsCrossRoleAndPrivilegedEnvWithoutOverride", testRunRejectsCrossRoleAndPrivilegedEnvWithoutOverride),
    ("testPolicyMutationsAndRawOverridesRequireUserPresence", testPolicyMutationsAndRawOverridesRequireUserPresence),
    ("testRunBrowserLaunchesConfiguredBrowserAndDetaches", testRunBrowserLaunchesConfiguredBrowserAndDetaches)
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

print("PASS \(tests.count) tests")
