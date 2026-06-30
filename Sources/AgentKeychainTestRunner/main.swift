import AgentKeychainCore
import Foundation
import CryptoKit
import Security

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
    struct RoleKeychainCreation {
        let path: String
        let password: String
        let ttlSeconds: Int
    }

    struct RolePassword {
        let service: String
        let password: String
    }

    struct GenericPasswordWrite: Equatable {
        let service: String
        let value: String
        let roleKeychainPath: String?
    }

    var roleKeychainCreations: [RoleKeychainCreation] = []
    var rolePasswords: [RolePassword] = []
    var genericPasswordWrites: [GenericPasswordWrite] = []
    var roleUnlocks: [String] = []
    var roleLocks: [String] = []
    var roleUnlockStatusChecks: [String] = []
    var unlockedRoles: Set<String> = []
    var secrets: [String: String] = [:]
    var deletedServices: [String] = []
    var failingReadServices: Set<String> = []

    func useProject(config: ProjectConfig, projectRoot: URL) throws {}

    func createRoleKeychain(path: String, password: String, ttlSeconds: Int) throws {
        roleKeychainCreations.append(RoleKeychainCreation(path: path, password: password, ttlSeconds: ttlSeconds))
    }

    func storeRoleKeychainPassword(service: String, password: String) throws {
        rolePasswords.append(RolePassword(service: service, password: password))
    }

    func unlockRoleKeychain(roleName: String, keychain: RoleKeychainConfig) throws {
        roleUnlocks.append(roleName)
        unlockedRoles.insert(roleName)
    }

    func lockRoleKeychain(roleName: String, keychain: RoleKeychainConfig) throws {
        roleLocks.append(roleName)
        unlockedRoles.remove(roleName)
    }

    func isRoleKeychainUnlocked(roleName: String, keychain: RoleKeychainConfig) throws -> Bool {
        roleUnlockStatusChecks.append(roleName)
        return unlockedRoles.contains(roleName)
    }

    func storeGenericPassword(service: String, value: String, roleKeychain: RoleKeychainConfig) throws {
        genericPasswordWrites.append(GenericPasswordWrite(service: service, value: value, roleKeychainPath: roleKeychain.path))
        secrets[service] = value
    }

    func readGenericPassword(service: String, roleKeychain: RoleKeychainConfig) throws -> String {
        if failingReadServices.contains(service) {
            throw AgentKeychainError.filesystem("simulated keychain read failure")
        }
        guard let value = secrets[service] else {
            throw TestFailure(description: "missing keychain value for \(service)")
        }
        return value
    }

    func deleteGenericPassword(service: String, roleKeychain: RoleKeychainConfig) throws {
        deletedServices.append(service)
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
        let additionalArguments: [String]
    }

    var launches: [Launch] = []

    func launchChrome(userDataDir: String, additionalArguments: [String]) throws {
        launches.append(Launch(userDataDir: userDataDir, additionalArguments: additionalArguments))
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

    func authorize(reason: String, progressReporter: ProgressMessageReporting) throws {
        progressReporter.report("Waiting for macOS authentication: \(reason)")
        reasons.append(reason)
    }
}

final class FailingUserPresenceAuthorizer: UserPresenceAuthorizing {
    func authorize(reason: String, progressReporter: ProgressMessageReporting) throws {
        progressReporter.report("Waiting for macOS authentication: \(reason)")
        throw AgentKeychainError.policy("simulated authentication failure")
    }
}

final class RecordingProgressReporter: ProgressMessageReporting {
    var messages: [String] = []

    func report(_ message: String) {
        messages.append(message)
    }
}

final class MutableClock: Clock {
    var date: Date

    init(date: Date) {
        self.date = date
    }

    func now() -> Date {
        date
    }
}

struct RecordingRunIDFactory: RunIDMaking {
    func makeRunID(date: Date) -> String {
        "run_\(iso8601UTC(date).replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: ""))"
    }
}

struct FixedPasswordGeneratorForTests: PasswordGenerating {
    let password: String

    func generatePassword() throws -> String {
        password
    }
}

func createExampleRolesFixture(cli: AgentKeychainCLI, workingDirectory: URL) throws {
    let regular = cli.run([
        "role", "create", "regular",
        "--reason", "Create regular example role",
        "--description", "Day-to-day low-risk agent work",
    ], workingDirectory: workingDirectory)
    try expectEqual(regular.exitCode, 0, "regular role fixture")

    let workspaceAdmin = cli.run([
        "role", "create", "workspace-admin",
        "--reason", "Create workspace admin example role",
        "--description", "Identity and workspace administration",
    ], workingDirectory: workingDirectory)
    try expectEqual(workspaceAdmin.exitCode, 0, "workspace-admin role fixture")

    let finance = cli.run([
        "role", "create", "finance",
        "--reason", "Create finance example role",
        "--description", "Money movement and financial administration",
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
    progressReporter: ProgressMessageReporting = RecordingProgressReporter(),
    createExampleRoles: Bool = true
) throws -> AgentKeychainCLI {
    let cli = AgentKeychainCLI(dependencies: .testing(
        keychainStore: keychain,
        secretPrompt: prompt,
        diskImageStore: disk,
        browserLauncher: browser,
        commandRunner: commandRunner,
        userPresenceAuthorizer: authorizer,
        progressReporter: progressReporter,
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

func testLoginKeychainFallbackPolicyUsesUnsignedCLIPathOnlyForMissingEntitlement() throws {
    try expect(
        LoginKeychainAccessControlFallback.shouldStoreWithoutAccessControl(after: errSecMissingEntitlement),
        "missing entitlement should use unsigned CLI fallback"
    )
    try expect(
        !LoginKeychainAccessControlFallback.shouldStoreWithoutAccessControl(after: errSecAuthFailed),
        "auth failure should not use unsigned CLI fallback"
    )
    try expect(
        !LoginKeychainAccessControlFallback.shouldStoreWithoutAccessControl(after: errSecDuplicateItem),
        "duplicate item should not use unsigned CLI fallback"
    )
}

func testCustomKeychainItemAccessPolicyAllowsExecutableIndependentReads() throws {
    try expect(
        CustomKeychainItemAccessPolicy.allowsAnyApplicationAfterUnlock,
        "role keychain items should not be tied to the executable path that created them"
    )
}

func testTopLevelHelpIsUsefulAndDoesNotRequireProject() throws {
    let cli = AgentKeychainCLI(dependencies: .testing(
        keychainStore: RecordingKeychainStore(),
        secretPrompt: QueueSecretPrompt([]),
        diskImageStore: RecordingDiskImageStore(),
        browserLauncher: RecordingBrowserLauncher(),
        commandRunner: RecordingCommandRunner(),
        userPresenceAuthorizer: RecordingUserPresenceAuthorizer(),
        progressReporter: RecordingProgressReporter(),
        randomPassword: "generated-project-keychain-password",
        now: ISO8601DateFormatter().date(from: "2026-06-28T16:40:11Z")!
    ))
    let temp = try TemporaryDirectory()

    let noArguments = cli.run([], workingDirectory: temp.url)
    try expectEqual(noArguments.exitCode, 2, "no-argument help exit code")
    try expect(noArguments.stdout.isEmpty, "no-argument help should not write stdout")
    try expect(noArguments.stderr.contains("Project-scoped credential and browser-session isolation"), "no-argument help description")
    try expect(noArguments.stderr.contains("Commands:"), "no-argument help command section")
    try expect(noArguments.stderr.contains("  init       Initialize agent-keychain state in a project"), "no-argument help init command")
    try expect(!noArguments.stderr.contains("No agent-keychain project found"), "no-argument help should not require a project")

    for helpArguments in [["--help"], ["-h"], ["help"]] {
        let result = cli.run(helpArguments, workingDirectory: temp.url)
        try expectEqual(result.exitCode, 0, "\(helpArguments) exit code")
        try expect(result.stdout.contains("Usage:"), "\(helpArguments) usage section")
        try expect(result.stdout.contains("agent-keychain [--project PATH] <command> [options]"), "\(helpArguments) top-level usage")
        try expect(result.stdout.contains("Examples:"), "\(helpArguments) examples section")
        try expect(result.stderr.isEmpty, "\(helpArguments) should not write stderr")
    }

    let unknown = cli.run(["not-a-command"], workingDirectory: temp.url)
    try expectEqual(unknown.exitCode, 2, "unknown command exit code")
    try expect(unknown.stderr.contains("Unknown command: not-a-command"), "unknown command message")
    try expect(unknown.stderr.contains("Commands:"), "unknown command help")
    try expect(!unknown.stderr.contains("No agent-keychain project found"), "unknown command should not require a project")
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
        progressReporter: RecordingProgressReporter(),
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
    try expect(!configText.contains("keychainPath"), "config must not contain legacy project keychain path")
    try expect(!configText.contains("keychainPasswordService"), "config must not contain legacy project keychain password service")
    try expect(!FileManager.default.fileExists(atPath: projectDir.appendingPathComponent("keychains/project.keychain-db").path), "init must not create a legacy project keychain")
    try expectEqual(keychain.roleKeychainCreations.count, 0, "init must not create role keychains before roles exist")
    try expectEqual(keychain.rolePasswords.count, 0, "init must not store role keychain passwords before roles exist")

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

func testRoleCreateListShow() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, createExampleRoles: false)

    let missingReason = cli.run(["role", "create", "analyst"], workingDirectory: temp.url)
    try expectEqual(missingReason.exitCode, 2, "missing reason exit code")
    try expect(missingReason.stderr.contains("Policy mutations require --reason"), "missing reason message: \(missingReason.stderr)")

    let created = cli.run([
        "role", "create", "analyst",
        "--reason", "Create analyst role for reporting workflows",
        "--description", "Reporting and read-only analytics",
    ], workingDirectory: temp.url)

    try expectEqual(created.exitCode, 0, "role create exit code")
    try expect(created.stderr.isEmpty, "role create stderr: \(created.stderr)")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    let config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    let analyst = try expectUnwrapped(config.roles["analyst"], "expected analyst role in config")
    try expectEqual(analyst.description, "Reporting and read-only analytics", "analyst description")
    let analystKeychain = try expectUnwrapped(analyst.keychain, "expected analyst role keychain")
    try expectEqual(analystKeychain.path, ".agent-keychain/keychains/roles/analyst.keychain-db", "analyst keychain path")
    try expectEqual(analystKeychain.passwordService, "agent-keychain.project.demo.role.analyst.keychain-password", "analyst keychain password service")
    try expectEqual(analystKeychain.ttlSeconds, 300, "analyst keychain ttl")
    try expect(
        keychain.roleKeychainCreations.contains { $0.path == ".agent-keychain/keychains/roles/analyst.keychain-db" && $0.ttlSeconds == 300 },
        "role create should create role keychain"
    )
    try expect(
        keychain.rolePasswords.contains { $0.service == "agent-keychain.project.demo.role.analyst.keychain-password" },
        "role create should store role keychain password"
    )

    let list = cli.run(["role", "list"], workingDirectory: temp.url)
    try expectEqual(list.exitCode, 0, "role list exit code")
    try expect(list.stdout.contains("analyst\n"), "role list should include analyst: \(list.stdout)")

    let show = cli.run(["role", "show", "analyst"], workingDirectory: temp.url)
    try expectEqual(show.exitCode, 0, "role show exit code")
    try expectEqual(
        show.stdout,
        "{\"description\":\"Reporting and read-only analytics\",\"keychain\":{\"passwordService\":\"agent-keychain.project.demo.role.analyst.keychain-password\",\"path\":\".agent-keychain/keychains/roles/analyst.keychain-db\",\"ttlSeconds\":300}}\n",
        "role show JSON"
    )
    let removedReasonFlag = cli.run([
        "role", "create", "auditor",
        "--reason", "Create auditor role",
        "--require-reason",
    ], workingDirectory: temp.url)
    try expectEqual(removedReasonFlag.exitCode, 2, "removed role create require reason flag exit code")
    let removedFlag = cli.run([
        "role", "create", "auditor",
        "--reason", "Create auditor role",
        "--deny-secret-export",
    ], workingDirectory: temp.url)
    try expectEqual(removedFlag.exitCode, 2, "removed role create export flag exit code")

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

    let missingDescription = cli.run([
        "role", "update", "analyst",
        "--reason", "No-op role update",
    ], workingDirectory: temp.url)
    try expectEqual(missingDescription.exitCode, 2, "role update without description exit code")
    try expect(missingDescription.stderr.contains("role update requires --description"), "role update without description error")
    try expect(!authorizer.reasons.contains("No-op role update"), "role update without description should not authorize")

    let update = cli.run([
        "role", "update", "analyst",
        "--reason", "Update analyst role description",
        "--description", "Read-only reporting",
    ], workingDirectory: temp.url)
    try expectEqual(update.exitCode, 0, "role update exit code")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    var config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    let analyst = try expectUnwrapped(config.roles["analyst"], "expected analyst role after update")
    try expectEqual(analyst.description, "Read-only reporting", "updated role description")
    let removedRequireReasonFlag = cli.run([
        "role", "update", "analyst",
        "--reason", "Try removed require reason flag",
        "--require-reason",
    ], workingDirectory: temp.url)
    try expectEqual(removedRequireReasonFlag.exitCode, 2, "removed require reason update flag exit code")

    let removedNoRequireReasonFlag = cli.run([
        "role", "update", "analyst",
        "--reason", "Try removed no require reason flag",
        "--no-require-reason",
    ], workingDirectory: temp.url)
    try expectEqual(removedNoRequireReasonFlag.exitCode, 2, "removed no require reason update flag exit code")

    let removedDenyFlag = cli.run([
        "role", "update", "analyst",
        "--reason", "Try removed deny export flag",
        "--deny-secret-export",
    ], workingDirectory: temp.url)
    try expectEqual(removedDenyFlag.exitCode, 2, "removed deny secret export update flag exit code")

    let removedAllowFlag = cli.run([
        "role", "update", "analyst",
        "--reason", "Try removed allow export flag",
        "--allow-secret-export",
    ], workingDirectory: temp.url)
    try expectEqual(removedAllowFlag.exitCode, 2, "removed allow secret export update flag exit code")

    let setSecret = cli.run([
        "secret", "set", "analyst-token",
        "--role", "analyst",
        "--reason", "Add analyst token",
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
    try expect(authorizer.reasons.contains("Update analyst role description"), "role update should require user presence")
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
    ], workingDirectory: temp.url)

    try expectEqual(set.exitCode, 0, "secret set exit code")
    let service = "agent-keychain.role.regular.secret.github-readonly"
    try expectEqual(keychain.secrets[service], "ghp_regular_secret", "stored secret value")

    let configURL = temp.url.appendingPathComponent(".agent-keychain/config.json")
    let configText = try String(contentsOf: configURL, encoding: .utf8)
    try expect(configText.contains(service), "config should contain keychain service metadata")
    try expect(!configText.contains("ghp_regular_secret"), "config must not contain secret value")
    let config = try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    let metadata = try expectUnwrapped(config.secrets["github-readonly"], "expected github-readonly secret metadata")
    let metadataText = String(decoding: try CanonicalJSON.encode(metadata), as: UTF8.self)
    try expectEqual(metadataText, "{\"keychainService\":\"agent-keychain.role.regular.secret.github-readonly\",\"role\":\"regular\"}", "secret metadata JSON")

    let list = cli.run(["secret", "list", "--role", "regular"], workingDirectory: temp.url)
    try expectEqual(list.exitCode, 0, "secret list exit code")
    try expect(list.stdout.contains("github-readonly\n"), "secret list should include name: \(list.stdout)")
    try expect(!list.stdout.contains("ghp_regular_secret"), "secret list must not print value")

    let get = cli.run(["secret", "get", "github-readonly"], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 0, "secret get exit code")
    try expectEqual(get.stdout, "ghp_regular_secret\n", "secret get stdout")

    let rejectedRole = cli.run(["secret", "get", "github-readonly", "--role", "regular"], workingDirectory: temp.url)
    try expectEqual(rejectedRole.exitCode, 2, "secret get explicit role exit code")
    try expect(
        rejectedRole.stderr.contains("secret get infers the role from secret ownership; omit --role"),
        "secret get explicit role rejection: \(rejectedRole.stderr)"
    )

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

func testSecretGetReusesRoleUnlockWithinTTL() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token for regular agent work",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "ttl fixture secret set")

    let first = cli.run(["secret", "get", "github-readonly"], workingDirectory: temp.url)
    try expectEqual(first.exitCode, 0, "first inferred secret get")
    try expectEqual(first.stdout, "ghp_regular_secret\n", "first inferred secret value")

    let second = cli.run(["secret", "get", "github-readonly"], workingDirectory: temp.url)
    try expectEqual(second.exitCode, 0, "second inferred secret get")
    try expectEqual(second.stdout, "ghp_regular_secret\n", "second inferred secret value")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expectEqual(
        occurrenceCount(in: auditText, of: "\"event\":\"role_keychain_unlock_succeeded\""),
        1,
        "role keychain should unlock once within TTL"
    )
    try expect(auditText.contains("\"role\":\"regular\""), "role keychain unlock audit should include role")
}

func testSecretGetRequiresPromptWhenRoleSessionIsMissing() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token for regular agent work",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "missing session fixture secret set")
    try expectEqual(keychain.roleUnlocks.filter { $0 == "regular" }.count, 1, "set should unlock regular once")
    try expect(keychain.unlockedRoles.contains("regular"), "fixture role keychain should still be unlocked")

    try ConfigStore(projectRoot: temp.url).deleteRoleSession(roleName: "regular")
    keychain.roleUnlockStatusChecks.removeAll()
    let get = cli.run(["secret", "get", "github-readonly"], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 0, "missing session secret get exit code")
    try expectEqual(get.stdout, "ghp_regular_secret\n", "missing session secret value")
    try expectEqual(keychain.roleUnlocks.filter { $0 == "regular" }.count, 2, "missing session should unlock regular again")
    try expect(keychain.roleLocks.contains("regular"), "missing session should lock regular before re-unlock")
    try expectEqual(keychain.roleUnlockStatusChecks, [], "missing session should not probe role keychain status before forced lock")
}

func testSecretGetPromptsAgainAfterRoleUnlockTTLExpires() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let clock = MutableClock(date: ISO8601DateFormatter().date(from: "2026-06-28T16:40:11Z")!)
    let cli = AgentKeychainCLI(dependencies: AgentKeychainDependencies(
        keychainStore: keychain,
        secretPrompt: prompt,
        diskImageStore: RecordingDiskImageStore(),
        browserLauncher: RecordingBrowserLauncher(),
        commandRunner: RecordingCommandRunner(),
        userPresenceAuthorizer: RecordingUserPresenceAuthorizer(),
        progressReporter: RecordingProgressReporter(),
        passwordGenerator: FixedPasswordGeneratorForTests(password: "generated-project-keychain-password"),
        clock: clock,
        runIDFactory: RecordingRunIDFactory()
    ))

    let initResult = cli.run(["init", "--project-name", "demo"], workingDirectory: temp.url)
    try expectEqual(initResult.exitCode, 0, "ttl expiry init")
    try createExampleRolesFixture(cli: cli, workingDirectory: temp.url)
    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token for regular agent work",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "ttl expiry fixture secret set")
    try expectEqual(keychain.roleUnlocks.filter { $0 == "regular" }.count, 1, "set should unlock regular once")

    clock.date = clock.date.addingTimeInterval(301)
    let get = cli.run(["secret", "get", "github-readonly"], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 0, "expired secret get exit code")
    try expectEqual(get.stdout, "ghp_regular_secret\n", "expired secret value")
    try expectEqual(keychain.roleUnlocks.filter { $0 == "regular" }.count, 2, "expired role should unlock again")
    try expect(keychain.roleLocks.contains("regular"), "expired role should be locked before re-unlock")
}

func testRemovedConfigMigrationAndRepairCommandsAreRejected() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain)

    let migrate = cli.run([
        "config", "migrate-role-keychains",
        "--reason", "Migrate legacy role keychains"
    ], workingDirectory: temp.url)
    try expectEqual(migrate.exitCode, 2, "removed role keychain migration exit code")
    try expect(migrate.stderr.contains("Unknown config command: migrate-role-keychains"), "removed migration message: \(migrate.stderr)")

    let repair = cli.run([
        "config", "repair-keychain-access",
        "--reason", "Repair executable-bound keychain ACLs"
    ], workingDirectory: temp.url)
    try expectEqual(repair.exitCode, 2, "removed keychain repair exit code")
    try expect(repair.stderr.contains("Unknown config command: repair-keychain-access"), "removed repair message: \(repair.stderr)")
}

func testUnfilteredDiscoveryOutputIncludesRoleContext() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "discovery fixture secret set")

    let createVolume = cli.run([
        "volume", "create", "RegularBrowser",
        "--role", "regular",
        "--size", "20g",
        "--reason", "Create regular browser volume",
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "discovery fixture volume create")

    let createBrowser = cli.run([
        "browser", "create", "GitHub",
        "--role", "regular",
        "--volume", "RegularBrowser",
        "--reason", "Create GitHub browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "discovery fixture browser create")

    let secrets = cli.run(["secret", "list"], workingDirectory: temp.url)
    try expectEqual(secrets.exitCode, 0, "unfiltered secret list exit code")
    try expect(secrets.stdout.contains("ROLE"), "secret list should include role header: \(secrets.stdout)")
    try expect(secrets.stdout.contains("regular  github-readonly"), "secret list should include role and secret: \(secrets.stdout)")
    try expect(!secrets.stdout.contains("ghp_regular_secret"), "secret list must not print secret values")

    let browsers = cli.run(["browser", "list"], workingDirectory: temp.url)
    try expectEqual(browsers.exitCode, 0, "unfiltered browser list exit code")
    try expect(browsers.stdout.contains("ROLE"), "browser list should include role header: \(browsers.stdout)")
    try expect(browsers.stdout.contains("regular  GitHub"), "browser list should include role and browser: \(browsers.stdout)")

    let volumes = cli.run(["volume", "status"], workingDirectory: temp.url)
    try expectEqual(volumes.exitCode, 0, "unfiltered volume status exit code")
    try expect(volumes.stdout.contains("ROLE"), "volume status should include role header: \(volumes.stdout)")
    try expect(volumes.stdout.contains("regular  RegularBrowser  unmounted"), "volume status should include role, volume, and status: \(volumes.stdout)")
}

func testSecretGetInfersRoleAndRejectsRemovedRawOutputFlag() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["mercury_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key for finance workflows",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "finance secret set exit code")

    let rejectedRole = cli.run([
        "secret", "get", "mercury-api-key",
        "--role", "regular"
    ], workingDirectory: temp.url)
    try expectEqual(rejectedRole.exitCode, 2, "explicit role secret get exit code")
    try expect(
        rejectedRole.stderr.contains("secret get infers the role from secret ownership; omit --role"),
        "explicit role rejection message: \(rejectedRole.stderr)"
    )

    let allowed = cli.run([
        "secret", "get", "mercury-api-key",
    ], workingDirectory: temp.url)
    try expectEqual(allowed.exitCode, 0, "secret get exit code")
    try expectEqual(allowed.stdout, "mercury_secret\n", "secret get stdout")

    let removedFlag = cli.run([
        "secret", "get", "mercury-api-key",
        "--reason", "Review approved contractor invoices",
        "--allow-raw-secret"
    ], workingDirectory: temp.url)
    try expectEqual(removedFlag.exitCode, 2, "removed raw secret flag exit code")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(!auditText.contains("\"event\":\"raw_secret_stdout_override\""), "audit should not include removed raw secret override")
    try expect(!auditText.contains("mercury_secret"), "audit must not contain secret value")
}

func testPhysicalSecretReadAuditsRoleKeychainUnlockLifecycle() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "role keychain audit fixture secret set")

    let get = cli.run([
        "secret", "get", "github-readonly"
    ], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 0, "role keychain audit secret get")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"role_keychain_unlock_requested\""), "audit should include role keychain unlock request")
    try expect(auditText.contains("\"event\":\"role_keychain_unlock_succeeded\""), "audit should include role keychain unlock success")
}

func testPhysicalSecretReadAuditsRoleKeychainUnlockFailureAndCommandFailure() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "role keychain failure fixture secret set")

    keychain.failingReadServices.insert("agent-keychain.role.regular.secret.github-readonly")
    let get = cli.run([
        "secret", "get", "github-readonly"
    ], workingDirectory: temp.url)
    try expectEqual(get.exitCode, 1, "role keychain audit failed secret get")
    try expect(get.stderr.contains("simulated keychain read failure"), "failed keychain read message: \(get.stderr)")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"role_keychain_unlock_requested\""), "audit should include role unlock request")
    try expect(auditText.contains("\"event\":\"command_failed\""), "audit should include command_failed for keychain failure")
}

func testPhysicalSecretSetAndDeleteAuditRoleKeychainUnlockLifecycle() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["ghp_regular_secret"])
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt)

    let set = cli.run([
        "secret", "set", "github-readonly",
        "--role", "regular",
        "--reason", "Add GitHub token",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "role keychain write fixture secret set")

    let delete = cli.run([
        "secret", "delete", "github-readonly",
        "--role", "regular",
        "--reason", "Remove GitHub token"
    ], workingDirectory: temp.url)
    try expectEqual(delete.exitCode, 0, "role keychain delete fixture secret delete")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"role_keychain_unlock_requested\""), "set/delete should request role keychain unlock")
    try expect(auditText.contains("\"event\":\"role_keychain_unlock_succeeded\""), "set/delete should succeed role keychain unlock")
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
    let volumeText = String(decoding: try CanonicalJSON.encode(volume), as: UTF8.self)
    try expectEqual(
        volumeText,
        "{\"image\":\".agent-keychain/volumes/FinanceBrowser.sparsebundle\",\"keychainService\":\"agent-keychain.role.finance.volume.FinanceBrowser.password\",\"mountpoint\":\"/Volumes/AgentKeychain-demo-FinanceBrowser\",\"role\":\"finance\"}",
        "volume metadata JSON"
    )

    let rejectedRole = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--role", "regular"
    ], workingDirectory: temp.url)
    try expectEqual(rejectedRole.exitCode, 2, "explicit role volume unlock exit code")
    try expect(rejectedRole.stderr.contains("volume unlock infers the role from resource ownership; omit --role"), "explicit role volume message: \(rejectedRole.stderr)")
    try expectEqual(disk.attached.count, 0, "rejected unlock must not attach")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
    ], workingDirectory: temp.url)
    try expectEqual(unlock.exitCode, 0, "volume unlock exit code")
    try expectEqual(disk.attached.count, 1, "volume attach count")
    try expectEqual(disk.attached[0].mountpoint, "/Volumes/AgentKeychain-demo-FinanceBrowser", "attach mountpoint")
    try expectEqual(disk.attached[0].password, "generated-project-keychain-password", "attach password")

    let status = cli.run(["volume", "status", "FinanceBrowser"], workingDirectory: temp.url)
    try expectEqual(status.exitCode, 0, "volume status exit code")
    try expect(status.stdout.contains("FinanceBrowser mounted"), "volume status stdout: \(status.stdout)")

    let lock = cli.run([
        "volume", "lock", "FinanceBrowser"
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
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "busy fixture volume create")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
        "--reason", "Review approved contractor invoices"
    ], workingDirectory: temp.url)
    try expectEqual(unlock.exitCode, 0, "busy fixture volume unlock")

    disk.busyMountpoints.insert("/Volumes/AgentKeychain-demo-FinanceBrowser")
    let lock = cli.run([
        "volume", "lock", "FinanceBrowser"
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
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "detach failure fixture volume")

    disk.detachShouldFail = true
    let lock = cli.run([
        "volume", "lock", "RegularBrowser"
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
        "--reason", "Review payment status for approved invoices"
    ], workingDirectory: temp.url)
    try expectEqual(blocked.exitCode, 1, "held lock browser exit code")
    try expect(blocked.stderr.contains("Managed volume FinanceBrowser is already in use"), "held lock message: \(blocked.stderr)")
    try expectEqual(browser.launches.count, 0, "held lock browser should not launch")

    try FileManager.default.removeItem(at: lockURL)
    let opened = cli.run([
        "browser", "open", "Mercury",
        "--reason", "Review payment status for approved invoices"
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
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "verify fixture volume create")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
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

    let rejectedRole = cli.run([
        "browser", "open", "Mercury",
        "--role", "workspace-admin",
        "--reason", "Try wrong role"
    ], workingDirectory: temp.url)
    try expectEqual(rejectedRole.exitCode, 2, "explicit role browser exit code")
    try expect(rejectedRole.stderr.contains("browser open infers the role from resource ownership; omit --role"), "explicit role browser message: \(rejectedRole.stderr)")
    try expectEqual(browser.launches.count, 0, "rejected browser must not launch")

    let oldDetachFlag = cli.run([
        "browser", "open", "Mercury",
        "--reason", "Review payment status for approved invoices",
        "--detach-on-exit"
    ], workingDirectory: temp.url)
    try expectEqual(oldDetachFlag.exitCode, 2, "browser open detach-on-exit exit code")
    try expect(oldDetachFlag.stderr.contains("browser open no longer accepts --detach-on-exit"), "browser open detach-on-exit message: \(oldDetachFlag.stderr)")
    try expectEqual(browser.launches.count, 0, "browser detach-on-exit rejection should not launch")

    let open = cli.run([
        "browser", "open", "Mercury",
    ], workingDirectory: temp.url)
    try expectEqual(open.exitCode, 0, "browser open exit code")
    try expectEqual(disk.attached.count, 1, "browser should attach volume once")
    try expectEqual(browser.launches, [
        RecordingBrowserLauncher.Launch(userDataDir: "/Volumes/AgentKeychain-demo-FinanceBrowser/ChromeProfiles/Mercury", additionalArguments: [])
    ], "browser launches")
    try expectEqual(disk.detached, [], "browser open should leave browser volume mounted")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"browser_created\""), "audit should include browser_created")
    try expect(auditText.contains("\"event\":\"browser_opened\""), "audit should include browser_opened")
    try expect(!auditText.contains("\"event\":\"browser_exited\""), "browser open should not audit an unobserved browser exit")
}

func testBrowserPathMountsVolumeAndPrintsProfilePath() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let disk = RecordingDiskImageStore()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, disk: disk)

    let createVolume = cli.run([
        "volume", "create", "FinanceBrowser",
        "--role", "finance",
        "--size", "20g",
        "--reason", "Create encrypted browser volume for finance sessions",
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "browser path fixture volume")

    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile for finance workflows"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "browser path fixture browser")

    let rejectedRole = cli.run([
        "browser", "path", "Mercury",
        "--role", "regular"
    ], workingDirectory: temp.url)
    try expectEqual(rejectedRole.exitCode, 2, "browser path explicit role exit code")
    try expect(rejectedRole.stderr.contains("browser path infers the role from resource ownership; omit --role"), "browser path explicit role message: \(rejectedRole.stderr)")

    let path = cli.run([
        "browser", "path", "Mercury",
    ], workingDirectory: temp.url)
    try expectEqual(path.exitCode, 0, "browser path exit code")
    try expectEqual(path.stdout, "/Volumes/AgentKeychain-demo-FinanceBrowser/ChromeProfiles/Mercury\n", "browser path stdout")
    try expectEqual(disk.attached.count, 1, "browser path should attach volume")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(auditText.contains("\"event\":\"browser_path_resolved\""), "audit should include browser_path_resolved")
    try expect(!auditText.contains("/ChromeProfiles/Mercury"), "audit should not contain resolved profile path")
}

func testBrowserOpenPassesGuardedChromeArguments() throws {
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
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "browser args fixture volume")

    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile for finance workflows"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "browser args fixture browser")

    let headed = cli.run([
        "browser", "open", "Mercury",
        "--reason", "Open Mercury headed for passkey login",
        "--",
        "https://app.mercury.com"
    ], workingDirectory: temp.url)

    try expectEqual(headed.exitCode, 0, "browser headed open exit code")
    try expectEqual(browser.launches, [
        RecordingBrowserLauncher.Launch(
            userDataDir: "/Volumes/AgentKeychain-demo-FinanceBrowser/ChromeProfiles/Mercury",
            additionalArguments: [
                "https://app.mercury.com"
            ]
        )
    ], "browser headed launch")

    let open = cli.run([
        "browser", "open", "Mercury",
        "--reason", "Open Mercury for approved automation",
        "--",
        "--headless=new",
        "--remote-debugging-port=9222",
        "about:blank"
    ], workingDirectory: temp.url)

    try expectEqual(open.exitCode, 0, "browser args open exit code")
    try expectEqual(browser.launches, [
        RecordingBrowserLauncher.Launch(
            userDataDir: "/Volumes/AgentKeychain-demo-FinanceBrowser/ChromeProfiles/Mercury",
            additionalArguments: [
                "https://app.mercury.com"
            ]
        ),
        RecordingBrowserLauncher.Launch(
            userDataDir: "/Volumes/AgentKeychain-demo-FinanceBrowser/ChromeProfiles/Mercury",
            additionalArguments: [
                "--headless=new",
                "--remote-debugging-port=9222",
                "about:blank",
                "--remote-debugging-address=127.0.0.1"
            ]
        )
    ], "browser args launch")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(!auditText.contains("--headless=new"), "audit should not contain raw Chrome args")
    try expect(!auditText.contains("about:blank"), "audit should not contain raw Chrome URL args")
}

func testBrowserOpenRejectsUnsafeChromeArguments() throws {
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
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "unsafe args fixture volume")

    let createBrowser = cli.run([
        "browser", "create", "GitHub",
        "--role", "regular",
        "--volume", "RegularBrowser",
        "--reason", "Create GitHub browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "unsafe args fixture browser")

    let userDataEquals = cli.run([
        "browser", "open", "GitHub",
        "--",
        "--user-data-dir=/tmp/not-managed"
    ], workingDirectory: temp.url)
    try expectEqual(userDataEquals.exitCode, 1, "user-data-dir equals exit code")
    try expect(userDataEquals.stderr.contains("Refusing Chrome argument --user-data-dir because agent-keychain manages the browser profile path"), "user-data-dir equals message: \(userDataEquals.stderr)")

    let profileSeparate = cli.run([
        "browser", "open", "GitHub",
        "--",
        "--profile-directory", "Default"
    ], workingDirectory: temp.url)
    try expectEqual(profileSeparate.exitCode, 1, "profile-directory separate exit code")
    try expect(profileSeparate.stderr.contains("Refusing Chrome argument --profile-directory because agent-keychain manages the browser profile path"), "profile-directory separate message: \(profileSeparate.stderr)")

    let nonLoopback = cli.run([
        "browser", "open", "GitHub",
        "--",
        "--remote-debugging-address=0.0.0.0",
        "--remote-debugging-port", "9222"
    ], workingDirectory: temp.url)
    try expectEqual(nonLoopback.exitCode, 1, "non-loopback debugging exit code")
    try expect(nonLoopback.stderr.contains("Refusing non-loopback Chrome remote debugging address: 0.0.0.0"), "non-loopback debugging message: \(nonLoopback.stderr)")

    try expectEqual(browser.launches.count, 0, "unsafe args should not launch Chrome")
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
        "browser", "open", "GitHub"
    ], workingDirectory: temp.url)

    try expectEqual(open.exitCode, 1, "unsafe browser profile open exit code")
    try expect(open.stderr.contains("Refusing to use unsafe browser profile path"), "unsafe profile message: \(open.stderr)")
    try expectEqual(disk.attached.count, 0, "unsafe profile path should fail before attaching volume")
    try expectEqual(browser.launches.count, 0, "unsafe profile path should not launch Chrome")
}

func testBrowserOpenLeavesBrowserVolumeMounted() throws {
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
        "--reason", "Review payment status for approved invoices"
    ], workingDirectory: temp.url)
    try expectEqual(open.exitCode, 0, "privileged browser open exit code")
    try expectEqual(disk.detached, [], "browser open should leave privileged browser volume mounted")

    try expectEqual(runner.invocations.count, 0, "browser open should not invoke run command")
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
    try expect(!status.stdout.contains("Project keychain:"), "status should not report legacy project keychain state: \(status.stdout)")
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
    ], workingDirectory: temp.url)
    try expectEqual(create.exitCode, 0, "status volume fixture create")

    var status = cli.run(["status"], workingDirectory: temp.url)
    try expectEqual(status.exitCode, 0, "status unmounted exit code")
    try expect(status.stdout.contains("FinanceBrowser: unmounted"), "status should show unmounted volume: \(status.stdout)")

    let unlock = cli.run([
        "volume", "unlock", "FinanceBrowser",
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
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "run fixture secret set")

    let run = cli.run([
        "run",
        "--role", "regular",
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

func testRunRejectsCrossRoleAndRemovedPrivilegedEnvFlag() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["mercury_secret"])
    let runner = RecordingCommandRunner()
    let cli = try makeInitializedCLI(at: temp.url, keychain: keychain, prompt: prompt, commandRunner: runner)

    let set = cli.run([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key",
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

    let allowed = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(allowed.exitCode, 0, "same-role run with secret exit code")
    try expectEqual(runner.invocations.count, 1, "same-role run invokes command")
    try expectEqual(runner.invocations[0].environment["MERCURY_API_KEY"], "mercury_secret", "same-role secret export value")

    let removedFlag = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--allow-privileged-env",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(removedFlag.exitCode, 2, "removed privileged env flag exit code")
    try expectEqual(runner.invocations.count, 1, "removed flag must not invoke another command")

    let auditText = try String(contentsOf: temp.url.appendingPathComponent(".agent-keychain/audit.jsonl"), encoding: .utf8)
    try expect(!auditText.contains("\"event\":\"privileged_secret_export_override\""), "audit should not include removed privileged secret export override")
    try expect(auditText.contains("\"event\":\"policy_rejection\""), "audit should include run policy rejection")
    try expect(!auditText.contains("mercury_secret"), "audit must not contain finance secret")
}

func testPolicyMutationsRequireUserPresence() throws {
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
    ], workingDirectory: temp.url)
    try expectEqual(secretSet.exitCode, 0, "authorized secret set")
    try expect(authorizer.reasons.contains("Add Mercury API key"), "secret set should require user presence")

    let rawGet = cli.run([
        "secret", "get", "mercury-api-key",
        "--reason", "Review approved contractor invoices",
    ], workingDirectory: temp.url)
    try expectEqual(rawGet.exitCode, 0, "secret get exit code")
    try expect(!authorizer.reasons.contains("Review approved contractor invoices"), "secret get should rely on role keychain unlock, not a raw secret override")
}

func testUserPresenceAuthorizationReportsProgressWithoutStdoutPollution() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let progress = RecordingProgressReporter()
    let cli = try makeInitializedCLI(
        at: temp.url,
        keychain: keychain,
        progressReporter: progress,
        createExampleRoles: false
    )

    let roleCreate = cli.run([
        "role", "create", "regular",
        "--reason", "Create regular role",
        "--description", "Day-to-day low-risk agent work",
    ], workingDirectory: temp.url)

    try expectEqual(roleCreate.exitCode, 0, "role create with progress exit code")
    try expectEqual(roleCreate.stdout, "Created role regular\n", "progress should not pollute stdout")
    try expect(
        progress.messages.contains("Waiting for macOS authentication: Create regular role"),
        "user-presence authorization should report progress: \(progress.messages)"
    )
}

func testRunSecretExportDoesNotRequireOverrideProgress() throws {
    let temp = try TemporaryDirectory()
    let keychain = RecordingKeychainStore()
    let prompt = QueueSecretPrompt(["mercury_secret"])
    let runner = RecordingCommandRunner()
    let progress = RecordingProgressReporter()
    let cli = try makeInitializedCLI(
        at: temp.url,
        keychain: keychain,
        prompt: prompt,
        commandRunner: runner,
        progressReporter: progress
    )

    let set = cli.run([
        "secret", "set", "mercury-api-key",
        "--role", "finance",
        "--reason", "Add Mercury API key",
    ], workingDirectory: temp.url)
    try expectEqual(set.exitCode, 0, "progress fixture secret set")

    progress.messages.removeAll()
    let run = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--secret", "MERCURY_API_KEY=mercury-api-key",
        "--", "agent-command"
    ], workingDirectory: temp.url)

    try expectEqual(run.exitCode, 0, "run exit code")
    try expectEqual(run.stdout, "child stdout\n", "progress should not pollute run stdout")
    try expectEqual(runner.invocations.count, 1, "run child invocation count")
    try expectEqual(runner.invocations[0].environment["MERCURY_API_KEY"], "mercury_secret", "run injected env")
    try expect(
        !progress.messages.contains("Waiting for macOS authentication: Review approved payments"),
        "same-role secret export should not require a separate override prompt: \(progress.messages)"
    )
}

func testUserPresenceAuthorizationFailureStillReportsProgress() throws {
    let temp = try TemporaryDirectory()
    let progress = RecordingProgressReporter()
    let cli = try makeInitializedCLI(
        at: temp.url,
        authorizer: FailingUserPresenceAuthorizer(),
        progressReporter: progress,
        createExampleRoles: false
    )

    let roleCreate = cli.run([
        "role", "create", "regular",
        "--reason", "Create regular role",
        "--description", "Day-to-day low-risk agent work",
    ], workingDirectory: temp.url)

    try expectEqual(roleCreate.exitCode, 1, "failed user-presence exit code")
    try expect(roleCreate.stderr.contains("simulated authentication failure"), "failed auth stderr: \(roleCreate.stderr)")
    try expect(
        progress.messages.contains("Waiting for macOS authentication: Create regular role"),
        "failed user-presence authorization should still report progress: \(progress.messages)"
    )
}

func testRunRejectsVolumeBrowserDetachAndZeroSecretInvocations() throws {
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
    ], workingDirectory: temp.url)
    try expectEqual(createVolume.exitCode, 0, "run browser fixture volume")

    let createBrowser = cli.run([
        "browser", "create", "Mercury",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--reason", "Create Mercury browser profile"
    ], workingDirectory: temp.url)
    try expectEqual(createBrowser.exitCode, 0, "run browser fixture browser")

    let browserRun = cli.run([
        "run",
        "--role", "finance",
        "--reason", "Review approved payments",
        "--browser", "Mercury",
        "--detach-on-exit",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(browserRun.exitCode, 2, "run browser flag exit code")
    try expect(browserRun.stderr.contains("Unexpected run argument: --browser"), "run browser flag message: \(browserRun.stderr)")

    let volumeRun = cli.run([
        "run",
        "--role", "finance",
        "--volume", "FinanceBrowser",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(volumeRun.exitCode, 2, "run volume flag exit code")
    try expect(volumeRun.stderr.contains("Unexpected run argument: --volume"), "run volume flag message: \(volumeRun.stderr)")

    let detachRun = cli.run([
        "run",
        "--role", "finance",
        "--detach-on-exit",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(detachRun.exitCode, 2, "run detach flag exit code")
    try expect(detachRun.stderr.contains("Unexpected run argument: --detach-on-exit"), "run detach flag message: \(detachRun.stderr)")

    let zeroSecretRun = cli.run([
        "run",
        "--role", "finance",
        "--", "agent-command"
    ], workingDirectory: temp.url)
    try expectEqual(zeroSecretRun.exitCode, 2, "run zero secret exit code")
    try expect(zeroSecretRun.stderr.contains("run requires at least one --secret"), "run zero secret message: \(zeroSecretRun.stderr)")
    try expectEqual(browser.launches, [], "removed run browser flag must not launch browser")
    try expectEqual(disk.attached.count, 0, "removed run volume flag must not attach volume")
    try expectEqual(runner.invocations.count, 0, "invalid run invocations must not invoke command")
}

func expectUnwrapped<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else {
        throw TestFailure(description: message)
    }
    return value
}

let tests: [(String, () throws -> Void)] = [
    ("testCLITypeExists", testCLITypeExists),
    ("testLoginKeychainFallbackPolicyUsesUnsignedCLIPathOnlyForMissingEntitlement", testLoginKeychainFallbackPolicyUsesUnsignedCLIPathOnlyForMissingEntitlement),
    ("testCustomKeychainItemAccessPolicyAllowsExecutableIndependentReads", testCustomKeychainItemAccessPolicyAllowsExecutableIndependentReads),
    ("testTopLevelHelpIsUsefulAndDoesNotRequireProject", testTopLevelHelpIsUsefulAndDoesNotRequireProject),
    ("testInitCreatesProjectLayoutConfigIntegrityAndAudit", testInitCreatesProjectLayoutConfigIntegrityAndAudit),
    ("testRoleCreateListShow", testRoleCreateListShow),
    ("testRoleUpdateAndDeleteMutatePolicyWithAudit", testRoleUpdateAndDeleteMutatePolicyWithAudit),
    ("testConfigTamperRejectsPolicyMutationUntilTrusted", testConfigTamperRejectsPolicyMutationUntilTrusted),
    ("testHeldConfigLockBlocksPolicyMutation", testHeldConfigLockBlocksPolicyMutation),
    ("testHeldConfigLockAuditsSecretSetMutationFailure", testHeldConfigLockAuditsSecretSetMutationFailure),
    ("testSecretSetGetListDeleteDoesNotLeakValues", testSecretSetGetListDeleteDoesNotLeakValues),
    ("testSecretGetReusesRoleUnlockWithinTTL", testSecretGetReusesRoleUnlockWithinTTL),
    ("testSecretGetRequiresPromptWhenRoleSessionIsMissing", testSecretGetRequiresPromptWhenRoleSessionIsMissing),
    ("testSecretGetPromptsAgainAfterRoleUnlockTTLExpires", testSecretGetPromptsAgainAfterRoleUnlockTTLExpires),
    ("testRemovedConfigMigrationAndRepairCommandsAreRejected", testRemovedConfigMigrationAndRepairCommandsAreRejected),
    ("testUnfilteredDiscoveryOutputIncludesRoleContext", testUnfilteredDiscoveryOutputIncludesRoleContext),
    ("testSecretGetInfersRoleAndRejectsRemovedRawOutputFlag", testSecretGetInfersRoleAndRejectsRemovedRawOutputFlag),
    ("testPhysicalSecretReadAuditsRoleKeychainUnlockLifecycle", testPhysicalSecretReadAuditsRoleKeychainUnlockLifecycle),
    ("testPhysicalSecretReadAuditsRoleKeychainUnlockFailureAndCommandFailure", testPhysicalSecretReadAuditsRoleKeychainUnlockFailureAndCommandFailure),
    ("testPhysicalSecretSetAndDeleteAuditRoleKeychainUnlockLifecycle", testPhysicalSecretSetAndDeleteAuditRoleKeychainUnlockLifecycle),
    ("testVolumeCreateUnlockLockStatusAndRolePolicy", testVolumeCreateUnlockLockStatusAndRolePolicy),
    ("testVolumeLockSkipsDetachWhenMountpointBusy", testVolumeLockSkipsDetachWhenMountpointBusy),
    ("testVolumeLockAuditsDetachFailure", testVolumeLockAuditsDetachFailure),
    ("testBrowserOpenUsesManagedVolumeLockFile", testBrowserOpenUsesManagedVolumeLockFile),
    ("testVolumeUnlockFailsClosedWhenAttachDoesNotVerifyMountedImage", testVolumeUnlockFailsClosedWhenAttachDoesNotVerifyMountedImage),
    ("testVolumeUnlockRejectsExistingMountpointThatIsNotExpectedImage", testVolumeUnlockRejectsExistingMountpointThatIsNotExpectedImage),
    ("testVolumeUnlockRejectsSymlinkMountpoint", testVolumeUnlockRejectsSymlinkMountpoint),
    ("testBrowserCreateOpenListAndRolePolicy", testBrowserCreateOpenListAndRolePolicy),
    ("testBrowserPathMountsVolumeAndPrintsProfilePath", testBrowserPathMountsVolumeAndPrintsProfilePath),
    ("testBrowserOpenPassesGuardedChromeArguments", testBrowserOpenPassesGuardedChromeArguments),
    ("testBrowserOpenRejectsUnsafeChromeArguments", testBrowserOpenRejectsUnsafeChromeArguments),
    ("testBrowserOpenRejectsProfilePathTraversal", testBrowserOpenRejectsProfilePathTraversal),
    ("testBrowserOpenLeavesBrowserVolumeMounted", testBrowserOpenLeavesBrowserVolumeMounted),
    ("testBrowserDeleteAndVolumeDeleteCleanUpMetadataAndStorage", testBrowserDeleteAndVolumeDeleteCleanUpMetadataAndStorage),
    ("testStatusConfigPathProjectDiscoveryAndTrustCurrent", testStatusConfigPathProjectDiscoveryAndTrustCurrent),
    ("testStatusReportsVolumeMountedState", testStatusReportsVolumeMountedState),
    ("testReadOnlyCommandsAuditLifecycle", testReadOnlyCommandsAuditLifecycle),
    ("testRunInjectsAllowedSecretAndAuditsCommand", testRunInjectsAllowedSecretAndAuditsCommand),
    ("testRunRejectsCrossRoleAndRemovedPrivilegedEnvFlag", testRunRejectsCrossRoleAndRemovedPrivilegedEnvFlag),
    ("testPolicyMutationsRequireUserPresence", testPolicyMutationsRequireUserPresence),
    ("testUserPresenceAuthorizationReportsProgressWithoutStdoutPollution", testUserPresenceAuthorizationReportsProgressWithoutStdoutPollution),
    ("testRunSecretExportDoesNotRequireOverrideProgress", testRunSecretExportDoesNotRequireOverrideProgress),
    ("testUserPresenceAuthorizationFailureStillReportsProgress", testUserPresenceAuthorizationFailureStillReportsProgress),
    ("testRunRejectsVolumeBrowserDetachAndZeroSecretInvocations", testRunRejectsVolumeBrowserDetachAndZeroSecretInvocations)
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
