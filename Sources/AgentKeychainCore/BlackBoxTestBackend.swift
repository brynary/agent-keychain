#if DEBUG
import Foundation

public struct BlackBoxRoleKeychainCreation: Codable, Equatable, Sendable {
    public var path: String
    public var password: String
    public var ttlSeconds: Int
}

public struct BlackBoxRolePassword: Codable, Equatable, Sendable {
    public var service: String
    public var password: String
}

public struct BlackBoxCreatedImage: Codable, Equatable, Sendable {
    public var imagePath: String
    public var size: String
    public var volumeName: String
    public var password: String
}

public struct BlackBoxAttachedImage: Codable, Equatable, Sendable {
    public var imagePath: String
    public var mountpoint: String
    public var password: String
}

public struct BlackBoxBrowserLaunch: Codable, Equatable, Sendable {
    public var userDataDir: String
    public var additionalArguments: [String]
}

public struct BlackBoxBrowserStatus: Codable, Equatable, Sendable {
    public var running: Bool
    public var headless: Bool?
    public var cdpPort: Int?

    public init(running: Bool, headless: Bool?, cdpPort: Int?) {
        self.running = running
        self.headless = headless
        self.cdpPort = cdpPort
    }
}

public struct BlackBoxCDPVersion: Codable, Equatable, Sendable {
    public var browser: String
    public var webSocketDebuggerUrl: String?

    public init(browser: String, webSocketDebuggerUrl: String?) {
        self.browser = browser
        self.webSocketDebuggerUrl = webSocketDebuggerUrl
    }
}

public struct BlackBoxCommandInvocation: Codable, Equatable, Sendable {
    public var command: [String]
    public var environment: [String: String]
}

public struct BlackBoxTestState: Codable, Equatable, Sendable {
    public var roleKeychainCreations: [BlackBoxRoleKeychainCreation]
    public var rolePasswords: [BlackBoxRolePassword]
    public var roleUnlocks: [String]
    public var roleLocks: [String]
    public var unlockedRoles: [String]
    public var keychainItems: [String: String]
    public var deletedServices: [String]
    public var createdImages: [BlackBoxCreatedImage]
    public var attachedImages: [BlackBoxAttachedImage]
    public var detachedMountpoints: [String]
    public var deletedImages: [String]
    public var mountedImages: [String: String]
    public var busyMountpoints: [String]
    public var browserLaunches: [BlackBoxBrowserLaunch]
    public var browserStops: [String]
    public var browserStatuses: [String: BlackBoxBrowserStatus]
    public var cdpVersions: [String: BlackBoxCDPVersion]
    public var cdpInspections: [Int]
    public var commandInvocations: [BlackBoxCommandInvocation]
    public var authorizations: [String]
    public var attachShouldLeaveUnmounted: Bool
    public var detachShouldFail: Bool
    public var commandExitCode: Int32
    public var commandStdout: String
    public var commandStderr: String

    public init(
        roleKeychainCreations: [BlackBoxRoleKeychainCreation] = [],
        rolePasswords: [BlackBoxRolePassword] = [],
        roleUnlocks: [String] = [],
        roleLocks: [String] = [],
        unlockedRoles: [String] = [],
        keychainItems: [String: String] = [:],
        deletedServices: [String] = [],
        createdImages: [BlackBoxCreatedImage] = [],
        attachedImages: [BlackBoxAttachedImage] = [],
        detachedMountpoints: [String] = [],
        deletedImages: [String] = [],
        mountedImages: [String: String] = [:],
        busyMountpoints: [String] = [],
        browserLaunches: [BlackBoxBrowserLaunch] = [],
        browserStops: [String] = [],
        browserStatuses: [String: BlackBoxBrowserStatus] = [:],
        cdpVersions: [String: BlackBoxCDPVersion] = [:],
        cdpInspections: [Int] = [],
        commandInvocations: [BlackBoxCommandInvocation] = [],
        authorizations: [String] = [],
        attachShouldLeaveUnmounted: Bool = false,
        detachShouldFail: Bool = false,
        commandExitCode: Int32 = 0,
        commandStdout: String = "child stdout\n",
        commandStderr: String = ""
    ) {
        self.roleKeychainCreations = roleKeychainCreations
        self.rolePasswords = rolePasswords
        self.roleUnlocks = roleUnlocks
        self.roleLocks = roleLocks
        self.unlockedRoles = unlockedRoles
        self.keychainItems = keychainItems
        self.deletedServices = deletedServices
        self.createdImages = createdImages
        self.attachedImages = attachedImages
        self.detachedMountpoints = detachedMountpoints
        self.deletedImages = deletedImages
        self.mountedImages = mountedImages
        self.busyMountpoints = busyMountpoints
        self.browserLaunches = browserLaunches
        self.browserStops = browserStops
        self.browserStatuses = browserStatuses
        self.cdpVersions = cdpVersions
        self.cdpInspections = cdpInspections
        self.commandInvocations = commandInvocations
        self.authorizations = authorizations
        self.attachShouldLeaveUnmounted = attachShouldLeaveUnmounted
        self.detachShouldFail = detachShouldFail
        self.commandExitCode = commandExitCode
        self.commandStdout = commandStdout
        self.commandStderr = commandStderr
    }

    public static func load(from url: URL) throws -> BlackBoxTestState {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return BlackBoxTestState()
        }
        return try JSONDecoder().decode(BlackBoxTestState.self, from: Data(contentsOf: url))
    }

    public func save(to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: url)
    }
}

public extension AgentKeychainDependencies {
    static func blackBoxTesting(stateURL: URL, secretValue: String?) -> AgentKeychainDependencies {
        let store = BlackBoxStateStore(url: stateURL)
        return AgentKeychainDependencies(
            keychainStore: BlackBoxKeychainStore(store: store),
            secretPrompt: BlackBoxSecretPrompt(secretValue: secretValue),
            diskImageStore: BlackBoxDiskImageStore(store: store),
            browserLauncher: BlackBoxBrowserLauncher(store: store),
            commandRunner: BlackBoxCommandRunner(store: store),
            userPresenceAuthorizer: BlackBoxUserPresenceAuthorizer(store: store),
            progressReporter: BlackBoxProgressReporter(),
            passwordGenerator: BlackBoxPasswordGenerator(),
            clock: BlackBoxClock(),
            runIDFactory: BlackBoxRunIDFactory()
        )
    }
}

private final class BlackBoxStateStore {
    private let url: URL

    init(url: URL) {
        self.url = url
    }

    func read() throws -> BlackBoxTestState {
        try BlackBoxTestState.load(from: url)
    }

    func update<T>(_ body: (inout BlackBoxTestState) throws -> T) throws -> T {
        var state = try read()
        let result = try body(&state)
        try state.save(to: url)
        return result
    }
}

private final class BlackBoxKeychainStore: KeychainStoring {
    private let store: BlackBoxStateStore

    init(store: BlackBoxStateStore) {
        self.store = store
    }

    func useProject(config: ProjectConfig, projectRoot: URL) throws {}

    func createRoleKeychain(path: String, password: String, ttlSeconds: Int) throws {
        try store.update { state in
            state.roleKeychainCreations.append(BlackBoxRoleKeychainCreation(path: path, password: password, ttlSeconds: ttlSeconds))
        }
        try FileManager.default.createDirectory(
            at: URL(fileURLWithPath: path).deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        FileManager.default.createFile(atPath: path, contents: Data())
    }

    func storeRoleKeychainPassword(service: String, password: String) throws {
        try store.update { state in
            state.rolePasswords.append(BlackBoxRolePassword(service: service, password: password))
        }
    }

    func unlockRoleKeychain(roleName: String, keychain: RoleKeychainConfig) throws {
        try store.update { state in
            state.roleUnlocks.append(roleName)
            if !state.unlockedRoles.contains(roleName) {
                state.unlockedRoles.append(roleName)
            }
        }
    }

    func lockRoleKeychain(roleName: String, keychain: RoleKeychainConfig) throws {
        try store.update { state in
            state.roleLocks.append(roleName)
            state.unlockedRoles.removeAll { $0 == roleName }
        }
    }

    func isRoleKeychainUnlocked(roleName: String, keychain: RoleKeychainConfig) throws -> Bool {
        try store.read().unlockedRoles.contains(roleName)
    }

    func storeGenericPassword(service: String, value: String, roleKeychain: RoleKeychainConfig) throws {
        try store.update { state in
            state.keychainItems[service] = value
        }
    }

    func readGenericPassword(service: String, roleKeychain: RoleKeychainConfig) throws -> String {
        let state = try store.read()
        guard let value = state.keychainItems[service] else {
            throw AgentKeychainError.filesystem("missing black-box keychain item: \(service)")
        }
        return value
    }

    func deleteGenericPassword(service: String, roleKeychain: RoleKeychainConfig) throws {
        try store.update { state in
            state.deletedServices.append(service)
            state.keychainItems.removeValue(forKey: service)
        }
    }
}

private final class BlackBoxSecretPrompt: SecretPrompting {
    private let secretValue: String?

    init(secretValue: String?) {
        self.secretValue = secretValue
    }

    func readSecret(prompt: String) throws -> String {
        guard let secretValue else {
            throw AgentKeychainError.invalidArguments("black-box secret value missing")
        }
        return secretValue
    }
}

private final class BlackBoxDiskImageStore: DiskImageManaging {
    private let store: BlackBoxStateStore

    init(store: BlackBoxStateStore) {
        self.store = store
    }

    func createEncryptedSparsebundle(imagePath: String, size: String, volumeName: String, password: String) throws {
        try store.update { state in
            state.createdImages.append(BlackBoxCreatedImage(imagePath: imagePath, size: size, volumeName: volumeName, password: password))
        }
        try FileManager.default.createDirectory(at: URL(fileURLWithPath: imagePath), withIntermediateDirectories: true)
    }

    func attach(imagePath: String, mountpoint: String, password: String) throws {
        try store.update { state in
            state.attachedImages.append(BlackBoxAttachedImage(imagePath: imagePath, mountpoint: mountpoint, password: password))
            if !state.attachShouldLeaveUnmounted {
                state.mountedImages[mountpoint] = imagePath
            }
        }
        let state = try store.read()
        if !state.attachShouldLeaveUnmounted {
            try FileManager.default.createDirectory(atPath: mountpoint, withIntermediateDirectories: true)
        }
    }

    func detach(mountpoint: String) throws {
        try store.update { state in
            if state.detachShouldFail {
                throw AgentKeychainError.filesystem("black-box detach failure")
            }
            state.detachedMountpoints.append(mountpoint)
            state.mountedImages.removeValue(forKey: mountpoint)
        }
        if FileManager.default.fileExists(atPath: mountpoint) {
            try? FileManager.default.removeItem(atPath: mountpoint)
        }
    }

    func isMounted(imagePath: String, mountpoint: String) throws -> Bool {
        let state = try store.read()
        let expectedImage = URL(fileURLWithPath: imagePath).standardizedFileURL.path
        let actualImage = state.mountedImages[mountpoint].map { URL(fileURLWithPath: $0).standardizedFileURL.path }
        return actualImage == expectedImage
    }

    func isBusy(mountpoint: String) throws -> Bool {
        try store.read().busyMountpoints.contains(mountpoint)
    }

    func deleteImage(imagePath: String) throws {
        try store.update { state in
            state.deletedImages.append(imagePath)
        }
        if FileManager.default.fileExists(atPath: imagePath) {
            try FileManager.default.removeItem(atPath: imagePath)
        }
    }
}

private final class BlackBoxBrowserLauncher: BrowserLaunching {
    private let store: BlackBoxStateStore

    init(store: BlackBoxStateStore) {
        self.store = store
    }

    func launchChrome(userDataDir: String, additionalArguments: [String]) throws {
        try store.update { state in
            state.browserLaunches.append(BlackBoxBrowserLaunch(userDataDir: userDataDir, additionalArguments: additionalArguments))
            state.browserStatuses[userDataDir] = BlackBoxBrowserStatus(
                running: true,
                headless: additionalArguments.contains("--headless=new"),
                cdpPort: remoteDebuggingPort(in: additionalArguments)
            )
        }
    }

    func stopChromeProcesses(userDataDir: String) throws -> Int {
        try store.update { state in
            state.browserStops.append(userDataDir)
            let wasRunning = state.browserStatuses[userDataDir]?.running == true
            state.browserStatuses[userDataDir] = BlackBoxBrowserStatus(running: false, headless: nil, cdpPort: nil)
            return wasRunning ? 1 : 0
        }
    }

    func managedChromeStatus(userDataDir: String) throws -> (running: Bool, headless: Bool?, cdpPort: Int?) {
        let status = try store.read().browserStatuses[userDataDir]
        return (
            running: status?.running ?? false,
            headless: status?.headless,
            cdpPort: status?.cdpPort
        )
    }

    func inspectCDP(port: Int) throws -> (browser: String, webSocketDebuggerUrl: String?)? {
        let version = try store.update { state in
            state.cdpInspections.append(port)
            return state.cdpVersions[String(port)]
        }
        return version.map { (browser: $0.browser, webSocketDebuggerUrl: $0.webSocketDebuggerUrl) }
    }

    private func remoteDebuggingPort(in arguments: [String]) -> Int? {
        for index in arguments.indices {
            let argument = arguments[index]
            if argument.hasPrefix("--remote-debugging-port=") {
                return Int(argument.dropFirst("--remote-debugging-port=".count))
            }
            if argument == "--remote-debugging-port", arguments.indices.contains(index + 1) {
                return Int(arguments[index + 1])
            }
        }
        return nil
    }
}

private final class BlackBoxCommandRunner: CommandRunning {
    private let store: BlackBoxStateStore

    init(store: BlackBoxStateStore) {
        self.store = store
    }

    func run(command: [String], environment: [String: String]) throws -> ChildProcessResult {
        let state = try store.update { state in
            state.commandInvocations.append(BlackBoxCommandInvocation(command: command, environment: environment))
            return state
        }
        return ChildProcessResult(
            exitCode: state.commandExitCode,
            stdout: state.commandStdout,
            stderr: state.commandStderr
        )
    }
}

private final class BlackBoxUserPresenceAuthorizer: UserPresenceAuthorizing {
    private let store: BlackBoxStateStore

    init(store: BlackBoxStateStore) {
        self.store = store
    }

    func authorize(reason: String, progressReporter: ProgressMessageReporting) throws {
        try store.update { state in
            state.authorizations.append(reason)
        }
    }
}

private final class BlackBoxProgressReporter: ProgressMessageReporting {
    func report(_ message: String) {}
}

private struct BlackBoxPasswordGenerator: PasswordGenerating {
    func generatePassword() throws -> String {
        "black-box-generated-password"
    }
}

private struct BlackBoxClock: Clock {
    func now() -> Date {
        ISO8601DateFormatter().date(from: "2026-06-28T16:40:11Z")!
    }
}

private struct BlackBoxRunIDFactory: RunIDMaking {
    func makeRunID(date: Date) -> String {
        "run_20260628T164011Z_blackbox"
    }
}
#endif
