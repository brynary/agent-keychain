import CryptoKit
import Darwin
import Foundation

public enum AgentKeychainError: Error, Equatable {
    case invalidArguments(String)
    case filesystem(String)
    case configIntegrity(String)
    case policy(String)

    public var exitCode: Int32 {
        switch self {
        case .invalidArguments:
            return 2
        case .filesystem, .configIntegrity, .policy:
            return 1
        }
    }

    public var message: String {
        switch self {
        case .invalidArguments(let message), .filesystem(let message), .configIntegrity(let message), .policy(let message):
            return message
        }
    }
}

public protocol KeychainStoring: AnyObject {
    func createProjectKeychain(path: String, password: String) throws
    func useProject(config: ProjectConfig, projectRoot: URL) throws
    func storeProjectKeychainPassword(service: String, password: String) throws
    func storeGenericPassword(service: String, value: String) throws
    func readGenericPassword(service: String) throws -> String
    func deleteGenericPassword(service: String) throws
}

public protocol SecretPrompting: AnyObject {
    func readSecret(prompt: String) throws -> String
}

public protocol UserPresenceAuthorizing: AnyObject {
    func authorize(reason: String, progressReporter: ProgressMessageReporting) throws
}

public protocol ProgressMessageReporting: AnyObject {
    func report(_ message: String)
}

public protocol PasswordGenerating {
    func generatePassword() throws -> String
}

public protocol Clock {
    func now() -> Date
}

public protocol RunIDMaking {
    func makeRunID(date: Date) -> String
}

public struct AgentKeychainDependencies {
    public var keychainStore: KeychainStoring
    public var secretPrompt: SecretPrompting
    public var diskImageStore: DiskImageManaging
    public var browserLauncher: BrowserLaunching
    public var commandRunner: CommandRunning
    public var userPresenceAuthorizer: UserPresenceAuthorizing
    public var progressReporter: ProgressMessageReporting
    public var passwordGenerator: PasswordGenerating
    public var clock: Clock
    public var runIDFactory: RunIDMaking

    public init(
        keychainStore: KeychainStoring,
        secretPrompt: SecretPrompting,
        diskImageStore: DiskImageManaging,
        browserLauncher: BrowserLaunching,
        commandRunner: CommandRunning,
        userPresenceAuthorizer: UserPresenceAuthorizing,
        passwordGenerator: PasswordGenerating,
        clock: Clock,
        runIDFactory: RunIDMaking
    ) {
        self.init(
            keychainStore: keychainStore,
            secretPrompt: secretPrompt,
            diskImageStore: diskImageStore,
            browserLauncher: browserLauncher,
            commandRunner: commandRunner,
            userPresenceAuthorizer: userPresenceAuthorizer,
            progressReporter: StandardErrorProgressReporter(),
            passwordGenerator: passwordGenerator,
            clock: clock,
            runIDFactory: runIDFactory
        )
    }

    public init(
        keychainStore: KeychainStoring,
        secretPrompt: SecretPrompting,
        diskImageStore: DiskImageManaging,
        browserLauncher: BrowserLaunching,
        commandRunner: CommandRunning,
        userPresenceAuthorizer: UserPresenceAuthorizing,
        progressReporter: ProgressMessageReporting,
        passwordGenerator: PasswordGenerating,
        clock: Clock,
        runIDFactory: RunIDMaking
    ) {
        self.keychainStore = keychainStore
        self.secretPrompt = secretPrompt
        self.diskImageStore = diskImageStore
        self.browserLauncher = browserLauncher
        self.commandRunner = commandRunner
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.progressReporter = progressReporter
        self.passwordGenerator = passwordGenerator
        self.clock = clock
        self.runIDFactory = runIDFactory
    }

    public static func production() -> AgentKeychainDependencies {
        let progressReporter = StandardErrorProgressReporter()
        return AgentKeychainDependencies(
            keychainStore: MacOSKeychainStore(progressReporter: progressReporter),
            secretPrompt: TerminalSecretPrompt(),
            diskImageStore: ProcessDiskImageStore(),
            browserLauncher: ProcessBrowserLauncher(),
            commandRunner: ProcessCommandRunner(),
            userPresenceAuthorizer: LocalAuthenticationAuthorizer(),
            progressReporter: progressReporter,
            passwordGenerator: SecurePasswordGenerator(),
            clock: SystemClock(),
            runIDFactory: DefaultRunIDFactory()
        )
    }

    public static func testing(
        keychainStore: KeychainStoring,
        secretPrompt: SecretPrompting,
        diskImageStore: DiskImageManaging,
        browserLauncher: BrowserLaunching,
        commandRunner: CommandRunning,
        userPresenceAuthorizer: UserPresenceAuthorizing,
        randomPassword: String,
        now: Date
    ) -> AgentKeychainDependencies {
        testing(
            keychainStore: keychainStore,
            secretPrompt: secretPrompt,
            diskImageStore: diskImageStore,
            browserLauncher: browserLauncher,
            commandRunner: commandRunner,
            userPresenceAuthorizer: userPresenceAuthorizer,
            progressReporter: StandardErrorProgressReporter(),
            randomPassword: randomPassword,
            now: now
        )
    }

    public static func testing(
        keychainStore: KeychainStoring,
        secretPrompt: SecretPrompting,
        diskImageStore: DiskImageManaging,
        browserLauncher: BrowserLaunching,
        commandRunner: CommandRunning,
        userPresenceAuthorizer: UserPresenceAuthorizing,
        progressReporter: ProgressMessageReporting,
        randomPassword: String,
        now: Date
    ) -> AgentKeychainDependencies {
        AgentKeychainDependencies(
            keychainStore: keychainStore,
            secretPrompt: secretPrompt,
            diskImageStore: diskImageStore,
            browserLauncher: browserLauncher,
            commandRunner: commandRunner,
            userPresenceAuthorizer: userPresenceAuthorizer,
            progressReporter: progressReporter,
            passwordGenerator: FixedPasswordGenerator(password: randomPassword),
            clock: FixedClock(date: now),
            runIDFactory: FixedRunIDFactory()
        )
    }
}

public enum CanonicalJSON {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
}

public enum SHA256Hex {
    public static func hash(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

public struct ParsedOptions {
    private var values: [String: String] = [:]
    private var flags: Set<String> = []

    public init(arguments: [String], booleanFlags: Set<String> = []) throws {
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            guard argument.hasPrefix("--") else {
                throw AgentKeychainError.invalidArguments("Unexpected argument: \(argument)")
            }
            if booleanFlags.contains(argument) {
                flags.insert(argument)
                index += 1
                continue
            }
            guard index + 1 < arguments.count else {
                throw AgentKeychainError.invalidArguments("Missing value for \(argument)")
            }
            values[argument] = arguments[index + 1]
            index += 2
        }
    }

    public func value(for option: String) -> String? {
        values[option]
    }

    public func hasFlag(_ option: String) -> Bool {
        flags.contains(option)
    }
}

public func sanitizeProjectName(_ value: String) -> String {
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
    let scalars = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" }
    let sanitized = String(scalars).trimmingCharacters(in: CharacterSet(charactersIn: "-_"))
    return sanitized.isEmpty ? "project" : sanitized
}

public func iso8601UTC(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.string(from: date)
}

public func fsyncDirectory(_ url: URL) {
    let fd = open(url.path, O_RDONLY)
    guard fd >= 0 else { return }
    _ = fsync(fd)
    close(fd)
}

private struct SecurePasswordGenerator: PasswordGenerating {
    func generatePassword() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to generate secure random password")
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct FixedPasswordGenerator: PasswordGenerating {
    let password: String

    func generatePassword() throws -> String {
        password
    }
}

private struct SystemClock: Clock {
    func now() -> Date {
        Date()
    }
}

private struct FixedClock: Clock {
    let date: Date

    func now() -> Date {
        date
    }
}

private struct DefaultRunIDFactory: RunIDMaking {
    func makeRunID(date: Date) -> String {
        let compact = iso8601UTC(date)
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: ":", with: "")
        let timestamp = compact.replacingOccurrences(of: ".000", with: "")
        let suffix = UUID().uuidString.prefix(6).lowercased()
        return "run_\(timestamp)_\(suffix)"
    }
}

private struct FixedRunIDFactory: RunIDMaking {
    func makeRunID(date: Date) -> String {
        "run_20260628T164011Z_test00"
    }
}

final class StandardErrorProgressReporter: ProgressMessageReporting {
    func report(_ message: String) {
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}

private final class TerminalSecretPrompt: SecretPrompting {
    func readSecret(prompt: String) throws -> String {
        FileHandle.standardError.write(Data("\(prompt): ".utf8))
        var original = termios()
        var noEcho = termios()
        let canDisableEcho = tcgetattr(STDIN_FILENO, &original) == 0
        if canDisableEcho {
            noEcho = original
            noEcho.c_lflag &= ~UInt(ECHO)
            tcsetattr(STDIN_FILENO, TCSANOW, &noEcho)
        }
        defer {
            if canDisableEcho {
                tcsetattr(STDIN_FILENO, TCSANOW, &original)
                FileHandle.standardError.write(Data("\n".utf8))
            }
        }
        guard let value = readLine() else {
            throw AgentKeychainError.filesystem("Unable to read secret value")
        }
        return value
    }
}
