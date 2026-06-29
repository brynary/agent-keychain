import Darwin
import Foundation

public struct ConfigStore {
    public let projectRoot: URL

    public init(projectRoot: URL) {
        self.projectRoot = projectRoot
    }

    public var projectDirectoryURL: URL {
        projectRoot.appendingPathComponent(".agent-keychain", isDirectory: true)
    }

    public var configURL: URL {
        projectDirectoryURL.appendingPathComponent("config.json")
    }

    public var integrityURL: URL {
        projectDirectoryURL.appendingPathComponent("config.integrity.json")
    }

    public var auditURL: URL {
        projectDirectoryURL.appendingPathComponent("audit.jsonl")
    }

    public var sessionsDirectoryURL: URL {
        projectDirectoryURL.appendingPathComponent("sessions", isDirectory: true)
    }

    public func createProjectDirectories() throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(at: projectDirectoryURL, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: projectDirectoryURL.appendingPathComponent("locks", isDirectory: true), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: projectDirectoryURL.appendingPathComponent("keychains", isDirectory: true), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: projectDirectoryURL.appendingPathComponent("keychains/roles", isDirectory: true), withIntermediateDirectories: true)
        try fileManager.createDirectory(at: sessionsDirectoryURL, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: projectDirectoryURL.appendingPathComponent("volumes", isDirectory: true), withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: auditURL.path) {
            fileManager.createFile(atPath: auditURL.path, contents: nil)
        }
    }

    public func writeConfig(_ config: ProjectConfig) throws {
        let lock = try acquireConfigLock()
        defer { lock.release() }
        try writeAtomically(config.canonicalData(), to: configURL)
    }

    public func loadConfig() throws -> ProjectConfig {
        guard FileManager.default.fileExists(atPath: configURL.path) else {
            throw AgentKeychainError.filesystem("No agent-keychain project found. Run `agent-keychain init`.")
        }
        return try JSONDecoder().decode(ProjectConfig.self, from: Data(contentsOf: configURL))
    }

    public func loadIntegrity() throws -> ConfigIntegrity {
        guard FileManager.default.fileExists(atPath: integrityURL.path) else {
            throw AgentKeychainError.configIntegrity("Config integrity check failed. Run `agent-keychain config trust-current --reason TEXT`.")
        }
        return try JSONDecoder().decode(ConfigIntegrity.self, from: Data(contentsOf: integrityURL))
    }

    public func verifyIntegrity(for config: ProjectConfig) throws {
        let integrity = try loadIntegrity()
        let currentHash = try config.canonicalHash()
        guard integrity.configHash == currentHash else {
            throw AgentKeychainError.configIntegrity("Config integrity check failed. Run `agent-keychain config trust-current --reason TEXT`.")
        }
    }

    public func writeIntegrity(for config: ProjectConfig, updatedAt: Date) throws {
        let integrity = ConfigIntegrity(
            version: 1,
            configHash: try config.canonicalHash(),
            updatedAt: iso8601UTC(updatedAt)
        )
        try writeAtomically(CanonicalJSON.encode(integrity), to: integrityURL)
    }

    public func roleSessionURL(roleName: String) -> URL {
        sessionsDirectoryURL.appendingPathComponent("\(sanitizeProjectName(roleName)).json")
    }

    public func loadRoleSession(roleName: String) throws -> RoleKeychainSession? {
        let url = roleSessionURL(roleName: roleName)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        return try JSONDecoder().decode(RoleKeychainSession.self, from: Data(contentsOf: url))
    }

    public func writeRoleSession(_ session: RoleKeychainSession, roleName: String) throws {
        try FileManager.default.createDirectory(at: sessionsDirectoryURL, withIntermediateDirectories: true)
        try writeAtomically(CanonicalJSON.encode(session), to: roleSessionURL(roleName: roleName))
    }

    public func deleteRoleSession(roleName: String) throws {
        let url = roleSessionURL(roleName: roleName)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return
        }
        try FileManager.default.removeItem(at: url)
    }

    private func writeAtomically(_ data: Data, to destination: URL) throws {
        let temporaryURL = projectDirectoryURL.appendingPathComponent(".\(destination.lastPathComponent).tmp.\(UUID().uuidString)")
        try data.write(to: temporaryURL)
        let handle = try FileHandle(forWritingTo: temporaryURL)
        try handle.synchronize()
        try handle.close()
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.moveItem(at: temporaryURL, to: destination)
        fsyncDirectory(projectDirectoryURL)
    }

    private func acquireConfigLock() throws -> ConfigWriteLock {
        let locksDirectory = projectDirectoryURL.appendingPathComponent("locks", isDirectory: true)
        try FileManager.default.createDirectory(at: locksDirectory, withIntermediateDirectories: true)
        let lockURL = locksDirectory.appendingPathComponent("config.lock")
        let fd = open(lockURL.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard fd >= 0 else {
            if errno == EEXIST {
                throw AgentKeychainError.filesystem("Config is locked by another agent-keychain process.")
            }
            throw AgentKeychainError.filesystem("Unable to acquire config lock.")
        }
        let payload = "\(getpid())\n"
        _ = payload.withCString { pointer in
            write(fd, pointer, strlen(pointer))
        }
        close(fd)
        return ConfigWriteLock(url: lockURL)
    }
}

private final class ConfigWriteLock {
    private let url: URL
    private var released = false

    init(url: URL) {
        self.url = url
    }

    deinit {
        release()
    }

    func release() {
        guard !released else {
            return
        }
        released = true
        try? FileManager.default.removeItem(at: url)
    }
}
