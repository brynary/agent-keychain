import Foundation

public enum AuditLevel: String, Codable, Equatable, Sendable {
    case normal
    case verbose
}

public struct ProjectInfo: Codable, Equatable, Sendable {
    public var name: String
    public var root: String
    public var keychainPath: String
    public var keychainPasswordService: String
}

public struct RoleConfig: Codable, Equatable, Sendable {
    public var description: String
    public var requireReason: Bool
    public var allowEnvInjection: Bool
    public var auditLevel: AuditLevel
}

public struct SecretMetadata: Codable, Equatable, Sendable {
    public var role: String
    public var keychainService: String
}

public struct VolumeMetadata: Codable, Equatable, Sendable {
    public var role: String
    public var image: String
    public var mountpoint: String
    public var keychainService: String
}

public struct BrowserMetadata: Codable, Equatable, Sendable {
    public var role: String
    public var volume: String
    public var profilePath: String
}

public struct ProjectConfig: Codable, Equatable, Sendable {
    public var project: ProjectInfo
    public var roles: [String: RoleConfig]
    public var secrets: [String: SecretMetadata]
    public var volumes: [String: VolumeMetadata]
    public var browsers: [String: BrowserMetadata]

    public static func defaultConfig(projectName: String, projectRoot: String) -> ProjectConfig {
        ProjectConfig(
            project: ProjectInfo(
                name: projectName,
                root: projectRoot,
                keychainPath: ".agent-keychain/keychains/project.keychain-db",
                keychainPasswordService: "agent-keychain.project.\(projectName).keychain-password"
            ),
            roles: [:],
            secrets: [:],
            volumes: [:],
            browsers: [:]
        )
    }

    public func canonicalData() throws -> Data {
        try CanonicalJSON.encode(self)
    }

    public func canonicalHash() throws -> String {
        try SHA256Hex.hash(canonicalData())
    }
}

public struct ConfigIntegrity: Codable, Equatable, Sendable {
    public var version: Int
    public var configHash: String
    public var updatedAt: String
}
