import Foundation

public struct ProjectInfo: Codable, Equatable, Sendable {
    public var name: String
    public var root: String
}

public struct RoleKeychainConfig: Codable, Equatable, Sendable {
    public var path: String
    public var passwordService: String
    public var ttlSeconds: Int
}

public struct RoleConfig: Codable, Equatable, Sendable {
    public var description: String
    public var keychain: RoleKeychainConfig
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
                root: projectRoot
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

public struct RoleKeychainSession: Codable, Equatable, Sendable {
    public var unlockedAt: String
    public var expiresAt: String
}

public enum RoleKeychainDefaults {
    public static let ttlSeconds = 300

    public static func config(projectName: String, roleName: String) -> RoleKeychainConfig {
        let safeRoleName = sanitizeProjectName(roleName)
        return RoleKeychainConfig(
            path: ".agent-keychain/keychains/roles/\(safeRoleName).keychain-db",
            passwordService: "agent-keychain.project.\(projectName).role.\(roleName).keychain-password",
            ttlSeconds: ttlSeconds
        )
    }
}
