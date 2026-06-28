import Foundation

public enum KeychainMode: String, Codable, Equatable, Sendable {
    case physical
    case fallback
}

public enum AuditLevel: String, Codable, Equatable, Sendable {
    case normal
    case verbose
}

public struct ProjectInfo: Codable, Equatable, Sendable {
    public var name: String
    public var root: String
    public var keychainMode: KeychainMode
    public var keychainPath: String
    public var keychainPasswordService: String
}

public struct RoleConfig: Codable, Equatable, Sendable {
    public var description: String
    public var requireReason: Bool
    public var requireTouchId: Bool
    public var defaultIdleTimeoutSeconds: Int
    public var allowEnvInjection: Bool
    public var requireDualApproval: Bool
    public var auditLevel: AuditLevel
}

public struct SecretMetadata: Codable, Equatable, Sendable {
    public var role: String
    public var keychainService: String
    public var touchId: Bool
}

public struct VolumeMetadata: Codable, Equatable, Sendable {
    public var role: String
    public var image: String
    public var mountpoint: String
    public var keychainService: String
    public var touchId: Bool
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
                keychainMode: .physical,
                keychainPath: ".agent-keychain/keychains/project.keychain-db",
                keychainPasswordService: "agent-keychain.project.\(projectName).keychain-password"
            ),
            roles: defaultRoles,
            secrets: [:],
            volumes: [:],
            browsers: [:]
        )
    }

    public static let defaultRoles: [String: RoleConfig] = [
        "regular": RoleConfig(
            description: "Day-to-day low-risk agent work",
            requireReason: false,
            requireTouchId: true,
            defaultIdleTimeoutSeconds: 900,
            allowEnvInjection: true,
            requireDualApproval: false,
            auditLevel: .normal
        ),
        "workspace-admin": RoleConfig(
            description: "Identity and workspace administration",
            requireReason: true,
            requireTouchId: true,
            defaultIdleTimeoutSeconds: 300,
            allowEnvInjection: false,
            requireDualApproval: false,
            auditLevel: .verbose
        ),
        "finance": RoleConfig(
            description: "Money movement and financial administration",
            requireReason: true,
            requireTouchId: true,
            defaultIdleTimeoutSeconds: 180,
            allowEnvInjection: false,
            requireDualApproval: false,
            auditLevel: .verbose
        )
    ]

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
