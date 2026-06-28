import Foundation

public enum PolicyEngine {
    public static func requireMutationReason(_ reason: String?) throws -> String {
        guard let reason, !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AgentKeychainError.invalidArguments("Policy mutations require --reason")
        }
        return reason
    }

    public static func requireRole(_ config: ProjectConfig, _ roleName: String) throws -> RoleConfig {
        guard let role = config.roles[roleName] else {
            throw AgentKeychainError.invalidArguments("Unknown role: \(roleName)")
        }
        return role
    }

    public static func requireReasonIfNeeded(roleName: String, role: RoleConfig, reason: String?) throws {
        if role.requireReason && (reason?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true) {
            throw AgentKeychainError.invalidArguments("Role \(roleName) requires --reason")
        }
    }
}
