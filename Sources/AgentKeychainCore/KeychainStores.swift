import Foundation
import LocalAuthentication
import Security

public enum LoginKeychainAccessControlFallback {
    public static func shouldStoreWithoutAccessControl(after status: OSStatus) -> Bool {
        status == errSecMissingEntitlement
    }
}

public enum ProjectKeychainUnlockPolicy {
    public static let useProvidedPassword = true
}

public final class MacOSKeychainStore: KeychainStoring {
    private let account = "default"
    private var projectKeychainPath: String?
    private var projectKeychainPasswordService: String?

    public init() {}

    public func createProjectKeychain(path: String, password: String) throws {
        if FileManager.default.fileExists(atPath: path) {
            return
        }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)

        var keychain: SecKeychain?
        let status = password.withCString { passwordPointer in
            SecKeychainCreate(path, UInt32(strlen(passwordPointer)), passwordPointer, false, nil, &keychain)
        }
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to create project keychain: \(securityMessage(status))")
        }
        if let keychain {
            SecKeychainLock(keychain)
        }
    }

    public func useProject(config: ProjectConfig, projectRoot: URL) throws {
        projectKeychainPasswordService = config.project.keychainPasswordService
        projectKeychainPath = projectRoot.appendingPathComponent(config.project.keychainPath).path
    }

    public func storeProjectKeychainPassword(service: String, password: String) throws {
        do {
            try storeLoginKeychainItem(service: service, value: password, requireUserPresence: true)
        } catch let error as KeychainStatusError where LoginKeychainAccessControlFallback.shouldStoreWithoutAccessControl(after: error.status) {
            try storeLoginKeychainItem(service: service, value: password, requireUserPresence: false)
        }
    }

    public func storeGenericPassword(service: String, value: String) throws {
        try withUnlockedProjectKeychain { keychain in
            try deleteGenericPasswordIfPresent(service: service, keychain: keychain)
            try addGenericPassword(service: service, value: value, keychain: keychain)
        }
    }

    public func readGenericPassword(service: String) throws -> String {
        try withUnlockedProjectKeychain { keychain in
            try readGenericPassword(service: service, keychain: keychain)
        }
    }

    public func deleteGenericPassword(service: String) throws {
        try withUnlockedProjectKeychain { keychain in
            try deleteGenericPasswordIfPresent(service: service, keychain: keychain)
        }
    }

    private func withUnlockedProjectKeychain<T>(_ body: (SecKeychain) throws -> T) throws -> T {
        guard let path = projectKeychainPath, let passwordService = projectKeychainPasswordService else {
            throw AgentKeychainError.filesystem("Project keychain context is not configured")
        }
        let password = try readLoginKeychainItem(
            service: passwordService,
            prompt: "Authenticate to unlock the agent-keychain project keychain"
        )
        var keychain: SecKeychain?
        var status = SecKeychainOpen(path, &keychain)
        guard status == errSecSuccess, let keychain else {
            throw AgentKeychainError.filesystem("Unable to open project keychain: \(securityMessage(status))")
        }
        status = password.withCString { passwordPointer in
            SecKeychainUnlock(keychain, UInt32(strlen(passwordPointer)), passwordPointer, ProjectKeychainUnlockPolicy.useProvidedPassword)
        }
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to unlock project keychain: \(securityMessage(status))")
        }
        defer {
            SecKeychainLock(keychain)
        }
        return try body(keychain)
    }

    private func storeLoginKeychainItem(service: String, value: String, requireUserPresence: Bool) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
        query[kSecValueData as String] = Data(value.utf8)

        if requireUserPresence {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.userPresence],
                &error
            ) else {
                throw AgentKeychainError.filesystem("Unable to create keychain access control")
            }
            query[kSecAttrAccessControl as String] = access
        } else {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainStatusError(message: "Unable to store login keychain item: \(securityMessage(status))", status: status)
        }
    }

    private func readLoginKeychainItem(service: String, prompt: String) throws -> String {
        let context = LAContext()
        context.localizedReason = prompt
        try UserPresenceAuthorization.authorize(context: context, reason: prompt)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecUseOperationPrompt as String: prompt
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to read login keychain item: \(securityMessage(status))")
        }
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw AgentKeychainError.filesystem("Invalid keychain item data")
        }
        return value
    }

    private func deleteLoginKeychainItem(service: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AgentKeychainError.filesystem("Unable to delete login keychain item: \(securityMessage(status))")
        }
    }

    private func addGenericPassword(service: String, value: String, keychain: SecKeychain) throws {
        let status = service.withCString { servicePointer in
            account.withCString { accountPointer in
                value.withCString { valuePointer in
                    SecKeychainAddGenericPassword(
                        keychain,
                        UInt32(strlen(servicePointer)),
                        servicePointer,
                        UInt32(strlen(accountPointer)),
                        accountPointer,
                        UInt32(strlen(valuePointer)),
                        valuePointer,
                        nil
                    )
                }
            }
        }
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to store project keychain item: \(securityMessage(status))")
        }
    }

    private func readGenericPassword(service: String, keychain: SecKeychain) throws -> String {
        var length: UInt32 = 0
        var data: UnsafeMutableRawPointer?
        let status = service.withCString { servicePointer in
            account.withCString { accountPointer in
                SecKeychainFindGenericPassword(
                    keychain,
                    UInt32(strlen(servicePointer)),
                    servicePointer,
                    UInt32(strlen(accountPointer)),
                    accountPointer,
                    &length,
                    &data,
                    nil
                )
            }
        }
        guard status == errSecSuccess, let data else {
            throw AgentKeychainError.filesystem("Unable to read project keychain item: \(securityMessage(status))")
        }
        defer {
            SecKeychainItemFreeContent(nil, data)
        }
        let bytes = Data(bytes: data, count: Int(length))
        guard let value = String(data: bytes, encoding: .utf8) else {
            throw AgentKeychainError.filesystem("Invalid project keychain item data")
        }
        return value
    }

    private func deleteGenericPasswordIfPresent(service: String, keychain: SecKeychain) throws {
        var item: SecKeychainItem?
        let status = service.withCString { servicePointer in
            account.withCString { accountPointer in
                SecKeychainFindGenericPassword(
                    keychain,
                    UInt32(strlen(servicePointer)),
                    servicePointer,
                    UInt32(strlen(accountPointer)),
                    accountPointer,
                    nil,
                    nil,
                    &item
                )
            }
        }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AgentKeychainError.filesystem("Unable to find project keychain item for deletion: \(securityMessage(status))")
        }
        if let item {
            let deleteStatus = SecKeychainItemDelete(item)
            guard deleteStatus == errSecSuccess else {
                throw AgentKeychainError.filesystem("Unable to delete project keychain item: \(securityMessage(deleteStatus))")
            }
        }
    }

    private func securityMessage(_ status: OSStatus) -> String {
        if let message = SecCopyErrorMessageString(status, nil) as String? {
            return "\(message) (\(status))"
        }
        return "Security framework status \(status)"
    }
}

private struct KeychainStatusError: Error, CustomStringConvertible, LocalizedError {
    let message: String
    let status: OSStatus

    var description: String {
        message
    }

    var errorDescription: String? {
        message
    }
}
