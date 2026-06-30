import Foundation
import LocalAuthentication
import Security

public enum LoginKeychainAccessControlFallback {
    public static func shouldStoreWithoutAccessControl(after status: OSStatus) -> Bool {
        status == errSecMissingEntitlement
    }
}

public enum CustomKeychainItemAccessPolicy {
    public static let descriptor = "agent-keychain item"
    public static let allowsAnyApplicationAfterUnlock = true
    public static let genericPasswordItemClass = SecItemClass(rawValue: 0x67656e70)!
    public static let accountItemAttribute: UInt32 = 0x61636374
    public static let serviceItemAttribute: UInt32 = 0x73766365
}

public final class MacOSKeychainStore: KeychainStoring {
    private let account = "default"
    private let progressReporter: ProgressMessageReporting
    private var projectRoot: URL?

    public convenience init() {
        self.init(progressReporter: StandardErrorProgressReporter())
    }

    public init(progressReporter: ProgressMessageReporting) {
        self.progressReporter = progressReporter
    }

    public func useProject(config: ProjectConfig, projectRoot: URL) throws {
        self.projectRoot = projectRoot
    }

    public func createRoleKeychain(path: String, password: String, ttlSeconds: Int) throws {
        let absolutePath = try absoluteKeychainPath(path)
        guard !FileManager.default.fileExists(atPath: absolutePath) else {
            throw AgentKeychainError.filesystem("Role keychain already exists at \(absolutePath). Move it aside before retrying.")
        }
        let keychain = try createKeychain(path: absolutePath, password: password, label: "role")
        try applyRoleKeychainSettings(keychain: keychain, ttlSeconds: ttlSeconds)
        SecKeychainLock(keychain)
    }

    public func storeRoleKeychainPassword(service: String, password: String) throws {
        do {
            try storeLoginKeychainItem(service: service, value: password, requireUserPresence: true)
        } catch let error as KeychainStatusError where LoginKeychainAccessControlFallback.shouldStoreWithoutAccessControl(after: error.status) {
            try storeLoginKeychainItem(service: service, value: password, requireUserPresence: false)
        }
    }

    public func unlockRoleKeychain(roleName: String, keychain: RoleKeychainConfig) throws {
        let keychainRef = try openKeychainWithoutInteraction(path: try absoluteKeychainPath(keychain.path), label: "role")
        let password = try readLoginKeychainItem(
            service: keychain.passwordService,
            prompt: "Authenticate to unlock the agent-keychain \(roleName) role keychain"
        )
        try unlockKeychainWithoutInteraction(keychainRef, password: password, label: "role")
        try applyRoleKeychainSettings(keychain: keychainRef, ttlSeconds: keychain.ttlSeconds)
    }

    public func lockRoleKeychain(roleName: String, keychain: RoleKeychainConfig) throws {
        let keychainRef = try openKeychainWithoutInteraction(path: try absoluteKeychainPath(keychain.path), label: "role")
        let status = SecKeychainLock(keychainRef)
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to lock role keychain: \(securityMessage(status))")
        }
    }

    public func isRoleKeychainUnlocked(roleName: String, keychain: RoleKeychainConfig) throws -> Bool {
        let keychainRef = try openKeychainWithoutInteraction(path: try absoluteKeychainPath(keychain.path), label: "role")
        return try isUnlockedWithoutInteraction(keychain: keychainRef)
    }

    public func storeGenericPassword(service: String, value: String, roleKeychain: RoleKeychainConfig) throws {
        try withRoleKeychain(roleKeychain) { keychain in
            try deleteGenericPasswordIfPresent(service: service, keychain: keychain)
            try addGenericPassword(service: service, value: value, keychain: keychain)
        }
    }

    public func readGenericPassword(service: String, roleKeychain: RoleKeychainConfig) throws -> String {
        try withRoleKeychain(roleKeychain) { keychain in
            try readGenericPassword(service: service, keychain: keychain)
        }
    }

    public func deleteGenericPassword(service: String, roleKeychain: RoleKeychainConfig) throws {
        try withRoleKeychain(roleKeychain) { keychain in
            try deleteGenericPasswordIfPresent(service: service, keychain: keychain)
        }
    }

    private func withRoleKeychain<T>(_ roleKeychain: RoleKeychainConfig, _ body: (SecKeychain) throws -> T) throws -> T {
        let keychain = try openKeychainWithoutInteraction(path: try absoluteKeychainPath(roleKeychain.path), label: "role")
        guard try isUnlockedWithoutInteraction(keychain: keychain) else {
            throw AgentKeychainError.filesystem("Role keychain is locked")
        }
        return try body(keychain)
    }

    private func createKeychain(path: String, password: String, label: String) throws -> SecKeychain {
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)

        var keychain: SecKeychain?
        let status = password.withCString { passwordPointer in
            SecKeychainCreate(path, UInt32(strlen(passwordPointer)), passwordPointer, false, nil, &keychain)
        }
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to create \(label) keychain: \(securityMessage(status))")
        }
        guard let keychain else {
            throw AgentKeychainError.filesystem("Unable to create \(label) keychain")
        }
        return keychain
    }

    private func openKeychain(path: String, label: String) throws -> SecKeychain {
        var keychain: SecKeychain?
        let status = SecKeychainOpen(path, &keychain)
        guard status == errSecSuccess, let keychain else {
            throw AgentKeychainError.filesystem("Unable to open \(label) keychain: \(securityMessage(status))")
        }
        return keychain
    }

    private func openKeychainWithoutInteraction(path: String, label: String) throws -> SecKeychain {
        try withKeychainUserInteractionAllowed(false) {
            try openKeychain(path: path, label: label)
        }
    }

    private func unlockKeychainWithoutInteraction(_ keychain: SecKeychain, password: String, label: String) throws {
        try withKeychainUserInteractionAllowed(false) {
            let status = password.withCString { passwordPointer in
                SecKeychainUnlock(keychain, UInt32(strlen(passwordPointer)), passwordPointer, true)
            }
            guard status == errSecSuccess else {
                throw AgentKeychainError.filesystem("Unable to unlock \(label) keychain: \(securityMessage(status))")
            }
        }
    }

    private func absoluteKeychainPath(_ path: String) throws -> String {
        if path.hasPrefix("/") {
            return path
        }
        guard let projectRoot else {
            throw AgentKeychainError.filesystem("Project context is not configured")
        }
        return projectRoot.appendingPathComponent(path).path
    }

    private func applyRoleKeychainSettings(keychain: SecKeychain, ttlSeconds: Int) throws {
        var settings = SecKeychainSettings()
        settings.version = UInt32(SEC_KEYCHAIN_SETTINGS_VERS1)
        settings.lockOnSleep = true
        settings.useLockInterval = true
        settings.lockInterval = UInt32(ttlSeconds)
        let status = SecKeychainSetSettings(keychain, &settings)
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to configure role keychain TTL: \(securityMessage(status))")
        }
    }

    private func isUnlocked(keychain: SecKeychain) throws -> Bool {
        var keychainStatus: SecKeychainStatus = 0
        let status = SecKeychainGetStatus(keychain, &keychainStatus)
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to read keychain status: \(securityMessage(status))")
        }
        return (keychainStatus & SecKeychainStatus(kSecUnlockStateStatus)) != 0
    }

    private func isUnlockedWithoutInteraction(keychain: SecKeychain) throws -> Bool {
        try withKeychainUserInteractionAllowed(false) {
            try isUnlocked(keychain: keychain)
        }
    }

    private func withKeychainUserInteractionAllowed<T>(_ allowed: Bool, _ body: () throws -> T) throws -> T {
        var previous = DarwinBoolean(false)
        let previousStatus = SecKeychainGetUserInteractionAllowed(&previous)
        let setStatus = SecKeychainSetUserInteractionAllowed(allowed)
        defer {
            if previousStatus == errSecSuccess {
                SecKeychainSetUserInteractionAllowed(previous.boolValue)
            }
        }
        guard setStatus == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to configure keychain interaction: \(securityMessage(setStatus))")
        }
        return try body()
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
        try UserPresenceAuthorization.authorize(
            context: context,
            reason: prompt,
            progressReporter: progressReporter
        )
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
        let status = try withKeychainUserInteractionAllowed(false) {
            let access = try customKeychainItemAccess()

            return service.withCString { servicePointer in
                account.withCString { accountPointer in
                    value.withCString { valuePointer in
                        var attributes = [
                            SecKeychainAttribute(
                                tag: CustomKeychainItemAccessPolicy.serviceItemAttribute,
                                length: UInt32(strlen(servicePointer)),
                                data: UnsafeMutableRawPointer(mutating: servicePointer)
                            ),
                            SecKeychainAttribute(
                                tag: CustomKeychainItemAccessPolicy.accountItemAttribute,
                                length: UInt32(strlen(accountPointer)),
                                data: UnsafeMutableRawPointer(mutating: accountPointer)
                            )
                        ]
                        return attributes.withUnsafeMutableBufferPointer { attributesBuffer in
                            var attributeList = SecKeychainAttributeList(
                                count: UInt32(attributesBuffer.count),
                                attr: attributesBuffer.baseAddress
                            )
                            return SecKeychainItemCreateFromContent(
                                CustomKeychainItemAccessPolicy.genericPasswordItemClass,
                                &attributeList,
                                UInt32(strlen(valuePointer)),
                                valuePointer,
                                keychain,
                                access,
                                nil
                            )
                        }
                    }
                }
            }
        }
        guard status == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to store keychain item: \(securityMessage(status))")
        }
    }

    private func customKeychainItemAccess() throws -> SecAccess {
        var access: SecAccess?
        // Avoid SecAccessCreate's nil-list default, which trusts the creating executable.
        let emptyTrustedApplications = [] as CFArray
        let createStatus = SecAccessCreate(
            CustomKeychainItemAccessPolicy.descriptor as CFString,
            emptyTrustedApplications,
            &access
        )
        guard createStatus == errSecSuccess, let access else {
            throw AgentKeychainError.filesystem("Unable to create keychain item access: \(securityMessage(createStatus))")
        }

        var acl: SecACL?
        let aclStatus = SecACLCreateWithSimpleContents(
            access,
            nil,
            CustomKeychainItemAccessPolicy.descriptor as CFString,
            SecKeychainPromptSelector(),
            &acl
        )
        _ = acl
        guard aclStatus == errSecSuccess else {
            throw AgentKeychainError.filesystem("Unable to configure keychain item access: \(securityMessage(aclStatus))")
        }

        return access
    }

    private func readGenericPassword(service: String, keychain: SecKeychain) throws -> String {
        var length: UInt32 = 0
        var data: UnsafeMutableRawPointer?
        let status = try withKeychainUserInteractionAllowed(false) {
            service.withCString { servicePointer in
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
        }
        guard status == errSecSuccess, let data else {
            throw AgentKeychainError.filesystem("Unable to read keychain item: \(securityMessage(status))")
        }
        defer {
            SecKeychainItemFreeContent(nil, data)
        }
        let bytes = Data(bytes: data, count: Int(length))
        guard let value = String(data: bytes, encoding: .utf8) else {
            throw AgentKeychainError.filesystem("Invalid keychain item data")
        }
        return value
    }

    private func deleteGenericPasswordIfPresent(service: String, keychain: SecKeychain) throws {
        var item: SecKeychainItem?
        let status = try withKeychainUserInteractionAllowed(false) {
            service.withCString { servicePointer in
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
        }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AgentKeychainError.filesystem("Unable to find keychain item for deletion: \(securityMessage(status))")
        }
        if let item {
            let deleteStatus = SecKeychainItemDelete(item)
            guard deleteStatus == errSecSuccess else {
                throw AgentKeychainError.filesystem("Unable to delete keychain item: \(securityMessage(deleteStatus))")
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
