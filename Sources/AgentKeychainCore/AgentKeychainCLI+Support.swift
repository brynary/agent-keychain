import Foundation

extension AgentKeychainCLI {
    func loadTrustedConfig(store: ConfigStore, reason: String?) throws -> ProjectConfig {
        let config = try store.loadConfig()
        do {
            try store.verifyIntegrity(for: config)
            return config
        } catch let error as AgentKeychainError {
            if case .configIntegrity = error {
                let audit = AuditLog(url: store.auditURL)
                try? audit.append(AuditEvent(
                    timestamp: dependencies.clock.now(),
                    runID: dependencies.runIDFactory.makeRunID(date: dependencies.clock.now()),
                    project: config.project.name,
                    event: "config_tamper_detected",
                    result: "denied",
                    reason: reason,
                    message: error.message
                ))
            }
            throw error
        }
    }

    func writeConfigOrAuditMutationFailure(
        _ config: ProjectConfig,
        store: ConfigStore,
        audit: AuditLog,
        runID: String,
        role: String?,
        resource: String?,
        reason: String?,
        oldHash: String,
        newHash: String
    ) throws {
        do {
            try store.writeConfig(config)
        } catch {
            try? audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "config_mutation_failed",
                result: "failed",
                role: role,
                resource: resource,
                reason: reason,
                message: "\(error)",
                oldConfigHash: oldHash,
                newConfigHash: newHash
            ))
            throw error
        }
    }

    func secretService(role: String, name: String) -> String {
        "agent-keychain.role.\(role).secret.\(name)"
    }

    func rejectRemovedRoleOption(_ options: ParsedOptions, command: String) throws {
        guard options.value(for: "--role") == nil else {
            let ownership = command.hasPrefix("secret") ? "secret ownership" : "resource ownership"
            throw AgentKeychainError.invalidArguments("\(command) infers the role from \(ownership); omit --role")
        }
    }

    func requireSecret(config: ProjectConfig, name: String) throws -> SecretMetadata {
        guard let secret = config.secrets[name] else {
            throw AgentKeychainError.invalidArguments("Unknown secret: \(name)")
        }
        return secret
    }

    func requireRoleKeychain(config: ProjectConfig, roleName: String) throws -> RoleKeychainConfig {
        let role = try PolicyEngine.requireRole(config, roleName)
        return role.keychain
    }

    func makeRoleKeychainConfig(config: ProjectConfig, roleName: String) -> RoleKeychainConfig {
        RoleKeychainDefaults.config(projectName: config.project.name, roleName: roleName)
    }

    func createRoleKeychain(_ keychain: RoleKeychainConfig) throws {
        let password = try dependencies.passwordGenerator.generatePassword()
        try dependencies.keychainStore.createRoleKeychain(
            path: keychain.path,
            password: password,
            ttlSeconds: keychain.ttlSeconds
        )
        try dependencies.keychainStore.storeRoleKeychainPassword(
            service: keychain.passwordService,
            password: password
        )
    }

    func requireVolume(config: ProjectConfig, name: String, roleName: String, reason: String?, auditURL: URL) throws -> VolumeMetadata {
        guard let volume = config.volumes[name] else {
            throw AgentKeychainError.invalidArguments("Unknown volume: \(name)")
        }
        if volume.role != roleName {
            try? AuditLog(url: auditURL).append(AuditEvent(timestamp: dependencies.clock.now(), runID: dependencies.runIDFactory.makeRunID(date: dependencies.clock.now()), project: config.project.name, event: "policy_rejection", result: "denied", role: roleName, resource: name, reason: reason, message: "Volume \(name) belongs to role \(volume.role), not \(roleName)"))
            throw AgentKeychainError.policy("Volume \(name) belongs to role \(volume.role), not \(roleName).")
        }
        return volume
    }

    func requireVolume(config: ProjectConfig, name: String) throws -> VolumeMetadata {
        guard let volume = config.volumes[name] else {
            throw AgentKeychainError.invalidArguments("Unknown volume: \(name)")
        }
        return volume
    }

    func requireBrowser(config: ProjectConfig, name: String) throws -> BrowserMetadata {
        guard let browser = config.browsers[name] else {
            throw AgentKeychainError.invalidArguments("Unknown browser profile: \(name)")
        }
        return browser
    }

    func browserUserDataDir(mountpoint: String, profilePath: String) throws -> String {
        let components = profilePath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !profilePath.isEmpty,
              !profilePath.hasPrefix("/"),
              !profilePath.hasPrefix("~"),
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw AgentKeychainError.policy("Refusing to use unsafe browser profile path \(profilePath).")
        }

        let mountpointURL = URL(fileURLWithPath: mountpoint, isDirectory: true).standardizedFileURL
        let userDataURL = mountpointURL.appendingPathComponent(profilePath, isDirectory: true).standardizedFileURL
        let mountpointPrefix = mountpointURL.path.hasSuffix("/") ? mountpointURL.path : mountpointURL.path + "/"
        guard userDataURL.path.hasPrefix(mountpointPrefix) else {
            throw AgentKeychainError.policy("Refusing to use unsafe browser profile path \(profilePath).")
        }
        return userDataURL.path
    }

    func formatTable(headers: [String], rows: [[String]]) -> String {
        guard !rows.isEmpty else {
            return ""
        }
        let allRows = [headers] + rows
        let widths = headers.indices.map { column in
            allRows.map { $0[column].count }.max() ?? 0
        }
        return allRows.map { row in
            row.indices.map { column in
                row[column].padding(toLength: widths[column], withPad: " ", startingAt: 0)
            }.joined(separator: "  ").trimmingCharacters(in: .whitespaces)
        }.joined(separator: "\n") + "\n"
    }

    func volumeService(role: String, name: String) -> String {
        "agent-keychain.role.\(role).volume.\(name).password"
    }

    func absoluteProjectPath(workingDirectory: URL, path: String) -> String {
        if path.hasPrefix("/") {
            return path
        }
        return workingDirectory.appendingPathComponent(path).path
    }

    func configureKeychainContext(config: ProjectConfig, workingDirectory: URL) throws {
        try dependencies.keychainStore.useProject(config: config, projectRoot: workingDirectory)
    }

    func ensureRoleKeychainUnlocked(
        config: ProjectConfig,
        store: ConfigStore,
        audit: AuditLog,
        runID: String,
        roleName: String,
        resource: String?,
        reason: String?
    ) throws -> RoleKeychainConfig {
        let keychain = try requireRoleKeychain(config: config, roleName: roleName)
        let now = dependencies.clock.now()
        let session = try store.loadRoleSession(roleName: roleName)
        let expiresAt = session.flatMap { ISO8601DateFormatter().date(from: $0.expiresAt) }
        if let expiresAt,
           expiresAt > now,
           try dependencies.keychainStore.isRoleKeychainUnlocked(roleName: roleName, keychain: keychain) {
            return keychain
        }

        try? dependencies.keychainStore.lockRoleKeychain(roleName: roleName, keychain: keychain)
        if session != nil {
            try? store.deleteRoleSession(roleName: roleName)
            if expiresAt.map({ $0 <= now }) ?? true {
                try? audit.append(AuditEvent(timestamp: now, runID: runID, project: config.project.name, event: "role_keychain_locked", result: "success", role: roleName, resource: resource, reason: reason))
            }
        }

        try audit.append(AuditEvent(timestamp: now, runID: runID, project: config.project.name, event: "role_keychain_unlock_requested", result: "success", role: roleName, resource: resource, reason: reason))
        do {
            try dependencies.keychainStore.unlockRoleKeychain(roleName: roleName, keychain: keychain)
            let expiresAt = now.addingTimeInterval(TimeInterval(keychain.ttlSeconds))
            try store.writeRoleSession(
                RoleKeychainSession(unlockedAt: iso8601UTC(now), expiresAt: iso8601UTC(expiresAt)),
                roleName: roleName
            )
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "role_keychain_unlock_succeeded", result: "success", role: roleName, resource: resource, reason: reason))
            return keychain
        } catch {
            try? audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "role_keychain_unlock_failed", result: "failed", role: roleName, resource: resource, reason: reason, message: "\(error)"))
            try? audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "command_failed", result: "failed", role: roleName, resource: resource, reason: reason, message: "\(error)"))
            throw error
        }
    }

    func attachAndVerifyVolume(name: String, metadata: VolumeMetadata, password: String, workingDirectory: URL) throws {
        let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: metadata.image)
        let mountpointURL = URL(fileURLWithPath: metadata.mountpoint)
        if let values = try? mountpointURL.resourceValues(forKeys: [.isSymbolicLinkKey]), values.isSymbolicLink == true {
            throw AgentKeychainError.policy("Refusing to use symlink mountpoint \(metadata.mountpoint) for volume \(name).")
        }
        if FileManager.default.fileExists(atPath: metadata.mountpoint) {
            if try dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: metadata.mountpoint) {
                return
            }
            throw AgentKeychainError.policy("Refusing to use existing mountpoint \(metadata.mountpoint) because it is not the configured image for volume \(name).")
        }
        try dependencies.diskImageStore.attach(
            imagePath: imagePath,
            mountpoint: metadata.mountpoint,
            password: password
        )
        guard try dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: metadata.mountpoint) else {
            throw AgentKeychainError.policy("Mounted image verification failed for volume \(name).")
        }
    }

    func storeKeychainItem(
        service: String,
        value: String,
        config: ProjectConfig,
        store: ConfigStore,
        audit: AuditLog,
        runID: String,
        role: String,
        resource: String?,
        reason: String?
    ) throws {
        let roleKeychain = try ensureRoleKeychainUnlocked(config: config, store: store, audit: audit, runID: runID, roleName: role, resource: resource, reason: reason)
        try dependencies.keychainStore.storeGenericPassword(service: service, value: value, roleKeychain: roleKeychain)
    }

    func deleteKeychainItem(
        service: String,
        config: ProjectConfig,
        store: ConfigStore,
        audit: AuditLog,
        runID: String,
        role: String,
        resource: String?,
        reason: String?
    ) throws {
        let roleKeychain = try ensureRoleKeychainUnlocked(config: config, store: store, audit: audit, runID: runID, roleName: role, resource: resource, reason: reason)
        try dependencies.keychainStore.deleteGenericPassword(service: service, roleKeychain: roleKeychain)
    }

    func readKeychainItem(
        service: String,
        config: ProjectConfig,
        store: ConfigStore,
        audit: AuditLog,
        runID: String,
        role: String,
        resource: String?,
        reason: String?
    ) throws -> String {
        let roleKeychain = try ensureRoleKeychainUnlocked(config: config, store: store, audit: audit, runID: runID, roleName: role, resource: resource, reason: reason)
        do {
            return try dependencies.keychainStore.readGenericPassword(service: service, roleKeychain: roleKeychain)
        } catch {
            try? audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "project_keychain_unlock_failed",
                result: "failed",
                role: role,
                resource: resource,
                reason: reason,
                message: "\(error)"
            ))
            try? audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "command_failed",
                result: "failed",
                role: role,
                resource: resource,
                reason: reason,
                message: "\(error)"
            ))
            throw error
        }
    }
}
