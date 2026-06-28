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

    func requireReasonIfNeeded(
        config: ProjectConfig,
        roleName: String,
        role: RoleConfig,
        reason: String?,
        resource: String?,
        audit: AuditLog,
        runID: String
    ) throws {
        guard role.requireReason && (reason?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true) else {
            return
        }
        let message = "Role \(roleName) requires --reason"
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "policy_rejection",
            result: "denied",
            role: roleName,
            resource: resource,
            reason: reason,
            message: message
        ))
        throw AgentKeychainError.invalidArguments(message)
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

    func detachVolumeIfNotBusy(project: String, runID: String, role: String, volumeName: String, metadata: VolumeMetadata, reason: String?, auditURL: URL) throws {
        let audit = AuditLog(url: auditURL)
        if try dependencies.diskImageStore.isBusy(mountpoint: metadata.mountpoint) {
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: project, event: "volume_lock_skipped_because_busy", result: "skipped", role: role, resource: volumeName, reason: reason, message: "Mountpoint is busy"))
            return
        }
        do {
            try dependencies.diskImageStore.detach(mountpoint: metadata.mountpoint)
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: project, event: "volume_lock_succeeded", result: "success", role: role, resource: volumeName, reason: reason))
        } catch {
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: project, event: "volume_lock_failed", result: "failed", role: role, resource: volumeName, reason: reason, message: "\(error)"))
            throw error
        }
    }

    func storeKeychainItem(
        service: String,
        value: String,
        config: ProjectConfig,
        audit: AuditLog,
        runID: String,
        role: String?,
        resource: String?,
        reason: String?
    ) throws {
        try withProjectKeychainAudit(config: config, audit: audit, runID: runID, role: role, resource: resource, reason: reason) {
            try dependencies.keychainStore.storeGenericPassword(service: service, value: value)
        }
    }

    func deleteKeychainItem(
        service: String,
        config: ProjectConfig,
        audit: AuditLog,
        runID: String,
        role: String?,
        resource: String?,
        reason: String?
    ) throws {
        try withProjectKeychainAudit(config: config, audit: audit, runID: runID, role: role, resource: resource, reason: reason) {
            try dependencies.keychainStore.deleteGenericPassword(service: service)
        }
    }

    func readKeychainItem(
        service: String,
        config: ProjectConfig,
        audit: AuditLog,
        runID: String,
        role: String?,
        resource: String?,
        reason: String?
    ) throws -> String {
        try withProjectKeychainAudit(config: config, audit: audit, runID: runID, role: role, resource: resource, reason: reason) {
            try dependencies.keychainStore.readGenericPassword(service: service)
        }
    }

    func withProjectKeychainAudit<T>(
        config: ProjectConfig,
        audit: AuditLog,
        runID: String,
        role: String?,
        resource: String?,
        reason: String?,
        operation: () throws -> T
    ) throws -> T {
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "project_keychain_unlock_requested",
            result: "success",
            role: role,
            resource: resource,
            reason: reason
        ))

        do {
            let value = try operation()
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "project_keychain_unlock_succeeded",
                result: "success",
                role: role,
                resource: resource,
                reason: reason
            ))
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "project_keychain_locked",
                result: "success",
                role: role,
                resource: resource,
                reason: reason
            ))
            return value
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

    func defaultsToDetachOnExit(_ role: RoleConfig) -> Bool {
        role.requireReason || !role.allowEnvInjection
    }
}
