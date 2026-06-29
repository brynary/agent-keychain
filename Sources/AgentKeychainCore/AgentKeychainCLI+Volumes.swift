import Foundation

extension AgentKeychainCLI {
    func volume(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let subcommand = arguments.first else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain volume <create|unlock|lock|status>")
        }

        switch subcommand {
        case "create":
            return try volumeCreate(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "unlock":
            return try volumeUnlock(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "lock":
            return try volumeLock(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "status":
            return try volumeStatus(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "delete":
            return try volumeDelete(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        default:
            throw AgentKeychainError.invalidArguments("Unknown volume command: \(subcommand)")
        }
    }

    private func volumeCreate(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain volume create NAME --role ROLE --size SIZE --reason TEXT [--path PATH]")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("volume create requires --role")
        }
        guard let size = options.value(for: "--size") else {
            throw AgentKeychainError.invalidArguments("volume create requires --size")
        }
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        _ = try PolicyEngine.requireRole(config, roleName)
        guard config.volumes[name] == nil else {
            throw AgentKeychainError.invalidArguments("Volume already exists: \(name)")
        }

        let relativeImage = options.value(for: "--path") ?? ".agent-keychain/volumes/\(name).sparsebundle"
        let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: relativeImage)
        let mountpoint = "/Volumes/AgentKeychain-\(sanitizeProjectName(config.project.name))-\(name)"
        let service = volumeService(role: roleName, name: name)
        let password = try dependencies.passwordGenerator.generatePassword()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try storeKeychainItem(
            service: service,
            value: password,
            config: config,
            audit: audit,
            runID: runID,
            role: roleName,
            resource: name,
            reason: reason
        )
        try dependencies.diskImageStore.createEncryptedSparsebundle(
            imagePath: imagePath,
            size: size,
            volumeName: "AgentKeychain-\(name)",
            password: password
        )

        let oldHash = try config.canonicalHash()
        config.volumes[name] = VolumeMetadata(
            role: roleName,
            image: relativeImage,
            mountpoint: mountpoint,
            keychainService: service
        )
        let newHash = try config.canonicalHash()

        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_requested", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: roleName, resource: name, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_created", result: "success", role: roleName, resource: name, reason: reason))
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_succeeded", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash, newConfigHash: newHash))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())

        return CommandResult(exitCode: 0, stdout: "Created volume \(name)\n")
    }

    private func volumeUnlock(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain volume unlock NAME --role ROLE [--reason TEXT]")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("volume unlock requires --role")
        }
        let reason = options.value(for: "--reason")
        let store = ConfigStore(projectRoot: workingDirectory)
        let config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let role = try PolicyEngine.requireRole(config, roleName)
        let metadata = try requireVolume(config: config, name: name, roleName: roleName, reason: reason, auditURL: store.auditURL)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try requireReasonIfNeeded(
            config: config,
            roleName: roleName,
            role: role,
            reason: reason,
            resource: name,
            audit: audit,
            runID: runID
        )
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_unlock_requested", result: "success", role: roleName, resource: name, reason: reason))
        let password = try readKeychainItem(
            service: metadata.keychainService,
            config: config,
            audit: audit,
            runID: runID,
            role: roleName,
            resource: name,
            reason: reason
        )
        do {
            try attachAndVerifyVolume(
                name: name,
                metadata: metadata,
                password: password,
                workingDirectory: workingDirectory
            )
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_unlock_succeeded", result: "success", role: roleName, resource: name, reason: reason))
        } catch {
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_unlock_failed", result: "failed", role: roleName, resource: name, reason: reason, message: "\(error)"))
            throw error
        }
        return CommandResult(exitCode: 0, stdout: "Unlocked volume \(name)\n")
    }

    private func volumeLock(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain volume lock NAME --role ROLE")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("volume lock requires --role")
        }
        let store = ConfigStore(projectRoot: workingDirectory)
        let config = try loadTrustedConfig(store: store, reason: nil)
        _ = try PolicyEngine.requireRole(config, roleName)
        let metadata = try requireVolume(config: config, name: name, roleName: roleName, reason: nil, auditURL: store.auditURL)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        if try dependencies.diskImageStore.isBusy(mountpoint: metadata.mountpoint) {
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_lock_skipped_because_busy", result: "skipped", role: roleName, resource: name, message: "Mountpoint is busy"))
            return CommandResult(exitCode: 0, stdout: "Skipped locking volume \(name) because mountpoint is busy\n")
        }
        do {
            try dependencies.diskImageStore.detach(mountpoint: metadata.mountpoint)
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_lock_succeeded", result: "success", role: roleName, resource: name))
        } catch {
            try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_lock_failed", result: "failed", role: roleName, resource: name, message: "\(error)"))
            throw error
        }
        return CommandResult(exitCode: 0, stdout: "Locked volume \(name)\n")
    }

    private func volumeStatus(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        let config = try ConfigStore(projectRoot: workingDirectory).loadConfig()
        let selectedName = arguments.first
        let volumes = config.volumes
            .filter { selectedName == nil || $0.key == selectedName }
            .sorted { $0.key < $1.key }
        let lines = try volumes.map { name, metadata in
            let mounted = try dependencies.diskImageStore.isMounted(
                imagePath: absoluteProjectPath(workingDirectory: workingDirectory, path: metadata.image),
                mountpoint: metadata.mountpoint
            )
            return "\(name) \(mounted ? "mounted" : "unmounted")\n"
        }.joined()
        return CommandResult(exitCode: 0, stdout: lines)
    }

    private func volumeDelete(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain volume delete NAME --role ROLE --reason TEXT")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("volume delete requires --role")
        }
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        _ = try PolicyEngine.requireRole(config, roleName)
        let metadata = try requireVolume(config: config, name: name, roleName: roleName, reason: reason, auditURL: store.auditURL)
        let browserUsers = config.browsers.filter { $0.value.volume == name }
        if !browserUsers.isEmpty {
            throw AgentKeychainError.policy("Refusing to delete volume \(name) because browser profiles still use it.")
        }
        let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: metadata.image)
        if try dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: metadata.mountpoint) {
            throw AgentKeychainError.policy("Refusing to delete mounted volume \(name). Lock it first.")
        }

        let oldHash = try config.canonicalHash()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try deleteKeychainItem(
            service: metadata.keychainService,
            config: config,
            audit: audit,
            runID: runID,
            role: roleName,
            resource: name,
            reason: reason
        )
        try dependencies.diskImageStore.deleteImage(imagePath: imagePath)
        config.volumes.removeValue(forKey: name)
        let newHash = try config.canonicalHash()
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_requested", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: roleName, resource: name, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "volume_deleted", result: "success", role: roleName, resource: name, reason: reason))
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_succeeded", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash, newConfigHash: newHash))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())
        return CommandResult(exitCode: 0, stdout: "Deleted volume \(name)\n")
    }
}
