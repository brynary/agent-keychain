import Foundation

extension AgentKeychainCLI {
    func browser(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let subcommand = arguments.first else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser <create|open|list>")
        }

        switch subcommand {
        case "create":
            return try browserCreate(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "open":
            return try browserOpen(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "list":
            return try browserList(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "delete":
            return try browserDelete(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        default:
            throw AgentKeychainError.invalidArguments("Unknown browser command: \(subcommand)")
        }
    }

    private func browserCreate(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser create NAME --role ROLE --volume VOLUME --reason TEXT")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("browser create requires --role")
        }
        guard let volumeName = options.value(for: "--volume") else {
            throw AgentKeychainError.invalidArguments("browser create requires --volume")
        }
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        _ = try PolicyEngine.requireRole(config, roleName)
        let volume = try requireVolume(config: config, name: volumeName, roleName: roleName, reason: reason, auditURL: store.auditURL)
        guard volume.role == roleName else {
            throw AgentKeychainError.policy("Volume \(volumeName) belongs to role \(volume.role), not \(roleName).")
        }

        let oldHash = try config.canonicalHash()
        config.browsers[name] = BrowserMetadata(role: roleName, volume: volumeName, profilePath: "ChromeProfiles/\(name)")
        let newHash = try config.canonicalHash()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_requested", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: roleName, resource: name, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "browser_created", result: "success", role: roleName, resource: name, reason: reason))
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_succeeded", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash, newConfigHash: newHash))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())
        return CommandResult(exitCode: 0, stdout: "Created browser \(name)\n")
    }

    private func browserOpen(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser open NAME --role ROLE [--reason TEXT] [--detach-on-exit]")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()), booleanFlags: ["--detach-on-exit"])
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("browser open requires --role")
        }
        let reason = options.value(for: "--reason")
        let store = ConfigStore(projectRoot: workingDirectory)
        let config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let role = try PolicyEngine.requireRole(config, roleName)
        guard let browser = config.browsers[name] else {
            throw AgentKeychainError.invalidArguments("Unknown browser profile: \(name)")
        }
        if browser.role != roleName {
            try AuditLog(url: store.auditURL).append(AuditEvent(timestamp: dependencies.clock.now(), runID: dependencies.runIDFactory.makeRunID(date: dependencies.clock.now()), project: config.project.name, event: "policy_rejection", result: "denied", role: roleName, resource: name, reason: reason, message: "Browser profile \(name) belongs to role \(browser.role), not \(roleName)"))
            throw AgentKeychainError.policy("Browser profile \(name) belongs to role \(browser.role), not \(roleName).")
        }
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
        let volume = try requireVolume(config: config, name: browser.volume, roleName: roleName, reason: reason, auditURL: store.auditURL)
        let userDataDir = try browserUserDataDir(mountpoint: volume.mountpoint, profilePath: browser.profilePath)
        let managedLock = try ManagedVolumeLock.acquire(projectRoot: workingDirectory, volumeName: browser.volume)
        defer { managedLock.release() }
        let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: volume.image)
        if try !dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: volume.mountpoint) {
            let password = try readKeychainItem(
                service: volume.keychainService,
                config: config,
                audit: audit,
                runID: runID,
                role: roleName,
                resource: browser.volume,
                reason: reason
            )
            try attachAndVerifyVolume(name: browser.volume, metadata: volume, password: password, workingDirectory: workingDirectory)
        }
        if FileManager.default.fileExists(atPath: volume.mountpoint) {
            try FileManager.default.createDirectory(atPath: userDataDir, withIntermediateDirectories: true)
        }
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "browser_opened", result: "success", role: roleName, resource: name, reason: reason))
        try dependencies.browserLauncher.launchChrome(userDataDir: userDataDir)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "browser_exited", result: "success", role: roleName, resource: name, reason: reason))
        if options.hasFlag("--detach-on-exit") || defaultsToDetachOnExit(role) {
            try detachVolumeIfNotBusy(project: config.project.name, runID: runID, role: roleName, volumeName: browser.volume, metadata: volume, reason: reason, auditURL: store.auditURL)
        }
        return CommandResult(exitCode: 0, stdout: "Opened browser \(name)\n")
    }

    private func browserList(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        let options = try ParsedOptions(arguments: arguments)
        let roleFilter = options.value(for: "--role")
        let config = try ConfigStore(projectRoot: workingDirectory).loadConfig()
        let names = config.browsers
            .filter { _, metadata in roleFilter == nil || metadata.role == roleFilter }
            .keys
            .sorted()
        return CommandResult(exitCode: 0, stdout: names.map { "\($0)\n" }.joined())
    }

    private func browserDelete(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser delete NAME --role ROLE --reason TEXT")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("browser delete requires --role")
        }
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        _ = try PolicyEngine.requireRole(config, roleName)
        guard let browser = config.browsers[name] else {
            throw AgentKeychainError.invalidArguments("Unknown browser profile: \(name)")
        }
        if browser.role != roleName {
            throw AgentKeychainError.policy("Browser profile \(name) belongs to role \(browser.role), not \(roleName).")
        }

        let oldHash = try config.canonicalHash()
        config.browsers.removeValue(forKey: name)
        let newHash = try config.canonicalHash()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_requested", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: roleName, resource: name, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "browser_deleted", result: "success", role: roleName, resource: name, reason: reason))
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_succeeded", result: "success", role: roleName, resource: name, reason: reason, oldConfigHash: oldHash, newConfigHash: newHash))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())
        return CommandResult(exitCode: 0, stdout: "Deleted browser \(name)\n")
    }
}
