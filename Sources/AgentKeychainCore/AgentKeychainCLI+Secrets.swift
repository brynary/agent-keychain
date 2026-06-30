import Foundation

extension AgentKeychainCLI {
    func secret(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let subcommand = arguments.first else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain secret <set|get|list|delete>")
        }

        switch subcommand {
        case "set":
            return try secretSet(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "get":
            return try secretGet(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "list":
            return try secretList(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "delete":
            return try secretDelete(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        default:
            throw AgentKeychainError.invalidArguments("Unknown secret command: \(subcommand)")
        }
    }

    private func secretSet(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain secret set NAME --role ROLE --reason TEXT")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("secret set requires --role")
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
        if let existing = config.secrets[name], existing.role != roleName {
            throw AgentKeychainError.policy("Secret \(name) belongs to role \(existing.role), not \(roleName). Delete it before recreating it for another role.")
        }
        let oldHash = try config.canonicalHash()
        let service = secretService(role: roleName, name: name)
        let value = try dependencies.secretPrompt.readSecret(prompt: "Secret value for \(name)")
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try storeKeychainItem(
            service: service,
            value: value,
            config: config,
            store: store,
            audit: audit,
            runID: runID,
            role: roleName,
            resource: name,
            reason: reason
        )

        config.secrets[name] = SecretMetadata(
            role: roleName,
            keychainService: service
        )
        let newHash = try config.canonicalHash()

        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_requested",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason,
            oldConfigHash: oldHash
        ))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: roleName, resource: name, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "secret_set",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_succeeded",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason,
            oldConfigHash: oldHash,
            newConfigHash: newHash
        ))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())

        return CommandResult(exitCode: 0, stdout: "Set secret \(name)\n")
    }

    private func secretGet(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain secret get NAME [--reason TEXT]")
        }
        let options = try ParsedOptions(
            arguments: Array(arguments.dropFirst()),
            valueOptions: ["--reason", "--role"]
        )
        try rejectRemovedRoleOption(options, command: "secret get")
        let reason = options.value(for: "--reason")
        let store = ConfigStore(projectRoot: workingDirectory)
        let config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let secret = try requireSecret(config: config, name: name)
        let roleName = secret.role
        let role = try PolicyEngine.requireRole(config, roleName)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "command_started",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason
        ))

        try requireReasonIfNeeded(
            config: config,
            roleName: roleName,
            role: role,
            reason: reason,
            resource: name,
            audit: audit,
            runID: runID
        )

        let value = try readKeychainItem(
            service: secret.keychainService,
            config: config,
            store: store,
            audit: audit,
            runID: runID,
            role: roleName,
            resource: name,
            reason: reason
        )
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "secret_read",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "command_completed",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason
        ))
        return CommandResult(exitCode: 0, stdout: "\(value)\n")
    }

    private func secretList(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        let options = try ParsedOptions(arguments: arguments)
        let roleFilter = options.value(for: "--role")
        let config = try ConfigStore(projectRoot: workingDirectory).loadConfig()
        if let roleFilter {
            let names = config.secrets
                .filter { _, metadata in metadata.role == roleFilter }
                .keys
                .sorted()
            return CommandResult(exitCode: 0, stdout: names.map { "\($0)\n" }.joined())
        }
        let rows = config.secrets
            .sorted { left, right in
                if left.value.role == right.value.role {
                    return left.key < right.key
                }
                return left.value.role < right.value.role
            }
            .map { name, metadata in [metadata.role, name] }
        return CommandResult(exitCode: 0, stdout: formatTable(headers: ["ROLE", "SECRET"], rows: rows))
    }

    private func secretDelete(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain secret delete NAME --role ROLE --reason TEXT")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("secret delete requires --role")
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
        guard let secret = config.secrets[name] else {
            throw AgentKeychainError.invalidArguments("Unknown secret: \(name)")
        }
        guard secret.role == roleName else {
            throw AgentKeychainError.policy("Secret \(name) belongs to role \(secret.role), not \(roleName)")
        }

        let oldHash = try config.canonicalHash()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try deleteKeychainItem(
            service: secret.keychainService,
            config: config,
            store: store,
            audit: audit,
            runID: runID,
            role: roleName,
            resource: name,
            reason: reason
        )
        config.secrets.removeValue(forKey: name)
        let newHash = try config.canonicalHash()

        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_requested",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason,
            oldConfigHash: oldHash
        ))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: roleName, resource: name, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "secret_delete",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_succeeded",
            result: "success",
            role: roleName,
            resource: name,
            reason: reason,
            oldConfigHash: oldHash,
            newConfigHash: newHash
        ))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())

        return CommandResult(exitCode: 0, stdout: "Deleted secret \(name)\n")
    }
}
