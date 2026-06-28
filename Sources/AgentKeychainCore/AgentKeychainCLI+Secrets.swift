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
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        _ = try PolicyEngine.requireRole(config, roleName)
        let oldHash = try config.canonicalHash()
        let service = secretService(role: roleName, name: name)
        let value = try dependencies.secretPrompt.readSecret(prompt: "Secret value for \(name)")
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try storeKeychainItem(
            service: service,
            value: value,
            config: config,
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
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain secret get NAME --role ROLE [--reason TEXT] [--allow-raw-secret]")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()), booleanFlags: ["--allow-raw-secret"])
        guard let roleName = options.value(for: "--role") else {
            throw AgentKeychainError.invalidArguments("secret get requires --role")
        }
        let reason = options.value(for: "--reason")
        let store = ConfigStore(projectRoot: workingDirectory)
        let config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let role = try PolicyEngine.requireRole(config, roleName)
        guard let secret = config.secrets[name] else {
            throw AgentKeychainError.invalidArguments("Unknown secret: \(name)")
        }
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

        if secret.role != roleName {
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "policy_rejection",
                result: "denied",
                role: roleName,
                resource: name,
                reason: reason,
                message: "Secret \(name) belongs to role \(secret.role), not \(roleName)"
            ))
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "command_failed",
                result: "failed",
                role: roleName,
                resource: name,
                reason: reason,
                message: "Secret \(name) belongs to role \(secret.role), not \(roleName)"
            ))
            throw AgentKeychainError.policy("Refusing to use secret \(name) from role \(secret.role) in role \(roleName).\nRe-run with --role \(secret.role) --reason \"...\"")
        }

        try requireReasonIfNeeded(
            config: config,
            roleName: roleName,
            role: role,
            reason: reason,
            resource: name,
            audit: audit,
            runID: runID
        )

        if !role.allowSecretExport && !options.hasFlag("--allow-raw-secret") {
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "policy_rejection",
                result: "denied",
                role: roleName,
                resource: name,
                reason: reason,
                message: "Role \(roleName) disallows secret export"
            ))
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "command_failed",
                result: "failed",
                role: roleName,
                resource: name,
                reason: reason,
                message: "Role \(roleName) disallows secret export"
            ))
            throw AgentKeychainError.policy("Role \(roleName) disallows secret export. Re-run with --allow-raw-secret --reason TEXT.")
        }

        if options.hasFlag("--allow-raw-secret") {
            try dependencies.userPresenceAuthorizer.authorize(reason: reason ?? "Allow raw secret stdout")
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "raw_secret_stdout_override",
                result: "success",
                role: roleName,
                resource: name,
                reason: reason
            ))
        }

        let value = try readKeychainItem(
            service: secret.keychainService,
            config: config,
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
        let names = config.secrets
            .filter { _, metadata in roleFilter == nil || metadata.role == roleFilter }
            .keys
            .sorted()
        return CommandResult(exitCode: 0, stdout: names.map { "\($0)\n" }.joined())
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
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
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
