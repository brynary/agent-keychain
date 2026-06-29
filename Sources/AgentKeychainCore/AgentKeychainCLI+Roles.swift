import Foundation

extension AgentKeychainCLI {
    func role(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let subcommand = arguments.first else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain role <create|list|show>")
        }

        switch subcommand {
        case "create":
            return try roleCreate(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "list":
            return try roleList(workingDirectory: workingDirectory)
        case "show":
            return try roleShow(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "update":
            return try roleUpdate(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "delete":
            return try roleDelete(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        default:
            throw AgentKeychainError.invalidArguments("Unknown role command: \(subcommand)")
        }
    }

    private func roleCreate(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain role create NAME --reason TEXT [options]")
        }
        let options = try ParsedOptions(
            arguments: Array(arguments.dropFirst()),
            booleanFlags: ["--require-reason", "--deny-secret-export"]
        )
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try store.loadConfig()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())

        do {
            try store.verifyIntegrity(for: config)
        } catch let error as AgentKeychainError {
            if case .configIntegrity = error {
                try? audit.append(AuditEvent(
                    timestamp: dependencies.clock.now(),
                    runID: runID,
                    project: config.project.name,
                    event: "config_tamper_detected",
                    result: "denied",
                    reason: reason,
                    message: error.message
                ))
            }
            throw error
        }

        guard config.roles[name] == nil else {
            throw AgentKeychainError.invalidArguments("Role already exists: \(name)")
        }

        let oldHash = try config.canonicalHash()
        let description = options.value(for: "--description") ?? ""
        config.roles[name] = RoleConfig(
            description: description,
            requireReason: options.hasFlag("--require-reason"),
            allowSecretExport: !options.hasFlag("--deny-secret-export")
        )
        let newHash = try config.canonicalHash()

        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "command_started",
            result: "success",
            role: name,
            reason: reason
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_requested",
            result: "success",
            role: name,
            reason: reason,
            oldConfigHash: oldHash
        ))
        do {
            try store.writeConfig(config)
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "role_created",
                result: "success",
                role: name,
                reason: reason
            ))
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "config_mutation_succeeded",
                result: "success",
                role: name,
                reason: reason,
                oldConfigHash: oldHash,
                newConfigHash: newHash
            ))
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "command_completed",
                result: "success",
                role: name,
                reason: reason
            ))
            try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())
        } catch {
            try? audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "config_mutation_failed",
                result: "failed",
                role: name,
                reason: reason,
                message: "\(error)",
                oldConfigHash: oldHash,
                newConfigHash: newHash
            ))
            throw error
        }

        return CommandResult(exitCode: 0, stdout: "Created role \(name)\n")
    }

    private func roleList(workingDirectory: URL) throws -> CommandResult {
        let config = try ConfigStore(projectRoot: workingDirectory).loadConfig()
        let stdout = config.roles.keys.sorted().map { "\($0)\n" }.joined()
        return CommandResult(exitCode: 0, stdout: stdout)
    }

    private func roleShow(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain role show NAME")
        }
        let config = try ConfigStore(projectRoot: workingDirectory).loadConfig()
        guard let role = config.roles[name] else {
            throw AgentKeychainError.invalidArguments("Unknown role: \(name)")
        }
        let data = try CanonicalJSON.encode(role)
        return CommandResult(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
    }

    private func roleUpdate(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain role update NAME --reason TEXT [options]")
        }
        let options = try ParsedOptions(
            arguments: Array(arguments.dropFirst()),
            booleanFlags: ["--require-reason", "--no-require-reason", "--deny-secret-export", "--allow-secret-export"]
        )
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        guard var role = config.roles[name] else {
            throw AgentKeychainError.invalidArguments("Unknown role: \(name)")
        }

        let oldHash = try config.canonicalHash()
        if let description = options.value(for: "--description") {
            role.description = description
        }
        if options.hasFlag("--require-reason") {
            role.requireReason = true
        }
        if options.hasFlag("--no-require-reason") {
            role.requireReason = false
        }
        if options.hasFlag("--deny-secret-export") {
            role.allowSecretExport = false
        }
        if options.hasFlag("--allow-secret-export") {
            role.allowSecretExport = true
        }
        config.roles[name] = role
        let newHash = try config.canonicalHash()

        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_requested", result: "success", role: name, reason: reason, oldConfigHash: oldHash))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: name, resource: nil, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "role_updated", result: "success", role: name, reason: reason))
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_succeeded", result: "success", role: name, reason: reason, oldConfigHash: oldHash, newConfigHash: newHash))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())
        return CommandResult(exitCode: 0, stdout: "Updated role \(name)\n")
    }

    private func roleDelete(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain role delete NAME --reason TEXT")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        guard config.roles[name] != nil else {
            throw AgentKeychainError.invalidArguments("Unknown role: \(name)")
        }
        let ownsResources =
            config.secrets.values.contains { $0.role == name } ||
            config.volumes.values.contains { $0.role == name } ||
            config.browsers.values.contains { $0.role == name }
        if ownsResources {
            throw AgentKeychainError.policy("Refusing to delete role \(name) because it still owns resources.")
        }

        let oldHash = try config.canonicalHash()
        config.roles.removeValue(forKey: name)
        let newHash = try config.canonicalHash()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_requested", result: "success", role: name, reason: reason, oldConfigHash: oldHash))
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: name, resource: nil, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "role_deleted", result: "success", role: name, reason: reason))
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: config.project.name, event: "config_mutation_succeeded", result: "success", role: name, reason: reason, oldConfigHash: oldHash, newConfigHash: newHash))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())
        return CommandResult(exitCode: 0, stdout: "Deleted role \(name)\n")
    }
}
