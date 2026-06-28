import Foundation

public struct CommandResult: Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public init(exitCode: Int32, stdout: String = "", stderr: String = "") {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public struct AgentKeychainCLI {
    public static let name = "agent-keychain"

    private let dependencies: AgentKeychainDependencies

    public init(dependencies: AgentKeychainDependencies = .production()) {
        self.dependencies = dependencies
    }

    public func run(_ arguments: [String], workingDirectory: URL) -> CommandResult {
        do {
            var arguments = arguments
            let explicitProject = try consumeProjectOverride(arguments: &arguments)
            guard let command = arguments.first else {
                return CommandResult(exitCode: 2, stderr: "Usage: agent-keychain <command>\n")
            }
            let projectRoot = try resolveProjectRoot(
                command: command,
                explicitProject: explicitProject,
                workingDirectory: workingDirectory
            )

            switch command {
            case "init":
                return try initializeProject(arguments: Array(arguments.dropFirst()), workingDirectory: projectRoot)
            default:
                return try withCommandLifecycleAudit(command: command, projectRoot: projectRoot) {
                    switch command {
                    case "status":
                        return try status(workingDirectory: projectRoot)
                    case "config":
                        return try config(arguments: Array(arguments.dropFirst()), workingDirectory: projectRoot)
                    case "role":
                        return try role(arguments: Array(arguments.dropFirst()), workingDirectory: projectRoot)
                    case "secret":
                        return try secret(arguments: Array(arguments.dropFirst()), workingDirectory: projectRoot)
                    case "volume":
                        return try volume(arguments: Array(arguments.dropFirst()), workingDirectory: projectRoot)
                    case "browser":
                        return try browser(arguments: Array(arguments.dropFirst()), workingDirectory: projectRoot)
                    case "run":
                        return try runCommand(arguments: Array(arguments.dropFirst()), workingDirectory: projectRoot)
                    default:
                        return CommandResult(exitCode: 2, stderr: "Unknown command: \(command)\n")
                    }
                }
            }
        } catch let error as AgentKeychainError {
            return CommandResult(exitCode: error.exitCode, stderr: "\(error.message)\n")
        } catch {
            return CommandResult(exitCode: 1, stderr: "\(error)\n")
        }
    }

    private func consumeProjectOverride(arguments: inout [String]) throws -> URL? {
        guard arguments.first == "--project" else {
            return nil
        }
        guard arguments.count >= 3 else {
            throw AgentKeychainError.invalidArguments("--project requires a path and command")
        }
        let url = URL(fileURLWithPath: arguments[1])
        arguments.removeFirst(2)
        return url
    }

    private func resolveProjectRoot(command: String, explicitProject: URL?, workingDirectory: URL) throws -> URL {
        if command == "init" {
            return explicitProject ?? workingDirectory
        }
        return try ProjectLocator.locate(startingAt: workingDirectory, explicitProject: explicitProject)
    }

    private func withCommandLifecycleAudit(
        command: String,
        projectRoot: URL,
        operation: () throws -> CommandResult
    ) throws -> CommandResult {
        let store = ConfigStore(projectRoot: projectRoot)
        let config = try store.loadConfig()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "command_started",
            result: "success",
            message: command
        ))

        do {
            let result = try operation()
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: result.exitCode == 0 ? "command_completed" : "command_failed",
                result: result.exitCode == 0 ? "success" : "failed",
                message: command
            ))
            return result
        } catch let error as AgentKeychainError {
            try? audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "command_failed",
                result: "failed",
                message: "\(command): \(error.message)"
            ))
            throw error
        } catch {
            try? audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "command_failed",
                result: "failed",
                message: "\(command): \(error)"
            ))
            throw error
        }
    }

    private func initializeProject(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        let options = try ParsedOptions(arguments: arguments)
        let projectName = options.value(for: "--project-name") ?? sanitizeProjectName(workingDirectory.lastPathComponent)
        let store = ConfigStore(projectRoot: workingDirectory)

        try store.createProjectDirectories()

        let config = ProjectConfig.defaultConfig(
            projectName: projectName,
            projectRoot: workingDirectory.path
        )
        let password = try dependencies.passwordGenerator.generatePassword()
        try dependencies.keychainStore.createProjectKeychain(
            path: workingDirectory.appendingPathComponent(config.project.keychainPath).path,
            password: password
        )
        try dependencies.keychainStore.storeProjectKeychainPassword(
            service: config.project.keychainPasswordService,
            password: password
        )

        try store.writeConfig(config)

        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        let audit = AuditLog(url: store.auditURL)
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "command_started",
            result: "success"
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "project_initialized",
            result: "success",
            message: "Initialized agent-keychain project"
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_succeeded",
            result: "success",
            newConfigHash: try config.canonicalHash()
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "command_completed",
            result: "success"
        ))

        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())

        return CommandResult(exitCode: 0, stdout: "Initialized agent-keychain project \(projectName)\n")
    }

    private func status(workingDirectory: URL) throws -> CommandResult {
        let config = try ConfigStore(projectRoot: workingDirectory).loadConfig()
        let roleNames = config.roles.keys.sorted()
        let roles = roleNames.isEmpty ? "none" : roleNames.joined(separator: ", ")
        let volumeLines: [String]
        if config.volumes.isEmpty {
            volumeLines = ["Volumes: none"]
        } else {
            volumeLines = try ["Volumes:"] + config.volumes
                .sorted { $0.key < $1.key }
                .map { name, metadata in
                    let mounted = try dependencies.diskImageStore.isMounted(
                        imagePath: absoluteProjectPath(workingDirectory: workingDirectory, path: metadata.image),
                        mountpoint: metadata.mountpoint
                    )
                    return "  \(name): \(mounted ? "mounted" : "unmounted")"
                }
        }
        let browsers = config.browsers.keys.sorted()
        let stdout = ([
            "Project: \(config.project.name)",
            "Root: \(config.project.root)",
            "Project keychain: configured",
            "Roles: \(roles)"
        ] + volumeLines + [
            "Browsers: \(browsers.isEmpty ? "none" : browsers.joined(separator: ", "))"
        ]).joined(separator: "\n") + "\n"
        return CommandResult(exitCode: 0, stdout: stdout)
    }

    private func config(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let subcommand = arguments.first else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain config <path|trust-current>")
        }
        let store = ConfigStore(projectRoot: workingDirectory)
        switch subcommand {
        case "path":
            return CommandResult(exitCode: 0, stdout: store.configURL.path + "\n")
        case "trust-current":
            let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
            let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
            try dependencies.userPresenceAuthorizer.authorize(reason: reason)
            let current = try store.loadConfig()
            try AuditLog(url: store.auditURL).append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: dependencies.runIDFactory.makeRunID(date: dependencies.clock.now()),
                project: current.project.name,
                event: "config_trust_baseline_updated",
                result: "success",
                reason: reason,
                newConfigHash: try current.canonicalHash()
            ))
            try store.writeIntegrity(for: current, updatedAt: dependencies.clock.now())
            return CommandResult(exitCode: 0, stdout: "Trusted current config\n")
        default:
            throw AgentKeychainError.invalidArguments("Unknown config command: \(subcommand)")
        }
    }

    private func role(arguments: [String], workingDirectory: URL) throws -> CommandResult {
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
            booleanFlags: ["--require-reason", "--deny-env-injection"]
        )
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
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
            allowEnvInjection: !options.hasFlag("--deny-env-injection")
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
            booleanFlags: ["--require-reason", "--no-require-reason", "--deny-env-injection", "--allow-env-injection"]
        )
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
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
        if options.hasFlag("--deny-env-injection") {
            role.allowEnvInjection = false
        }
        if options.hasFlag("--allow-env-injection") {
            role.allowEnvInjection = true
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
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
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

    private func secret(arguments: [String], workingDirectory: URL) throws -> CommandResult {
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

        if !role.allowEnvInjection && !options.hasFlag("--allow-raw-secret") {
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "policy_rejection",
                result: "denied",
                role: roleName,
                resource: name,
                reason: reason,
                message: "Role \(roleName) disallows raw secret output"
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
                message: "Role \(roleName) disallows raw secret output"
            ))
            throw AgentKeychainError.policy("Role \(roleName) disallows raw secret output. Re-run with --allow-raw-secret --reason TEXT.")
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

    private func loadTrustedConfig(store: ConfigStore, reason: String?) throws -> ProjectConfig {
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

    private func writeConfigOrAuditMutationFailure(
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

    private func secretService(role: String, name: String) -> String {
        "agent-keychain.role.\(role).secret.\(name)"
    }

    private func volume(arguments: [String], workingDirectory: URL) throws -> CommandResult {
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
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
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
        try dependencies.userPresenceAuthorizer.authorize(reason: reason)
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

    private func browser(arguments: [String], workingDirectory: URL) throws -> CommandResult {
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

    private func requireVolume(config: ProjectConfig, name: String, roleName: String, reason: String?, auditURL: URL) throws -> VolumeMetadata {
        guard let volume = config.volumes[name] else {
            throw AgentKeychainError.invalidArguments("Unknown volume: \(name)")
        }
        if volume.role != roleName {
            try? AuditLog(url: auditURL).append(AuditEvent(timestamp: dependencies.clock.now(), runID: dependencies.runIDFactory.makeRunID(date: dependencies.clock.now()), project: config.project.name, event: "policy_rejection", result: "denied", role: roleName, resource: name, reason: reason, message: "Volume \(name) belongs to role \(volume.role), not \(roleName)"))
            throw AgentKeychainError.policy("Volume \(name) belongs to role \(volume.role), not \(roleName).")
        }
        return volume
    }

    private func requireReasonIfNeeded(
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

    private func browserUserDataDir(mountpoint: String, profilePath: String) throws -> String {
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

    private func volumeService(role: String, name: String) -> String {
        "agent-keychain.role.\(role).volume.\(name).password"
    }

    private func absoluteProjectPath(workingDirectory: URL, path: String) -> String {
        if path.hasPrefix("/") {
            return path
        }
        return workingDirectory.appendingPathComponent(path).path
    }

    private func configureKeychainContext(config: ProjectConfig, workingDirectory: URL) throws {
        try dependencies.keychainStore.useProject(config: config, projectRoot: workingDirectory)
    }

    private func attachAndVerifyVolume(name: String, metadata: VolumeMetadata, password: String, workingDirectory: URL) throws {
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

    private func detachVolumeIfNotBusy(project: String, runID: String, role: String, volumeName: String, metadata: VolumeMetadata, reason: String?, auditURL: URL) throws {
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

    private func storeKeychainItem(
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

    private func deleteKeychainItem(
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

    private func readKeychainItem(
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

    private func withProjectKeychainAudit<T>(
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

    private func defaultsToDetachOnExit(_ role: RoleConfig) -> Bool {
        role.requireReason || !role.allowEnvInjection
    }

    private func runCommand(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        let request = try RunRequest(arguments: arguments)
        let store = ConfigStore(projectRoot: workingDirectory)
        let config = try loadTrustedConfig(store: store, reason: request.reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let role = try PolicyEngine.requireRole(config, request.role)

        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try requireReasonIfNeeded(
            config: config,
            roleName: request.role,
            role: role,
            reason: request.reason,
            resource: nil,
            audit: audit,
            runID: runID
        )
        var environment: [String: String] = [:]

        if !role.allowEnvInjection && !request.secretBindings.isEmpty {
            guard request.allowPrivilegedEnv else {
                try audit.append(AuditEvent(
                    timestamp: dependencies.clock.now(),
                    runID: runID,
                    project: config.project.name,
                    event: "policy_rejection",
                    result: "denied",
                    role: request.role,
                    reason: request.reason,
                    message: "Role \(request.role) disallows environment-variable secret injection"
                ))
                throw AgentKeychainError.policy("Role \(request.role) disallows environment-variable secret injection. Re-run with --allow-privileged-env --reason TEXT.")
            }
            _ = try PolicyEngine.requireMutationReason(request.reason)
            try dependencies.userPresenceAuthorizer.authorize(reason: request.reason ?? "Allow privileged environment injection")
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "privileged_environment_injection_override",
                result: "success",
                role: request.role,
                reason: request.reason
            ))
        }

        for binding in request.secretBindings {
            guard let secret = config.secrets[binding.secretName] else {
                throw AgentKeychainError.invalidArguments("Unknown secret: \(binding.secretName)")
            }
            if secret.role != request.role {
                try audit.append(AuditEvent(
                    timestamp: dependencies.clock.now(),
                    runID: runID,
                    project: config.project.name,
                    event: "policy_rejection",
                    result: "denied",
                    role: request.role,
                    resource: binding.secretName,
                    reason: request.reason,
                    message: "Secret \(binding.secretName) belongs to role \(secret.role), not \(request.role)"
                ))
                throw AgentKeychainError.policy("Refusing to use secret \(binding.secretName) from role \(secret.role) in role \(request.role).\nRe-run with --role \(secret.role) --reason \"...\"")
            }
            environment[binding.environmentName] = try readKeychainItem(
                service: secret.keychainService,
                config: config,
                audit: audit,
                runID: runID,
                role: request.role,
                resource: binding.secretName,
                reason: request.reason
            )
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "secret_read",
                result: "success",
                role: request.role,
                resource: binding.secretName,
                reason: request.reason
            ))
        }

        var mountedForRun: [VolumeMetadata] = []
        var managedLocks: [String: ManagedVolumeLock] = [:]
        defer {
            for lock in managedLocks.values {
                lock.release()
            }
        }
        for volumeName in request.volumes {
            let volume = try requireVolume(config: config, name: volumeName, roleName: request.role, reason: request.reason, auditURL: store.auditURL)
            if managedLocks[volumeName] == nil {
                managedLocks[volumeName] = try ManagedVolumeLock.acquire(projectRoot: workingDirectory, volumeName: volumeName)
            }
            let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: volume.image)
            if try !dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: volume.mountpoint) {
                let password = try readKeychainItem(
                    service: volume.keychainService,
                    config: config,
                    audit: audit,
                    runID: runID,
                    role: request.role,
                    resource: volumeName,
                    reason: request.reason
                )
                try attachAndVerifyVolume(name: volumeName, metadata: volume, password: password, workingDirectory: workingDirectory)
                mountedForRun.append(volume)
            }
        }

        for browserName in request.browsers {
            guard let browser = config.browsers[browserName] else {
                throw AgentKeychainError.invalidArguments("Unknown browser profile: \(browserName)")
            }
            if browser.role != request.role {
                try audit.append(AuditEvent(
                    timestamp: dependencies.clock.now(),
                    runID: runID,
                    project: config.project.name,
                    event: "policy_rejection",
                    result: "denied",
                    role: request.role,
                    resource: browserName,
                    reason: request.reason,
                    message: "Browser profile \(browserName) belongs to role \(browser.role), not \(request.role)"
                ))
                throw AgentKeychainError.policy("Browser profile \(browserName) belongs to role \(browser.role), not \(request.role).")
            }
            let volume = try requireVolume(config: config, name: browser.volume, roleName: request.role, reason: request.reason, auditURL: store.auditURL)
            if managedLocks[browser.volume] == nil {
                managedLocks[browser.volume] = try ManagedVolumeLock.acquire(projectRoot: workingDirectory, volumeName: browser.volume)
            }
            let userDataDir = try browserUserDataDir(mountpoint: volume.mountpoint, profilePath: browser.profilePath)
            let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: volume.image)
            if try !dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: volume.mountpoint) {
                let password = try readKeychainItem(
                    service: volume.keychainService,
                    config: config,
                    audit: audit,
                    runID: runID,
                    role: request.role,
                    resource: browser.volume,
                    reason: request.reason
                )
                try attachAndVerifyVolume(name: browser.volume, metadata: volume, password: password, workingDirectory: workingDirectory)
                if !mountedForRun.contains(where: { $0.mountpoint == volume.mountpoint }) {
                    mountedForRun.append(volume)
                }
            }
            if FileManager.default.fileExists(atPath: volume.mountpoint) {
                try FileManager.default.createDirectory(atPath: userDataDir, withIntermediateDirectories: true)
            }
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "browser_opened",
                result: "success",
                role: request.role,
                resource: browserName,
                reason: request.reason
            ))
            try dependencies.browserLauncher.launchChrome(userDataDir: userDataDir)
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "browser_exited",
                result: "success",
                role: request.role,
                resource: browserName,
                reason: request.reason
            ))
        }

        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "command_started",
            result: "success",
            role: request.role,
            reason: request.reason
        ))
        let child = try dependencies.commandRunner.run(command: request.command, environment: environment)
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: child.exitCode == 0 ? "command_completed" : "command_failed",
            result: child.exitCode == 0 ? "success" : "failed",
            role: request.role,
            reason: request.reason
        ))

        if request.detachOnExit || defaultsToDetachOnExit(role) {
            for volume in mountedForRun {
                let volumeName = config.volumes.first { $0.value.mountpoint == volume.mountpoint }?.key ?? volume.mountpoint
                try detachVolumeIfNotBusy(project: config.project.name, runID: runID, role: request.role, volumeName: volumeName, metadata: volume, reason: request.reason, auditURL: store.auditURL)
            }
        }

        return CommandResult(exitCode: child.exitCode, stdout: child.stdout, stderr: child.stderr)
    }
}

private struct SecretBinding {
    let environmentName: String
    let secretName: String
}

private struct RunRequest {
    let role: String
    let reason: String?
    let secretBindings: [SecretBinding]
    let volumes: [String]
    let browsers: [String]
    let allowPrivilegedEnv: Bool
    let detachOnExit: Bool
    let command: [String]

    init(arguments: [String]) throws {
        var role: String?
        var reason: String?
        var secretBindings: [SecretBinding] = []
        var volumes: [String] = []
        var browsers: [String] = []
        var allowPrivilegedEnv = false
        var detachOnExit = false
        var index = 0
        var command: [String] = []

        while index < arguments.count {
            let argument = arguments[index]
            if argument == "--" {
                command = Array(arguments.dropFirst(index + 1))
                break
            }
            switch argument {
            case "--role":
                index += 1
                guard index < arguments.count else { throw AgentKeychainError.invalidArguments("--role requires a value") }
                role = arguments[index]
            case "--reason":
                index += 1
                guard index < arguments.count else { throw AgentKeychainError.invalidArguments("--reason requires a value") }
                reason = arguments[index]
            case "--secret":
                index += 1
                guard index < arguments.count else { throw AgentKeychainError.invalidArguments("--secret requires ENV=SECRET") }
                let parts = arguments[index].split(separator: "=", maxSplits: 1).map(String.init)
                guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else {
                    throw AgentKeychainError.invalidArguments("--secret requires ENV=SECRET")
                }
                secretBindings.append(SecretBinding(environmentName: parts[0], secretName: parts[1]))
            case "--volume":
                index += 1
                guard index < arguments.count else { throw AgentKeychainError.invalidArguments("--volume requires a value") }
                volumes.append(arguments[index])
            case "--browser":
                index += 1
                guard index < arguments.count else { throw AgentKeychainError.invalidArguments("--browser requires a value") }
                browsers.append(arguments[index])
            case "--allow-privileged-env":
                allowPrivilegedEnv = true
            case "--detach-on-exit":
                detachOnExit = true
            default:
                throw AgentKeychainError.invalidArguments("Unexpected run argument: \(argument)")
            }
            index += 1
        }

        guard let role else {
            throw AgentKeychainError.invalidArguments("run requires --role")
        }
        guard !command.isEmpty else {
            throw AgentKeychainError.invalidArguments("run requires a command after --")
        }

        self.role = role
        self.reason = reason
        self.secretBindings = secretBindings
        self.volumes = volumes
        self.browsers = browsers
        self.allowPrivilegedEnv = allowPrivilegedEnv
        self.detachOnExit = detachOnExit
        self.command = command
    }
}
