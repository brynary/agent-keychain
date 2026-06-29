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
    private static let projectCommands: Set<String> = [
        "status",
        "config",
        "role",
        "secret",
        "volume",
        "browser",
        "run"
    ]
    private static let topLevelHelp = """
    agent-keychain

    Project-scoped credential and browser-session isolation for local AI agent workflows.

    Usage:
      agent-keychain [--project PATH] <command> [options]
      agent-keychain help
      agent-keychain --help

    Commands:
      init       Initialize agent-keychain state in a project
      status     Show project status, roles, volumes, and browsers
      config     Show, trust, or migrate project configuration
      role       Create, list, show, update, delete, unlock, or lock roles
      secret     Set, get, list, or delete role-scoped secrets
      volume     Create, unlock, lock, inspect, or delete encrypted volumes
      browser    Create, open, list, or delete isolated Chrome profiles
      run        Run a command with role-scoped secrets, volumes, or browser profiles

    Global options:
      --project PATH  Use a specific agent-keychain project root
      -h, --help      Show this help

    Examples:
      agent-keychain init --project-name my-project
      agent-keychain status
      agent-keychain role create regular --reason "Create regular role"
      agent-keychain run --role regular --secret GITHUB_TOKEN=github-readonly -- agent-command

    """

    let dependencies: AgentKeychainDependencies

    public init(dependencies: AgentKeychainDependencies = .production()) {
        self.dependencies = dependencies
    }

    public func run(_ arguments: [String], workingDirectory: URL) -> CommandResult {
        do {
            var arguments = arguments
            let explicitProject = try consumeProjectOverride(arguments: &arguments)
            guard let command = arguments.first else {
                return CommandResult(exitCode: 2, stderr: Self.topLevelHelp)
            }
            if ["help", "--help", "-h"].contains(command) {
                return CommandResult(exitCode: 0, stdout: Self.topLevelHelp)
            }
            guard command == "init" || Self.projectCommands.contains(command) else {
                return CommandResult(exitCode: 2, stderr: "Unknown command: \(command)\n\n\(Self.topLevelHelp)")
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
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain config <path|trust-current|migrate-role-keychains|repair-keychain-access>")
        }
        let store = ConfigStore(projectRoot: workingDirectory)
        switch subcommand {
        case "path":
            return CommandResult(exitCode: 0, stdout: store.configURL.path + "\n")
        case "trust-current":
            let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
            let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
            try dependencies.userPresenceAuthorizer.authorize(
                reason: reason,
                progressReporter: dependencies.progressReporter
            )
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
        case "migrate-role-keychains":
            return try migrateRoleKeychains(arguments: Array(arguments.dropFirst()), store: store, workingDirectory: workingDirectory)
        case "repair-keychain-access":
            return try repairKeychainAccess(arguments: Array(arguments.dropFirst()), store: store, workingDirectory: workingDirectory)
        default:
            throw AgentKeychainError.invalidArguments("Unknown config command: \(subcommand)")
        }
    }

    private func migrateRoleKeychains(arguments: [String], store: ConfigStore, workingDirectory: URL) throws -> CommandResult {
        let options = try ParsedOptions(arguments: arguments)
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        var config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let missingRoleKeychains = config.roles
            .filter { _, role in role.keychain == nil }
            .keys
            .sorted()
        guard !missingRoleKeychains.isEmpty else {
            return CommandResult(exitCode: 0, stdout: "Role keychains already migrated\n")
        }

        let oldHash = try config.canonicalHash()
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_requested",
            result: "success",
            reason: reason,
            oldConfigHash: oldHash
        ))

        for roleName in missingRoleKeychains {
            var role = try PolicyEngine.requireRole(config, roleName)
            let roleKeychain = makeRoleKeychainConfig(config: config, roleName: roleName)
            try createRoleKeychain(roleKeychain)
            role.keychain = roleKeychain
            config.roles[roleName] = role
        }

        for (name, secret) in config.secrets.sorted(by: { $0.key < $1.key }) {
            let value = try dependencies.keychainStore.readGenericPassword(service: secret.keychainService)
            let roleKeychain = try ensureRoleKeychainUnlocked(config: config, store: store, audit: audit, runID: runID, roleName: secret.role, resource: name, reason: reason)
            try dependencies.keychainStore.storeGenericPassword(service: secret.keychainService, value: value, roleKeychain: roleKeychain)
        }
        for (name, volume) in config.volumes.sorted(by: { $0.key < $1.key }) {
            let value = try dependencies.keychainStore.readGenericPassword(service: volume.keychainService)
            let roleKeychain = try ensureRoleKeychainUnlocked(config: config, store: store, audit: audit, runID: runID, roleName: volume.role, resource: name, reason: reason)
            try dependencies.keychainStore.storeGenericPassword(service: volume.keychainService, value: value, roleKeychain: roleKeychain)
        }

        let newHash = try config.canonicalHash()
        try writeConfigOrAuditMutationFailure(config, store: store, audit: audit, runID: runID, role: nil, resource: nil, reason: reason, oldHash: oldHash, newHash: newHash)
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "role_keychains_migrated",
            result: "success",
            reason: reason,
            oldConfigHash: oldHash,
            newConfigHash: newHash
        ))
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "config_mutation_succeeded",
            result: "success",
            reason: reason,
            oldConfigHash: oldHash,
            newConfigHash: newHash
        ))
        try store.writeIntegrity(for: config, updatedAt: dependencies.clock.now())
        return CommandResult(exitCode: 0, stdout: "Migrated \(missingRoleKeychains.count) role keychain\(missingRoleKeychains.count == 1 ? "" : "s")\n")
    }

    private func repairKeychainAccess(arguments: [String], store: ConfigStore, workingDirectory: URL) throws -> CommandResult {
        let options = try ParsedOptions(arguments: arguments)
        let reason = try PolicyEngine.requireMutationReason(options.value(for: "--reason"))
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        let config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        var repaired = 0

        for (name, secret) in config.secrets.sorted(by: { $0.key < $1.key }) {
            repaired += try repairKeychainItem(
                service: secret.keychainService,
                role: secret.role,
                resource: name,
                config: config,
                store: store,
                audit: audit,
                runID: runID,
                reason: reason
            )
        }

        for (name, volume) in config.volumes.sorted(by: { $0.key < $1.key }) {
            repaired += try repairKeychainItem(
                service: volume.keychainService,
                role: volume.role,
                resource: name,
                config: config,
                store: store,
                audit: audit,
                runID: runID,
                reason: reason
            )
        }

        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: config.project.name,
            event: "keychain_access_repaired",
            result: "success",
            reason: reason,
            message: "Repaired access for \(repaired) keychain item\(repaired == 1 ? "" : "s")"
        ))
        return CommandResult(exitCode: 0, stdout: "Repaired access for \(repaired) keychain item\(repaired == 1 ? "" : "s")\n")
    }

    private func repairKeychainItem(
        service: String,
        role: String,
        resource: String,
        config: ProjectConfig,
        store: ConfigStore,
        audit: AuditLog,
        runID: String,
        reason: String
    ) throws -> Int {
        let roleConfig = try PolicyEngine.requireRole(config, role)
        guard roleConfig.keychain != nil else {
            try dependencies.keychainStore.repairGenericPasswordAccess(service: service)
            return 1
        }

        let roleKeychain = try ensureRoleKeychainUnlocked(
            config: config,
            store: store,
            audit: audit,
            runID: runID,
            roleName: role,
            resource: resource,
            reason: reason
        )
        try dependencies.keychainStore.repairGenericPasswordAccess(service: service, roleKeychain: roleKeychain)
        return 1
    }
}
