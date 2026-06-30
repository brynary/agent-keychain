import Foundation

extension AgentKeychainCLI {
    func runCommand(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        let request = try RunRequest(arguments: arguments)
        let store = ConfigStore(projectRoot: workingDirectory)
        let config = try loadTrustedConfig(store: store, reason: request.reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        _ = try PolicyEngine.requireRole(config, request.role)

        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        var environment: [String: String] = [:]

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
                store: store,
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
    let command: [String]

    init(arguments: [String]) throws {
        var role: String?
        var reason: String?
        var secretBindings: [SecretBinding] = []
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
            default:
                throw AgentKeychainError.invalidArguments("Unexpected run argument: \(argument)")
            }
            index += 1
        }

        guard let role else {
            throw AgentKeychainError.invalidArguments("run requires --role")
        }
        guard !secretBindings.isEmpty else {
            throw AgentKeychainError.invalidArguments("run requires at least one --secret")
        }
        guard !command.isEmpty else {
            throw AgentKeychainError.invalidArguments("run requires a command after --")
        }

        self.role = role
        self.reason = reason
        self.secretBindings = secretBindings
        self.command = command
    }
}
