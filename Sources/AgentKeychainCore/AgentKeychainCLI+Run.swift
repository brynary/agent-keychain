import Foundation

extension AgentKeychainCLI {
    func runCommand(arguments: [String], workingDirectory: URL) throws -> CommandResult {
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

        if !role.allowSecretExport && !request.secretBindings.isEmpty {
            guard request.allowPrivilegedEnv else {
                try audit.append(AuditEvent(
                    timestamp: dependencies.clock.now(),
                    runID: runID,
                    project: config.project.name,
                    event: "policy_rejection",
                    result: "denied",
                    role: request.role,
                    reason: request.reason,
                    message: "Role \(request.role) disallows secret export to environment variables"
                ))
                throw AgentKeychainError.policy("Role \(request.role) disallows secret export to environment variables. Re-run with --allow-privileged-env --reason TEXT.")
            }
            _ = try PolicyEngine.requireMutationReason(request.reason)
            try dependencies.userPresenceAuthorizer.authorize(
                reason: request.reason ?? "Allow privileged secret export to environment variables",
                progressReporter: dependencies.progressReporter
            )
            try audit.append(AuditEvent(
                timestamp: dependencies.clock.now(),
                runID: runID,
                project: config.project.name,
                event: "privileged_secret_export_override",
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
        var browserVolumeMountpoints = Set<String>()
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
            browserVolumeMountpoints.insert(volume.mountpoint)
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
            try dependencies.browserLauncher.launchChrome(userDataDir: userDataDir, additionalArguments: [])
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
                if browserVolumeMountpoints.contains(volume.mountpoint) {
                    continue
                }
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
