import Foundation

private struct ResolvedBrowserProfile {
    let config: ProjectConfig
    let browser: BrowserMetadata
    let volume: VolumeMetadata
    let userDataDir: String
}

private enum ManagedBrowserMode {
    case headed
    case headless

    var commandName: String {
        switch self {
        case .headed:
            return "headed"
        case .headless:
            return "headless"
        }
    }

    var auditEvent: String {
        switch self {
        case .headed:
            return "browser_headed_started"
        case .headless:
            return "browser_headless_started"
        }
    }
}

private struct BrowserCDPOutput: Encodable {
    let browser: String?
    let role: String
    let running: Bool
    let headless: Bool?
    let cdpPort: Int?
    let webSocketDebuggerUrl: String?
    let profilePath: String
    let agentBrowserCommand: String?

    enum CodingKeys: String, CodingKey {
        case browser
        case role
        case running
        case headless
        case cdpPort
        case webSocketDebuggerUrl
        case profilePath
        case agentBrowserCommand
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try encodeNullable(browser, forKey: .browser, into: &container)
        try container.encode(role, forKey: .role)
        try container.encode(running, forKey: .running)
        try encodeNullable(headless, forKey: .headless, into: &container)
        try encodeNullable(cdpPort, forKey: .cdpPort, into: &container)
        try encodeNullable(webSocketDebuggerUrl, forKey: .webSocketDebuggerUrl, into: &container)
        try container.encode(profilePath, forKey: .profilePath)
        try encodeNullable(agentBrowserCommand, forKey: .agentBrowserCommand, into: &container)
    }

    private func encodeNullable<T: Encodable>(
        _ value: T?,
        forKey key: CodingKeys,
        into container: inout KeyedEncodingContainer<CodingKeys>
    ) throws {
        if let value {
            try container.encode(value, forKey: key)
        } else {
            try container.encodeNil(forKey: key)
        }
    }
}

extension AgentKeychainCLI {
    func browser(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let subcommand = arguments.first else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser <create|open|headed|headless|stop|cdp|session|path|list|delete>")
        }

        switch subcommand {
        case "create":
            return try browserCreate(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "open":
            return try browserOpen(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "headed":
            return try browserManagedStart(mode: .headed, arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "headless":
            return try browserManagedStart(mode: .headless, arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "stop":
            return try browserStop(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "cdp":
            return try browserCDP(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "session":
            return try browserSession(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
        case "path":
            return try browserPath(arguments: Array(arguments.dropFirst()), workingDirectory: workingDirectory)
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
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
        let store = ConfigStore(projectRoot: workingDirectory)
        var config = try loadTrustedConfig(store: store, reason: reason)
        _ = try PolicyEngine.requireRole(config, roleName)
        guard config.browsers[name] == nil else {
            throw AgentKeychainError.invalidArguments("Browser profile already exists: \(name)")
        }
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
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser open NAME [--reason TEXT] [-- CHROME_ARG...]")
        }
        let (optionArguments, rawChromeArguments) = splitPassthroughArguments(Array(arguments.dropFirst()))
        if optionArguments.contains("--detach-on-exit") {
            throw AgentKeychainError.invalidArguments("browser open no longer accepts --detach-on-exit. Close Chrome, then run `agent-keychain volume lock NAME`.")
        }
        let options = try ParsedOptions(arguments: optionArguments)
        try rejectRemovedRoleOption(options, command: "browser open")
        let chromeArguments = try validatedChromeArguments(rawChromeArguments)
        let reason = options.value(for: "--reason")
        let store = ConfigStore(projectRoot: workingDirectory)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        let resolved = try resolveBrowserProfile(
            name: name,
            reason: reason,
            store: store,
            workingDirectory: workingDirectory,
            audit: audit,
            runID: runID
        )
        let roleName = resolved.browser.role
        let managedLock = try ManagedVolumeLock.acquire(projectRoot: workingDirectory, volumeName: resolved.browser.volume)
        defer { managedLock.release() }
        try mountBrowserVolumeIfNeeded(resolved, roleName: roleName, reason: reason, store: store, audit: audit, runID: runID, workingDirectory: workingDirectory)
        try ensureBrowserProfileDirectory(resolved)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: resolved.config.project.name, event: "browser_opened", result: "success", role: roleName, resource: name, reason: reason))
        try dependencies.browserLauncher.launchChrome(userDataDir: resolved.userDataDir, additionalArguments: chromeArguments)
        return CommandResult(exitCode: 0, stdout: "Opened browser \(name)\n")
    }

    private func browserManagedStart(mode: ManagedBrowserMode, arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser \(mode.commandName) NAME --url URL --cdp-port PORT [--reason TEXT]")
        }
        let options = try ParsedOptions(
            arguments: Array(arguments.dropFirst()),
            valueOptions: ["--url", "--cdp-port", "--reason", "--role"]
        )
        try rejectRemovedRoleOption(options, command: "browser \(mode.commandName)")
        guard let url = options.value(for: "--url") else {
            throw AgentKeychainError.invalidArguments("browser \(mode.commandName) requires --url")
        }
        guard let cdpPortValue = options.value(for: "--cdp-port") else {
            throw AgentKeychainError.invalidArguments("browser \(mode.commandName) requires --cdp-port")
        }
        let validatedURL = try validatedManagedBrowserURL(url)
        let cdpPort = try validatedCDPPort(cdpPortValue)
        let reason = options.value(for: "--reason")
        let store = ConfigStore(projectRoot: workingDirectory)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        let resolved = try resolveBrowserProfile(
            name: name,
            reason: reason,
            store: store,
            workingDirectory: workingDirectory,
            audit: audit,
            runID: runID
        )
        let roleName = resolved.browser.role
        let managedLock = try ManagedVolumeLock.acquire(projectRoot: workingDirectory, volumeName: resolved.browser.volume)
        defer { managedLock.release() }
        try mountBrowserVolumeIfNeeded(resolved, roleName: roleName, reason: reason, store: store, audit: audit, runID: runID, workingDirectory: workingDirectory)
        try ensureBrowserProfileDirectory(resolved)
        _ = try dependencies.browserLauncher.stopChromeProcesses(userDataDir: resolved.userDataDir)
        try dependencies.browserLauncher.launchChrome(
            userDataDir: resolved.userDataDir,
            additionalArguments: managedChromeArguments(mode: mode, url: validatedURL, cdpPort: cdpPort)
        )
        if mode == .headless {
            let version = try waitForCDPVersion(port: cdpPort)
            guard let version else {
                throw AgentKeychainError.policy("Headless Chrome did not become available on 127.0.0.1:\(cdpPort).")
            }
            guard version.browser.contains("HeadlessChrome") else {
                throw AgentKeychainError.policy("CDP /json/version did not report HeadlessChrome on 127.0.0.1:\(cdpPort).")
            }
        }
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: resolved.config.project.name,
            event: mode.auditEvent,
            result: "success",
            role: roleName,
            resource: name,
            reason: reason
        ))
        return CommandResult(exitCode: 0, stdout: "Started \(mode.commandName) browser \(name)\n")
    }

    private func browserStop(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser stop NAME [--lock-volume]")
        }
        let options = try ParsedOptions(
            arguments: Array(arguments.dropFirst()),
            booleanFlags: ["--lock-volume"],
            valueOptions: ["--role"]
        )
        try rejectRemovedRoleOption(options, command: "browser stop")
        let store = ConfigStore(projectRoot: workingDirectory)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        let resolved = try resolveBrowserProfile(
            name: name,
            reason: nil,
            store: store,
            workingDirectory: workingDirectory,
            audit: audit,
            runID: runID
        )
        _ = try dependencies.browserLauncher.stopChromeProcesses(userDataDir: resolved.userDataDir)
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: resolved.config.project.name,
            event: "browser_stopped",
            result: "success",
            role: resolved.browser.role,
            resource: name
        ))
        var stdout = "Stopped browser \(name)\n"
        if options.hasFlag("--lock-volume") {
            let lockResult = try volumeLock(arguments: [resolved.browser.volume], workingDirectory: workingDirectory)
            stdout += lockResult.stdout
        }
        return CommandResult(exitCode: 0, stdout: stdout)
    }

    private func browserCDP(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser cdp NAME")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()), valueOptions: ["--role"])
        try rejectRemovedRoleOption(options, command: "browser cdp")
        let store = ConfigStore(projectRoot: workingDirectory)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        let resolved = try resolveBrowserProfile(
            name: name,
            reason: nil,
            store: store,
            workingDirectory: workingDirectory,
            audit: audit,
            runID: runID
        )
        let status = try dependencies.browserLauncher.managedChromeStatus(userDataDir: resolved.userDataDir)
        let version = try status.cdpPort.flatMap { try dependencies.browserLauncher.inspectCDP(port: $0) }
        let output = BrowserCDPOutput(
            browser: version?.browser,
            role: resolved.browser.role,
            running: status.running,
            headless: status.headless,
            cdpPort: status.cdpPort,
            webSocketDebuggerUrl: version?.webSocketDebuggerUrl,
            profilePath: resolved.userDataDir,
            agentBrowserCommand: version == nil ? nil : status.cdpPort.map { agentBrowserCommand(name: name, cdpPort: $0) }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(output)
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: resolved.config.project.name,
            event: "browser_cdp_inspected",
            result: "success",
            role: resolved.browser.role,
            resource: name
        ))
        return CommandResult(exitCode: 0, stdout: String(decoding: data, as: UTF8.self) + "\n")
    }

    private func browserSession(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser session NAME")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()), valueOptions: ["--role"])
        try rejectRemovedRoleOption(options, command: "browser session")
        let store = ConfigStore(projectRoot: workingDirectory)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        let resolved = try resolveBrowserProfile(
            name: name,
            reason: nil,
            store: store,
            workingDirectory: workingDirectory,
            audit: audit,
            runID: runID
        )
        let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: resolved.volume.image)
        let mounted = try dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: resolved.volume.mountpoint)
        let status = try dependencies.browserLauncher.managedChromeStatus(userDataDir: resolved.userDataDir)
        let version = try status.cdpPort.flatMap { try dependencies.browserLauncher.inspectCDP(port: $0) }
        let stdout = [
            name,
            mounted ? "mounted" : "unmounted",
            status.running ? "running" : "stopped",
            browserModeDescription(status),
            cdpStatusDescription(port: status.cdpPort, available: version != nil)
        ]
            .filter { !$0.isEmpty }
            .joined(separator: " ") + "\n"
        try audit.append(AuditEvent(
            timestamp: dependencies.clock.now(),
            runID: runID,
            project: resolved.config.project.name,
            event: "browser_session_inspected",
            result: "success",
            role: resolved.browser.role,
            resource: name
        ))
        return CommandResult(exitCode: 0, stdout: stdout)
    }

    private func browserPath(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        guard let name = arguments.first, !name.hasPrefix("--") else {
            throw AgentKeychainError.invalidArguments("Usage: agent-keychain browser path NAME [--reason TEXT]")
        }
        let options = try ParsedOptions(arguments: Array(arguments.dropFirst()))
        try rejectRemovedRoleOption(options, command: "browser path")
        let reason = options.value(for: "--reason")
        let store = ConfigStore(projectRoot: workingDirectory)
        let audit = AuditLog(url: store.auditURL)
        let runID = dependencies.runIDFactory.makeRunID(date: dependencies.clock.now())
        let resolved = try resolveBrowserProfile(
            name: name,
            reason: reason,
            store: store,
            workingDirectory: workingDirectory,
            audit: audit,
            runID: runID
        )
        let roleName = resolved.browser.role
        let managedLock = try ManagedVolumeLock.acquire(projectRoot: workingDirectory, volumeName: resolved.browser.volume)
        defer { managedLock.release() }
        try mountBrowserVolumeIfNeeded(resolved, roleName: roleName, reason: reason, store: store, audit: audit, runID: runID, workingDirectory: workingDirectory)
        try ensureBrowserProfileDirectory(resolved)
        try audit.append(AuditEvent(timestamp: dependencies.clock.now(), runID: runID, project: resolved.config.project.name, event: "browser_path_resolved", result: "success", role: roleName, resource: name, reason: reason))
        return CommandResult(exitCode: 0, stdout: resolved.userDataDir + "\n")
    }

    private func browserList(arguments: [String], workingDirectory: URL) throws -> CommandResult {
        let options = try ParsedOptions(arguments: arguments)
        let roleFilter = options.value(for: "--role")
        let config = try ConfigStore(projectRoot: workingDirectory).loadConfig()
        if let roleFilter {
            let names = config.browsers
                .filter { _, metadata in metadata.role == roleFilter }
                .keys
                .sorted()
            return CommandResult(exitCode: 0, stdout: names.map { "\($0)\n" }.joined())
        }
        let rows = config.browsers
            .sorted { left, right in
                if left.value.role == right.value.role {
                    return left.key < right.key
                }
                return left.value.role < right.value.role
            }
            .map { name, metadata in [metadata.role, name] }
        return CommandResult(exitCode: 0, stdout: formatTable(headers: ["ROLE", "BROWSER"], rows: rows))
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
        try dependencies.userPresenceAuthorizer.authorize(
            reason: reason,
            progressReporter: dependencies.progressReporter
        )
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

    private func resolveBrowserProfile(
        name: String,
        reason: String?,
        store: ConfigStore,
        workingDirectory: URL,
        audit: AuditLog,
        runID: String
    ) throws -> ResolvedBrowserProfile {
        let config = try loadTrustedConfig(store: store, reason: reason)
        try configureKeychainContext(config: config, workingDirectory: workingDirectory)
        let browser = try requireBrowser(config: config, name: name)
        let roleName = browser.role
        _ = try PolicyEngine.requireRole(config, roleName)
        let volume = try requireVolume(config: config, name: browser.volume, roleName: roleName, reason: reason, auditURL: store.auditURL)
        let userDataDir = try browserUserDataDir(mountpoint: volume.mountpoint, profilePath: browser.profilePath)
        return ResolvedBrowserProfile(config: config, browser: browser, volume: volume, userDataDir: userDataDir)
    }

    private func mountBrowserVolumeIfNeeded(
        _ resolved: ResolvedBrowserProfile,
        roleName: String,
        reason: String?,
        store: ConfigStore,
        audit: AuditLog,
        runID: String,
        workingDirectory: URL
    ) throws {
        let imagePath = absoluteProjectPath(workingDirectory: workingDirectory, path: resolved.volume.image)
        if try dependencies.diskImageStore.isMounted(imagePath: imagePath, mountpoint: resolved.volume.mountpoint) {
            return
        }
        let password = try readKeychainItem(
            service: resolved.volume.keychainService,
            config: resolved.config,
            store: store,
            audit: audit,
            runID: runID,
            role: roleName,
            resource: resolved.browser.volume,
            reason: reason
        )
        try attachAndVerifyVolume(name: resolved.browser.volume, metadata: resolved.volume, password: password, workingDirectory: workingDirectory)
    }

    private func ensureBrowserProfileDirectory(_ resolved: ResolvedBrowserProfile) throws {
        if FileManager.default.fileExists(atPath: resolved.volume.mountpoint) {
            try FileManager.default.createDirectory(atPath: resolved.userDataDir, withIntermediateDirectories: true)
        }
    }

    private func managedChromeArguments(mode: ManagedBrowserMode, url: String, cdpPort: Int) -> [String] {
        var arguments: [String] = []
        if mode == .headless {
            arguments.append("--headless=new")
        }
        arguments.append("--remote-debugging-address=127.0.0.1")
        arguments.append("--remote-debugging-port=\(cdpPort)")
        arguments.append(url)
        return arguments
    }

    private func validatedManagedBrowserURL(_ value: String) throws -> String {
        if value == "about:blank" {
            return value
        }
        guard
            let components = URLComponents(string: value),
            let scheme = components.scheme?.lowercased(),
            ["http", "https"].contains(scheme),
            components.host != nil
        else {
            throw AgentKeychainError.invalidArguments("--url must be http://, https://, or about:blank")
        }
        return value
    }

    private func validatedCDPPort(_ value: String) throws -> Int {
        guard let port = Int(value), (1...65535).contains(port) else {
            throw AgentKeychainError.invalidArguments("--cdp-port must be an integer from 1 to 65535")
        }
        return port
    }

    private func waitForCDPVersion(port: Int) throws -> (browser: String, webSocketDebuggerUrl: String?)? {
        for attempt in 0..<5 {
            if let version = try dependencies.browserLauncher.inspectCDP(port: port) {
                return version
            }
            if attempt < 4 {
                Thread.sleep(forTimeInterval: 0.1)
            }
        }
        return nil
    }

    private func agentBrowserCommand(name: String, cdpPort: Int) -> String {
        "agent-browser --session \(sanitizeProjectName(name.lowercased())) connect \(cdpPort)"
    }

    private func browserModeDescription(_ status: (running: Bool, headless: Bool?, cdpPort: Int?)) -> String {
        guard status.running else {
            return ""
        }
        switch status.headless {
        case true:
            return "headless"
        case false:
            return "headed"
        case nil:
            return "mode unknown"
        }
    }

    private func cdpStatusDescription(port: Int?, available: Bool) -> String {
        guard let port else {
            return "CDP unavailable"
        }
        if available {
            return "CDP available on 127.0.0.1:\(port)"
        }
        return "CDP unavailable on 127.0.0.1:\(port)"
    }

    private func splitPassthroughArguments(_ arguments: [String]) -> (options: [String], passthrough: [String]) {
        guard let separator = arguments.firstIndex(of: "--") else {
            return (arguments, [])
        }
        return (Array(arguments[..<separator]), Array(arguments[arguments.index(after: separator)...]))
    }

    private func validatedChromeArguments(_ arguments: [String]) throws -> [String] {
        var hasRemoteDebuggingPort = false
        var hasRemoteDebuggingAddress = false
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            let optionName = argument.split(separator: "=", maxSplits: 1).first.map(String.init) ?? argument

            if optionName == "--user-data-dir" || optionName == "--profile-directory" {
                throw AgentKeychainError.policy("Refusing Chrome argument \(optionName) because agent-keychain manages the browser profile path.")
            }

            if optionName == "--remote-debugging-port" {
                hasRemoteDebuggingPort = true
            }

            if argument == "--remote-debugging-address" {
                guard index + 1 < arguments.count else {
                    throw AgentKeychainError.invalidArguments("Missing value for --remote-debugging-address")
                }
                let address = arguments[index + 1]
                try requireLoopbackRemoteDebuggingAddress(address)
                hasRemoteDebuggingAddress = true
                index += 2
                continue
            }

            if let address = remoteDebuggingAddressValue(argument) {
                try requireLoopbackRemoteDebuggingAddress(address)
                hasRemoteDebuggingAddress = true
            }

            index += 1
        }

        if hasRemoteDebuggingPort && !hasRemoteDebuggingAddress {
            return arguments + ["--remote-debugging-address=127.0.0.1"]
        }
        return arguments
    }

    private func remoteDebuggingAddressValue(_ argument: String) -> String? {
        let prefix = "--remote-debugging-address="
        guard argument.hasPrefix(prefix) else {
            return nil
        }
        return String(argument.dropFirst(prefix.count))
    }

    private func requireLoopbackRemoteDebuggingAddress(_ address: String) throws {
        guard ["127.0.0.1", "localhost", "::1"].contains(address) else {
            throw AgentKeychainError.policy("Refusing non-loopback Chrome remote debugging address: \(address)")
        }
    }
}
