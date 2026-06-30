import Darwin
import Foundation

public protocol BrowserLaunching: AnyObject {
    func launchChrome(userDataDir: String, additionalArguments: [String]) throws
    func stopChromeProcesses(userDataDir: String) throws -> Int
    func managedChromeStatus(userDataDir: String) throws -> (running: Bool, headless: Bool?, cdpPort: Int?)
    func inspectCDP(port: Int) throws -> (browser: String, webSocketDebuggerUrl: String?)?
}

private final class CDPResponseBox: @unchecked Sendable {
    private let lock = NSLock()
    private var responseData: Data?
    private var responseStatus: Int?

    func set(data: Data?, status: Int?) {
        lock.lock()
        responseData = data
        responseStatus = status
        lock.unlock()
    }

    func snapshot() -> (data: Data?, status: Int?) {
        lock.lock()
        defer { lock.unlock() }
        return (responseData, responseStatus)
    }
}

public final class ProcessBrowserLauncher: BrowserLaunching {
    public init() {}

    public func launchChrome(userDataDir: String, additionalArguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = [
            "-na",
            "Google Chrome",
            "--args",
            "--user-data-dir=\(userDataDir)",
            "--no-first-run"
        ] + additionalArguments
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw AgentKeychainError.filesystem("Chrome launch request exited with status \(process.terminationStatus)")
        }
    }

    public func stopChromeProcesses(userDataDir: String) throws -> Int {
        let matches = try matchingChromeProcesses(userDataDir: userDataDir)
        for match in matches {
            try sendSignal(SIGTERM, to: match.pid)
        }
        if !matches.isEmpty {
            usleep(200_000)
            let remaining = try matchingChromeProcesses(userDataDir: userDataDir)
            for match in remaining {
                try sendSignal(SIGKILL, to: match.pid)
            }
        }
        return matches.count
    }

    public func managedChromeStatus(userDataDir: String) throws -> (running: Bool, headless: Bool?, cdpPort: Int?) {
        let matches = try matchingChromeProcesses(userDataDir: userDataDir)
        guard !matches.isEmpty else {
            return (running: false, headless: nil, cdpPort: nil)
        }
        let headless = matches.contains { $0.headless }
        let cdpPort = matches.compactMap(\.cdpPort).first
        return (running: true, headless: headless, cdpPort: cdpPort)
    }

    public func inspectCDP(port: Int) throws -> (browser: String, webSocketDebuggerUrl: String?)? {
        guard let url = URL(string: "http://127.0.0.1:\(port)/json/version") else {
            return nil
        }
        var request = URLRequest(url: url)
        request.timeoutInterval = 1

        let semaphore = DispatchSemaphore(value: 0)
        let responseBox = CDPResponseBox()

        let task = URLSession.shared.dataTask(with: request) { data, response, _ in
            responseBox.set(data: data, status: (response as? HTTPURLResponse)?.statusCode)
            semaphore.signal()
        }
        task.resume()
        guard semaphore.wait(timeout: .now() + 1.5) == .success else {
            task.cancel()
            return nil
        }
        let response = responseBox.snapshot()
        guard response.status == 200, let responseData = response.data else {
            return nil
        }

        struct CDPVersion: Decodable {
            let browser: String
            let webSocketDebuggerUrl: String?

            enum CodingKeys: String, CodingKey {
                case browser = "Browser"
                case webSocketDebuggerUrl
            }
        }

        guard let version = try? JSONDecoder().decode(CDPVersion.self, from: responseData) else {
            return nil
        }
        return (browser: version.browser, webSocketDebuggerUrl: version.webSocketDebuggerUrl)
    }

    private func sendSignal(_ signal: Int32, to pid: Int32) throws {
        guard Darwin.kill(pid, signal) != 0 else {
            return
        }
        let errorNumber = errno
        if errorNumber == ESRCH {
            return
        }
        throw AgentKeychainError.filesystem("Unable to signal Chrome process \(pid): \(String(cString: strerror(errorNumber)))")
    }

    private struct ChromeProcess {
        let pid: Int32
        let headless: Bool
        let cdpPort: Int?
    }

    private func matchingChromeProcesses(userDataDir: String) throws -> [ChromeProcess] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "pid=,command="]
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        let outputData = output.fileHandleForReading.readDataToEndOfFile()
        let errorData = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(data: errorData, encoding: .utf8) ?? "ps failed"
            throw AgentKeychainError.filesystem(message.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        let text = String(data: outputData, encoding: .utf8) ?? ""
        return text.split(separator: "\n").compactMap { line in
            chromeProcess(from: String(line), userDataDir: userDataDir)
        }
    }

    private func chromeProcess(from line: String, userDataDir: String) -> ChromeProcess? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard let separator = trimmed.firstIndex(where: { $0 == " " || $0 == "\t" }) else {
            return nil
        }
        let pidText = String(trimmed[..<separator])
        let command = String(trimmed[separator...]).trimmingCharacters(in: .whitespaces)
        guard command.contains("Google Chrome"), let pid = Int32(pidText) else {
            return nil
        }

        let tokens = shellLikeTokens(command)
        guard chromeArguments(tokens, containUserDataDir: userDataDir) else {
            return nil
        }
        return ChromeProcess(
            pid: pid,
            headless: tokens.contains { $0 == "--headless" || $0.hasPrefix("--headless=") },
            cdpPort: remoteDebuggingPort(in: tokens)
        )
    }

    private func chromeArguments(_ tokens: [String], containUserDataDir userDataDir: String) -> Bool {
        for index in tokens.indices {
            let token = tokens[index]
            if token == "--user-data-dir", tokens.indices.contains(index + 1), tokens[index + 1] == userDataDir {
                return true
            }
            if token.hasPrefix("--user-data-dir="), String(token.dropFirst("--user-data-dir=".count)) == userDataDir {
                return true
            }
        }
        return false
    }

    private func remoteDebuggingPort(in tokens: [String]) -> Int? {
        for index in tokens.indices {
            let token = tokens[index]
            if token == "--remote-debugging-port", tokens.indices.contains(index + 1) {
                return Int(tokens[index + 1])
            }
            if token.hasPrefix("--remote-debugging-port=") {
                return Int(token.dropFirst("--remote-debugging-port=".count))
            }
        }
        return nil
    }

    private func shellLikeTokens(_ command: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var quote: Character?
        var escaping = false

        for character in command {
            if escaping {
                current.append(character)
                escaping = false
                continue
            }
            if character == "\\" {
                escaping = true
                continue
            }
            if let activeQuote = quote {
                if character == activeQuote {
                    quote = nil
                } else {
                    current.append(character)
                }
                continue
            }
            if character == "\"" || character == "'" {
                quote = character
                continue
            }
            if character == " " || character == "\t" {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
                continue
            }
            current.append(character)
        }

        if !current.isEmpty {
            tokens.append(current)
        }
        return tokens
    }
}
