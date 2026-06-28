import Foundation

public struct ChildProcessResult: Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public init(exitCode: Int32, stdout: String, stderr: String) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public protocol CommandRunning: AnyObject {
    func run(command: [String], environment: [String: String]) throws -> ChildProcessResult
}

public final class ProcessCommandRunner: CommandRunning {
    public init() {}

    public func run(command: [String], environment: [String: String]) throws -> ChildProcessResult {
        guard !command.isEmpty else {
            throw AgentKeychainError.invalidArguments("run requires a command after --")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = command
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }

        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()

        return ChildProcessResult(
            exitCode: process.terminationStatus,
            stdout: String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            stderr: String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }
}
