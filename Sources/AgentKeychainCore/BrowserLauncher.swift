import Foundation

public protocol BrowserLaunching: AnyObject {
    func launchChrome(userDataDir: String, additionalArguments: [String]) throws
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
}
