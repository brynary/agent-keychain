import Foundation

public protocol BrowserLaunching: AnyObject {
    func launchChrome(userDataDir: String) throws
}

public final class ProcessBrowserLauncher: BrowserLaunching {
    public init() {}

    public func launchChrome(userDataDir: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        process.arguments = [
            "--user-data-dir=\(userDataDir)",
            "--no-first-run"
        ]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw AgentKeychainError.filesystem("Chrome exited with status \(process.terminationStatus)")
        }
    }
}
