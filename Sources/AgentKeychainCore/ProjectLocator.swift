import Foundation

public enum ProjectLocator {
    public static func locate(startingAt start: URL, explicitProject: URL? = nil) throws -> URL {
        if let explicitProject {
            let candidate = explicitProject.standardizedFileURL
            if FileManager.default.fileExists(atPath: candidate.appendingPathComponent(".agent-keychain/config.json").path) {
                return candidate
            }
            throw AgentKeychainError.filesystem("No agent-keychain project found at \(candidate.path). Run `agent-keychain init`.")
        }

        var current = start.standardizedFileURL
        while true {
            if FileManager.default.fileExists(atPath: current.appendingPathComponent(".agent-keychain/config.json").path) {
                return current
            }
            let parent = current.deletingLastPathComponent()
            if parent.path == current.path {
                throw AgentKeychainError.filesystem("No agent-keychain project found. Run `agent-keychain init`.")
            }
            current = parent
        }
    }
}
