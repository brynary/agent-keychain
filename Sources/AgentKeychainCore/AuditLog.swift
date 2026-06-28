import Foundation

public struct AuditEvent {
    public var timestamp: Date
    public var runID: String
    public var project: String
    public var event: String
    public var result: String
    public var role: String?
    public var resource: String?
    public var reason: String?
    public var message: String?
    public var oldConfigHash: String?
    public var newConfigHash: String?

    public init(
        timestamp: Date,
        runID: String,
        project: String,
        event: String,
        result: String,
        role: String? = nil,
        resource: String? = nil,
        reason: String? = nil,
        message: String? = nil,
        oldConfigHash: String? = nil,
        newConfigHash: String? = nil
    ) {
        self.timestamp = timestamp
        self.runID = runID
        self.project = project
        self.event = event
        self.result = result
        self.role = role
        self.resource = resource
        self.reason = reason
        self.message = message
        self.oldConfigHash = oldConfigHash
        self.newConfigHash = newConfigHash
    }
}

public struct AuditLog {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    public func append(_ event: AuditEvent) throws {
        let previousHash = try lastEntryHash() ?? "genesis"
        var entry = AuditLogEntry(
            ts: iso8601UTC(event.timestamp),
            runID: event.runID,
            project: event.project,
            event: event.event,
            result: event.result,
            role: event.role,
            resource: event.resource,
            reason: event.reason,
            message: event.message,
            oldConfigHash: event.oldConfigHash,
            newConfigHash: event.newConfigHash,
            previousHash: previousHash,
            entryHash: nil
        )
        entry.entryHash = try SHA256Hex.hash(CanonicalJSON.encode(entry))
        var line = try CanonicalJSON.encode(entry)
        line.append(0x0a)

        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }

        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        try handle.write(contentsOf: line)
        try handle.synchronize()
        try handle.close()
    }

    private func lastEntryHash() throws -> String? {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        guard let lastLine = text.split(separator: "\n").last else {
            return nil
        }
        let data = Data(lastLine.utf8)
        let entry = try JSONDecoder().decode(AuditLogEntry.self, from: data)
        return entry.entryHash
    }
}

private struct AuditLogEntry: Codable {
    var ts: String
    var runID: String
    var project: String
    var event: String
    var result: String
    var role: String?
    var resource: String?
    var reason: String?
    var message: String?
    var oldConfigHash: String?
    var newConfigHash: String?
    var previousHash: String
    var entryHash: String?

    enum CodingKeys: String, CodingKey {
        case ts
        case runID = "run_id"
        case project
        case event
        case result
        case role
        case resource
        case reason
        case message
        case oldConfigHash = "old_config_hash"
        case newConfigHash = "new_config_hash"
        case previousHash = "previous_hash"
        case entryHash = "entry_hash"
    }
}
