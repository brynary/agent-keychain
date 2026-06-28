import Foundation

public protocol DiskImageManaging: AnyObject {
    func createEncryptedSparsebundle(imagePath: String, size: String, volumeName: String, password: String) throws
    func attach(imagePath: String, mountpoint: String, password: String) throws
    func detach(mountpoint: String) throws
    func isMounted(imagePath: String, mountpoint: String) throws -> Bool
    func isBusy(mountpoint: String) throws -> Bool
    func deleteImage(imagePath: String) throws
}

public final class ProcessDiskImageStore: DiskImageManaging {
    public init() {}

    public func createEncryptedSparsebundle(imagePath: String, size: String, volumeName: String, password: String) throws {
        let parent = URL(fileURLWithPath: imagePath).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        try runHdiutil(
            arguments: [
                "create",
                "-type", "SPARSEBUNDLE",
                "-size", size,
                "-fs", "APFS",
                "-volname", volumeName,
                "-encryption", "AES-256",
                "-stdinpass",
                imagePath
            ],
            stdin: password + "\0"
        )
    }

    public func attach(imagePath: String, mountpoint: String, password: String) throws {
        try validateMountpoint(mountpoint)
        try FileManager.default.createDirectory(
            at: URL(fileURLWithPath: mountpoint).deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try runHdiutil(
            arguments: [
                "attach",
                imagePath,
                "-stdinpass",
                "-mountpoint",
                mountpoint
            ],
            stdin: password + "\0"
        )
    }

    public func detach(mountpoint: String) throws {
        try runHdiutil(arguments: ["detach", mountpoint], stdin: nil)
    }

    public func isMounted(imagePath: String, mountpoint: String) throws -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = ["info", "-plist"]
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            return false
        }

        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard
            let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
            let images = plist["images"] as? [[String: Any]]
        else {
            return false
        }

        let expectedImage = URL(fileURLWithPath: imagePath).standardizedFileURL.path
        let expectedMountpoint = URL(fileURLWithPath: mountpoint).standardizedFileURL.path
        return images.contains { image in
            let imagePath = (image["image-path"] as? String).map { URL(fileURLWithPath: $0).standardizedFileURL.path }
            guard imagePath == expectedImage, let systemEntities = image["system-entities"] as? [[String: Any]] else {
                return false
            }
            return systemEntities.contains { entity in
                (entity["mount-point"] as? String).map { URL(fileURLWithPath: $0).standardizedFileURL.path } == expectedMountpoint
            }
        }
    }

    public func isBusy(mountpoint: String) throws -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["+D", mountpoint]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    public func deleteImage(imagePath: String) throws {
        if FileManager.default.fileExists(atPath: imagePath) {
            try FileManager.default.removeItem(atPath: imagePath)
        }
    }

    private func runHdiutil(arguments: [String], stdin: String?) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = arguments

        let input = Pipe()
        let output = Pipe()
        let error = Pipe()
        if stdin != nil {
            process.standardInput = input
        }
        process.standardOutput = output
        process.standardError = error

        try process.run()
        if let stdin {
            input.fileHandleForWriting.write(Data(stdin.utf8))
            input.fileHandleForWriting.closeFile()
        }
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let message = String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "hdiutil failed"
            throw AgentKeychainError.filesystem(message.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    private func validateMountpoint(_ mountpoint: String) throws {
        let url = URL(fileURLWithPath: mountpoint)
        if let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]), values.isSymbolicLink == true {
            throw AgentKeychainError.policy("Refusing to use symlink mountpoint: \(mountpoint)")
        }
    }
}
