import Darwin
import Foundation

public final class ManagedVolumeLock {
    private let url: URL
    private var released = false

    private init(url: URL) {
        self.url = url
    }

    deinit {
        release()
    }

    public static func acquire(projectRoot: URL, volumeName: String) throws -> ManagedVolumeLock {
        let locksDirectory = projectRoot.appendingPathComponent(".agent-keychain/locks", isDirectory: true)
        try FileManager.default.createDirectory(at: locksDirectory, withIntermediateDirectories: true)
        let url = locksDirectory.appendingPathComponent("\(volumeName).lock")
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard fd >= 0 else {
            if errno == EEXIST {
                throw AgentKeychainError.policy("Managed volume \(volumeName) is already in use.")
            }
            throw AgentKeychainError.filesystem("Unable to acquire managed volume lock for \(volumeName)")
        }
        let payload = "\(getpid())\n"
        _ = payload.withCString { pointer in
            write(fd, pointer, strlen(pointer))
        }
        close(fd)
        return ManagedVolumeLock(url: url)
    }

    public func release() {
        guard !released else {
            return
        }
        released = true
        try? FileManager.default.removeItem(at: url)
    }
}
