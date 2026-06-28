import AgentKeychainCore
import Darwin
import Foundation

let cli = AgentKeychainCLI()
let result = cli.run(
    Array(CommandLine.arguments.dropFirst()),
    workingDirectory: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
)

if !result.stdout.isEmpty {
    print(result.stdout, terminator: "")
}

if !result.stderr.isEmpty {
    FileHandle.standardError.write(Data(result.stderr.utf8))
}

exit(result.exitCode)
