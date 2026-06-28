import AgentKeychainCore
import Darwin
import Foundation

let arguments = Array(CommandLine.arguments.dropFirst())
let environment = ProcessInfo.processInfo.environment

#if DEBUG
if let statePath = environment["AGENT_KEYCHAIN_BLACK_BOX_STATE"],
   arguments.first == "__test-backend-healthcheck" {
    do {
        let stateURL = URL(fileURLWithPath: statePath)
        let state = try BlackBoxTestState.load(from: stateURL)
        try state.save(to: stateURL)
        print("agent-keychain black-box backend ready")
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("black-box backend unavailable: \(error)\n".utf8))
        exit(1)
    }
}
#endif

let cli: AgentKeychainCLI
#if DEBUG
if let statePath = environment["AGENT_KEYCHAIN_BLACK_BOX_STATE"] {
    cli = AgentKeychainCLI(dependencies: .blackBoxTesting(
        stateURL: URL(fileURLWithPath: statePath),
        secretValue: environment["AGENT_KEYCHAIN_BLACK_BOX_SECRET"]
    ))
} else {
    cli = AgentKeychainCLI()
}
#else
cli = AgentKeychainCLI()
#endif

let result = cli.run(
    arguments,
    workingDirectory: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
)

if !result.stdout.isEmpty {
    print(result.stdout, terminator: "")
}

if !result.stderr.isEmpty {
    FileHandle.standardError.write(Data(result.stderr.utf8))
}

exit(result.exitCode)
