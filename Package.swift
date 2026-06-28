// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "agent-keychain",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "agent-keychain", targets: ["agent-keychain"]),
        .executable(name: "agent-keychain-test-runner", targets: ["AgentKeychainTestRunner"]),
        .library(name: "AgentKeychainCore", targets: ["AgentKeychainCore"])
    ],
    targets: [
        .target(name: "AgentKeychainCore"),
        .executableTarget(
            name: "agent-keychain",
            dependencies: ["AgentKeychainCore"]
        ),
        .executableTarget(
            name: "AgentKeychainTestRunner",
            dependencies: ["AgentKeychainCore"]
        )
    ]
)
