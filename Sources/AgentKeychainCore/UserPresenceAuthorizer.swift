import Foundation
import LocalAuthentication

public final class LocalAuthenticationAuthorizer: UserPresenceAuthorizing {
    public init() {}

    public func authorize(reason: String) throws {
        let context = LAContext()
        context.localizedReason = reason
        try UserPresenceAuthorization.authorize(context: context, reason: reason)
    }
}

enum UserPresenceAuthorization {
    static func authorize(context: LAContext, reason: String) throws {
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            throw AgentKeychainError.policy("User-presence authentication is unavailable")
        }

        let semaphore = DispatchSemaphore(value: 0)
        let result = UserPresenceEvaluationResult()
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            result.authorized = success
            result.error = error
            semaphore.signal()
        }
        semaphore.wait()

        if !result.authorized {
            if let error = result.error {
                throw AgentKeychainError.policy("User-presence authentication failed: \(error.localizedDescription)")
            }
            throw AgentKeychainError.policy("User-presence authentication failed")
        }
    }
}

private final class UserPresenceEvaluationResult: @unchecked Sendable {
    var authorized = false
    var error: Error?
}
