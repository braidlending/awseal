import Foundation
import LocalAuthentication
import Logging
import Security

enum AuthenticationPolicy {
    static let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryCurrentSet]

    static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            flags, &error
        ) else {
            _ = error?.takeRetainedValue()
            // Do not weaken the policy on systems that cannot support it.
            throw AwsealError.generic("Unable to create the required biometric access control.")
        }
        return control
    }

    static func context(reason: String) -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        return context
    }
}

enum SDKLogging {
    static let disabled: Void = LoggingSystem.bootstrap { _ in SwiftLogNoOpLogHandler() }
}

func authenticationReason(profile: String, account: String, role: String) -> String {
    "AWS credentials: \(profile)\nAccount \(account)\nRole \(role)"
}

func validateProfileName(_ profile: String) throws {
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
    guard !profile.isEmpty, profile.utf8.count <= 64, profile != ".", profile != "..",
          profile.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
        throw AwsealError.generic("Profile names must be 1–64 ASCII letters, digits, underscores, dots or hyphens; not . or ...")
    }
}

func validateAuthority(account: String, role: String) throws {
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+=,.@-")
    guard account.utf8.count == 12, account.utf8.allSatisfy({ (48...57).contains($0) }),
          !role.isEmpty, role.utf8.count <= 64,
          role.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
        throw AwsealError.generic("Use a 12-digit AWS account ID and a valid IAM role name (up to 64 ASCII characters).")
    }
}

// Never send underlying SDK, decoding or crypto diagnostics to a caller:
// they may contain response bodies or credential-bearing values.
func commandError(_ error: Error) -> AwsealError {
    if let known = error as? AwsealError { return known }
    if localAuthenticationCode(error) == .biometryLockout {
        return .generic("Touch ID is locked. Lock your Mac, unlock it with your login password, then retry.")
    }
    return .generic("Operation failed. Check configuration, Touch ID authorization, connectivity and SSO login; underlying details suppressed to protect credentials.")
}

private func localAuthenticationCode(_ error: Error) -> LAError.Code? {
    var current = error as NSError

    // Security and CryptoKit may wrap the LocalAuthentication failure. Inspect
    // only the stable domain/code pair and never include an error description.
    for _ in 0..<4 {
        if current.domain == LAError.errorDomain {
            return LAError.Code(rawValue: current.code)
        }
        guard let underlying = current.userInfo[NSUnderlyingErrorKey] as? NSError,
              underlying !== current else { return nil }
        current = underlying
    }
    return nil
}
