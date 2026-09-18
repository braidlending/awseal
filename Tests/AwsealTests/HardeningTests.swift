import Foundation
import LocalAuthentication
import Security
import Testing
@testable import awseal

struct HardeningTests {
    private final class SharedState: @unchecked Sendable {
        let value: StateDirectory

        init(_ value: StateDirectory) {
            self.value = value
        }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["AWSEAL_HARDWARE_TEST"] == "1"))
    func syntheticHardwareRoundTrip() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = try StateDirectory(path: directory.path)
        let creds = Creds(ssoCreds: SsoCreds(clientId: "FAKE_CLIENT", clientSecret: "FAKE_SECRET"))
        try saveCreds(profile: "synthetic", creds: creds, state: state)
        for _ in 0..<2 {
            let decrypted = try loadDecrypted(from: state.credentialURL(profile: "synthetic"), state: state,
                reason: authenticationReason(profile: "synthetic", account: "123456789012", role: "FakeRole"))
            let json = try #require(JSONSerialization.jsonObject(with: decrypted.data) as? [String: Any])
            #expect(Set(json.keys) == ["ssoCreds"])
            let decoded = try JSONDecoder().decode(Creds.self, from: decrypted.data)
            #expect(decoded.ssoCreds.clientId == "FAKE_CLIENT")
        }
    }

    @Test func testLegacyRoleCredentialsAreIgnoredEvenWhenMalformed() throws {
        for legacyRole in ["null", "17", #"{"accessKeyId":"ROLE_ACCESS_SENTINEL","secretAccessKey":"ROLE_SECRET_SENTINEL","sessionToken":"ROLE_SESSION_SENTINEL","expiration":0}"#] {
            let data = Data("""
                {"ssoCreds":{"clientId":"client","clientSecret":"sso-secret","accessToken":"sso-access","refreshToken":"sso-refresh"},"roleCreds":\(legacyRole)}
                """.utf8)
            let creds = try JSONDecoder().decode(Creds.self, from: data)
            #expect(creds.ssoCreds.refreshToken == "sso-refresh")
            let encoded = try JSONEncoder().encode(creds)
            let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
            #expect(Set(object.keys) == ["ssoCreds"])
            let text = String(decoding: encoded, as: UTF8.self)
            for forbidden in ["roleCreds", "ROLE_ACCESS_SENTINEL", "ROLE_SECRET_SENTINEL", "ROLE_SESSION_SENTINEL", "AccessKeyId", "SecretAccessKey", "SessionToken"] {
                #expect(!(text.contains(forbidden)))
            }
        }
    }

    @Test func testVerifiedKeyIsNeverSerializedIntoCredentialRecord() throws {
        var creds = Creds(ssoCreds: SsoCreds(clientId: "client", clientSecret: "fake"))
        creds.encryptionKey = KeyMetadata(id: UUID(), label: keyLabel, createdAt: Date(),
            keyPersistentRef: Data("KEY_SENTINEL".utf8), publicKeyX963: Data())
        let data = try JSONEncoder().encode(creds)
        let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(json.keys) == ["ssoCreds"])
        #expect(try JSONDecoder().decode(Creds.self, from: data).encryptionKey == nil)
    }

    @Test func testInjectedEncryptionKeyIsIgnoredOnDecode() throws {
        let data = Data("""
            {"ssoCreds":{"clientId":"client","clientSecret":"secret"},"encryptionKey":{"id":"00000000-0000-0000-0000-000000000001","label":"attacker-controlled","createdAt":0,"keyPersistentRef":"SU5KRUNURURfS0VZ","publicKeyX963":""}}
            """.utf8)

        let creds = try JSONDecoder().decode(Creds.self, from: data)
        #expect(creds.encryptionKey == nil)

        let encoded = try JSONEncoder().encode(creds)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("INJECTED_KEY"))
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(Set(object.keys) == ["ssoCreds"])
    }

    @Test func testIndependentLoginsPreserveBothKeyRecords() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = try StateDirectory(path: directory.path)
        let first = try KeyDB(state: state)
        let second = try KeyDB(state: state)
        for db in [first, second] {
            try db.add(KeyMetadata(id: UUID(), label: keyLabel, createdAt: Date(),
                keyPersistentRef: Data(), publicKeyX963: Data()))
        }
        #expect(try KeyDB(state: state).list().count == 2)
    }

    @Test func testConcurrentKeyDatabaseAddsPreserveEveryRecord() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = try StateDirectory(path: directory.path)
        let sharedState = SharedState(state)
        let ids = (0..<8).map { _ in UUID() }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for id in ids {
                group.addTask {
                    try KeyDB(state: sharedState.value).add(KeyMetadata(
                        id: id, label: keyLabel, createdAt: Date(), keyPersistentRef: Data(), publicKeyX963: Data()))
                }
            }
            try await group.waitForAll()
        }

        let persisted = try KeyDB(state: state).list()
        #expect(Set(persisted.map(\.id)) == Set(ids))
    }

    @Test func testMalformedKeyDatabaseErrorsAreSanitized() throws {
        let secret = "MALFORMED_KEY_DB_SECRET"
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keyFile = directory.appendingPathComponent("keys.json")
        try Data("{\"leaked\":\"\(secret)\"}".utf8).write(to: keyFile)

        let state = try StateDirectory(path: directory.path)
        #expect(throws: (any Error).self) { try KeyDB(state: state) }
        do {
            _ = try KeyDB(state: state)
            Issue.record("Expected malformed key database to fail")
        } catch {
            #expect(!commandError(error).localizedDescription.contains(secret))
        }
    }

    @Test func testPromptIdentifiesRequestedAuthority() throws {
        try validateProfileName("prod-admin")
        try validateAuthority(account: "123456789012", role: "AdministratorAccess")
        #expect(authenticationReason(profile: "prod-admin", account: "123456789012", role: "AdministratorAccess") == "AWS credentials: prod-admin\nAccount 123456789012\nRole AdministratorAccess")
    }

    @Test func testRejectsPromptSpoofingAndPathTraversal() {
        for profile in ["", ".", "..", "../keys.json", "/tmp/profile", "prod\nRole ReadOnly", "prod\u{202E}", String(repeating: "a", count: 65)] {
            #expect(throws: (any Error).self) { try validateProfileName(profile) }
        }
        #expect(throws: (any Error).self) { try validateAuthority(account: "123\n45678901", role: "Admin") }
        #expect(throws: (any Error).self) { try validateAuthority(account: "123456789012", role: "ReadOnly\nAdmin") }
    }

    @Test func testCredentialProcessSchema() throws {
        let expiration = Date(timeIntervalSince1970: 1_800_000_000)
        let data = try roleCredentialsJSON(creds: RoleCreds(accessKeyId: "TEST_ACCESS", secretAccessKey: "TEST_SECRET", sessionToken: "TEST_SESSION", expiration: expiration))
        let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(json.keys) == ["Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"])
        #expect(json["Version"] as? Int == 1)
        #expect(json["AccessKeyId"] as? String == "TEST_ACCESS")
        #expect(json["SecretAccessKey"] as? String == "TEST_SECRET")
        #expect(json["SessionToken"] as? String == "TEST_SESSION")
        #expect(ISO8601DateFormatter().date(from: try #require(json["Expiration"] as? String)) == expiration)
    }

    @Test func testExternalErrorsNeverExposeTheirPayload() {
        let secret = "SECRET_SENTINEL"
        let errors: [Error] = [
            NSError(domain: secret, code: 1, userInfo: [NSLocalizedDescriptionKey: secret]),
            DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: secret)),
        ]
        for error in errors {
            #expect(!(commandError(error).localizedDescription.contains(secret)))
        }
    }

    @Test func testBiometryLockoutHasActionableSanitizedError() {
        let secret = "LOCAL_AUTH_SECRET_SENTINEL"
        let lockout = NSError(
            domain: LAError.errorDomain,
            code: LAError.Code.biometryLockout.rawValue,
            userInfo: [NSLocalizedDescriptionKey: secret]
        )
        let wrapped = NSError(
            domain: NSCocoaErrorDomain,
            code: 1,
            userInfo: [NSUnderlyingErrorKey: lockout, NSLocalizedDescriptionKey: secret]
        )

        for error in [lockout, wrapped] {
            let message = commandError(error).localizedDescription
            #expect(message == "Touch ID is locked. Lock your Mac, unlock it with your login password, then retry.")
            #expect(!message.contains(secret))
        }
    }

    @Test func testOtherLocalAuthenticationErrorsRemainGeneric() {
        let error = NSError(
            domain: LAError.errorDomain,
            code: LAError.Code.authenticationFailed.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "LOCAL_AUTH_SECRET_SENTINEL"]
        )
        let message = commandError(error).localizedDescription
        #expect(message.contains("underlying details suppressed"))
        #expect(!message.contains("LOCAL_AUTH_SECRET_SENTINEL"))
    }

    @Test func testStrictPolicyAndFreshContexts() throws {
        #expect(AuthenticationPolicy.flags == [.privateKeyUsage, .biometryCurrentSet])
        _ = try AuthenticationPolicy.accessControl()
        let first = AuthenticationPolicy.context(reason: "first")
        let second = AuthenticationPolicy.context(reason: "second")
        defer { first.invalidate(); second.invalidate() }
        #expect(!(first === second))
        #expect(first.touchIDAuthenticationAllowableReuseDuration == 0)
        #expect(second.touchIDAuthenticationAllowableReuseDuration == 0)
        #expect(first.localizedFallbackTitle == "")
        #expect(second.localizedReason == "second")
    }

    @Test func testDefaultUsesExistingAwsealLocation() throws {
        let expected = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".awseal").standardizedFileURL.resolvingSymlinksInPath()
        #expect(try StateDirectory().url == expected)
    }

    @Test func testLegacyKeyRequiresReloginWithoutRewritingRecord() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = try StateDirectory(path: directory.path)
        let old = KeyMetadata(id: UUID(), label: "consulting.hyperscale.awseal.key", createdAt: Date(), keyPersistentRef: Data(), publicKeyX963: Data())
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let bytes = try encoder.encode([old])
        let path = directory.appendingPathComponent("keys.json")
        try bytes.write(to: path)
        #expect(throws: (any Error).self) { try KeyDB(state: state) }
        #expect(throws: (any Error).self) {
            try loadCreds(profile: "missing", state: state, reason: "synthetic")
        }
        #expect(try Data(contentsOf: path) == bytes)
    }

    @Test func testCredentialNamesCannotOverwriteKeyOrConfigFiles() throws {
        let state = try StateDirectory(path: "/private/tmp/awseal-layout-test")
        #expect(try state.credentialURL(profile: "keys.json").deletingLastPathComponent().lastPathComponent == "credentials")
        #expect(throws: (any Error).self) { try state.credentialURL(profile: "../config.json") }
    }
}
