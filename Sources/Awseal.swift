import ArgumentParser
import AWSSSO
import AWSSSOOIDC
import Foundation
import CryptoKit
import LocalAuthentication
import Security
import Darwin

enum AwsealError: Error, LocalizedError {
    case generic(String)
    case keyAlreadyExists
    case clientRegistration(String)
    case notLoggedIn

    var errorDescription: String? {
        switch self {
            case .generic(let s): return s
            case .keyAlreadyExists: return "Attempt to generate key that already exists"
            case .clientRegistration(let s): return "Unable to register client \(s)"
            case .notLoggedIn: return "No active SSO credentials found, please run `awseal login` to login."
        }
    }
}

struct EnclaveKeyManager {

    static func generateKey(label: String) throws -> KeyMetadata {
        let la = AuthenticationPolicy.context(reason: "Create awseal Touch ID key")
        defer { la.invalidate() }

        let ac = try AuthenticationPolicy.accessControl()
        let priv = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: ac,
            authenticationContext: la
        )

        let persistentRef = priv.dataRepresentation
        let pubX963 = priv.publicKey.x963Representation

        return KeyMetadata(
            id: UUID(),
            label: label,
            createdAt: Date(),
            keyPersistentRef: persistentRef,
            publicKeyX963: pubX963
        )
    }

    static func openPrivateKey(_ md: KeyMetadata, context: LAContext) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: md.keyPersistentRef,
            authenticationContext: context
        )
    }
}

struct KeyMetadata: Codable {
    let id: UUID
    var label: String
    let createdAt: Date
    let keyPersistentRef: Data
    let publicKeyX963: Data
}

final class KeyDB {
    private let fileURL: URL
    private let lockURL: URL
    private var items: [KeyMetadata] = []

    init(state: StateDirectory) throws {
        let dir = state.url
        self.fileURL = dir.appendingPathComponent("keys.json", isDirectory: false)
        self.lockURL = dir.appendingPathComponent("keys.lock", isDirectory: false)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try load()
    }

    private func load() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            self.items = []
            return
        }
        let data = try Data(contentsOf: fileURL)
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        dec.dataDecodingStrategy = .base64
        self.items = try dec.decode([KeyMetadata].self, from: data)
        guard items.allSatisfy({ $0.label == keyLabel }) else {
            throw AwsealError.generic("Legacy or unknown key policy. Re-login in a new hardened state directory; keep old state intact.")
        }
    }

    private func save() throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        enc.dataEncodingStrategy = .base64
        let data = try enc.encode(items)
        try data.write(to: fileURL, options: [.atomic])
    }

    func list() -> [KeyMetadata] { items }

    func add(_ item: KeyMetadata) throws {
        // Concurrent first logins must not overwrite one another's key records.
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw AwsealError.generic("Unable to lock key database.") }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw AwsealError.generic("Unable to lock key database.") }
        defer { flock(descriptor, LOCK_UN) }
        try load()
        if items.contains(where: { $0.id == item.id }) {
            throw AwsealError.keyAlreadyExists
        }
        items.append(item)
        try save()
    }

    func resolve(_ id: UUID) -> KeyMetadata? {
        return items.first { $0.id == id }
    }
}

struct Envelope: Codable {
    let version: Int = 1
    let keyId: UUID
    let encapsulatedKey: Data
    let ciphertext: Data

    private enum CodingKeys: String, CodingKey {
        case keyId, encapsulatedKey, ciphertext
    }
}

let keyLabel = "awseal.biometry-current-set.v1"
let protocolInfo = "awseal hardened SSO state v1".data(using: .utf8)!
let ciphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256

func genKey(state: StateDirectory) throws -> KeyMetadata {
    let db = try KeyDB(state: state)
    let md = try EnclaveKeyManager.generateKey(label: keyLabel)
    try db.add(md)
    return md
}

func saveEncrypted(plaintext: Data, to: URL, key md: KeyMetadata) throws {
    let enclavePub = try P256.KeyAgreement.PublicKey(x963Representation: md.publicKeyX963)
    var hpke = try HPKE.Sender(recipientKey: enclavePub, ciphersuite: ciphersuite, info: protocolInfo)
    let ciphertext = try hpke.seal(plaintext)
    let encapsulatedKey = hpke.encapsulatedKey

    let env = Envelope(
        keyId: md.id,
        encapsulatedKey: encapsulatedKey,
        ciphertext: ciphertext
    )

    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    enc.dataEncodingStrategy = .base64
    let out = try enc.encode(env)
    try out.write(to: to, options: [.atomic])
}

func loadDecrypted(from: URL, state: StateDirectory, reason: String) throws -> (data: Data, key: KeyMetadata) {
    let recoveryInstructions = "Re-login in a new hardened state directory. Do not delete existing keys or state."
    let db = try KeyDB(state: state)
    let envelopeData = try Data(contentsOf: from)
    let dec = JSONDecoder()
    dec.dataDecodingStrategy = .base64
    let envelope = try dec.decode(Envelope.self, from: envelopeData)

    guard let md = db.resolve(envelope.keyId) else {
        throw AwsealError.generic("Envelope key not found. \(recoveryInstructions)")
    }

    let context = AuthenticationPolicy.context(reason: reason)
    defer { context.invalidate() }
    let priv = try EnclaveKeyManager.openPrivateKey(md, context: context)
    // Never re-encrypt SSO tokens to a replaceable, unverified public key.
    guard priv.publicKey.x963Representation == md.publicKeyX963 else {
        throw AwsealError.generic("Key metadata mismatch. Refusing to access or rewrite state.")
    }

    var hpke = try HPKE.Recipient(
        privateKey: priv,
        ciphersuite: ciphersuite,
        info: protocolInfo,
        encapsulatedKey: envelope.encapsulatedKey
    )
    let plaintext = try hpke.open(envelope.ciphertext)

    return (plaintext, md)
}

struct AWSEALProfile: Codable {
    let ssoStartUrl: String
    let roleName: String
    let accountId: String
    let region: String
    let ssoRegion: String
}

struct AWSEALConfig: Codable {
    let profiles: [String: AWSEALProfile]

    static func load(from url: URL) throws -> AWSEALConfig {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        let rawProfiles = try decoder.decode([String: AWSEALProfile].self, from: data)
        return AWSEALConfig(profiles: rawProfiles)
    }

    func profile(named name: String) throws -> AWSEALProfile {
        guard let profile = profiles[name] else {
            throw AwsealError.generic("Profile \(name) not found")
        }
        return profile
    }
}

func loadConfig(state: StateDirectory) throws -> AWSEALConfig {
    try AWSEALConfig.load(from: state.url.appendingPathComponent("config.json"))
}

struct Creds: Codable {
    var ssoCreds: SsoCreds
    // Retain the exact key proven by decryption; never reload a replacement
    // public key from disk while plaintext tokens are in memory.
    var encryptionKey: KeyMetadata? = nil

    private enum CodingKeys: String, CodingKey { case ssoCreds }
}

struct RoleCreds {
    var accessKeyId: String
    var secretAccessKey: String
    var sessionToken: String
    var expiration: Date
}

struct SsoCreds: Codable {
    var clientId: String
    var clientSecret: String
    var accessToken: String?
    var refreshToken: String?
}

func ssoLogin(
    oidc: SSOOIDCClient,
    profile: String,
    ssoCreds: SsoCreds,
    ssoStartUrl: String
) async throws -> SsoCreds {
    let startDeviceAuthorizationInput = StartDeviceAuthorizationInput(
        clientId: ssoCreds.clientId, clientSecret: ssoCreds.clientSecret, startUrl: ssoStartUrl
    )
    let resp = try await oidc.startDeviceAuthorization(input: startDeviceAuthorizationInput)

    guard
        let deviceCode = resp.deviceCode,
        let userCode = resp.userCode
    else {
        throw AwsealError.generic("Missing required fields in device authorization response")
    }

    let expiresIn = resp.expiresIn
    let verificationUri = resp.verificationUri
    let verificationUriComplete = resp.verificationUriComplete
    let interval = resp.interval

    print("""
    To complete SSO login, open the following URL in your browser and confirm / enter the code (\(userCode)) if required:

      \(verificationUriComplete ?? verificationUri ?? "<no verification URL>")
    """)

    if let urlString = verificationUriComplete ?? verificationUri,
       let url = URL(string: urlString) {
        _ = try? Process.run(URL(fileURLWithPath: "/usr/bin/open"), arguments: [url.absoluteString])
    }

    let start = Date()
    while Date().timeIntervalSince(start) < Double(expiresIn) {
        do {
            let createTokenInput = CreateTokenInput(
                clientId: ssoCreds.clientId,
                clientSecret: ssoCreds.clientSecret,
                deviceCode: deviceCode,
                grantType: "urn:ietf:params:oauth:grant-type:device_code"
            )
            let tok = try await oidc.createToken(
                input: createTokenInput
            )

            if let accessToken = tok.accessToken {
                var updatedCreds = ssoCreds
                updatedCreds.accessToken = accessToken
                if let refreshToken = tok.refreshToken {
                    updatedCreds.refreshToken = refreshToken
                }
                return updatedCreds
            }
        } catch is AuthorizationPendingException, is SlowDownException {
            try await Task.sleep(nanoseconds: UInt64(interval) * 1_000_000_000)
            continue
        } catch {
            throw error
        }
    }
    throw AwsealError.generic("Device authorization timed out.")
}

func loadCreds(profile: String, state: StateDirectory, reason: String) throws -> Creds? {
    let fileURL = try state.credentialURL(profile: profile)
    guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
    let decrypted = try loadDecrypted(from: fileURL, state: state, reason: reason)
    // Synthesized Decodable deliberately ignores the legacy roleCreds field.
    var creds = try JSONDecoder().decode(Creds.self, from: decrypted.data)
    creds.encryptionKey = decrypted.key
    return creds
}

func saveCreds(profile: String, creds: Creds, state: StateDirectory) throws {
    let fileURL = try state.credentialURL(profile: profile)
    try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(),
        withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let data = try JSONEncoder().encode(creds)
    // New logins provision their own key rather than trusting an imported key.
    let key = try creds.encryptionKey ?? genKey(state: state)
    try saveEncrypted(plaintext: data, to: fileURL, key: key)
}

func registerClient(oidc: SSOOIDCClient, profile: String) async throws -> SsoCreds {
    let input = RegisterClientInput(
        clientName: "awseal-\(profile)",
        clientType: "public",
        grantTypes: [
            "urn:ietf:params:oauth:grant-type:device_code",
            "refresh_token",
        ],
        scopes: ["sso:account:access"]
    )
    let resp = try await oidc.registerClient(input: input)

    guard let clientId = resp.clientId else {
        throw AwsealError.clientRegistration("no clientId returned")
    }
    guard let clientSecret = resp.clientSecret else {
        throw AwsealError.clientRegistration("no clientSecret returned")
    }
    let ssoCreds = SsoCreds(clientId: clientId, clientSecret: clientSecret)

    return ssoCreds
}

func refreshAccessToken(profile: String, oidc: SSOOIDCClient, ssoCreds: SsoCreds) async throws -> (String, String) {
    guard let refreshToken = ssoCreds.refreshToken else {
        throw AwsealError.notLoggedIn
    }
    let createTokenInput = CreateTokenInput(
        clientId: ssoCreds.clientId,
        clientSecret: ssoCreds.clientSecret,
        grantType: "refresh_token",
        refreshToken: refreshToken
    )
    do {
        let tok = try await oidc.createToken(
            input: createTokenInput
        )

        if let accessToken = tok.accessToken {
            var updatedCreds = ssoCreds
            updatedCreds.accessToken = accessToken
            if let refreshToken = tok.refreshToken {
                updatedCreds.refreshToken = refreshToken
            }
            return (accessToken, updatedCreds.refreshToken ?? refreshToken)
        }
        throw AwsealError.notLoggedIn
    } catch is ExpiredTokenException {
        throw AwsealError.notLoggedIn
    }
}

func getRoleCreds(sso: SSOClient, accessToken: String, accountId: String, roleName: String) async throws -> RoleCreds {
    let input = GetRoleCredentialsInput(accessToken: accessToken, accountId: accountId, roleName: roleName)
    let response = try await sso.getRoleCredentials(input: input)
    guard let roleCreds = response.roleCredentials,
          let accessKeyId = roleCreds.accessKeyId,
          let secretAccessKey = roleCreds.secretAccessKey,
          let sessionToken = roleCreds.sessionToken,
          !accessKeyId.isEmpty, !secretAccessKey.isEmpty, !sessionToken.isEmpty,
          roleCreds.expiration > 0 else {
        throw AwsealError.notLoggedIn
    }

    let expiration = Date(timeIntervalSince1970: TimeInterval(roleCreds.expiration / 1000))
    return RoleCreds(
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
        sessionToken: sessionToken,
        expiration: expiration
    )
}

func fetchRoleCreds(
    profile: String, state: StateDirectory, oidc: SSOOIDCClient, sso: SSOClient, accountId: String, roleName: String
) async throws -> RoleCreds {

    guard var creds = try loadCreds(profile: profile, state: state,
        reason: authenticationReason(profile: profile, account: accountId, role: roleName)) else {
        throw AwsealError.notLoggedIn
    }

    guard let accessToken = creds.ssoCreds.accessToken else {
        throw AwsealError.notLoggedIn
    }

    var roleCreds: RoleCreds
    do {
        roleCreds = try await getRoleCreds(
            sso: sso,
            accessToken: accessToken,
            accountId: accountId,
            roleName: roleName
        )
    } catch is UnauthorizedException {
        let (accessToken, refreshToken) = try await refreshAccessToken(
            profile: profile,
            oidc: oidc,
            ssoCreds: creds.ssoCreds
        )
        creds.ssoCreds.accessToken = accessToken
        creds.ssoCreds.refreshToken = refreshToken
        // Preserve token rotation even if the subsequent role request fails.
        try saveCreds(profile: profile, creds: creds, state: state)
        return try await getRoleCreds(
            sso: sso,
            accessToken: accessToken,
            accountId: accountId,
            roleName: roleName
        )
    }
    try saveCreds(profile: profile, creds: creds, state: state)
    return roleCreds
}

func roleCredentialsJSON(creds: RoleCreds) throws -> Data {
    struct RoleCredsOutput: Codable {
        let version: Int
        let accessKeyId: String
        let secretAccessKey: String
        let sessionToken: String
        let expiration: String

        enum CodingKeys: String, CodingKey {
            case version = "Version"
            case accessKeyId = "AccessKeyId"
            case secretAccessKey = "SecretAccessKey"
            case sessionToken = "SessionToken"
            case expiration = "Expiration"
        }
    }

    let output = RoleCredsOutput(
        version: 1,
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        sessionToken: creds.sessionToken,
        expiration: ISO8601DateFormatter().string(from: creds.expiration)
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted]

    return try encoder.encode(output)
}

@main
struct Awseal: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "An AWS CLI credential_process using AWS SSO to mint credentials while storing secrets under a Secure Enclave key.",
        version: "0.4.0-hardening",
        subcommands: [Login.self, FetchRoleCreds.self]
    )
}

struct Options: ParsableArguments {
    @Option(name: [.long, .customShort("p")], help: "The profile to use.")
    var profile = "default"

    @Option(name: .long, help: "Isolated hardened state directory (default: ~/.awseal-hardened). Never use ~/.awseal.")
    var stateDir: String?
}

extension Awseal {
    struct Login: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Login to AWS SSO."
        )

        @OptionGroup var options: Options

        func run() async throws {
            do { try await execute() }
            catch { throw commandError(error) }
        }

        private func execute() async throws {
            _ = SDKLogging.disabled
            let state = try StateDirectory(path: options.stateDir)
            try validateProfileName(options.profile)
            let config = try loadConfig(state: state)
            let profileConfig = try config.profile(named: options.profile)
            try validateAuthority(account: profileConfig.accountId, role: profileConfig.roleName)
            _ = try KeyDB(state: state)
            let oidc = try await SSOOIDCClient(config: .init(
                ignoreConfiguredEndpointURLs: true, region: profileConfig.ssoRegion, clientLogMode: .some(.none)))
            var creds: Creds
            if let existing = try loadCreds(profile: options.profile, state: state,
                reason: authenticationReason(profile: options.profile, account: profileConfig.accountId, role: profileConfig.roleName)) {
                creds = existing
            } else {
                let ssoCreds = try await registerClient(oidc: oidc, profile: options.profile)
                creds = Creds(ssoCreds: ssoCreds)
            }

            var ssoCreds: SsoCreds
            do {
                ssoCreds = try await ssoLogin(
                    oidc: oidc,
                    profile: options.profile,
                    ssoCreds: creds.ssoCreds,
                    ssoStartUrl: profileConfig.ssoStartUrl
                )
            } catch is InvalidClientException, is UnauthorizedException {
                ssoCreds = try await registerClient(oidc: oidc, profile: options.profile)
                creds = Creds(ssoCreds: ssoCreds)
                ssoCreds = try await ssoLogin(
                    oidc: oidc,
                    profile: options.profile,
                    ssoCreds: creds.ssoCreds,
                    ssoStartUrl: profileConfig.ssoStartUrl
                )
            }
            creds.ssoCreds = ssoCreds
            try saveCreds(profile: options.profile, creds: creds, state: state)
        }
    }

    struct FetchRoleCreds: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Fetch and print role credentials for AWS CLI credential_process use."
        )

        @OptionGroup var options: Options

        func run() async throws {
            do { try await execute() }
            catch { throw commandError(error) }
        }

        private func execute() async throws {
            _ = SDKLogging.disabled
            let state = try StateDirectory(path: options.stateDir)
            try validateProfileName(options.profile)
            let config = try loadConfig(state: state)
            let profileConfig = try config.profile(named: options.profile)
            try validateAuthority(account: profileConfig.accountId, role: profileConfig.roleName)
            let oidc = try await SSOOIDCClient(config: .init(
                ignoreConfiguredEndpointURLs: true, region: profileConfig.ssoRegion, clientLogMode: .some(.none)))
            let sso = try await SSOClient(config: .init(
                ignoreConfiguredEndpointURLs: true, region: profileConfig.ssoRegion, clientLogMode: .some(.none)))
            let creds = try await fetchRoleCreds(
                profile: options.profile,
                state: state,
                oidc: oidc,
                sso: sso,
                accountId: profileConfig.accountId,
                roleName: profileConfig.roleName
            )
            let output = try roleCredentialsJSON(creds: creds)
            FileHandle.standardOutput.write(output)
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }

}
