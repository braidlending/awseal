import Foundation

struct StateDirectory {
    let url: URL

    init(path: String? = nil) throws {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidate = path.map { URL(fileURLWithPath: NSString(string: $0).expandingTildeInPath) }
            ?? home.appendingPathComponent(".awseal-hardened", isDirectory: true)
        let resolved = candidate.standardizedFileURL.resolvingSymlinksInPath()
        let legacy = home.appendingPathComponent(".awseal").resolvingSymlinksInPath().path
        guard resolved.path != legacy, !resolved.path.hasPrefix(legacy + "/") else {
            throw AwsealError.generic("Legacy ~/.awseal state is protected from modification. Configure a new hardened directory and re-login; do not copy keys or credential files.")
        }
        url = resolved
    }

    func credentialURL(profile: String) throws -> URL {
        try validateProfileName(profile)
        return url.appendingPathComponent("credentials", isDirectory: true)
            .appendingPathComponent(profile)
    }
}
