import Foundation

struct StateDirectory {
    let url: URL

    init(path: String? = nil) throws {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidate = path.map { URL(fileURLWithPath: NSString(string: $0).expandingTildeInPath) }
            ?? home.appendingPathComponent(".awseal", isDirectory: true)
        let resolved = candidate.standardizedFileURL.resolvingSymlinksInPath()
        url = resolved
    }

    func credentialURL(profile: String) throws -> URL {
        try validateProfileName(profile)
        return url.appendingPathComponent("credentials", isDirectory: true)
            .appendingPathComponent(profile)
    }
}
