# awseal — Touch ID credential issuance

A macOS 14+ `credential_process` for AWS IAM Identity Center. This hardening
branch starts from upstream `49cf00ed9fbd049de5a90cf335c67a0488cbbd0e`
(`v0.3.1` plus two commits). It retains CryptoKit Secure Enclave P-256 and HPKE.

**Local hardened release: review the acceptance record and limitations before use.**
Hardware acceptance remains required. This Mac can use an ad-hoc-signed local
release with Hardened Runtime, without notarization.
See [SECURITY.md](SECURITY.md) for the guarantees and limitations.

## Build and test

Requires Swift 6 and a macOS developer toolchain with Swift Testing support.
Never use the default `.build` here if an installed binary points into it.

```sh
swift build --scratch-path /private/tmp/awseal-hardened-debug
swift test --scratch-path /private/tmp/awseal-hardened-debug
swift build -c release --scratch-path /private/tmp/awseal-hardened-release
/private/tmp/awseal-hardened-release/release/awseal --version
```

These commands do not install the executable. Automated tests use synthetic
records and do not call AWS or create/use Secure Enclave keys.
The project has no configured formatter or linter.

## Replace existing state after review

The hardened executable defaults to `~/.awseal`. On its first use with legacy
state present, it renames that directory to a dated backup, creates a fresh
`~/.awseal`, and carries forward only non-secret `config.json` profile
configuration. It never migrates keys, encrypted session records, or role
credentials. Known legacy key records are refused before any write, so re-login
creates a new hardened key. Keep the dated backup intact; do not copy its keys
or encrypted records into the fresh directory.

Each subcommand also accepts `--state-dir /absolute/path/to/a/new/directory`
for an isolated state directory, including tests. Create only a new
`config.json` with non-secret profile configuration:

```json
{
  "prod-admin": {
    "ssoStartUrl": "https://example.awsapps.com/start",
    "ssoRegion": "us-east-2",
    "region": "us-east-2",
    "accountId": "123456789012",
    "roleName": "AdministratorAccess"
  }
}
```

Profile names allow up to 64 ASCII letters, digits, dots, underscores and
hyphens. Account IDs have 12 digits; role names use the IAM role-name character
set and maximum of 64 characters. Controls and bidirectional formatting are
rejected before constructing the prompt. `ssoRegion` selects both SSO APIs;
`region` remains available for your AWS service configuration.

Run the separately built binary's `login --profile prod-admin` when ready for
the browser and Touch ID acceptance tests. Use `--state-dir ...` only when an
isolated test state is intended. Login stores only SSO client/token state
encrypted on disk. Each `fetch-role-creds` invocation opens a fresh zero-reuse
authentication context, decrypts SSO state, obtains role credentials and
returns AWS JSON. Role credentials are never serialized to the protected
state. SDK logging is disabled and underlying errors are suppressed to avoid
exposing response contents. Login alone prints the browser authorization
URL/code; it does not print SSO bearer or role credentials.

The prompt is:

```text
AWS credentials: prod-admin
Account 123456789012
Role AdministratorAccess
```

Do not run `fetch-role-creds` into a terminal. Let the AWS CLI/SDK consume its
output using a temporary configuration as described in the integration plan.
Do not change existing AWS profiles until the hardened artifact is approved.

## Installed shell entry point

The shell default uses
a versioned installed copy of hardened 0.4.0-hardening.1, not this checkout's
`.build`. Core local acceptance passed and activation was explicitly approved.
Existing profiles require fresh login after `~/.awseal` is replaced with the
new hardened state directory.

## Release

Release procedures cover local ad-hoc signing with Hardened
Runtime, plus an optional Developer ID/notarization distribution workflow. The manual CI workflow produces only
unsigned/ad-hoc development artifacts. It does not publish releases.

MIT licensed; see [LICENSE](LICENSE). The maintained fork is [braidlending/awseal](https://github.com/braidlending/awseal).
