# awseal (organization fork)

Use your organization’s AWS access from your Mac with Touch ID. `awseal`
keeps your AWS IAM Identity Center session encrypted under a Secure Enclave
key and supplies short-lived credentials to the AWS CLI and SDKs through
`credential_process`.

Each credential issuance requires Touch ID. The CLI or SDK can reuse issued
credentials until they expire, so **not every AWS command produces a prompt**.
Only approve a prompt when you recognize the profile, account and role.

## Before you start

You need:

- A Mac running macOS 14 or later, with Secure Enclave and Touch ID enrolled.
- Swift 6 or later and Apple’s developer tools. A complete Xcode toolchain is
  needed to run the Swift Testing suite.
- AWS CLI v2 and Git.
- Access to your organization’s AWS access portal (the IAM Identity Center
  start URL). Get it from the person onboarding you; do not commit it here.
- The AWS account ID, permission-set/role name and Identity Center region for
  your assigned access. Confirm these with the person onboarding you; the
  account ID below is an example, not a real account.

Start with read-only access when that is sufficient. Installing awseal does not
request or grant additional AWS permissions.

## 1. Build and install this fork

Clone this fork, not the upstream Homebrew package:

```sh
git clone https://github.com/braidlending/awseal.git
cd awseal
swift --version
aws --version
```

Review the source revision you are installing. The following builds locally,
enables Hardened Runtime with an ad-hoc signature, and installs a versioned
copy under `~/.local/lib/awseal/releases`. It does not require Apple signing
credentials or notarization. It does not log you into AWS.

Run from the repository root:

```sh
(
  set -eu
  awseal_build_dir=$(mktemp -d /private/tmp/awseal-build.XXXXXX)
  swift build -c release --scratch-path "$awseal_build_dir"
  awseal_candidate="$awseal_build_dir/release/awseal"
  codesign --force --sign - --options runtime --timestamp=none "$awseal_candidate"
  codesign --verify --strict "$awseal_candidate"

  awseal_version=$("$awseal_candidate" --version)
  awseal_hash=$(shasum -a 256 "$awseal_candidate" | awk '{print $1}')
  awseal_install_dir="$HOME/.local/lib/awseal/releases/$awseal_version-$awseal_hash"
  mkdir -p "$awseal_install_dir" "$HOME/.local/bin"
  if [ -e "$awseal_install_dir/awseal" ]; then
    cmp "$awseal_candidate" "$awseal_install_dir/awseal"
  else
    install -m 755 "$awseal_candidate" "$awseal_install_dir/awseal"
  fi
  codesign --verify --strict "$awseal_install_dir/awseal"

  if [ -e "$HOME/.local/bin/awseal" ] && [ ! -L "$HOME/.local/bin/awseal" ]; then
    echo 'An existing non-symlink awseal needs to be backed up before activation.' >&2
    exit 1
  fi
  awseal_link="$HOME/.local/bin/.awseal-link-$$"
  ln -s "$awseal_install_dir/awseal" "$awseal_link"
  mv -f "$awseal_link" "$HOME/.local/bin/awseal"
  "$HOME/.local/bin/awseal" --version
)
```

Ensure your shell’s PATH includes `~/.local/bin` before other awseal locations.
For the current shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
command -v awseal
awseal --version
```

Add that PATH setting to your shell startup file if needed. The command should
resolve to `~/.local/bin/awseal`. **Do not link it into `.build`**: rebuilding or
cleaning a checkout must not change your installed executable. Keep previous
installed versions available for rollback.

These instructions are for a locally built binary. Downloaded, unnotarized
artifacts on other Macs may encounter Gatekeeper restrictions; do not disable
Gatekeeper to install them.

## 2. Configure your AWS profiles

awseal uses `~/.awseal/config.json`. If you already used vanilla awseal, follow
[the upgrade instructions below](#upgrading-from-vanilla-awseal) first. For a
new installation, create the private directory:

```sh
mkdir -p ~/.awseal
chmod 700 ~/.awseal
```

Create or edit `~/.awseal/config.json`, preserving any existing profiles. Use
this example as a template and replace the example account/region/role with
your assigned values:

```json
{
  "dev-readonly": {
    "ssoStartUrl": "https://example.awsapps.com/start",
    "ssoRegion": "us-east-2",
    "region": "us-east-2",
    "accountId": "123456789012",
    "roleName": "ReadOnlyAccess"
  }
}
```

```sh
chmod 600 ~/.awseal/config.json
```

| Field | Meaning |
| --- | --- |
| Profile name (`dev-readonly`) | The name passed to `awseal --profile`; choose a recognizable name |
| `ssoStartUrl` | Your organization’s AWS access portal (Identity Center start) URL |
| `ssoRegion` | Region where your Identity Center instance is configured |
| `region` | Default AWS service region to use in your AWS CLI profile |
| `accountId` | The 12-digit AWS account ID you are authorized to access |
| `roleName` | The exact permission-set/role name used for Identity Center access |

Profile names allow up to 64 ASCII letters, digits, dots, underscores and
hyphens. Role names allow up to 64 characters using the IAM role-name character
set. Add additional accounts or roles as separate profiles; never put access
keys, session tokens or passwords in this configuration.

## 3. Log in

```sh
awseal login --profile dev-readonly
```

Complete the browser authorization for your organization’s AWS portal. New
logins create hardened keys and store encrypted SSO state. Each awseal
profile has its own login; logging into one profile does not initialize the
others.

Use `awseal login` to renew your session. **Do not run `aws sso login`** for
these profiles: that creates a separate AWS CLI SSO credential source outside
awseal’s protected state.

## 4. Connect the AWS CLI and SDKs

Add the following section to `~/.aws/config`, or update the corresponding
existing section without replacing the rest of the file. Replace `YOUR_USER`
with your macOS username; use the absolute installed path.

```ini
[profile dev-readonly]
region = us-east-2
credential_process = /Users/YOUR_USER/.local/bin/awseal fetch-role-creds --profile dev-readonly
```

The AWS profile can have a different name, but the `--profile` argument must
match a name in awseal’s `config.json`. For an existing profile, do not leave
competing `sso_*`, static credentials or a direct role-assumption configuration
in the same profile. Preserve intentional role chains in separate profiles.
Never paste temporary AWS credentials into `~/.aws/credentials`.

To verify the setup:

```sh
aws sts get-caller-identity --profile dev-readonly
```

Check the Touch ID prompt before approving it. It should identify the requested
profile, account and role, for example:

```text
AWS credentials: dev-readonly
Account 123456789012
Role ReadOnlyAccess
```

The command should return the expected AWS account and assumed role. Cancelling
the prompt should make the command fail. A new CLI invocation that needs
credentials should require another fingerprint approval, even after recently
unlocking the Mac with Touch ID.

For SDKs and other tools that support shared AWS configuration:

```sh
export AWS_PROFILE=dev-readonly
```

Some SDKs require their shared-config option to be enabled. Remove inherited
AWS credential environment variables when troubleshooting: they may take
precedence over your selected profile. Never print those variables or use
`--debug` when sharing authentication diagnostics.

## Everyday use and troubleshooting

- **Session expired:** run `awseal login --profile <name>` and complete browser
  authorization again.
- **Touch ID is locked:** lock the Mac, unlock it with the login password, then
  retry. awseal reports this condition directly and does not offer a password
  fallback for decrypting an existing key.
- **Unexpected Touch ID prompt:** cancel it. A process can request a prompt;
  the displayed profile does not authenticate the calling process.
- **Profile not found:** check the name in `~/.awseal/config.json` and the
  `--profile` argument in your AWS configuration.
- **Legacy or unknown key policy:** use the upgrade procedure below. Changing
  a key’s label does not change its protection.
- **Touch ID enrollment changed:** adding/removing fingerprints can invalidate
  existing keys. Back up the current state, create fresh configuration and
  re-login. There is no convenience password fallback.
- **No prompt or wrong account:** check `command -v awseal`, the configured
  `credential_process` path and competing AWS credential sources. Confirm the
  returned identity before doing work.

Do not invoke `awseal fetch-role-creds` directly in a terminal: it prints live
credentials for consumption by AWS tooling. Do not share state files or token
contents. For support, provide the awseal version, macOS version, profile name
and a description of the failure, with sensitive values removed.

## Upgrading from vanilla awseal

**The binary does not automatically back up or migrate your state.** Old
Secure Enclave keys retain their original policy and are refused by this
version. Re-login is required.

Before continuing, stop commands using awseal. Preserve the current installed
binary and rename `~/.awseal` to a unique dated backup, for example
`~/.awseal.pre-hardening-YYYYMMDD-HHMMSS`. Create a fresh `~/.awseal` with mode
700 and carry over **only the non-secret `config.json`**, with mode 600. Do not
copy `keys.json` or encrypted credential records into the new directory.
Then follow the login and AWS verification steps above for each profile.

Keep the backup until you have reviewed the new setup. It still contains
legacy protected state and must be considered when retiring old credential
sources. Rollback requires restoring both the old binary and its state, not
just changing the executable symlink.

## Security and development

awseal protects SSO state at rest and requires a biometric operation to obtain
new credentials through its hardened flow. It cannot stop a caller from
retaining credentials after approval, prevent browser/IdP abuse, or defend
against a compromised OS or replaced binary. See [SECURITY.md](SECURITY.md).

Contributors with a complete macOS test toolchain can run:

```sh
swift test --scratch-path /private/tmp/awseal-tests
```

Tests use synthetic records; the real Touch ID test is opt-in.

Forked from [hyperscale-consulting/awseal](https://github.com/hyperscale-consulting/awseal).
MIT licensed; see [LICENSE](LICENSE).
