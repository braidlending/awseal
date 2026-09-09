# Security properties and limits

## Intended property

No fresh AWS credential lease **through the reviewed hardened awseal binary**
without an explicit human biometric authorization. This does not mean every
AWS API request requires Touch ID. `credential_process` necessarily returns
reusable temporary credentials to its caller.

The design protects encrypted SSO state at rest from arbitrary same-user
processes, and gates its decryption on a Secure Enclave private-key operation.
An unattended coding agent cannot decrypt correctly provisioned hardened state
without satisfying that operation. This claim requires the manual hardware
acceptance checks; compilation and unit tests cannot prove macOS UI behavior.

## Key policy

Before: `.privateKeyUsage + .userPresence`, accessibility
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

After: `.privateKeyUsage + .biometryCurrentSet`, accessibility
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. There is no OR with passcode,
user presence, companion/watch or other fallback constraint. Failure to create
or use this policy is an error, never a downgrade. Hiding the fallback button
is UX only; the private-key ACL supplies enforcement.

Apple's `SecAccessControl.h` documents current-set biometrics as invalidated
when fingerprints change. Adding, removing or re-enrolling fingers can require
a new key and re-login. The passcode-set accessibility constant is available
on macOS; actual CryptoKit key creation/use on each supported macOS release
must pass the integration test before this build is accepted for production.
If password/watch fallback succeeds, stop deployment and investigate.

Every decryption creates a new `LAContext`, explicitly sets
`touchIDAuthenticationAllowableReuseDuration = 0`, and invalidates it with
`defer` on success or error after the HPKE private-key operation. No context or
private key is retained across requests. Key creation has its own context and
invalidates it too. Plaintext Swift values are discarded normally; reliable
memory zeroization is not claimed.

References: [Apple's Secure Enclave guide](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[current-set flag](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset),
[accessibility](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly),
and [reuse duration](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration).
The general guide's fallback wording is broader than the specific current-set
constraint in the SDK headers; hardware acceptance must resolve UI behavior.

## State and old keys

CryptoKit reopens the opaque `PrivateKey.dataRepresentation` stored as
`keyPersistentRef` in `keys.json`; this is not a Keychain persistent-item ID.
Its supported interface does not expose a trustworthy ACL inspection facility.
An editable JSON label is not a security attestation.

This version therefore requires **re-login into a fresh directory**. It does
not migrate or delete old keys. The default directory, key label and HPKE info
string differ from upstream. Known legacy/unknown key labels are rejected.
The old directory is rejected before opening its files. These checks prevent
accidental reuse, not adversarial tampering with same-user files. Do not import
or relabel keys. The reviewed provisioning code must create the hardened key.
Fresh logins generate a new key in process. Each decrypted record retains its
verified key for re-encryption, rather than reloading an editable public key.
Key metadata additions are locked and reloaded to preserve concurrent logins.
A biometric enrollment change uses the same fresh-directory recovery process.

Legacy decrypted JSON remains decodable: the `roleCreds` field is ignored,
even if malformed. Encoding `Creds` emits only `ssoCreds`. That compatibility
does not automatically migrate legacy ciphertext or keys. New credential files
live under `credentials/`, separate from configuration/key metadata. Writes
are atomic ciphertext replacements; no plaintext credential files are created.
Concurrent issuances can still race on SSO refresh-token rotation, as upstream
could; avoid simultaneous login/issuance while recovering a profile.

The old vanilla state/binary remain usable until the user deliberately retires
them after acceptance. Consequently the machine-wide stronger policy is NOT
established merely by compiling or installing this branch. Old state/backups,
old executable paths, existing AWS caches and other credential sources must be
considered in that separate retirement review. Never delete them blindly.

## Unchanged limitations

- A malicious process can cause a prompt. Approving an unexpected or misleading
  request can give credentials to that process. Profile/account/role text is
  drawn from validated local configuration, not an authenticated caller identity.
- A caller can retain/copy issued credentials and make many AWS requests until
  they expire. Memory/environment credentials and already-issued leases remain
  usable. A compromised process holding decrypted SSO state is outside this
  at-rest guarantee.
- Browser/IdP session abuse and a new stock `aws sso login` flow outside awseal
  remain possible. awseal cannot mediate every source of AWS authentication.
- macOS/kernel/Secure Enclave compromise, source/build tampering, binary
  replacement, debugger injection into an unprotected development executable,
  and separate credential sources are outside the guarantee.
- Same-user processes can edit/delete/replay state and configuration, causing
  denial of service or misleading requests. File modes do not isolate agents
  running as the same user. Hardware ACLs do not attest the displayed role.

Caller-process reporting was omitted: it supplies no authorization boundary.
Local production use requires reviewed source, a trusted binary location and
Hardened Runtime without debugging/runtime exceptions. Ad-hoc signing is the
selected local path; it does not authenticate a developer identity. Developer
ID/notarization belong to the optional distribution workflow, not the biometric
access-control policy. Signing is
not a solution to arbitrary replacement of a user-writable executable.

## Reporting

Report security issues through [GitHub's private vulnerability reporting
feature](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
Do not publish tokens or credential-bearing logs.
