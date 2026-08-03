# frumioj/pkcs11-provider

Homebrew tap for [pkcs11-provider](https://github.com/openssl-projects/pkcs11-provider),
the OpenSSL 3.x provider that bridges PKCS#11 tokens into libcrypto.

```sh
brew tap frumioj/pkcs11-provider
brew install pkcs11-provider
```

## Why a tap

`pkcs11-provider` is not in homebrew-core. It comfortably clears Homebrew's
notability bar (120 stars, 73 forks at the time of writing) and now lives under
the `openssl-projects` organisation, so the likely reason is simply that nobody
has submitted it — its centre of gravity is Linux, where Fedora and RHEL package
it natively.

Homebrew does ship `libp11`, which provides the **deprecated** ENGINE-based
bridge. So without this tap, Homebrew serves the obsolete path to
OpenSSL/PKCS#11 and not the current one.

## The one wrinkle

Upstream installs into libcrypto's pkg-config `modulesdir`, which is inside the
`openssl@3` keg — and a formula may not write into another formula's keg. The
module therefore lands in this formula's own prefix and must be named
explicitly in `openssl.cnf`. `brew info` prints the exact stanza.

## Verified

`brew test` initialises a real SoftHSM token, generates an EC key inside it,
signs through the provider, and verifies the signature with the default
provider alone — so the check is performed by code that never loaded the token.

One thing that test deliberately avoids: `openssl dgst -sign`. SoftHSM
advertises `CKM_ECDSA_SHA256`, which sends the provider down the streaming
`C_SignUpdate` path, and that combination fails. `pkeyutl -sign` over a
precomputed digest works. That is an interaction between those two projects
rather than anything this formula controls, and tokens that advertise only
`CKM_ECDSA` are unaffected.
