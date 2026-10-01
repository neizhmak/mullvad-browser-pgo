# Signed automatic updates: preparation, not deployment

This project is unofficial. Public publication is deferred until the intended
platforms and a newer upstream release are ready. This document prepares only
the locked **Alpha Windows x86_64** installer and portable browser payload.
There is no project update server, publisher signing key, custom certificate
embedding, signed PGO MAR release, or deployed PGO update feed in this change.

`config/update-settings.example.json` is an **offline planning manifest**.
Neither Firefox nor RBM reads it. It is not Firefox's `update-settings.ini`,
and validating it does not activate automatic updates. No workflow consumes
it. `publication_enabled` must remain `false`; the validator cannot authorize
publication or claim that an updater works.

## Safe interim decision

Keep the upstream updater enabled, its official certificates intact, and its
Alpha update URL and accepted MAR ID unchanged. This is the safest available
security-update route while an independently signed PGO feed does not exist.

**An official update can replace the unofficial PGO executables with official
non-PGO executables.** A normal upstream partial MAR is computed against an
official source build, not these PGO binaries. It can fail, then fall back to the
signed complete MAR. Do not advertise continuing PGO optimization after an
upstream update. Test the complete-update path from the actual PGO installer
and portable layouts before relying on it. This preparation does not prove
that update application succeeds.

If retaining PGO across every update is essential, a publisher-operated,
signed track is required. Until it exists, do not disable security updates or
point the browser at unsigned custom archives. For regular browsing, the
supported official release is safer than an old, unmaintained unofficial
Alpha build. The lock is a build pin, not proof that a release is still current.

## Exact upstream controls

The build source is `mb-16.0a9-build1`, commit
`7dd751cf1837d667908b339aebf82567ece55e20`. Its Firefox input is
`mullvad-browser-153.0esr-16.0-1-build2`; the inspected browser source commit is
`a8a167fe41226f38158d8e169623e95a1bff846a`.

| Control | Locked Alpha Windows build |
| --- | --- |
| RBM updater switch | `var/updater_enabled: 1` |
| Firefox options | `--enable-updater`, `--enable-base-browser-update`, `--enable-update-channel=alpha` |
| RBM Firefox base URL | `https://cdn.mullvad.net/browser/update_responses/update_1/` |
| Build option for that base | `--with-updater-url=...` -> `BB_UPDATER_URL` |
| Compiled URL template | `BB_UPDATER_URL/%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL` |
| Current Windows build target in responses | `WINNT_x86_64-gcc3-x64` -> `windows-x86_64` |
| Version token | `AppConstants.BASE_BROWSER_VERSION`, here `16.0a9`, not Firefox's `153.0` |
| MAR product channel | `mullvadbrowser-mullvad-alpha` |
| Accepted channel list | exactly `mullvadbrowser-mullvad-alpha` |
| MAR crypto implementation on Windows | `--enable-nss-mar` |
| Windows maintenance service | disabled upstream |
| Separate OS background update agent | disabled upstream |

`alpha` is the browser/update-response channel. It is **not** the full MAR
channel ID. `MAR_CHANNEL_ID` and `ACCEPTED_MAR_CHANNEL_IDS` are exported by
`projects/firefox/mozconfig.in`. On Windows, the updater reads
`[Settings] ACCEPTED_MAR_CHANNEL_IDS=...` from the packaged
`Browser/update-settings.ini`. The native check requires an exact match with
one of the listed IDs. An empty accepted value skips the channel check; it is
not permitted by this design. There are no wildcard channels.

### `app.update.url` is not the configuration mechanism

The old `app.update.url` preference was removed. Setting it in `about:config`
or a default preference file does not configure this updater. The current
`UpdateService.sys.mjs` reads `Services.appinfo.updateURL`; the
`AppUpdateURL` enterprise policy can override that value. The template is
compiled from `build/application.ini.in` into application data. Editing the
shipped `application.ini` alone also does not change normal startup's compiled
application data. Set the URL in the build through `--with-updater-url` and
inspect the effective binary value.

For the current build a foreground check is equivalent to:

```text
https://cdn.mullvad.net/browser/update_responses/update_1/alpha/WINNT_x86_64-gcc3-x64/16.0a9/ALL?force=1
```

Periodic checks happen while the browser runs. The upstream Windows build
explicitly disables the standalone update agent, so this does not promise
updates while the browser is closed. Automatic download/apply also depends on
user settings and write access. Keep the existing non-service, user-writable
installation model; do not add privileged update execution to avoid a Windows
permission error. Test a read-only directory as a negative case.

## MAR integrity is mandatory; Authenticode is separate

A MAR is the updater's package, not an installer `.exe`, portable `.exe`, ZIP,
or a checksum file. `make_full_update.sh` and `make_incremental_update.sh`
create **unsigned** MARs with product/version headers. The official signing
stage signs them separately using NSS `signmar`. The inspected implementation
uses **RSA with SHA-384**. The official nightly key-management script selects
4096-bit RSA. A MAR signing certificate is an X.509 public DER certificate
pinned into the updater, not a requirement for a paid WebPKI certificate.

The publisher must protect the matching private key in its NSS database or
supported protected signing system. It must never be committed, embedded in
binaries, included in a portable package, uploaded as a workflow artifact, or
passed in an update URL. An NSS database that contains only a public certificate
is sufficient for an independent verification job; it cannot sign updates.

The official signing wrapper's relevant interface is:

```sh
# Only on a protected signer with an existing, authorized key:
signmar -d "$NSS_DB_DIR" -n "$NSS_CERTNAME" -s unsigned.mar signed.mar
# In a separate verifier with only the expected PUBLIC certificate:
signmar -d "$PUBLIC_NSS_DB" -n "$PUBLIC_CERTNAME" -v signed.mar
# Inspect the product channel, product version, and signature block:
signmar -T signed.mar
```

A signature block being present is not verification. Check the actual
signature against the approved certificate, the exact MAR channel, the version,
and the payload provenance. After stripping a signature with `signmar -r`,
compare the unsigned payload hash with the artifact approved for signing.
The upstream `marsigning_check.sh` does this comparison, but its channel
mismatch branch only prints a warning. A future publisher gate must make
channel mismatch fatal; do not treat that script alone as a channel gate.

The native updater verifies the MAR signature **before** applying files. It
also compares the MAR product version with `BASE_BROWSER_VERSION` and rejects
a lower version. Equal versions are allowed by the native version check;
metadata freshness and same-version rebuild routing are separate concerns.
Never set `--enable-unverified-updates`, unset `MOZ_VERIFY_MAR_SIGNATURE`, or
replace production certificates with publicly known test/development keys.
Never use disabled signature checks to make an unsigned updater appear usable.

Authenticode signs Windows PE/installer binaries. It can improve initial
publisher identity and Windows trust/SmartScreen behavior, but it does **not**
sign a MAR or replace its signature. This preparation allows installer and
portable artifacts without a purchased Authenticode certificate; the mandatory
MAR requirement is unchanged. Bootstrap downloads still need an authenticated
distribution and verification procedure. A checksum obtained from the same
untrusted source as an executable is not independent publisher authentication.
A future privileged/service updater would need its own separate Windows trust
review; this plan retains the upstream non-service model.

## Independent signed PGO track: future integration plan

1. **Choose an operator and endpoint first.** Choose an owned, stable HTTPS
   origin and directory, a security-release owner, supported platforms, and a
   maximum acceptable delay after upstream security releases. Do not ship a
   placeholder host. Plan retention, monitoring, TLS renewal, recovery, and
   backup. A GitHub private artifact URL that requires a token is not a usable
   browser update endpoint. Never place access tokens in the browser.
2. **Choose a distinct MAR ID**, for example the naming pattern
   `mullvadbrowser-<operator>-pgo-alpha`. Keep `MOZ_UPDATE_CHANNEL=alpha` so
   the production release certificate inputs are used. Do not invent a new
   Firefox update-channel name without also reviewing its certificate-selection
   rules: unknown names select development certificate inputs upstream.
3. **Choose key custody, then create keys only with separate approval.** Store
   the private key outside ordinary build jobs. A build job may output unsigned
   candidates; an approved signing job must verify provenance and bytes before
   signing. Record the public DER certificate SHA-256. Do not give arbitrary PR
   or build jobs a signing key. No keys were created in this preparation.
4. **Embed the correct public certificate in the updater at build time.**
   Upstream Alpha explicitly builds `primaryCert.h` and `secondaryCert.h` from
   `release_primary.der` and `release_secondary.der`. The official RBM
   `var/override_updater_url` hook requires `projects/firefox/marsigner.der`
   and copies it to `release_secondary.der` for Alpha/release. It overrides
   the URL and **one certificate slot**, not both.
   For a strictly independent publisher trust root, a future reviewed build
   change must also replace `release_primary.der` with the publisher public
   certificate (both slots can initially pin the same certificate). Otherwise
   the old primary upstream key remains trusted. The distinct MAR ID rejects
   stock upstream MARs, but does not remove that upstream signing authority.
   This manifest models one publisher certificate; a two-key rotation requires
   a reviewed schema and trust-policy change. No embedding patch is added here.
5. **Use the same custom ID at every layer.** Set `var/mar_channel_id` for
   Firefox and browser packaging, its exported accepted list, the full MAR
   header, incremental generation, and the response generator configuration.
   Inspect rendered RBM inputs and the packaged `update-settings.ini`. Do not
   accept both official and custom IDs as an accidental migration shortcut.
6. **Build one immutable release per update-visible version initially.** The
   official URL does not contain a build ID. Its response generator returns
   no update for a client at the advertised target version. Rebuilding PGO or
   changing only GitHub tags/filenames/build IDs will not provide a same-version
   update using those stock routing rules. Require a reviewed, monotonically
   ordered application/MAR version and routing policy before same-version
   rebuilds are supported. Do not guess a suffix ordering or defeat downgrade
   checks to work around this.
7. **Package, sign, verify, then promote.** Create both bootstrap artifacts
   from the same approved browser payload. A complete MAR updates the installed
   `Browser` tree, not the installer wrapper or user `Data` directory. Sign and
   test it separately. Preserve the installer/portable mode and profile. Only
   reuse one MAR for both layouts after a real update test proves that their
   application trees and updater paths are compatible.
8. **Plan rotation before shipping.** Ship new public trust material through
   an update signed by a key already trusted by installed clients. Test the
   transition before retiring that key. A lost or compromised sole signing key
   may require an authenticated manual reinstall; editing the server's XML
   cannot make installed clients trust an arbitrary replacement key.

Keeping an upstream primary key and official accepted ID for an emergency
upstream fallback is a different, shared-authority policy. It also means
accepting replacement with upstream non-PGO binaries. It needs an explicit
user decision and migration tests; the current validator deliberately accepts
only one ID and does not model that policy.

## Serving responses and complete/partial MAR rules

Use the pinned `tools/update-responses/update_responses` generator and
`projects/release/update_responses_config.yml` as the starting point, not a
plain directory of `.exe` downloads. It creates XML with `<updates>`, an
`<update>` carrying `appVersion`, `displayVersion`, `platformVersion`, and
`buildID`, and `<patch type="complete" URL="...mar" size="..."/>`. Optional
`hashes_in_responses` produces SHA-512 metadata. Hashes describe the **final
signed** bytes and are not a substitute for the native MAR signature.

The generator maps the Windows target to `windows-x86_64`. It emits XML and
Apache `.htaccess` rewrite rules for:

```text
<base>/<channel>/<build_target>/<browser_version>/ALL[?force=1]
```

A host must actually honor that routing. GitHub Releases can host immutable
assets, but a Release page is not an update XML service. GitHub Pages does not
execute Apache `.htaccess`; it needs equivalent pre-rendered paths or a
reviewed routing service. A server/edge handler must return valid XML for old
versions and an empty `<updates></updates>` for an up-to-date or unsupported
request as appropriate. Restrict offers to tested platforms and channels;
never serve another architecture as a default. TLS must be valid, without
credential-bearing URLs or downgrade redirects. Ship signed assets first,
verify availability and bytes, then atomically promote response metadata.
Keep versioned assets immutable and serve metadata with a cache/rollout policy
that cannot leave security releases indefinitely hidden.

**Start custom testing with complete MARs only.** Complete MARs are a valid
automatic-update mechanism; partials are optional bandwidth optimization.
`complete_mar_required=true` and `partial_updates=false` apply to future
project-produced update candidates. They cannot change what the official
Mullvad server advertises to the interim upstream track.

Partials, if added later, must be computed from the exact previous *shipped
application tree* to the exact new shipped tree, with matching platform,
channel, version, and signing policy. An upstream non-PGO tree is not the
source for a partial applied to PGO executables. Verify previous release
provenance before extracting it. Sign every partial too, offer it only for its
source version, and always offer the signed complete fallback. Firefox prefers
a partial when present and can fall back to a complete on download/application
failure. Test that path; it is not a reason to publish untested partials.

The build creates MARs with `MOZ_PRODUCT_VERSION`, `MAR_CHANNEL_ID`, and xz
compression. `make_full_update.sh` requires `precomplete`; preserve the normal
`createprecomplete.py`, removal instructions, packaged defaults/extensions,
and post-update handling. Do not put user profiles into a MAR.

## What can be tested now, without publisher secrets or publication

```sh
python3 scripts/validate-update-config.py
python3 -m unittest discover -s tests -p 'test_update_config.py' -v
```

These offline tests check fail-closed settings, strict field/type handling,
current Alpha/platform/lock, HTTPS URL syntax, exact accepted IDs, duplicate
JSON keys, mandatory signature checks, complete-only custom preparation, and
explicit acknowledgement of upstream PGO replacement. They make no network
requests, modify no secrets, and generate no key. A checked-in **public**
upstream certificate is encoded in the parser test only, not used as a custom
publisher key. Optional OpenSSL tests parse it and reject a mismatched digest,
PEM/key input, trailing data, and non-X.509 DER.

For a future `private-signed` planning file, set its own HTTPS base, distinct
operator-scoped ID and singleton accepted list, `mar_certificate.source` to
`publisher`, its existing public DER SHA-256, and
`acknowledge_pgo_replacement=false`. Keep `preparation_only=true` and
`publication_enabled=false`. Unknown fields, private-key fields, placeholder
hosts, missing/zero fingerprints, unsigned modes, extra accepted IDs, and
partials are rejected. Config-only lint checks fingerprint shape, not actual
certificate bytes; use `--certificate` for those checks.

```sh
# Only inspect an existing PUBLIC certificate; this does not sign anything.
python3 scripts/validate-update-config.py /path/to/private-plan.json \
  --certificate /path/to/publisher-public.der
```

Certificate inspection checks its digest, a single DER X.509 object, and RSA
with at least 2048 bits; upstream's key script chooses 4096. It is not MAR
signature verification or proof of key ownership. URL lint does not prove DNS
ownership, TLS validity, availability, or server routing. Production checks
must verify those independently. Changing a JSON boolean cannot enable
publication through this validator.

Further tests are possible with real private CI build artifacts: inspect the
effective updater options, compiled `Services.appinfo.updateURL`, public DER
inputs/generated headers, `Browser/update-settings.ini`, and a disposable
updater's `--channels-allowed` output. Verify genuine upstream signed MARs
against upstream public certificates. Inspect unsigned MAR headers without
installing them. None of these needs a publisher private key.

Before any custom rollout, a private integration test **does** need an
approved protected signer and a controlled HTTPS staging endpoint. Test a
signed complete N -> N+1 update from both installer and portable layouts;
verify that profiles survive. Test rejection of an unsigned/tampered MAR, a
wrong key, wrong channel, older product version, unavailable metadata, and
read-only installation. Check final logs and installed payload hashes, not
only download success. Do not use the repository's/public upstream's known
test key to sign packages offered to users. A signed custom track cannot be
proved functional by config validation alone.

## Source references

All build paths below refer to commit
`7dd751cf1837d667908b339aebf82567ece55e20` in the official
[Tor browser-build repository](https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/tree/7dd751cf1837d667908b339aebf82567ece55e20).
For this study GitLab networking was unavailable. The `tor-actions` mirror's
annotated tag object and peeled commit were checked against `upstream.lock.json`;
this is object matching, not new OpenPGP signer verification. CI's canonical
upstream URL is unchanged.

- [Firefox config: official URL, MAR ID, override input](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/projects/firefox/config)
- [Firefox build: certificate override and update channel](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/projects/firefox/build)
- [Firefox mozconfig: URL, updater, accepted MAR IDs](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/projects/firefox/mozconfig.in)
- [Browser build: `precomplete` and unsigned complete MAR creation](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/projects/browser/build)
- [Signing wrapper: NSS `signmar` interface](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/tools/signing/wrappers/sign-mar)
- [MAR verification and payload comparison](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/tools/marsigning_check.sh)
- [Response configuration: Windows ABI and incremental inputs](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/projects/release/update_responses_config.yml)
- [Response generator: complete/partial XML and routing](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/tools/update-responses/update_responses)
- [Response URL format](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/tools/update-responses/README.md)
- [Official nightly signing key parameters (reference only; not executed)](https://github.com/tor-actions/tor-browser-build/blob/7dd751cf1837d667908b339aebf82567ece55e20/tools/signing/nightly/create-nightly-mar-signing-key)

Browser verification was read at the exact input commit in Mullvad's public
source mirror, not inferred from unmodified Firefox `main` (which lacks
Mullvad's Alpha certificate-selection customization):

- [Compiled application update URL](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/build/application.ini.in)
- [URL template compilation into application data](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/build/appini_header.py)
- [URL token expansion](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/toolkit/modules/UpdateUtils.sys.mjs)
- [Update URL source, policy override, complete fallback](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/toolkit/mozapps/update/UpdateService.sys.mjs)
- [Certificate embedding and Alpha selection](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/toolkit/mozapps/update/updater/moz.build)
- [Signature and product/channel/version verification](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/toolkit/mozapps/update/updater/archivereader.cpp)
- [Verification before update application; Windows accepted-ID file](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/toolkit/mozapps/update/updater/updater.cpp)
- [Signature-verification defaults and update build options](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/build/moz.configure/update-programs.configure)
- [Windows non-service/NSS/update-agent settings](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/mozconfig-windows-x86_64)
- [RSA/SHA-384 signing](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/modules/libmar/sign/mar_sign.c)
- [RSA/SHA-384 verification](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/modules/libmar/verify/cryptox.c)
- [Complete MAR packaging rules](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/tools/update-packaging/make_full_update.sh)
- [Partial MAR packaging rules](https://github.com/mullvad/mullvad-browser/blob/a8a167fe41226f38158d8e169623e95a1bff846a/tools/update-packaging/make_incremental_update.sh)
