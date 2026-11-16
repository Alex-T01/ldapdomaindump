# Changelog

## 0.12.0
- `ldapdomaindump` (and `python -m ldapdomaindump`) now run the streaming
  collector by default. `ldd-stream` / `ldapdomaindump-stream` remain as
  aliases; the untouched upstream implementation is reachable as
  `ldapdomaindump-original`.

## 0.11.3
- Fixed: `--shard-usn` + `--dc` could hang indefinitely if a shard's
  connection setup failed (the failure skipped the queue's completion
  signal, and the worker thread's exception was silently discarded).
- Fixed: a `--dc` entry without an explicit `ldap(s)://` scheme silently fell
  back to plain LDAP, which fails outright against a DC that requires
  signing.
- Added a hard guard: `--shard-usn > 1` combined with more than one distinct
  `--dc` host is now refused. `uSNCreated` is local to each domain
  controller — splitting one range across multiple DCs can both duplicate
  and silently drop objects. There is no code-level fix for this within the
  current design; refusing the combination replaces a wrong-but-silent dump
  with a clear error. Single-DC sharding (`--shard-usn > 1` with one DC) and
  `--dc` with `--shard-usn 1` are both unaffected.

## 0.11.2
- Fixed: `domain_policy.json` crashed the whole run — `maxPwdAge`,
  `minPwdAge`, `lockoutDuration`, `lockOutObservationWindow` come back from
  ldap3 as `datetime.timedelta`, which the JSON serializer didn't handle.
- Fixed: `datetime` values in JSON output didn't match upstream's formatting
  (dropped microseconds, non-standard UTC offset). Now uses the same
  `str(obj)` upstream/ldap3 uses.
- Fixed: binary attribute values ldap3 can't decode as UTF-8
  (`userCertificate`, raw SIDs/GUIDs) serialized as a bare base64 string
  instead of upstream's `{"encoded": ..., "encoding": "base64"}` shape.

## 0.11.1
- Fixed: `run()` collected groups, computers and users fully concurrently.
  Primary-group resolution depends on the group list being complete first,
  so a user could be written before its own primary group had been read,
  rendering `NOT FOUND!` instead of the real group name. Groups are now
  collected to completion before computers/users start.
- Fixed: a connection used only to read `highestCommittedUSN` for sharding
  was never closed.

## 0.11.0
- Initial streaming/low-memory/parallel collector (`ldapdomaindump/ldd_stream.py`),
  exposed as `ldd-stream` / `ldapdomaindump-stream`. Same output files and
  formats as upstream. See README's "Large environments" section for the
  design (paged_search with `generator=True`, incremental writers, optional
  single-DC uSNCreated sharding, parallel DNS resolution).

## 0.10.1 and earlier
Upstream `dirkjanm/ldapdomaindump`.
