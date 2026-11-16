# CLAUDE.md — project context for Claude Code

Patched fork of `dirkjanm/ldapdomaindump` (MIT). `ldapdomaindump/__init__.py`
is the untouched upstream implementation. `ldapdomaindump/ldd_stream.py` is
the patch: a streaming, low-memory, parallel collector for large AD domains.
Output format is identical to upstream (`ldd2bloodhound` / `ldd2pretty` still
work). As of v0.12.0 the `ldapdomaindump` command itself runs `ldd_stream.py`
by default; `ldapdomaindump-original` reaches the untouched implementation.
See `CHANGELOG.md` for version history and `README.md` for usage/known
limitations.

## Conventions / ground rules
- **Do not modify `ldapdomaindump/__init__.py`** (the classic tool) unless a fix
  is explicitly for it. All streaming work goes in `ldd_stream.py`.
- **Preserve output-format compatibility** with `convert.py` (ldd2bloodhound):
  JSON attribute values must be **lists**, original attribute casing preserved.
  Re-run `ldd2bloodhound` after changes to confirm ingestion.
- **Validate before trusting.** Prefer parity against the upstream tool on a
  lab domain (order-insensitive DN-set + value comparison) over assuming
  correctness — several real bugs here were only reachable by running
  against a live DC, not by reading the code.
- **`--shard-usn` only shards within a single DC.** `uSNCreated` is local to
  each DC; don't try to make cross-DC sharding "work" by relaxing the guard
  in `_collect_users_sharded` — see the comment there and README's "Large
  environments" section for why.
- Keep `ldd_stream.py` importable **without** ldap3/dnspython (they're imported
  lazily inside DC-talking functions) so the offline tests run without them.

## Quick commands
```bash
python -m pytest -q                              # offline tests, no DC needed
ldapdomaindump -h                                 # help
python3 -m venv devenv && ./devenv/bin/pip install -e .   # editable install
python -m build                                   # -> dist/*.whl, *.tar.gz
```
