#!/usr/bin/env python3
"""Regression tests for the --shard-usn / --dc multi-DC path.

1. Deadlock on any producer failure. producer() in _collect_users_sharded()
   used to call _build_connection() (and ldap3.Server()) OUTSIDE its
   try/finally, so a failure there (bind error, network hiccup, ...) skipped
   `q.put(SENTINEL)` entirely. Since the ThreadPoolExecutor's Future from
   pool.submit() is never awaited, the exception vanished silently, and the
   consumer's `while done < len(ranges): q.get()` blocks forever - 0% CPU,
   no open sockets, no error, nothing printed.

2. --dc entries silently downgraded to plain ldap://. host == self.args.host
   compared the bare --dc value ('198.18.0.111') against the positional HOST
   arg as typed on the command line ('ldaps://198.18.0.111') - never equal,
   even for the primary DC itself - so every shard built a fresh
   ldap3.Server(host) from the bare string, which defaults to plain
   unencrypted ldap://. On a DC that requires LDAP signing (a common
   hardened-AD setting), that bind fails with strongerAuthRequired, which
   triggers bug 1's deadlock.

3. Sharding across >1 distinct DC silently corrupts the dump. Once bugs 1/2
   are fixed, `--shard-usn 4 --dc dc1,dc2` no longer hangs, but without a
   guard it "succeeds" while producing a wrong result: uSNCreated is
   assigned independently by each DC as it learns of an object (locally or
   via replication-in), so it has no defined meaning across DCs - a range
   computed from dc1's highestCommittedUSN and applied verbatim to dc2
   partitions nothing correctly, which can both duplicate and drop objects.
   There is no code-level fix for this within the current design - the fix
   is to refuse the combination rather than produce a dump that looks
   complete and isn't.
"""
import sys
import threading
import types

try:
    from ldapdomaindump import ldd_stream as L
except ImportError:
    import ldd_stream as L


def test_same_host_ignores_scheme():
    assert L._same_host('198.18.0.111', 'ldaps://198.18.0.111')
    assert L._same_host('ldap://DC01', 'LDAP://dc01')
    assert not L._same_host('198.18.0.111', 'ldaps://198.18.0.112')


def test_dc_uri_inherits_primarys_scheme():
    assert L._dc_uri('198.18.0.112', 'ldaps://198.18.0.111') == 'ldaps://198.18.0.112'
    assert L._dc_uri('ldap://198.18.0.112', 'ldaps://198.18.0.111') == 'ldap://198.18.0.112'  # explicit wins
    assert L._dc_uri('198.18.0.112', '198.18.0.111') == '198.18.0.112'  # primary has no scheme either


def _make_streamer(shard_usn, dcs, host='ldaps://198.18.0.111'):
    ds = L.DomainStreamer.__new__(L.DomainStreamer)   # bypass __init__ (no real server)
    cfg = L.Config()
    cfg.shard_usn = shard_usn
    cfg.dcs = dcs
    cfg.paged_size = 1000
    ds.config = cfg
    ds.server = object()
    ds.root = 'DC=lab01,DC=local'

    class FakeArgs:
        pass
    FakeArgs.host = host
    ds.args = FakeArgs()
    return ds


def test_multi_dc_sharding_refuses_to_run(monkeypatch):
    # uSNCreated has no cross-DC meaning, so there is no safe way to partition
    # by it across >1 distinct DC - refuse instead of silently corrupting
    # (some objects duplicated, others dropped, with no warning).
    monkeypatch.setattr(L, '_build_connection', lambda server, args: types.SimpleNamespace(unbind=lambda: None))
    monkeypatch.setattr(L, '_highest_usn', lambda server, conn: 300)
    ds = _make_streamer(shard_usn=4, dcs=['198.18.0.111', '198.18.0.112'])
    try:
        ds._collect_users_sharded('(objectClass=user)', ['cn'], lambda dn, a: None)
        assert False, 'expected RuntimeError for >1 distinct DC with --shard-usn > 1'
    except RuntimeError as e:
        assert 'uSNCreated' in str(e)


def test_single_dc_named_two_ways_is_still_allowed(monkeypatch):
    # --dc <same host as HOSTNAME, just without the ldap(s):// prefix> with
    # --shard-usn > 1 must still work: it's one real DC, so there's nothing
    # unsound about splitting uSNCreated ranges against it.
    monkeypatch.setattr(L, '_build_connection', lambda server, args: types.SimpleNamespace(unbind=lambda: None))
    monkeypatch.setattr(L, '_highest_usn', lambda server, conn: 300)
    fake_ldap3 = types.ModuleType('ldap3')
    fake_ldap3.ALL = 'ALL'
    fake_ldap3.Server = lambda *a, **kw: object()
    monkeypatch.setitem(sys.modules, 'ldap3', fake_ldap3)
    monkeypatch.setattr(L, '_paged', lambda *a, **kw: iter(()))

    ds = _make_streamer(shard_usn=4, dcs=['198.18.0.111'])   # bare IP, primary has ldaps://
    ds._collect_users_sharded('(objectClass=user)', ['cn'], lambda dn, a: None)  # must not raise


def test_multi_dc_with_shard_usn_1_is_still_allowed(monkeypatch):
    # --shard-usn 1 means a single [1, hi] range covering everything - there's
    # no partition to miscompute, so pointing it at a different DC (even
    # several, though only the first is ever used when shard_usn==1) is fine.
    monkeypatch.setattr(L, '_build_connection', lambda server, args: types.SimpleNamespace(unbind=lambda: None))
    monkeypatch.setattr(L, '_highest_usn', lambda server, conn: 300)
    monkeypatch.setattr(L, '_paged', lambda *a, **kw: iter(()))

    ds = _make_streamer(shard_usn=1, dcs=['198.18.0.111', '198.18.0.112'])
    ds._collect_users_sharded('(objectClass=user)', ['cn'], lambda dn, a: None)  # must not raise


def test_sharded_collection_survives_a_producer_failure(monkeypatch):
    # Stub out ldap3 entirely so this stays runnable without the real
    # dependency, per CLAUDE.md's "importable/testable without ldap3" rule.
    fake_ldap3 = types.ModuleType('ldap3')
    fake_ldap3.ALL = 'ALL'
    fake_ldap3.Server = lambda *a, **kw: object()
    monkeypatch.setitem(sys.modules, 'ldap3', fake_ldap3)

    ds = L.DomainStreamer.__new__(L.DomainStreamer)   # bypass __init__ (no real server)
    cfg = L.Config()
    cfg.shard_usn = 3
    cfg.paged_size = 1000
    ds.config = cfg
    ds.server = object()
    ds.root = 'DC=lab01,DC=local'

    class FakeArgs:
        host = 'ldaps://198.18.0.111'
    ds.args = FakeArgs()

    monkeypatch.setattr(L, '_highest_usn', lambda server, conn: 300)

    calls = []

    class FakeConn:
        def unbind(self):
            pass

    def fake_build_connection(server, args):
        calls.append(1)
        if len(calls) == 2:   # call 1 is the USN probe; make exactly one shard's bind fail
            raise RuntimeError('simulated: strongerAuthRequired (plain LDAP against a signing-required DC)')
        return FakeConn()
    monkeypatch.setattr(L, '_build_connection', fake_build_connection)

    def fake_paged(conn, base, filt, attrs, size):
        yield ('CN=x,DC=lab01,DC=local', {'cn': 'x'})
    monkeypatch.setattr(L, '_paged', fake_paged)

    consumed = []
    done = threading.Event()

    def run():
        ds._collect_users_sharded('(objectClass=user)', ['cn'],
                                  lambda dn, a: consumed.append(dn))
        done.set()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=5)
    assert done.is_set(), '_collect_users_sharded deadlocked - never returned'
    # the 2 surviving shards each yielded one entry; the failed one contributed nothing
    assert len(consumed) == 2, consumed


if __name__ == '__main__':
    test_same_host_ignores_scheme()
    test_dc_uri_inherits_primarys_scheme()

    class _MP:
        def setitem(self, d, k, v):
            d[k] = v
        def setattr(self, obj, name, val):
            setattr(obj, name, val)
    _mp = _MP()
    test_multi_dc_sharding_refuses_to_run(_mp)
    test_single_dc_named_two_ways_is_still_allowed(_mp)
    test_multi_dc_with_shard_usn_1_is_still_allowed(_mp)
    test_sharded_collection_survives_a_producer_failure(_mp)
    print('[+] shard/--dc deadlock + scheme + cross-DC-USN-corruption fix: OK')
