#!/usr/bin/env python3
"""Regression test for the groups-before-users/computers ordering bug.

DomainStreamer.run() used to launch collect_groups/collect_computers/
collect_users all in the same ThreadPoolExecutor. CellFormatter resolves a
user's primaryGroupID via self.gid_to_dn, which collect_groups() populates
incrementally while it streams - so a user could be formatted (and written
to domain_users.grep/.html) before its primary group had been read yet,
silently rendering "NOT FOUND!" instead of the real group name. This does
not need ldap3/a DC to catch: it only tests call ordering, so it stays
importable/offline like the rest of tests/.
"""
import threading
import time

try:
    from ldapdomaindump import ldd_stream as L
except ImportError:
    import ldd_stream as L


def test_groups_collected_before_users_and_computers():
    ds = L.DomainStreamer.__new__(L.DomainStreamer)   # bypass __init__ (no server)
    cfg = L.Config()
    cfg.parallel = True
    ds.config = cfg

    events = []
    lock = threading.Lock()

    def record(name):
        with lock:
            events.append(name)

    # collect_groups is the one method that must fully finish (and must be
    # observed to finish) before the other two even start. It sleeps here so
    # that if it were merely *started* concurrently with the other two
    # (the bug being guarded against) rather than run to completion first,
    # computers/users would race ahead and record before it - this only
    # passes when run() actually blocks on collect_groups() before
    # launching the rest.
    def slow_groups():
        time.sleep(0.05)
        record('groups_done')
    ds.collect_groups = slow_groups
    ds.collect_computers = lambda: record('computers')
    ds.collect_users = lambda: record('users')
    ds.collect_policy_and_trusts = lambda: record('policy')
    ds.build_grouped = lambda: record('grouped')

    ds.run()

    assert events[0] == 'groups_done', events
    assert set(events[1:3]) == {'computers', 'users'}, events
    assert events[3:] == ['policy', 'grouped'], events


if __name__ == '__main__':
    test_groups_collected_before_users_and_computers()
    print('[+] groups-before-users/computers ordering: OK')
