#!/usr/bin/env python3
"""Order-insensitive, DN-keyed diff between two ldapdomaindump output
directories (e.g. `ldapdomaindump-original` vs `ldapdomaindump` against the
same DC).

Usage: parity_check.py <dir_a> <dir_b> [--files domain_users.json,...]

For each *.json report file present in either directory:
  - DNs only in A / only in B (set diff - ordering is expected to differ
    between parallel/sharded runs and does NOT show up here).
  - for DNs in both: attribute keys only in A / only in B, and attributes
    present in both whose values differ (as sets, so multi-valued attribute
    order doesn't cause a false diff).

Exit code is 0 iff every compared file is identical DN-for-DN,
attribute-for-attribute. Prints a summary either way.
"""
import argparse
import json
import os
import sys

DEFAULT_FILES = [
    'domain_users.json', 'domain_computers.json', 'domain_groups.json',
    'domain_policy.json', 'domain_trusts.json',
]


def _hashable(x):
    # Binary attributes ldap3 can't decode as UTF-8 (userCertificate,
    # mS-DS-CreatorSID, ...) serialize as {"encoded": ..., "encoding": ...}
    # dicts, which aren't hashable - canonicalize to a JSON string so they
    # can still go in a set for comparison.
    return json.dumps(x, sort_keys=True) if isinstance(x, dict) else x


def load(path):
    with open(path, encoding='utf8') as f:
        data = json.load(f)
    out = {}
    for obj in data:
        out[obj['dn']] = {k: set(_hashable(x) for x in v) if isinstance(v, list) else {_hashable(v)}
                          for k, v in obj['attributes'].items()}
    return out


def diff_file(name, dir_a, dir_b):
    pa, pb = os.path.join(dir_a, name), os.path.join(dir_b, name)
    if not os.path.exists(pa) or not os.path.exists(pb):
        print('[!] %-28s SKIP (missing in %s)' %
              (name, dir_a if not os.path.exists(pa) else dir_b))
        return True

    a, b = load(pa), load(pb)
    dns_a, dns_b = set(a), set(b)
    only_a, only_b = dns_a - dns_b, dns_b - dns_a
    ok = not only_a and not only_b

    if only_a:
        print('[-] %-28s %d DN(s) only in %s' % (name, len(only_a), dir_a))
        for dn in sorted(only_a)[:10]:
            print('       -', dn)
    if only_b:
        print('[-] %-28s %d DN(s) only in %s' % (name, len(only_b), dir_b))
        for dn in sorted(only_b)[:10]:
            print('       -', dn)

    attr_diffs = 0
    for dn in sorted(dns_a & dns_b):
        attrs_a, attrs_b = a[dn], b[dn]
        keys_a, keys_b = set(attrs_a), set(attrs_b)
        if keys_a - keys_b:
            print('[-] %-28s %s: attrs only in %s: %s' %
                  (name, dn, dir_a, sorted(keys_a - keys_b)))
            attr_diffs += 1
        if keys_b - keys_a:
            print('[-] %-28s %s: attrs only in %s: %s' %
                  (name, dn, dir_b, sorted(keys_b - keys_a)))
            attr_diffs += 1
        for k in keys_a & keys_b:
            if attrs_a[k] != attrs_b[k]:
                print('[-] %-28s %s: %s differs: %s=%s %s=%s' %
                      (name, dn, k, dir_a, sorted(attrs_a[k]), dir_b, sorted(attrs_b[k])))
                attr_diffs += 1
    ok = ok and attr_diffs == 0

    print('[%s] %-28s %d DNs compared%s' %
          ('+' if ok else '!', name, len(dns_a & dns_b),
           '' if ok else ' - DIFFERENCES ABOVE'))
    return ok


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('dir_a')
    p.add_argument('dir_b')
    p.add_argument('--files', help='comma-separated filenames (default: the 5 standard reports)')
    args = p.parse_args()
    files = args.files.split(',') if args.files else DEFAULT_FILES

    ok = True
    for name in files:
        ok = diff_file(name, args.dir_a, args.dir_b) and ok

    print()
    print('PARITY OK' if ok else 'PARITY FAILED - see differences above')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
