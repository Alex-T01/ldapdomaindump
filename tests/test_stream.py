#!/usr/bin/env python3
"""Validate the pure logic of ldd_stream (formatting, JSON shape compatible with
ldd2bloodhound, incremental writers, grouped reports) without ldap3 or a DC."""
import os, json, shutil, tempfile
from datetime import datetime

try:
    from ldapdomaindump import ldd_stream as L
except ImportError:
    import ldd_stream as L

DOMSID = 'S-1-5-21-1111111111-2222222222-3333333333'

def sid(rid):
    return '%s-%d' % (DOMSID, rid)

# --- synthetic entries, exactly as ldap3 generator=True yields them ----------
# single-valued attrs => scalar ; multi-valued => list ; dates => datetime ;
# securityIdentifier (trust) => raw bytes.
def make_groups():
    return [
        ('CN=Domain Admins,CN=Users,DC=corp,DC=local', {
            'cn': 'Domain Admins', 'sAMAccountName': 'Domain Admins',
            'objectSid': sid(512), 'distinguishedName': 'CN=Domain Admins,CN=Users,DC=corp,DC=local',
            'memberOf': ['CN=Administrators,CN=Builtin,DC=corp,DC=local'],
            'description': ['Designated administrators'],
            'whenCreated': datetime(2020, 1, 1, 12, 0, 0), 'objectClass': ['top', 'group'],
        }),
        ('CN=Administrators,CN=Builtin,DC=corp,DC=local', {
            'cn': 'Administrators', 'sAMAccountName': 'Administrators',
            'objectSid': 'S-1-5-32-544',
            'distinguishedName': 'CN=Administrators,CN=Builtin,DC=corp,DC=local',
            'description': ['Full control'], 'whenCreated': datetime(2020, 1, 1, 12, 0, 0),
            'objectClass': ['top', 'group'],
        }),
        ('CN=Domain Users,CN=Users,DC=corp,DC=local', {
            'cn': 'Domain Users', 'sAMAccountName': 'Domain Users', 'objectSid': sid(513),
            'distinguishedName': 'CN=Domain Users,CN=Users,DC=corp,DC=local',
            'whenCreated': datetime(2020, 1, 1, 12, 0, 0), 'objectClass': ['top', 'group'],
        }),
    ]

def make_users():
    return [
        ('CN=Alice,CN=Users,DC=corp,DC=local', {
            'cn': 'Alice', 'name': 'Alice', 'sAMAccountName': 'alice',
            'memberOf': ['CN=Domain Admins,CN=Users,DC=corp,DC=local'],
            'primaryGroupID': 513,  # canonical AD name (capital ID) as ldap3 returns
            'userAccountControl': 0x00000200 | 0x00010000,  # NORMAL + DONT_EXPIRE_PASSWD
            'objectSid': sid(1104), 'pwdLastSet': datetime(2023, 5, 1, 9, 0, 0),
            'whenCreated': datetime(2021, 3, 3, 8, 0, 0), 'whenChanged': datetime(2023, 5, 1, 9, 0, 0),
            'description': ['CFO'], 'servicePrincipalName': ['HTTP/web01'],
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        }),
        ('CN=Bob,CN=Users,DC=corp,DC=local', {
            'cn': 'Bob', 'name': 'Bob', 'sAMAccountName': 'bob',
            'primaryGroupID': 513, 'userAccountControl': 0x00000202,  # disabled + normal
            'objectSid': sid(1105), 'whenCreated': datetime(2022, 6, 6, 8, 0, 0),
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        }),
    ]

def make_computers():
    return [
        ('CN=WS01,CN=Computers,DC=corp,DC=local', {
            'cn': 'WS01', 'sAMAccountName': 'WS01$', 'dNSHostName': 'ws01.corp.local',
            'operatingSystem': 'Windows 10 Pro', 'operatingSystemVersion': '10.0 (19045)',
            'userAccountControl': 0x1000, 'objectSid': sid(1200),
            'whenCreated': datetime(2021, 1, 1, 0, 0, 0),
            'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        }),
        ('CN=DC01,OU=Domain Controllers,DC=corp,DC=local', {
            'cn': 'DC01', 'sAMAccountName': 'DC01$', 'dNSHostName': 'dc01.corp.local',
            'operatingSystem': 'Windows Server 2019', 'userAccountControl': 0x82000,
            'objectSid': sid(1000), 'whenCreated': datetime(2020, 1, 1, 0, 0, 0),
            'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        }),
        ('CN=WS02,CN=Computers,DC=corp,DC=local', {
            'cn': 'WS02', 'sAMAccountName': 'WS02$', 'dNSHostName': 'ws02.corp.local',
            'operatingSystem': 'Windows 10 Pro', 'userAccountControl': 0x1000,
            'objectSid': sid(1201), 'whenCreated': datetime(2021, 2, 2, 0, 0, 0),
            'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        }),
    ]

def make_trusts():
    # entry_attributes_as_dict form: everything already a list
    return [
        ('CN=partner.local,CN=System,DC=corp,DC=local', {
            'cn': ['partner.local'], 'flatName': ['PARTNER'], 'name': ['partner.local'],
            'securityIdentifier': [bytes.fromhex('010400000000000515000000'
                                                 '01010101020202020303030300000000')],
            'trustAttributes': [0x8], 'trustDirection': [0x3], 'trustType': [0x2],
        }),
    ]


def build_config(outdir):
    c = L.Config()
    c.basepath = outdir
    c.minimal = True           # keeps DomainStreamer paths ldap3-free in this test
    c.grouped = True
    c.groupedjson = True       # also exercise grouped JSON
    return c


def check_json_file(path, expect_keys_present):
    with open(path) as f:
        data = json.load(f)                       # must be valid JSON
    assert isinstance(data, list), '%s is not a JSON list' % path
    for obj in data:
        assert set(obj.keys()) == {'dn', 'attributes'}, obj.keys()
        for k, v in obj['attributes'].items():
            assert isinstance(v, list), 'attribute %s is not a list in %s' % (k, path)
    # spot-check that expected attribute keys survived with list values
    joined = {k: v for obj in data for k, v in obj['attributes'].items()}
    for k in expect_keys_present:
        assert k in joined, 'missing attribute %s in %s' % (k, path)
    return data


def main():
    outdir = tempfile.mkdtemp(prefix='ldd_test_')
    try:
        cfg = build_config(outdir)
        attrs = L.report_attributes(cfg)
        fmt = L.CellFormatter(cfg, gid_to_dn={512: 'CN=Domain Admins,CN=Users,DC=corp,DC=local',
                                              513: 'CN=Domain Users,CN=Users,DC=corp,DC=local'})

        # ---- 1. stream each flat category through the real writer -----------
        for basename, key, entries in [
            (cfg.groupsfile, 'group', make_groups()),
            (cfg.usersfile, 'user', make_users()),
            (cfg.computersfile, 'computer', make_computers()),
            (cfg.trustsfile, 'trust', make_trusts()),
        ]:
            w = L.StreamCategoryWriter(cfg, basename, attrs[key], fmt,
                                       special_groups=(key == 'group'))
            for dn, a in entries:
                w.write(dn, a)
            w.close()

        # ---- 2. JSON validity + BloodHound-shape compatibility --------------
        users = check_json_file(os.path.join(outdir, 'domain_users.json'),
                                ['sAMAccountName', 'objectSid', 'memberOf', 'primaryGroupID'])
        groups = check_json_file(os.path.join(outdir, 'domain_groups.json'),
                                 ['sAMAccountName', 'objectSid'])
        check_json_file(os.path.join(outdir, 'domain_computers.json'),
                        ['sAMAccountName', 'objectSid'])
        trusts = check_json_file(os.path.join(outdir, 'domain_trusts.json'),
                                 ['trustAttributes', 'trustDirection', 'name'])

        # objectSid must be the STRING form ldd2bloodhound indexes as [0]
        alice = next(o for o in users if o['dn'].startswith('CN=Alice'))
        assert alice['attributes']['objectSid'][0] == sid(1104), alice['attributes']['objectSid']
        assert alice['attributes']['primaryGroupID'][0] == 513
        assert alice['attributes']['memberOf'] == ['CN=Domain Admins,CN=Users,DC=corp,DC=local']
        # trust ints preserved as ints in a list
        assert trusts[0]['attributes']['trustAttributes'][0] == 0x8
        assert trusts[0]['attributes']['trustDirection'][0] == 0x3

        # ---- 3. greppable output: header + flags decoded --------------------
        grep = open(os.path.join(outdir, 'domain_users.grep')).read().splitlines()
        assert grep[0].split('\t')[0] == 'cn'                       # header present
        alice_row = next(r for r in grep[1:] if r.split('\t')[2] == 'alice')
        # userAccountControl decoded to flag names, primaryGroupId resolved to CN
        assert 'NORMAL_ACCOUNT' in alice_row and 'DONT_EXPIRE_PASSWD' in alice_row
        assert 'Domain Users' in alice_row                          # primary group CN
        assert 'Domain Admins' in alice_row                         # memberOf CN

        # trust flags decoded in grep
        tgrep = open(os.path.join(outdir, 'domain_trusts.grep')).read()
        assert 'FOREST_TRANSITIVE' in tgrep and 'BIDIRECTIONAL' in tgrep
        # securityIdentifier rendered as a SID string
        assert 'S-1-5-21-16843009-33686018-50529027' in tgrep, tgrep

        # ---- 4. HTML well-formed-ish ---------------------------------------
        html = open(os.path.join(outdir, 'domain_users.html')).read()
        assert html.startswith('<!DOCTYPE html>') and html.rstrip().endswith('</html>')
        assert html.count('<tr') >= 2 and '</table>' in html

        # ---- 5. grouped reports from compact records -----------------------
        ds = L.DomainStreamer.__new__(L.DomainStreamer)   # bypass __init__ (no server)
        ds.config = cfg
        ds.attrs = attrs
        ds.gid_to_dn = {512: 'CN=Domain Admins,CN=Users,DC=corp,DC=local',
                        513: 'CN=Domain Users,CN=Users,DC=corp,DC=local'}
        # compact user records = grouped attrs + memberOf + primaryGroupId
        slim_fields = attrs['user_grouped'] + ['memberOf', 'primaryGroupId', 'objectClass']
        def slim(a, fields):
            low = L.ci_map(a)
            return {f: low[f.lower()] for f in fields if f.lower() in low}
        ds._users_compact = [(dn, slim(a, slim_fields)) for dn, a in make_users()]
        ds._computers_compact = [(dn, slim(a, attrs['computer'] + ['operatingSystem', 'objectClass']))
                                 for dn, a in make_computers()]
        ds.group_records = [(dn, L.ci_map(a).get('cn'), L.as_list(L.ci_map(a).get('memberof')), a)
                            for dn, a in make_groups()]

        ds._build_users_by_group()
        ds._build_computers_by_os()

        ubg = json.load(open(os.path.join(outdir, 'domain_users_by_group.json')))
        # find the "Domain Admins" bucket -> must contain Alice
        da = next(g for g in ubg if 'Domain Admins' in g)['Domain Admins'] \
            if any('Domain Admins' in g for g in ubg) else None
        assert da is not None, [list(g.keys())[0] for g in ubg]
        assert any(m['attributes']['sAMAccountName'][0] == 'alice' for m in da)
        # "Domain Admins" is memberOf "Administrators" -> Administrators bucket holds the group as a subgroup row
        admins_bucket = next((g['Administrators'] for g in ubg if 'Administrators' in g), None)
        assert admins_bucket is not None
        assert any(m['dn'].startswith('CN=Domain Admins') for m in admins_bucket)

        cbo = json.load(open(os.path.join(outdir, 'domain_computers_by_os.json')))
        win10 = next((g['Windows 10 Pro'] for g in cbo if 'Windows 10 Pro' in g), None)
        assert win10 is not None and len(win10) == 2       # WS01 + WS02
        ubg_html = open(os.path.join(outdir, 'domain_users_by_group.html')).read()
        assert 'id="cn_Domain_Admins"' in ubg_html

        # ---- 6. memory-shape sanity: compact record is far smaller than raw --
        import sys
        raw = make_users()[0][1]
        compact = ds._users_compact[0][1]
        assert set(compact).issubset(set(raw) | {'primaryGroupId'})
        print('[+] compact user record fields:', sorted(compact))

        print('\nAll checks passed. Output written to:', outdir)
        for fn in sorted(os.listdir(outdir)):
            print('   %8d  %s' % (os.path.getsize(os.path.join(outdir, fn)), fn))
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


if __name__ == '__main__':
    main()
