#!/usr/bin/env python3
"""
ldd_stream.py - Low-memory / parallel front-end for ldapdomaindump
==================================================================

Drop-in style runner that fixes the two problems of ldapdomaindump on large
domains (tens of thousands of accounts):

  1. RAM blow-up / OOM crash.
     The original calls paged_search(generator=False), which materialises the
     WHOLE result set twice (connection.response = dicts + connection.entries =
     heavy ldap3 Entry objects), then the report writer builds the entire
     HTML/JSON/greppable file as a single giant string in memory. For 50k+
     objects with ALL_ATTRIBUTES this is several GB.

     Here we use generator=True (ldap3 yields one lightweight dict per entry
     and does NOT accumulate), and we stream each entry straight to the output
     files. Nothing is kept except small "compact records" needed for the two
     grouped reports (and those can be turned off with --no-grouped for a truly
     flat memory profile).

  2. Slow, fully-sequential collection.
     users -> computers -> groups run one after another, and DNS resolution
     (-r) is one blocking lookup at a time. Here groups are collected first
     (needed to fully populate the primaryGroupID -> DN map before any user
     is formatted), then computers and users are collected concurrently (one
     connection each), DNS is resolved with a thread pool, and the big users
     query can optionally be sharded across N connections by uSNCreated range
     (--shard-usn N), optionally spread over several DCs (--dc dc1,dc2,...).

Output format is kept compatible with the original files (same filenames, same
JSON shape {"dn":..., "attributes":{name:[values...]}}) so ldd2bloodhound /
ldd2pretty keep working.

Only the collection + writing path is reimplemented; authentication and the
attribute selection mirror the upstream tool.

NOTE ON SPEED HONESTY: ldap3 is pure Python, so BER decoding of results holds
the GIL. Threads help when the DC / network is the bottleneck (socket recv
releases the GIL) and when you spread load across multiple DCs. Against a
single, fast DC where the client-side parsing is the bottleneck, thread-level
parallelism gives only a modest gain -- the real scaling lever there is
multiple processes / multiple DCs. See --shard-usn / --dc.
"""

import sys
import os
import re
import json
import codecs
import base64
import queue
import argparse
import getpass
import threading
import itertools
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Static flag tables (copied from ldapdomaindump so this module can be imported
# and unit-tested without ldap3 / dnspython installed).
# ---------------------------------------------------------------------------
uac_flags = {'ACCOUNT_DISABLED': 0x00000002, 'ACCOUNT_LOCKED': 0x00000010,
             'PASSWD_NOTREQD': 0x00000020, 'PASSWD_CANT_CHANGE': 0x00000040,
             'PASSWORD_STORE_CLEARTEXT': 0x00000080, 'NORMAL_ACCOUNT': 0x00000200,
             'WORKSTATION_ACCOUNT': 0x00001000, 'SERVER_TRUST_ACCOUNT': 0x00002000,
             'DONT_EXPIRE_PASSWD': 0x00010000, 'SMARTCARD_REQUIRED': 0x00040000,
             'TRUSTED_FOR_DELEGATION': 0x00080000, 'NOT_DELEGATED': 0x00100000,
             'USE_DES_KEY_ONLY': 0x00200000, 'DONT_REQ_PREAUTH': 0x00400000,
             'PASSWORD_EXPIRED': 0x00800000, 'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x01000000,
             'PARTIAL_SECRETS_ACCOUNT': 0x04000000}
pwd_flags = {'PASSWORD_COMPLEX': 0x01, 'PASSWORD_NO_ANON_CHANGE': 0x02,
             'PASSWORD_NO_CLEAR_CHANGE': 0x04, 'LOCKOUT_ADMINS': 0x08,
             'PASSWORD_STORE_CLEARTEXT': 0x10, 'REFUSE_PASSWORD_CHANGE': 0x20}
trust_flags = {'NON_TRANSITIVE': 0x00000001, 'UPLEVEL_ONLY': 0x00000002,
               'QUARANTINED_DOMAIN': 0x00000004, 'FOREST_TRANSITIVE': 0x00000008,
               'CROSS_ORGANIZATION': 0x00000010, 'WITHIN_FOREST': 0x00000020,
               'TREAT_AS_EXTERNAL': 0x00000040, 'USES_RC4_ENCRYPTION': 0x00000080,
               'CROSS_ORGANIZATION_NO_TGT_DELEGATION': 0x00000200,
               'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION': 0x00000800,
               'PIM_TRUST': 0x00000400}
trust_directions = {'INBOUND': 0x01, 'OUTBOUND': 0x02, 'BIDIRECTIONAL': 0x03}
trust_type = {'DOWNLEVEL': 0x01, 'UPLEVEL': 0x02, 'MIT': 0x03}

attr_translations = {'sAMAccountName': 'SAM Name', 'cn': 'CN',
                     'operatingSystem': 'Operating System',
                     'operatingSystemServicePack': 'Service Pack',
                     'operatingSystemVersion': 'OS Version',
                     'userAccountControl': 'Flags', 'objectSid': 'SID',
                     'memberOf': 'Member of groups', 'primaryGroupId': 'Primary group',
                     'dNSHostName': 'DNS Hostname', 'whenCreated': 'Created on',
                     'whenChanged': 'Changed on', 'IPv4': 'IPv4 Address',
                     'lockOutObservationWindow': 'Lockout time window',
                     'lockoutDuration': 'Lockout Duration',
                     'lockoutThreshold': 'Lockout Threshold',
                     'maxPwdAge': 'Max password age', 'minPwdAge': 'Min password age',
                     'minPwdLength': 'Min password length',
                     'pwdHistoryLength': 'Password history length',
                     'pwdProperties': 'Password properties',
                     'ms-DS-MachineAccountQuota': 'Machine Account Quota',
                     'flatName': 'NETBIOS Domain name'}

MINIMAL_COMPUTERATTRIBUTES = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem',
                              'operatingSystemServicePack', 'operatingSystemVersion',
                              'lastLogon', 'userAccountControl', 'whenCreated',
                              'objectSid', 'description', 'objectClass']
MINIMAL_USERATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId',
                          'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl',
                          'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName',
                          'objectClass']
MINIMAL_GROUPATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'description',
                           'whenCreated', 'whenChanged', 'objectSid',
                           'distinguishedName', 'objectClass']


# ---------------------------------------------------------------------------
# Small logging helpers
# ---------------------------------------------------------------------------
_print_lock = threading.Lock()
def log_warn(t):
    with _print_lock: print('[!] %s' % t)
def log_info(t):
    with _print_lock: print('[*] %s' % t)
def log_success(t):
    with _print_lock: print('[+] %s' % t)


# ---------------------------------------------------------------------------
# Value helpers (work on the plain dict entries yielded by generator=True)
# ---------------------------------------------------------------------------
def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]

def as_scalar(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v

def format_sid_bytes(b):
    """Format a raw binary SID to S-1-5-.... Pure-python, no ldap3 needed."""
    if not b:
        return ''
    if isinstance(b, str):
        return b
    revision = b[0]
    subauth_count = b[1]
    authority = int.from_bytes(b[2:8], 'big')
    sid = 'S-%d-%d' % (revision, authority)
    for i in range(subauth_count):
        off = 8 + i * 4
        sid += '-%d' % int.from_bytes(b[off:off + 4], 'little')
    return sid

def ci_map(attrs):
    """Case-insensitive view of an attributes dict (built once per entry)."""
    return {k.lower(): v for k, v in attrs.items()}

def ns_to_days(length):
    if isinstance(length, timedelta):
        return length.total_seconds() / 86400
    return abs(int(length)) * .0000001 / 86400

def ns_to_minutes(length):
    if isinstance(length, timedelta):
        return length.total_seconds() / 60
    return abs(int(length)) * .0000001 / 60

def parse_flags(value, flags_def):
    out = []
    if value is None:
        return out
    v = int(as_scalar(value))
    for flag, val in flags_def.items():
        if v & val:
            out.append(flag)
    return out

def parse_single_flag(value, flags_def):
    out = []
    if value is None:
        return out
    v = int(as_scalar(value))
    for flag, val in flags_def.items():
        if v == val:
            out.append(flag)
    return out

def dn_to_cn(dnstr):
    """CN of the first RDN of a DN, with the escaping the original undoes."""
    # first component up to the first unescaped comma
    m = re.match(r'(?:CN|OU)=((?:[^,\\]|\\.)+)', dnstr, flags=re.I)
    cn = m.group(1) if m else dnstr
    for c in ' "#+,;<=>\\\00':
        cn = cn.replace('\\' + c, c)
    return cn

def format_id(cn):
    return re.sub(r'[^a-zA-Z0-9_\-]+', '_', cn)

_SCHEME_RE = re.compile(r'^(ldaps?)://', re.I)

def _strip_scheme(host):
    return _SCHEME_RE.sub('', host)

def _same_host(a, b):
    """True if a and b name the same DC, ignoring an ldap(s):// prefix."""
    return _strip_scheme(a).lower() == _strip_scheme(b).lower()

def _dc_uri(host, primary):
    """Give a --dc entry (often just a bare hostname/IP) the same ldap(s)://
    scheme as the primary HOSTNAME arg, unless it already has its own. Without
    this, ldap3.Server(host) defaults to plain unencrypted ldap://, which on a
    DC that requires signing (a common hardened-AD setting) fails the bind
    outright - see the comment in _collect_users_sharded's producer()."""
    if _SCHEME_RE.match(host):
        return host
    m = _SCHEME_RE.match(primary)
    return '%s://%s' % (m.group(1), host) if m else host

def htmlescape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("'", "&#39;").replace('"', "&quot;"))

def format_string(value):
    if isinstance(value, datetime):
        try:
            return value.strftime('%x %X')
        except ValueError:
            return '0'
    if isinstance(value, bytes):
        try:
            return value.decode('utf8', 'replace')
        except Exception:
            return base64.b64encode(value).decode('ascii')
    if isinstance(value, int):
        return str(value)
    if value is None:
        return ''
    return value


# ---------------------------------------------------------------------------
# JSON serialisation, compatible with ldap3 Entry.entry_to_json():
#   {"dn": "...", "attributes": {"name": [v, ...], ...}}
# Every attribute is a LIST (ldd2bloodhound indexes [0]); bytes -> base64,
# datetime -> string, ints/strs kept native.
# ---------------------------------------------------------------------------
def _json_scalar(x):
    if isinstance(x, bytes):
        try:
            return x.decode('utf8', errors='strict')
        except UnicodeDecodeError:
            # Match ldap3's own format_json (utils/conv.py) exactly: bytes it
            # can't decode as UTF-8 (userCertificate, mS-DS-CreatorSID,
            # msDS-GenerationId, raw objectGUID/objectSid if schema info
            # wasn't loaded, ...) become {"encoded": <base64>,
            # "encoding": "base64"}, not a bare base64 string - otherwise the
            # JSON shape for binary attributes silently depends on which tool
            # produced the dump, and upstream's
            # json.load(...)['attributes'][k][0] would get a dict where it
            # expects a string.
            return {'encoded': base64.b64encode(x).decode('ascii'), 'encoding': 'base64'}
    if isinstance(x, (datetime, timedelta)):
        # Match ldap3's own Entry.entry_to_json() (utils/conv.py:format_json),
        # which just does str(obj) for both datetime and timedelta - that's
        # what upstream ldapdomaindump's JSON already looks like. strftime
        # ('%Y-%m-%d %H:%M:%S%z') would silently drop microseconds and render
        # the UTC offset without a colon (+0000 vs +00:00); timedelta
        # (maxPwdAge, minPwdAge, lockoutDuration, lockOutObservationWindow -
        # all on domain_policy) isn't handled by strftime at all.
        return str(x)
    return x  # str / int / bool / None

def entry_to_json_compat(dn, attrs):
    obj = {'dn': dn,
           'attributes': {k: [_json_scalar(x) for x in as_list(v)]
                          for k, v in attrs.items()}}
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


# ---------------------------------------------------------------------------
# Greppable + HTML cell formatting (dict form of formatGrepAttribute /
# formatAttribute from ldapdomaindump).
# ---------------------------------------------------------------------------
class CellFormatter:
    def __init__(self, config, gid_to_dn):
        self.config = config
        self.gid_to_dn = gid_to_dn or {}

    # ---- greppable -------------------------------------------------------
    def grep(self, aname, value):
        aname = aname.lower()
        if aname == 'useraccountcontrol':
            return ', '.join(parse_flags(value, uac_flags))
        if aname in ('member', 'memberof'):
            return ', '.join(dn_to_cn(g) for g in as_list(value))
        if aname == 'serviceprincipalname':
            return ','.join(as_list(value))
        if aname in ('primarygroupid',):
            dn = self.gid_to_dn.get(as_scalar(value))
            return dn_to_cn(dn) if dn else 'NOT FOUND!'
        if aname == 'description':
            return " ".join(str(x) for x in as_list(value))
        if aname == 'trustattributes':
            return ', '.join(parse_flags(value, trust_flags))
        if aname == 'trustdirection':
            return 'DISABLED' if as_scalar(value) == 0 else ', '.join(parse_single_flag(value, trust_directions))
        if aname == 'trusttype':
            return ', '.join(parse_single_flag(value, trust_type))
        if aname == 'securityidentifier':
            return format_sid_bytes(as_scalar(value))
        if aname == 'pwdproperties':
            return ', '.join(parse_flags(value, pwd_flags))
        if aname in ('minpwdage', 'maxpwdage'):
            return '%.2f days' % ns_to_days(as_scalar(value))
        if aname in ('lockoutobservationwindow', 'lockoutduration'):
            return '%.1f minutes' % ns_to_minutes(as_scalar(value))
        return format_string(as_scalar(value))

    # ---- html ------------------------------------------------------------
    def html(self, aname, value, format_cn_as_group=False):
        aname = aname.lower()
        if aname == 'useraccountcontrol':
            return ', '.join(parse_flags(value, uac_flags))
        if aname in ('member', 'memberof'):
            return self._groups_html(as_list(value))
        if aname == 'serviceprincipalname':
            return '<br />'.join(htmlescape(str(x)) for x in as_list(value))
        if aname == 'primarygroupid':
            dn = self.gid_to_dn.get(as_scalar(value))
            return self._groups_html([dn]) if dn else 'NOT FOUND!'
        if aname == 'description':
            return htmlescape(" ".join(str(x) for x in as_list(value)))
        if aname == 'pwdproperties':
            return ', '.join(parse_flags(value, pwd_flags))
        if aname == 'trustattributes':
            return ', '.join(parse_flags(value, trust_flags))
        if aname == 'trustdirection':
            return 'DISABLED' if as_scalar(value) == 0 else ', '.join(parse_single_flag(value, trust_directions))
        if aname == 'trusttype':
            return ', '.join(parse_single_flag(value, trust_type))
        if aname == 'securityidentifier':
            return format_sid_bytes(as_scalar(value))
        if aname in ('minpwdage', 'maxpwdage'):
            return '%.2f days' % ns_to_days(as_scalar(value))
        if aname in ('lockoutobservationwindow', 'lockoutduration'):
            return '%.1f minutes' % ns_to_minutes(as_scalar(value))
        if aname == 'objectsid':
            sv = as_scalar(value)
            sv = sv if isinstance(sv, str) else format_sid_bytes(sv)
            return '<abbr title="%s">%s</abbr>' % (sv, sv.split('-')[-1])
        if aname == 'cn' and format_cn_as_group:
            cn = as_scalar(value)
            return 'Group: <a href="#cn_%s" title="%s">%s</a>' % (
                format_id(cn), htmlescape(cn), htmlescape(cn))
        return htmlescape(format_string(as_scalar(value)))

    def _groups_html(self, grouplist):
        out = []
        for g in grouplist:
            if not g:
                continue
            cn = dn_to_cn(g)
            out.append('<a href="%s.html#cn_%s" title="%s">%s</a>' % (
                self.config.users_by_group, format_id(cn), htmlescape(g), htmlescape(cn)))
        return ', '.join(out)


# ---------------------------------------------------------------------------
# Streaming writer: one open file handle per format per category. Each entry is
# written immediately and then discarded. No whole-file string is ever built.
# ---------------------------------------------------------------------------
class StreamCategoryWriter:
    def __init__(self, config, basename, attributes, fmt, special_groups=False):
        self.config = config
        self.attributes = attributes
        self.fmt = fmt
        self.special_groups = special_groups
        self.count = 0
        os.makedirs(config.basepath, exist_ok=True)
        p = lambda ext: os.path.join(config.basepath, '%s.%s' % (basename, ext))

        self._html = self._grep = self._json = None
        self._json_first = True

        if config.outputhtml:
            self._html = codecs.open(p('html'), 'w', 'utf8')
            self._html.write('<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">')
            css = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'style.css')
            # style.css ships with ldapdomaindump; look next to this file too
            for cand in (css, os.path.join(os.path.dirname(__file__), 'style.css')):
                if os.path.exists(cand):
                    with open(cand, 'r') as sf:
                        self._html.write('<style type="text/css">%s</style>' % sf.read())
                    break
            self._html.write('</head><body><table>')
            self._write_html_header()

        if config.outputgrep:
            self._grep = codecs.open(p('grep'), 'w', 'utf8')
            self._grep.write(config.grepsplitchar.join(self.attributes))

        if config.outputjson:
            self._json = codecs.open(p('json'), 'w', 'utf8')
            self._json.write('[')

    def _write_html_header(self):
        cols = ''.join('<th>%s</th>' % htmlescape(attr_translations.get(h, h))
                       for h in self.attributes)
        self._html.write('<tbody><tr>%s</tr>\n' % cols)

    def write(self, dn, attrs):
        """attrs is the plain dict from ldap3 generator mode."""
        low = ci_map(attrs)
        self.count += 1

        if self._grep is not None:
            cells = []
            for a in self.attributes:
                cells.append(self.fmt.grep(a, low.get(a.lower())) or '')
            self._grep.write('\n' + self.config.grepsplitchar.join(cells))

        if self._html is not None:
            is_group = self.special_groups and 'group' in [str(x).lower() for x in as_list(low.get('objectclass'))]
            row = ['<tr class="group">' if is_group else '<tr>']
            for a in self.attributes:
                row.append('<td>%s</td>' % (self.fmt.html(a, low.get(a.lower()), is_group)))
            row.append('</tr>\n')
            self._html.write(''.join(row))

        if self._json is not None:
            if not self._json_first:
                self._json.write(',')
            self._json.write(entry_to_json_compat(dn, attrs))
            self._json_first = False

    def close(self):
        if self._html is not None:
            self._html.write('</tbody>\n</table></body></html>')
            self._html.close()
        if self._grep is not None:
            self._grep.close()
        if self._json is not None:
            self._json.write(']')
            self._json.close()


# ---------------------------------------------------------------------------
# Grouped reports (users_by_group, computers_by_os) built AFTER streaming from
# the compact records. These use generators so the output file is still written
# incrementally.
# ---------------------------------------------------------------------------
def write_grouped_html(config, path, groups_items, attributes, fmt, special_groups):
    os.makedirs(config.basepath, exist_ok=True)
    with codecs.open(os.path.join(config.basepath, path), 'w', 'utf8') as of:
        of.write('<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">')
        css = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'style.css')
        if os.path.exists(css):
            with open(css) as sf:
                of.write('<style type="text/css">%s</style>' % sf.read())
        of.write('</head><body><table>')
        first = True
        cols = ''.join('<th>%s</th>' % htmlescape(attr_translations.get(h, h)) for h in attributes)
        for groupname, members in groups_items:
            if first:
                of.write('<thead><tr><td colspan="%d" id="cn_%s">%s</td></tr></thead>'
                         % (len(attributes), format_id(groupname), htmlescape(groupname)))
                of.write('<tbody><tr>%s</tr>\n' % cols)
                first = False
            else:
                of.write('<tbody><tr><td colspan="%d" id="cn_%s">%s</td></tr>'
                         % (len(attributes), format_id(groupname), htmlescape(groupname)))
            for (mdn, mattrs) in members:
                low = ci_map(mattrs)
                is_group = special_groups and 'group' in [str(x).lower() for x in as_list(low.get('objectclass'))]
                row = ['<tr class="group">' if is_group else '<tr>']
                for a in attributes:
                    row.append('<td>%s</td>' % fmt.html(a, low.get(a.lower()), is_group))
                row.append('</tr>\n')
                of.write(''.join(row))
            of.write('</tbody>\n')
        of.write('</table></body></html>')


def write_grouped_json(config, path, groups_items):
    os.makedirs(config.basepath, exist_ok=True)
    with codecs.open(os.path.join(config.basepath, path), 'w', 'utf8') as of:
        of.write('[')
        first_group = True
        for groupname, members in groups_items:
            if not first_group:
                of.write(',')
            first_group = False
            of.write('{%s:[' % json.dumps(groupname))
            first = True
            for (mdn, mattrs) in members:
                if not first:
                    of.write(',')
                first = False
                of.write(entry_to_json_compat(mdn, mattrs))
            of.write(']}')
        of.write(']')


# ---------------------------------------------------------------------------
# Configuration object (same knobs as domainDumpConfig)
# ---------------------------------------------------------------------------
class Config:
    def __init__(self):
        self.basepath = '.'
        self.groupsfile = 'domain_groups'
        self.usersfile = 'domain_users'
        self.computersfile = 'domain_computers'
        self.policyfile = 'domain_policy'
        self.trustsfile = 'domain_trusts'
        self.users_by_group = 'domain_users_by_group'
        self.computers_by_os = 'domain_computers_by_os'
        self.outputhtml = True
        self.outputjson = True
        self.outputgrep = True
        self.groupedjson = False
        self.grepsplitchar = '\t'
        self.lookuphostnames = False
        self.dnsserver = ''
        self.minimal = False
        # new knobs
        self.paged_size = 1000
        self.parallel = True
        self.shard_usn = 1
        self.resolve_threads = 20
        self.grouped = True
        self.dcs = None  # list of hosts to spread shards over


# Attribute sets rendered in the reports (identical to reportWriter)
def report_attributes(config):
    if config.lookuphostnames:
        computerattributes = ['cn', 'sAMAccountName', 'dNSHostName', 'IPv4', 'operatingSystem',
                              'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon',
                              'userAccountControl', 'whenCreated', 'objectSid', 'description']
    else:
        computerattributes = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem',
                              'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon',
                              'userAccountControl', 'whenCreated', 'objectSid', 'description']
    return {
        'computer': computerattributes,
        'user': ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId', 'whenCreated',
                 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid',
                 'description', 'servicePrincipalName'],
        'user_grouped': ['cn', 'name', 'sAMAccountName', 'whenCreated', 'whenChanged', 'lastLogon',
                         'userAccountControl', 'pwdLastSet', 'objectSid', 'description',
                         'servicePrincipalName'],
        'group': ['cn', 'sAMAccountName', 'memberOf', 'description', 'whenCreated', 'whenChanged',
                  'objectSid'],
        'policy': ['distinguishedName', 'lockOutObservationWindow', 'lockoutDuration',
                   'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength',
                   'pwdHistoryLength', 'pwdProperties', 'ms-DS-MachineAccountQuota'],
        'trust': ['cn', 'flatName', 'securityIdentifier', 'trustAttributes', 'trustDirection',
                  'trustType'],
    }


# ===========================================================================
# Everything below needs ldap3 / dnspython and talks to a DC. Imported lazily
# so the module can be unit-tested (formatting + grouping) without them.
# ===========================================================================
def _build_connection(server, args):
    import ldap3
    from ldap3 import Connection, NTLM
    authentication = None
    if args.user is not None:
        authentication = 'SIMPLE' if args.authtype == 'SIMPLE' else NTLM
    c = Connection(server, user=args.user, password=args.password, authentication=authentication,
                   auto_referrals=False)
    if not c.bind():
        raise RuntimeError('Bind failed: %s' % c.result)
    return c


def _paged(conn, base, filt, attributes, paged_size):
    """Yield plain dict entries (generator mode -> no accumulation)."""
    import ldap3
    gen = conn.extend.standard.paged_search(
        base, filt, search_scope=ldap3.SUBTREE, attributes=attributes,
        paged_size=paged_size, generator=True)
    for e in gen:
        # skip referrals / non-entry responses
        if e.get('type') == 'searchResEntry':
            yield e['dn'], e['attributes']


def chunked(it, n):
    it = iter(it)
    while True:
        block = list(itertools.islice(it, n))
        if not block:
            return
        yield block


def _highest_usn(server, conn):
    try:
        return int(server.info.other['highestCommittedUSN'][0])
    except Exception:
        conn.search('', '(objectClass=*)', search_scope='BASE',
                    attributes=['highestCommittedUSN'])
        return int(conn.entries[0]['highestCommittedUSN'].value)


def _usn_ranges(hi, n):
    """n non-overlapping inclusive integer ranges covering [1, hi]."""
    n = max(1, n)
    step = max(1, (hi // n) + 1)
    lo = 1
    while lo <= hi:
        yield (lo, min(hi, lo + step - 1))
        lo += step


class DomainStreamer:
    def __init__(self, server, args, config):
        self.server = server
        self.args = args
        self.config = config
        self.root = server.info.other['defaultNamingContext'][0]
        self.attrs = report_attributes(config)

        # compact records kept for grouped reports (None => not collected)
        self._users_compact = [] if (config.grouped or config.groupedjson) else None
        self._computers_compact = [] if config.grouped else None
        # group maps (populated by collect_groups(), which run() always runs
        # to completion before collect_computers()/collect_users() start -
        # see the note on run() about why this can't be made concurrent)
        self.gid_to_dn = {}
        self.dn_to_cn = {}
        self.group_records = []       # (dn, memberOf-list) for subgroup nesting

    # ---- object-class collectors ----------------------------------------
    def _search_attrs(self, minimal_list):
        import ldap3
        return minimal_list if self.config.minimal else ldap3.ALL_ATTRIBUTES

    def collect_groups(self):
        conn = _build_connection(self.server, self.args)
        fmt = CellFormatter(self.config, self.gid_to_dn)
        writer = StreamCategoryWriter(self.config, self.config.groupsfile,
                                      self.attrs['group'], fmt)
        attrs = self._search_attrs(MINIMAL_GROUPATTRIBUTES)
        try:
            for dn, a in _paged(conn, self.root, '(objectClass=group)', attrs, self.config.paged_size):
                writer.write(dn, a)
                low = ci_map(a)
                sid = as_scalar(low.get('objectsid'))
                cn = as_scalar(low.get('cn'))
                real_dn = as_scalar(low.get('distinguishedname')) or dn
                if sid:
                    sids = sid if isinstance(sid, str) else format_sid_bytes(sid)
                    try:
                        rid = int(sids.split('-')[-1])
                        self.gid_to_dn[rid] = real_dn
                    except ValueError:
                        pass
                self.dn_to_cn[real_dn] = cn
                self.group_records.append((real_dn, cn, as_list(low.get('memberof')), a))
        finally:
            writer.close()
            conn.unbind()
        log_success('Groups collected: %d' % writer.count)

    def collect_computers(self):
        conn = _build_connection(self.server, self.args)
        fmt = CellFormatter(self.config, self.gid_to_dn)
        writer = StreamCategoryWriter(self.config, self.config.computersfile,
                                      self.attrs['computer'], fmt)
        attrs = self._search_attrs(MINIMAL_COMPUTERATTRIBUTES)
        resolver = self._make_resolver() if self.config.lookuphostnames else None
        try:
            src = _paged(conn, self.root, '(&(objectClass=computer)(objectClass=user))',
                         attrs, self.config.paged_size)
            # process per-chunk so DNS resolution can be parallelised
            for block in chunked(src, self.config.paged_size):
                if resolver is not None:
                    self._resolve_block(block, resolver)
                for dn, a in block:
                    writer.write(dn, a)
                    if self._computers_compact is not None:
                        self._computers_compact.append((dn, self._slim(a, self.attrs['computer'] + ['operatingSystem', 'IPv4', 'objectClass'])))
        finally:
            writer.close()
            conn.unbind()
        log_success('Computers collected: %d' % writer.count)

    def collect_users(self):
        """Single writer; N sharded producers when shard_usn>1."""
        fmt = CellFormatter(self.config, self.gid_to_dn)
        writer = StreamCategoryWriter(self.config, self.config.usersfile,
                                      self.attrs['user'], fmt)
        attrs = self._search_attrs(MINIMAL_USERATTRIBUTES)
        base_filter = '(&(objectCategory=person)(objectClass=user))'
        keep_full = bool(self.config.groupedjson)
        slim_fields = self.attrs['user_grouped'] + ['memberOf', 'primaryGroupId', 'objectClass']

        def consume(dn, a):
            writer.write(dn, a)
            if self._users_compact is not None:
                rec = a if keep_full else self._slim(a, slim_fields)
                self._users_compact.append((dn, rec))

        try:
            if self.config.shard_usn > 1:
                self._collect_users_sharded(base_filter, attrs, consume)
            else:
                conn = _build_connection(self.server, self.args)
                try:
                    for dn, a in _paged(conn, self.root, base_filter, attrs, self.config.paged_size):
                        consume(dn, a)
                finally:
                    conn.unbind()
        finally:
            writer.close()
        log_success('Users collected: %d' % writer.count)

    def _collect_users_sharded(self, base_filter, attrs, consume):
        """N producers push (dn, attrs) into a bounded queue; this thread (the
        single consumer) writes them, so output stays a valid single stream and
        the compact list needs no lock."""
        usn_conn = _build_connection(self.server, self.args)
        try:
            hi = _highest_usn(self.server, usn_conn)
        finally:
            usn_conn.unbind()
        ranges = list(_usn_ranges(hi, self.config.shard_usn))
        dcs = self.config.dcs or [self.args.host]

        # uSNCreated is a per-DC-LOCAL counter (each DC assigns it independently
        # as it learns about an object, by direct write or by replication-in) -
        # it is NOT a value synchronized across DCs. A range like [lo, hi]
        # computed from one DC's highestCommittedUSN has no defined meaning
        # against a *different* DC's uSNCreated numbering: the same real
        # object can land inside the ranges assigned to BOTH dc1 and dc2 (->
        # duplicate rows), while another object lands in NEITHER (-> silently
        # missing) - no error, no warning, just a wrong dump. Splitting shards
        # across >1 distinct DC is only safe when shard_usn == 1 (the single
        # "shard" covers the whole [1, hi] range, so there's no partition to
        # miscompute - it's just "run this DC instead"). Refuse the unsound
        # combination rather than produce a dump that looks complete and
        # isn't; --shard-usn > 1 against a single DC is unaffected and stays
        # exactly as fast as before.
        distinct_dcs = {_strip_scheme(h).lower() for h in dcs}
        if len(distinct_dcs) > 1 and self.config.shard_usn > 1:
            raise RuntimeError(
                'Refusing --shard-usn %d with %d distinct --dc hosts (%s): uSNCreated '
                'is local to each DC, so splitting one uSNCreated range across multiple '
                'DCs can both duplicate and silently drop objects. Use --shard-usn with '
                'a single DC (parallelism across connections to that one DC is still '
                'sound), or drop --shard-usn to 1 if you just want to point at a '
                'different DC.'
                % (self.config.shard_usn, len(distinct_dcs), ', '.join(sorted(distinct_dcs))))

        log_info('Sharding users into %d uSNCreated ranges over %d DC(s)' % (len(ranges), len(dcs)))

        q = queue.Queue(maxsize=self.config.paged_size * 4)
        SENTINEL = object()
        failed = []   # (idx, host, exception) - collected so a broken shard is reported, not silently dropped

        def producer(idx, lo, high):
            # Every step that can fail (Server()/connection setup INCLUDED, not
            # just the search) must stay inside this try/finally: q.put(SENTINEL)
            # is how the consumer below knows this shard is done. A failure
            # before the try skips the SENTINEL entirely, and since
            # ThreadPoolExecutor.submit()'s returned Future is never awaited,
            # the exception would vanish silently -> the consumer's `while
            # done < len(ranges)` blocks forever with no error printed.
            try:
                import ldap3
                host = dcs[idx % len(dcs)]
                srv = self.server if _same_host(host, self.args.host) else ldap3.Server(
                    _dc_uri(host, self.args.host), get_info=ldap3.ALL)
                conn = _build_connection(srv, self.args)
                try:
                    filt = '(&%s(uSNCreated>=%d)(uSNCreated<=%d))' % (base_filter, lo, high)
                    for item in _paged(conn, self.root, filt, attrs, self.config.paged_size):
                        q.put(item)
                finally:
                    conn.unbind()
            except Exception as e:
                failed.append((idx, dcs[idx % len(dcs)], e))
            finally:
                q.put(SENTINEL)

        pool = ThreadPoolExecutor(max_workers=len(ranges))
        for i, (lo, high) in enumerate(ranges):
            pool.submit(producer, i, lo, high)

        done = 0
        while done < len(ranges):
            item = q.get()
            if item is SENTINEL:
                done += 1
                continue
            consume(*item)
        pool.shutdown(wait=True)

        if failed:
            log_warn('%d/%d USN shard(s) FAILED - users collected below are INCOMPLETE:' %
                     (len(failed), len(ranges)))
            for idx, host, e in failed:
                log_warn('  shard %d (DC %s): %s' % (idx, host, e))

    # ---- helpers ---------------------------------------------------------
    def _slim(self, attrs, fields):
        low = ci_map(attrs)
        out = {}
        for f in fields:
            v = low.get(f.lower())
            if v is not None:
                out[f] = v
        return out

    def _make_resolver(self):
        import dns.resolver
        r = dns.resolver.Resolver()
        r.lifetime = 2
        if self.config.dnsserver:
            r.nameservers = [self.config.dnsserver]
        return r

    def _resolve_block(self, block, resolver):
        import dns.resolver
        def resolve_one(item):
            dn, a = item
            low = ci_map(a)
            host = as_scalar(low.get('dnshostname'))
            if not host:
                return
            try:
                ans = resolver.resolve(host, 'A') if hasattr(resolver, 'resolve') else resolver.query(host, 'A')
                ip = str(ans.response.answer[0][0])
            except dns.resolver.NXDOMAIN:
                ip = 'error.NXDOMAIN'
            except dns.resolver.Timeout:
                ip = 'error.TIMEOUT'
            except Exception:
                ip = 'error.NOHOSTNAME'
            a['IPv4'] = ip
        with ThreadPoolExecutor(max_workers=self.config.resolve_threads) as ex:
            list(ex.map(resolve_one, block))

    # ---- policy / trusts (tiny, no streaming needed) ---------------------
    def collect_policy_and_trusts(self):
        import ldap3
        conn = _build_connection(self.server, self.args)
        fmt = CellFormatter(self.config, self.gid_to_dn)
        try:
            conn.search(self.root, '(objectClass=domain)', attributes=ldap3.ALL_ATTRIBUTES)
            pol = [(e.entry_dn, e.entry_attributes_as_dict) for e in conn.entries]
            self._write_flat('policy', self.config.policyfile, pol, fmt)

            conn.search(self.root, '(objectClass=trustedDomain)', attributes=ldap3.ALL_ATTRIBUTES)
            trusts = [(e.entry_dn, e.entry_attributes_as_dict) for e in conn.entries]
            self._write_flat('trust', self.config.trustsfile, trusts, fmt)
        finally:
            conn.unbind()

    def _write_flat(self, key, basename, items, fmt):
        w = StreamCategoryWriter(self.config, basename, self.attrs[key], fmt)
        try:
            for dn, a in items:
                w.write(dn, a)
        finally:
            w.close()

    # ---- grouped reports -------------------------------------------------
    def build_grouped(self):
        if self.config.grouped:
            self._build_users_by_group()
            self._build_computers_by_os()
        elif self.config.groupedjson:
            self._build_users_by_group()

    def _build_users_by_group(self):
        if self._users_compact is None:
            return
        fmt = CellFormatter(self.config, self.gid_to_dn)
        groupsdict = {}
        for dn, a in self._users_compact:
            low = ci_map(a)
            cns = [dn_to_cn(g) for g in as_list(low.get('memberof'))]
            pg = self.gid_to_dn.get(as_scalar(low.get('primarygroupid')))
            if pg:
                cns.append(dn_to_cn(pg))
            for cn in cns:
                groupsdict.setdefault(cn, []).append((dn, a))
        # subgroups (groups that are members of groups)
        for gdn, gcn, gmemberof, gattrs in self.group_records:
            for parent in gmemberof:
                groupsdict.setdefault(dn_to_cn(parent), []).append((gdn, gattrs))

        items = list(groupsdict.items())
        if self.config.outputhtml:
            write_grouped_html(self.config, '%s.html' % self.config.users_by_group,
                               items, self.attrs['user_grouped'], fmt, special_groups=True)
        if self.config.outputjson and self.config.groupedjson:
            write_grouped_json(self.config, '%s.json' % self.config.users_by_group, items)

    def _build_computers_by_os(self):
        if self._computers_compact is None:
            return
        fmt = CellFormatter(self.config, self.gid_to_dn)
        osdict = {}
        for dn, a in self._computers_compact:
            low = ci_map(a)
            cos = as_scalar(low.get('operatingsystem')) or 'Unknown'
            osdict.setdefault(cos, []).append((dn, a))
        items = list(osdict.items())
        if self.config.outputhtml:
            write_grouped_html(self.config, '%s.html' % self.config.computers_by_os,
                               items, self.attrs['computer'], fmt, special_groups=False)
        if self.config.outputjson and self.config.groupedjson:
            write_grouped_json(self.config, '%s.json' % self.config.computers_by_os, items)

    # ---- orchestrator ----------------------------------------------------
    def run(self):
        # collect_groups() populates self.gid_to_dn (rid -> group DN), which
        # CellFormatter uses to resolve each user's primaryGroupID to a CN
        # (report_attributes()['user'] includes 'primaryGroupId'). It MUST
        # finish before any user is formatted, or users whose primary group
        # hasn't been read yet render "NOT FOUND!" instead of the real group -
        # a race, not a crash, so it's easy to miss in a small test but bites
        # on a real domain where groups keep streaming while users are being
        # written. So groups always run first, synchronously; only computers
        # and users (which don't depend on gid_to_dn being complete) are
        # collected concurrently.
        self.collect_groups()
        tasks = [self.collect_computers, self.collect_users]
        if self.config.parallel:
            with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
                futs = [ex.submit(t) for t in tasks]
                for f in futs:
                    f.result()
        else:
            for t in tasks:
                t()
        self.collect_policy_and_trusts()
        log_info('Building grouped reports')
        self.build_grouped()


def main():
    parser = argparse.ArgumentParser(
        description='Low-memory / parallel ldapdomaindump. Streams users/computers/groups '
                    'to HTML/JSON/greppable output without loading everything into RAM.')
    parser.add_argument("host", metavar='HOSTNAME',
                        help="Hostname/ip or ldap(s)://host:port")
    parser.add_argument("-u", "--user", metavar='USERNAME', help="DOMAIN\\username")
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password or LM:NTLM hash")
    parser.add_argument("-at", "--authtype", choices=['NTLM', 'SIMPLE'], default='NTLM')

    og = parser.add_argument_group("Output options")
    og.add_argument("-o", "--outdir", metavar='DIRECTORY')
    og.add_argument("--no-html", action='store_true')
    og.add_argument("--no-json", action='store_true')
    og.add_argument("--no-grep", action='store_true')
    og.add_argument("--grouped-json", action='store_true', default=False)
    og.add_argument("-d", "--delimiter")

    mg = parser.add_argument_group("Misc options")
    mg.add_argument("-r", "--resolve", action='store_true', help="Resolve computer hostnames")
    mg.add_argument("-n", "--dns-server")
    mg.add_argument("-m", "--minimal", action='store_true', default=False,
                    help="Only query a minimal set of attributes (much less RAM)")

    pg = parser.add_argument_group("Scaling options (new)")
    pg.add_argument("--paged-size", type=int, default=1000,
                    help="LDAP page size (default 1000, the AD server cap)")
    pg.add_argument("--sequential", action='store_true',
                    help="Collect users/computers/groups one after another (default: parallel)")
    pg.add_argument("--shard-usn", type=int, default=1, metavar='N',
                    help="Split the users query into N parallel sub-queries by uSNCreated range")
    pg.add_argument("--dc", help="Comma-separated DCs to spread shards over (default: HOSTNAME). "
                    "Only safe combined with --shard-usn > 1 if they all resolve to the SAME DC "
                    "(uSNCreated is per-DC-local, not synchronized - see --shard-usn's help); "
                    "with --shard-usn 1 (the default) any single DC here is fine.")
    pg.add_argument("--resolve-threads", type=int, default=20,
                    help="Parallel DNS lookups when -r is used (default 20)")
    pg.add_argument("--no-grouped", action='store_true',
                    help="Skip users_by_group / computers_by_os for a flat, minimal memory profile")

    args = parser.parse_args()

    import ldap3
    from ldap3 import Server, ALL, NTLM

    cnf = Config()
    cnf.lookuphostnames = args.resolve
    if args.dns_server:
        cnf.dnsserver = args.dns_server
    cnf.minimal = args.minimal
    if args.delimiter:
        cnf.grepsplitchar = args.delimiter
    cnf.outputhtml = not args.no_html
    cnf.outputjson = not args.no_json
    cnf.outputgrep = not args.no_grep
    if args.outdir:
        cnf.basepath = args.outdir
    cnf.groupedjson = args.grouped_json
    cnf.paged_size = args.paged_size
    cnf.parallel = not args.sequential
    cnf.shard_usn = max(1, args.shard_usn)
    cnf.resolve_threads = args.resolve_threads
    cnf.grouped = not args.no_grouped
    cnf.dcs = [h.strip() for h in args.dc.split(',')] if args.dc else None

    if args.user is not None:
        if '\\' not in args.user and args.authtype != 'SIMPLE':
            log_warn('Username must include a domain, use: DOMAIN\\username')
            sys.exit(1)
        if args.password is None:
            args.password = getpass.getpass()
    else:
        log_info('Connecting as anonymous user, dumping will probably fail.')

    s = Server(args.host, get_info=ALL)
    log_info('Connecting to host...')
    probe = _build_connection(s, args)
    probe.unbind()
    log_success('Bind OK')
    log_info('Starting domain dump (streaming)')

    dumper = DomainStreamer(s, args, cnf)
    dumper.run()
    log_success('Domain dump finished')


if __name__ == '__main__':
    main()
