#!/usr/bin/env python3
"""Regression tests for _json_scalar's handling of value types ldap3 hands
back for real AD attributes but that don't map onto plain JSON scalars.

1. timedelta crashed entirely. ldap3's schema formatting turns
   Interval-syntax policy attributes (maxPwdAge, minPwdAge, lockoutDuration,
   lockOutObservationWindow) into datetime.timedelta objects. json.dumps has
   no default encoder for timedelta, so writing domain_policy.json crashed
   mid-dump with "TypeError: Object of type timedelta is not JSON
   serializable" - after groups/computers/users had already streamed out
   fine. grep/html already special-cased timedelta via ns_to_days/
   ns_to_minutes; only the JSON path (_json_scalar) was missing it.

2. datetime silently mismatched upstream. _json_scalar used to render
   datetimes via strftime('%Y-%m-%d %H:%M:%S%z'), which drops microseconds
   and omits the colon in the UTC offset - e.g. accountExpires as
   '9999-12-31 23:59:59+0000' instead of upstream's
   '9999-12-31 23:59:59.999999+00:00'. Upstream (via ldap3's own
   Entry.entry_to_json()) just does str(obj). Now we do too, for both types.

3. Undecodable bytes changed shape vs upstream. Attributes that are raw
   binary rather than schema-decoded to a string (userCertificate,
   mS-DS-CreatorSID, msDS-GenerationId, ...) used to render as a bare base64
   string; upstream (ldap3's format_json) wraps them as
   {"encoded": <base64>, "encoding": "base64"}. convert.py never reads these
   attributes so BloodHound ingestion was never at risk, but anything else
   consuming this JSON would see a different type at that key depending on
   which tool produced the dump.
"""
import base64
import json
from datetime import datetime, timedelta

try:
    from ldapdomaindump import ldd_stream as L
except ImportError:
    import ldd_stream as L


def test_entry_to_json_compat_handles_timedelta():
    line = L.entry_to_json_compat(
        'CN=Policy,DC=lab01,DC=local',
        {'maxPwdAge': timedelta(days=-42), 'lockoutThreshold': 0})
    obj = json.loads(line)   # must not raise
    assert obj['attributes']['maxPwdAge'] == [str(timedelta(days=-42))]
    assert obj['attributes']['lockoutThreshold'] == [0]


def test_entry_to_json_compat_datetime_matches_upstream_str():
    dt = datetime(9999, 12, 31, 23, 59, 59, 999999)
    line = L.entry_to_json_compat('CN=user3,CN=Users,DC=lab01,DC=local',
                                  {'accountExpires': dt})
    obj = json.loads(line)
    assert obj['attributes']['accountExpires'] == [str(dt)] == ['9999-12-31 23:59:59.999999']


def test_entry_to_json_compat_undecodable_bytes_matches_upstream_shape():
    raw = bytes(range(256))   # not valid UTF-8
    line = L.entry_to_json_compat('CN=DC01,OU=Domain Controllers,DC=lab01,DC=local',
                                  {'mS-DS-CreatorSID': raw})
    obj = json.loads(line)
    assert obj['attributes']['mS-DS-CreatorSID'] == [
        {'encoded': base64.b64encode(raw).decode('ascii'), 'encoding': 'base64'}]


if __name__ == '__main__':
    test_entry_to_json_compat_handles_timedelta()
    test_entry_to_json_compat_datetime_matches_upstream_str()
    test_entry_to_json_compat_undecodable_bytes_matches_upstream_shape()
    print('[+] timedelta/datetime/binary -> JSON: OK')
