# LDAPDomainDump
Active Directory information dumper via LDAP

## Introduction
In an Active Directory domain, a lot of interesting information can be retrieved via LDAP by any authenticated user (or machine).
This makes LDAP an interesting protocol for gathering information in the recon phase of a pentest of an internal network.
A problem is that data from LDAP often is not available in an easy to read format.

ldapdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via LDAP and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files.

The tool was designed with the following goals in mind:
- Easy overview of all users/groups/computers/policies in the domain
- Authentication both via username and password, as with NTLM hashes (requires ldap3 >=1.3.1)
- Possibility to run the tool with an existing authenticated connection to an LDAP service, allowing for integration with relaying tools such as impackets ntlmrelayx

The tool outputs several files containing an overview of objects in the domain:
- *domain_groups*: List of groups in the domain
- *domain_users*: List of users in the domain
- *domain_computers*: List of computer accounts in the domain
- *domain_policy*: Domain policy such as password requirements and lockout policy
- *domain_trusts*: Incoming and outgoing domain trusts, and their properties

As well as two grouped files:
- *domain_users_by_group*: Domain users per group they are member of
- *domain_computers_by_os*: Domain computers sorted by Operating System

## Dependencies and installation
Requires [ldap3](https://github.com/cannatag/ldap3) > 2.0 and [dnspython](https://github.com/rthalley/dnspython). ldapdomaindump requires Python 3.6 or greater.

Dependencies can be installed manually with `pip install ldap3 dnspython future`, but should in most cases be handled by pip when you install the main package either from git or pypi.

The ldapdomaindump package can be installed with `python setup.py install` from the git source, or for the latest release with `pip install ldapdomaindump`. Note that the PyPI package is the plain upstream tool; this fork's extra flags (see "Large environments" below) require installing from this source, e.g. with `pipx install .` or `pip install -e .`.

## Usage
There are 3 ways to use the tool:
- With just the source, run `python ldapdomaindump.py`
- After installing, by running `python -m ldapdomaindump`
- After installing, by running `ldapdomaindump`

**As of v0.12.0, `ldapdomaindump` (and `python -m ldapdomaindump`) run the
streaming/low-memory/parallel collector described under "Large environments"
below** — parity with the classic implementation (identical output, byte for
byte, on a real test domain) was verified before making it the default. Every
flag below still means the same thing; nothing is removed. The untouched
classic implementation is still available as `ldapdomaindump-original` if
you ever need it for comparison.

Help can be obtained with the -h switch:
```
usage: ldapdomaindump [-h] [-u USERNAME] [-p PASSWORD] [-at {NTLM,SIMPLE}]
                      [-k] [-o DIRECTORY] [--no-html] [--no-json] [--no-grep]
                      [--grouped-json] [-d DELIMITER] [-r] [-n DNS_SERVER]
                      [-m] [--paged-size PAGED_SIZE] [--sequential]
                      [--shard-usn N] [--dc DC]
                      [--resolve-threads RESOLVE_THREADS] [--no-grouped]
                      HOSTNAME

Low-memory / parallel ldapdomaindump. Streams users/computers/groups to
HTML/JSON/greppable output without loading everything into RAM.

positional arguments:
  HOSTNAME              Hostname/ip or ldap(s)://host:port

options:
  -h, --help            show this help message and exit
  -u, --user USERNAME   DOMAIN\username
  -p, --password PASSWORD
                        Password or LM:NTLM hash
  -at, --authtype {NTLM,SIMPLE}

Output options:
  -o, --outdir DIRECTORY
  --no-html
  --no-json
  --no-grep
  --grouped-json
  -d, --delimiter DELIMITER

Misc options:
  -r, --resolve         Resolve computer hostnames
  -n, --dns-server DNS_SERVER
  -m, --minimal         Only query a minimal set of attributes (much less RAM)

Scaling options (new):
  --paged-size PAGED_SIZE
                        LDAP page size (default 1000, the AD server cap)
  --sequential          Collect users/computers/groups one after another
                        (default: parallel)
  --shard-usn N         Split the users query into N parallel sub-queries by
                        uSNCreated range
  --dc DC               Comma-separated DCs to spread shards over (default:
                        HOSTNAME). Only safe combined with --shard-usn > 1
                        if they all resolve to the SAME DC; with
                        --shard-usn 1 (the default) any single DC here is
                        fine — see "Large environments" below.
  --resolve-threads RESOLVE_THREADS
                        Parallel DNS lookups when -r is used (default 20)
  --no-grouped          Skip users_by_group / computers_by_os for a flat,
                        minimal memory profile
```

## Options
### Authentication
Most AD servers support NTLM authentication. In the rare case that it does not, use --authtype SIMPLE.

### Hardened DCs: LDAP signing and LDAPS
Domain controllers that require LDAP channel signing (the **default on
Windows Server 2025 and later**, and a common hardening GPO before that)
reject NTLM binds on plain `ldap://389` with `strongerAuthRequired`. ldap3
does not implement NTLM signing, so the fix is TLS, not signing: point the
tool at LDAPS by prefixing the host with the `ldaps://` scheme (port 636):

```bash
ldapdomaindump -u 'CORP\user' -p 'password' ldaps://dc01.corp.local:636 -o dump/
```

The scheme is propagated to every `--dc` entry that doesn't carry its own
(and to the sharding/producer connections), so `--shard-usn 8 --dc dc01...`
keeps using LDAPS automatically when HOSTNAME had it. Note that anonymous
binds and root-DSE reads still work on 389 on such DCs — only the
authenticated bind is refused — so a bind failure with `invalidCredentials`
rather than `strongerAuthRequired` means the credentials are wrong (or the
account locked), not that signing is the problem.

### Kerberos (`-k`)
Instead of NTLM/SIMPLE you can authenticate with Kerberos/GSSAPI from your
existing ccache (`kinit user@REALM` first), like BloodHound.py's `-k`:

```bash
kinit user@LAB01.LOCAL
ldapdomaindump -k ldaps://dc01.lab01.local:636 -o dump/
```

`-u/-p` are ignored in this mode; HOSTNAME must be the DC **FQDN** — an IP
cannot be resolved to an SPN (`ldap/<host>`) and the bind fails with
"Server not found in Kerberos database". A `[kerberos]` extra carries the
optional dependencies:

```bash
pipx inject ldapdomaindump kerberos     # gssapi + cryptography
# or: pip install 'ldapdomaindump[kerberos]'
```

`cryptography` is required on LDAPS: ldap3 binds TLS channel bindings into
the GSSAPI exchange there. Password, pass-the-hash (`-p 'LM:NTLM'`) and
Kerberos produce identical dumps (validated on a Server 2025 lab).

### Output formats
By default the tool outputs all files in HTML, JSON and tab delimited output (greppable). There are also two grouped files (users_by_group and computers_by_os) for convenience. These do not have a greppable output. JSON output for grouped files is disabled by default since it creates very large files without any data that isn't present in the other files already.

### DNS resolving
An important option is the *-r* option, which decides if a computers DNSHostName attribute should be resolved to an IPv4 address. 
While this can be very useful, the DNSHostName attribute is not automatically updated. When the AD Domain uses subdomains for computer hostnames, the DNSHostName will often be incorrect and will not resolve. Also keep in mind that resolving every hostname in the domain might cause a high load on the domain controller.

### Minimizing network and memory usage
By default ldapdomaindump will try to dump every single attribute it can read to disk in the .json files. In large networks, this uses a lot of memory (since group relationships are currently calculated in memory before being written to disk). To dump only the minimal required attributes (the ones shown by default in the .html and .grep files), use the `--minimal` switch.

## Visualizing groups with BloodHound
LDAPDomainDump includes a utility that can be used to convert ldapdomaindumps `.json` files to CSV files suitable for BloodHound. The utility is called `ldd2bloodhound` and is added to your path upon installation. Alternatively you can run it with `python -m ldapdomaindump.convert` or with `python ldapdomaindump/convert.py` if you are running it from the source.
The conversion tool will take the users/groups/computers/trusts `.json` file and convert those to `group_membership.csv` and `trust.csv` which you can add to BloodHound. *Note that these files are only compatible with **BloodHound 1.x** which is quite old. There are no plans to support the latest version as the [BloodHound.py project](https://github.com/fox-it/BloodHound.py) was made for this. With the DCOnly collection method this tool will also only talk to LDAP and collect more information than ldapdomaindump would*.

## Visualizing dump with a pretty output like enum4linux
LDAPDomainDump includes a utility that can be used to output ldapdomaindumps `.json` files to an enum4linux like output. The utility is called `ldd2pretty` and is added to your path upon installation. Alternatively you can run it with `python -m ldapdomaindump.pretty` or with `python ldapdomaindump/pretty.py` if you are running it from the source.

## License
MIT

## Large environments: streaming / low-memory / parallel collection

This fork adds a streaming collector for large domains (tens of thousands of
accounts or more) where the classic implementation exhausts RAM and crashes.
**As of v0.12.0 this is what `ldapdomaindump` runs by default** — there's no
separate command to remember. The same code is also reachable under two
alias names, and the untouched classic implementation is kept as an explicit
opt-out:

```
ldapdomaindump                    # default since v0.12.0: the streaming collector
ldd-stream                        # alias, same command
ldapdomaindump-stream             # alias, same command
python -m ldapdomaindump          # same command, module form

ldapdomaindump-original           # explicit opt-out: the untouched classic implementation
```

Output files/format are **identical** either way (verified byte-for-byte
against a real test domain before switching the default), so
`ldd2bloodhound` / `ldd2pretty` work the same regardless of which one produced
the dump.

### Why it does not blow up

The classic path uses `paged_search(generator=False)`, which materialises the
entire result set twice (`connection.response` dicts **and** heavy `connection.entries`
`Entry` objects), then builds each whole output file as one giant string in
memory — done three times (HTML/JSON/greppable) for each object class.

The streaming path uses `paged_search(generator=True)` (ldap3 yields one light
dict per entry and accumulates nothing) and writes every entry straight to
disk, keeping only small "compact records" needed for the two grouped
reports. With `--no-grouped` nothing is retained at all: memory is bounded by
a single page (~1000 entries) regardless of domain size.

### Speed

- groups are collected first, then computers and users concurrently (one
  connection each) — groups have to finish first so that primary-group
  resolution has a complete group list to look up against;
- DNS resolution (`-r`) runs on a thread pool instead of one lookup at a time;
- default page size is 1000 (the AD server cap) instead of 500;
- a single pass emits all three formats.

Optional sharding of the (usually largest) users query, against **one** DC:

```
--shard-usn N             # split the users query into N parallel connections by uSNCreated range
--dc dc1                  # optionally point that DC somewhere other than HOSTNAME
```

Note: ldap3 is pure Python (BER decoding holds the GIL), so thread-level
parallelism helps mostly when the DC/network is the bottleneck rather than
client-side parsing. Against a single fast DC the gain is modest.

**`--shard-usn` only shards within a single DC.** `uSNCreated` is a counter
each DC keeps *locally* — it is not synchronized across domain controllers, so
a range computed from one DC's `highestCommittedUSN` has no defined meaning
against a different DC's numbering. Passing `--dc` with more than one
*distinct* host together with `--shard-usn > 1` is refused (`RuntimeError`)
rather than silently producing a wrong dump — this was tried against a real
2-DC lab and it duplicated one object while dropping four others, with no
error, before the guard was added. `--dc` with a single host, at any
`--shard-usn`, is unaffected — it's just "run this DC instead of HOSTNAME".

### Examples

```bash
# medium environment
ldapdomaindump -u 'CORP\user' -p 'password' dc01.corp.local -o dump/

# very large: flat memory profile, minimal attributes, no (unusable) HTML
ldapdomaindump -u 'CORP\user' -p 'password' dc01.corp.local -o dump/ \
               -m --no-html --no-grouped

# very large + parallel connections against a single DC
ldapdomaindump -u 'CORP\user' -p 'password' dc01.corp.local -o dump/ \
               -m --no-html --shard-usn 8
```

All classic flags are supported (`-u/-p/-at`, `-o`, `--no-html/--no-json/--no-grep`,
`--grouped-json`, `-d`, `-r`, `-n`, `-m`) plus `-k` (Kerberos). New flags: `--paged-size`,
`--sequential`, `--shard-usn`, `--dc`, `--resolve-threads`, `--no-grouped`
(see `ldapdomaindump -h`).

### Known limitations

- Correctness (identical output vs. upstream, field decoding, DNS resolution,
  auth methods, single- and multi-DC `--dc` usage) has been validated against
  real Active Directory labs, including a Windows Server 2025 DC with LDAP
  signing required (`ldaps://`, ~550 objects, standard and `--shard-usn 4`
  runs with identical object sets). Memory and speed **at real scale** (tens
  of thousands of objects) have not — the largest lab used was on the order
  of a few hundred objects, too small for either to be more than noise. The
  design should hold (see "Why it does not blow up" above), but treat the
  memory/speed claims as unverified until tried on a domain that size.
- `--shard-usn` only shards within a single DC — see above.
