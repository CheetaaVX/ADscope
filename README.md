<div align="center">

# ADscope

**Read-only Active Directory reconnaissance and ACL permission review**

A Python tool for inventorying LDAP-readable Active Directory data, identifying security-relevant account configurations, reviewing ACL entries, and generating interactive HTML and JSON reports.

[Repository](https://github.com/CheetaaVX/ADscope) · [Source](https://github.com/CheetaaVX/ADscope/blob/main/adscope.py)

</div>

---

## Overview

ADscope helps security learners and authorized assessors review an Active Directory domain through LDAP. It collects directory information, highlights selected security indicators, and can inspect access control entries (ACEs) relevant to a selected user or to users across the domain.

ADscope is designed for **read-only reconnaissance and auditing**. It does not exploit findings or provide a complete Windows effective-access or attack-path calculation engine.

## Features

- **LDAP connection handling**
  - Attempts LDAPS first, then LDAP with StartTLS.
  - Unencrypted LDAP fallback is disabled unless explicitly enabled.
  - Supports `ntlm` and `simple` authentication.
  - Configurable LDAP/LDAPS ports and connection timeout.
- **Directory inventory**
  - Users, groups, computers, domain trusts, and Group Policy Object (GPO) metadata.
  - Selected user attributes and security-relevant `userAccountControl` flags.
- **Security observations**
  - Accounts with Kerberos pre-authentication disabled.
  - `PASSWD_NOTREQD` and password-never-expires indicators.
  - Accounts with service principal names (SPNs) and `adminCount=1`.
  - Unconstrained/constrained delegation indicators and populated resource-based constrained delegation (RBCD) attributes.
- **ACL permission review**
  - Review ACL entries for a selected user and resolved group relationships.
  - Optional domain-wide ACL review for users.
  - Highlights rights such as `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `WriteSPN`, and relevant property-write access when represented by matching ACEs.
  - Interactive, BloodHound-style graph for selected-user permission relationships.
- **Reports**
  - Searchable, filterable dark-themed HTML dashboard.
  - JSON report output.
  - Interactive tables and permission graph, with browser print/PDF support.
- **Connection diagnostics**
  - Records connection attempts and errors to help troubleshoot LDAP, TLS, and authentication issues.

## Requirements

- Python 3.10 or newer
- Network access to an authorized Active Directory domain controller
- Python packages: `ldap3` and `impacket`

## Installation

```bash
git clone https://github.com/CheetaaVX/ADscope.git
cd ADscope

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install ldap3 impacket
```

On Windows, activate the virtual environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Check the available arguments:

```bash
python adscope.py --help
```

## Usage

ADscope prompts for the LDAP password if `-p/--password` is omitted. This is recommended to avoid exposing the password in shell history.

### Basic domain inventory

```bash
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst'
```

### Review ACLs for one user

```bash
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst' \
  -c 'target.user'
```

### Review ACLs for domain users

```bash
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst' \
  -A
```

### Run both ACL review modes

```bash
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst' \
  -c 'target.user' -A
```

### Choose an output path

```bash
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst' \
  -o reports/domain-review
```

This writes `reports/domain-review.json` and, unless HTML output is disabled, `reports/domain-review.html`.

### JSON only

```bash
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst' \
  --json-only -o reports/domain-review
```

### Simple bind

```bash
python adscope.py -t dc.corp.example -d corp.example -u 'analyst@corp.example' \
  --auth simple
```

Simple bind should only be used with appropriate transport protection. Prefer LDAPS or StartTLS.

### Lab-only connection options

```bash
# Permit unencrypted LDAP fallback (lab use only)
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst' --plain

# Disable TLS certificate validation (lab use only)
python adscope.py -t 10.10.10.10 -d corp.example -u 'analyst' -k
```

**Security note:** `--plain` may expose credentials if the connection falls back to unencrypted LDAP. `-k` disables TLS certificate validation. Use these options only in controlled labs when you understand the risks.

## Command-line options

| Option | Description |
|---|---|
| `-t`, `--dc` | Domain controller hostname or IP (**required**) |
| `-d`, `--domain` | Active Directory DNS domain (**required**) |
| `-u`, `--username` | Account name or UPN (**required**) |
| `-p`, `--password` | Password; omitted by default to prompt securely |
| `--auth` | Bind type: `ntlm` (default) or `simple` |
| `--ldaps-port` | LDAPS port (default: `636`) |
| `--ldap-port` | LDAP port (default: `389`) |
| `--plain`, `--allow-plain-ldap` | Allow unencrypted LDAP fallback (lab only) |
| `-k`, `--insecure-tls` | Skip TLS certificate validation (lab only) |
| `--timeout` | Connection timeout in seconds (default: `6`) |
| `-c`, `--check-user` | Review ACLs for one user by `sAMAccountName` or UPN |
| `-A`, `--all-user-acls` | Review ACL permissions for all domain users |
| `-L`, `--acl-limit` | Maximum directory objects to inspect (default: `5000`) |
| `-o`, `--output` | Output path prefix without extension (default: `reports/adscope`) |
| `--json-only`, `--no-html` | Write JSON only; skip the HTML dashboard |
| `-h`, `--help` | Show help |

A password can also be provided through the `ADRECON_PASSWORD` environment variable. Prefer the interactive prompt where possible.

## Output

By default, ADscope writes reports with the prefix `reports/adscope`:

- `reports/adscope.json` — structured findings and inventory.
- `reports/adscope.html` — interactive HTML dashboard.

The dashboard includes inventory tables, security observations, connection diagnostics, and ACL review results when those options are selected.

Treat reports as sensitive: they may contain usernames, distinguished names, group membership, hostnames, and security configuration details.

## Important limitations

- ADscope reviews LDAP-readable data and matching ACEs; it is **not** a complete Windows effective-permissions or attack-path engine.
- Results may not capture every inheritance or protected-ACL nuance, object-specific rights/schema GUID interpretation, conditional ACE, `SIDHistory`, token privilege, or Windows authorization rule.
- A populated RBCD attribute is an indicator to investigate, not proof that it is exploitable.
- Findings depend on the privileges of the account used, LDAP server policy, query limits, and the accessible directory data.
- Manually validate findings before drawing conclusions or making remediation decisions.

## Troubleshooting

| Problem | What to check |
|---|---|
| LDAP bind rejected / error 49 | Verify domain, credentials, username format, and `--auth` mode. |
| LDAPS connection fails | Check port `636`, the DC certificate, certificate trust, and TLS settings. |
| StartTLS fails | Check port `389`, network reachability, and the domain controller's LDAP/TLS policy. |
| User cannot be resolved | Verify the account exists in the selected domain and use its supported account name or UPN. |
| Results appear incomplete | Check LDAP permissions, the `--acl-limit` value, and connection diagnostics. |
| HTML dashboard is missing | Confirm `--json-only`/`--no-html` was not supplied. |

## Responsible use

Use ADscope only on systems and Active Directory environments you own or are explicitly authorized to assess. Do not use it to access or collect data from systems without permission. Protect generated reports and credentials.

## License

No license is specified here yet. Add a `LICENSE` file and update this section before presenting the project as open source under a particular license.
