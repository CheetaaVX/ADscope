#!/usr/bin/env python3


#Dependencies:
  # pip install ldap3 impacket


from __future__ import annotations

import argparse
import getpass
import html
import json
import os
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ldap3 import ALL, BASE, NONE, NTLM, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

try:
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    security_descriptor_control = None

try:
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
except ImportError:
    SR_SECURITY_DESCRIPTOR = None

# Muted charcoal / slate palette with restrained cyan, blue, amber and red accents.
C = {
    "reset": "\033[0m", "muted": "\033[90m", "cyan": "\033[96m",
    "blue": "\033[94m", "green": "\033[92m", "yellow": "\033[93m",
    "red": "\033[91m", "white": "\033[97m",
}


def color(text: str, shade: str) -> str:
    return f"{C.get(shade, '')}{text}{C['reset']}" if sys.stdout.isatty() else text


def banner() -> None:
    print(color(r"""
    █▀█ █▀▄ █▀▀ █▀▀ █▀█ █▀█ █▀▀
    █▀█ █ █ ▀▀█ █   █ █ █▀█ █▀ 
    ▀ ▀ █▄▀ ▀▀▀ ▀▀▀ ▀▀▀ █   █▄▄
             ADScope  •  AD reconnaissance & permission analysis
    """, "cyan"))


def say(level: str, message: str) -> None:
    shades = {"+": "green", "*": "cyan", "!": "yellow", "-": "muted", "x": "red"}
    print(f"[{color(level, shades.get(level, 'white'))}] {message}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def value(entry: Any, attr: str, default: Any = None) -> Any:
    try:
        v = entry[attr].value
        return default if v is None else v
    except Exception:
        return default


def raw_value(entry: Any, attr: str) -> bytes | None:
    try:
        vals = entry[attr].raw_values
        return vals[0] if vals else None
    except Exception:
        return None


def as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def format_binary_sid(raw: bytes) -> str:
   
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        raise ValueError("Invalid binary SID")
    revision = raw[0]
    subauth_count = raw[1]
    expected_len = 8 + 4 * subauth_count
    if len(raw) < expected_len:
        raise ValueError("Truncated binary SID")
    identifier_authority = int.from_bytes(raw[2:8], byteorder="big", signed=False)
    subauthorities = [
        int.from_bytes(raw[8 + 4*i:12 + 4*i], byteorder="little", signed=False)
        for i in range(subauth_count)
    ]
    parts = ["S", str(revision), str(identifier_authority), *map(str, subauthorities)]
    return "-".join(parts)


def sid_of(entry: Any) -> str | None:
    raw = raw_value(entry, "objectSid")
    if not raw:
        return None
    try:
        return format_binary_sid(raw)
    except (ValueError, TypeError, IndexError):
        return None


def bool_flag(number: Any, bit: int) -> bool:
    try:
        return (int(number) & bit) != 0
    except (ValueError, TypeError):
        return False


def safe_json(value_: Any) -> Any:
    if isinstance(value_, bytes):
        return value_.hex()
    if isinstance(value_, (datetime,)):
        return value_.isoformat()
    if isinstance(value_, (list, tuple, set)):
        return [safe_json(x) for x in value_]
    if isinstance(value_, dict):
        return {str(k): safe_json(v) for k, v in value_.items()}
    if value_ is None or isinstance(value_, (str, int, float, bool)):
        return value_
    return str(value_)


def entry_record(entry: Any, attrs: list[str]) -> dict:
    out = {}
    for attr in attrs:
        v = value(entry, attr)
        if attr == "objectSid":
            v = sid_of(entry) or v
        if attr == "userAccountControl" and v is not None:
            try:
                flags = int(v)
                v = {"value": flags, "disabled": bool_flag(flags, 0x2),
                     "password_not_required": bool_flag(flags, 0x20),
                     "dont_require_preauth": bool_flag(flags, 0x400000),
                     "password_never_expires": bool_flag(flags, 0x10000),
                     "trusted_for_delegation": bool_flag(flags, 0x80000)}
            except Exception:
                pass
        out[attr] = safe_json(v)
    return out


def ldap_search(conn: Connection, base_dn: str, search_filter: str,
                attributes: list[str], page_size: int = 500, controls=None,
                max_entries: int | None = None) -> list:
    """Paged search; optional server-side controls are passed to every page."""
    found, cookie = [], None
    while True:
        kwargs = {"search_base": base_dn, "search_filter": search_filter,
                  "search_scope": SUBTREE, "attributes": attributes,
                  "paged_size": page_size}
        if cookie:
            kwargs["paged_cookie"] = cookie
        if controls:
            kwargs["controls"] = controls
        conn.search(**kwargs)
        found.extend(e for e in conn.entries if getattr(e, "entry_dn", None))
        if max_entries is not None and len(found) >= max_entries:
            return found[:max_entries]
        try:
            cookie = conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
        except Exception:
            cookie = None
        if not cookie:
            break
    return found


def bind_connection(args, password: str):
    """Try secure LDAP modes first; plain LDAP is opt-in only."""
    user = args.username
    if args.auth == "ntlm" and "\\" not in user:
        # Accept either a short account name or a UPN for convenience.
        if "@" in user:
            user = user.split("@", 1)[0]
        user = f"{args.domain}\\{user}"
    if args.auth == "simple":
        auth = SIMPLE
        bind_user = user
    else:
        auth = NTLM
        bind_user = user

    tls_validate = ssl.CERT_NONE if args.insecure_tls else ssl.CERT_REQUIRED
    tls = Tls(validate=tls_validate, version=ssl.PROTOCOL_TLS_CLIENT)
    attempts = [
        ("LDAPS", args.ldaps_port, True, False),
        ("LDAP+StartTLS", args.ldap_port, False, True),
    ]
    if args.allow_plain_ldap:
        attempts.append(("PLAIN LDAP (unencrypted)", args.ldap_port, False, False))

    diagnostics = []
    for label, port, use_ssl, use_starttls in attempts:
        conn = None
        try:
            say("*", f"Trying {label} on {args.dc}:{port} ...")
            server = Server(args.dc, port=port, use_ssl=use_ssl, get_info=ALL,
                            tls=tls if use_ssl or use_starttls else None,
                            connect_timeout=args.timeout)
            conn = Connection(server, user=bind_user, password=password,
                              authentication=auth, auto_bind=False,
                              receive_timeout=args.timeout, raise_exceptions=False)
            conn.open()
            if use_starttls:
                if not conn.start_tls():
                    raise RuntimeError(f"StartTLS failed: {conn.result}")
            if not conn.bind():
                raise RuntimeError(f"Bind failed: {conn.result}")
            say("+", f"Connected and authenticated using {label}.")
            return conn, label, diagnostics
        except Exception as exc:
            detail = str(exc)
            diagnostics.append({"mode": label, "port": port, "success": False,
                                "error": detail[:700]})
            if "data 52e" in detail or "invalidCredentials" in detail:
                say("!", f"{label} rejected the bind credentials/identity (LDAP 49 / data 52e). Check --auth and username format.")
            else:
                say("!", f"{label} failed: {detail[:220]}")
            if conn:
                try:
                    conn.unbind()
                except Exception:
                    pass
    raise RuntimeError("All permitted LDAP connection methods failed. " +
                       "Review connection diagnostics and DC LDAP policy.")


def enumerate_domain(conn: Connection, domain_dn: str) -> dict:
    user_attrs = ["cn", "displayName", "sAMAccountName", "userPrincipalName", "mail",
                  "description", "department", "title", "manager", "memberOf",
                  "adminCount", "userAccountControl", "pwdLastSet", "lastLogonTimestamp",
                  "servicePrincipalName", "whenCreated", "objectSid", "primaryGroupID"]
    group_attrs = ["cn", "sAMAccountName", "description", "member", "memberOf",
                   "adminCount", "objectSid", "groupType", "whenCreated"]
    computer_attrs = ["cn", "dNSHostName", "sAMAccountName", "operatingSystem",
                      "operatingSystemVersion", "description", "userAccountControl",
                      "servicePrincipalName", "msDS-AllowedToDelegateTo",
                      "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectSid", "whenCreated"]
    say("*", "Enumerating users, groups, computers, trusts and GPO metadata ...")
    users = ldap_search(conn, domain_dn,
        "(&(objectCategory=person)(objectClass=user))", user_attrs)
    groups = ldap_search(conn, domain_dn, "(objectCategory=group)", group_attrs)
    computers = ldap_search(conn, domain_dn, "(objectCategory=computer)", computer_attrs)
    trusts = ldap_search(conn, domain_dn, "(objectClass=trustedDomain)",
                         ["cn", "trustPartner", "trustDirection", "trustType",
                          "trustAttributes", "whenCreated"])
    gpo_dn = f"CN=Policies,CN=System,{domain_dn}"
    try:
        gpos = ldap_search(conn, gpo_dn, "(objectClass=groupPolicyContainer)",
                           ["displayName", "name", "gPCFileSysPath", "versionNumber",
                            "flags", "whenCreated", "whenChanged"])
    except Exception:
        gpos = []
    u_records = [entry_record(e, user_attrs) for e in users]
    g_records = [entry_record(e, group_attrs) for e in groups]
    c_records = [entry_record(e, [a for a in computer_attrs if a != "msDS-AllowedToActOnBehalfOfOtherIdentity"]) for e in computers]
    t_records = [entry_record(e, ["cn", "trustPartner", "trustDirection", "trustType",
                                  "trustAttributes", "whenCreated"]) for e in trusts]
    p_records = [entry_record(e, ["displayName", "name", "gPCFileSysPath", "versionNumber",
                                  "flags", "whenCreated", "whenChanged"]) for e in gpos]

    findings = []
    for u in users:
        name = value(u, "sAMAccountName", value(u, "cn", "unknown"))
        uac = value(u, "userAccountControl", 0)
        if bool_flag(uac, 0x400000):
            findings.append({"severity": "High", "category": "Kerberos", "title": "Kerberos pre-authentication disabled",
                             "object": name, "detail": "Account does not require Kerberos pre-authentication; review exposure to offline AS-REP cracking."})
        if bool_flag(uac, 0x20):
            findings.append({"severity": "High", "category": "Account hygiene", "title": "Password not required flag set",
                             "object": name, "detail": "PASSWD_NOTREQD is set. Verify password policy and account configuration."})
        if bool_flag(uac, 0x10000):
            findings.append({"severity": "Medium", "category": "Account hygiene", "title": "Password never expires",
                             "object": name, "detail": "Password expiration is disabled for this account."})
        if value(u, "adminCount") == 1 or str(value(u, "adminCount")) == "1":
            findings.append({"severity": "Info", "category": "Privileged accounts", "title": "adminCount=1",
                             "object": name, "detail": "Often associated with protected/privileged accounts; confirm actual group membership."})
        if as_list(value(u, "servicePrincipalName")):
            findings.append({"severity": "Info", "category": "Kerberos", "title": "User account has SPN",
                             "object": name, "detail": "Review whether this service account has a strong managed password and whether Kerberoasting exposure is acceptable."})
    for c in computers:
        name = value(c, "dNSHostName", value(c, "cn", "unknown"))
        uac = value(c, "userAccountControl", 0)
        if bool_flag(uac, 0x80000):
            findings.append({"severity": "High", "category": "Delegation", "title": "Unconstrained delegation enabled",
                             "object": name, "detail": "Computer account has TRUSTED_FOR_DELEGATION set; validate necessity and exclusions."})
        delegates = as_list(value(c, "msDS-AllowedToDelegateTo"))
        if delegates:
            findings.append({"severity": "Medium", "category": "Delegation", "title": "Constrained delegation configured",
                             "object": name, "detail": "; ".join(map(str, delegates))})
        rbcd = raw_value(c, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        if rbcd:
            findings.append({"severity": "Medium", "category": "Delegation", "title": "RBCD configured",
                             "object": name, "detail": "msDS-AllowedToActOnBehalfOfOtherIdentity is populated. Review the embedded security descriptor to verify which principals are trusted; configuration alone is not proof of abuse."})
    return {"users": u_records, "groups": g_records, "computers": c_records,
            "trusts": t_records, "gpos": p_records, "findings": findings}


def resolve_check_user(conn: Connection, domain_dn: str, supplied: str):
 
    raw = supplied.strip()
    candidates = [raw]
    if "\\" in raw:
        candidates.append(raw.rsplit("\\", 1)[-1])
    if "@" in raw:
        candidates.append(raw.split("@", 1)[0])
    # Preserve order while removing duplicate selectors.
    candidates = list(dict.fromkeys(x for x in candidates if x))
    attrs = ["cn", "sAMAccountName", "userPrincipalName", "distinguishedName",
             "objectSid", "primaryGroupID", "memberOf"]
    for candidate in candidates:
        escaped = escape_filter_chars(candidate)
        filt = f"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={escaped})(userPrincipalName={escaped})(distinguishedName={escaped})))"
        matches = ldap_search(conn, domain_dn, filt, attrs, max_entries=3)
        if not matches:
            continue
        # One selector should resolve to one directory object; if it matches
        # multiple objects, fail explicitly instead of choosing arbitrarily.
        unique = {value(e, "distinguishedName", e.entry_dn): e for e in matches}
        if len(unique) > 1:
            raise ValueError(f"User selector {candidate!r} matched multiple objects; use the exact sAMAccountName or DN.")
        return next(iter(unique.values()))
    tried = ", ".join(repr(x) for x in candidates)
    raise ValueError(f"Could not resolve user {supplied!r}. Tried sAMAccountName, UPN and DN selectors: {tried}. Verify the account exists in the selected domain and is visible to this bind account.")


def check_user_acl_permissions(conn: Connection, domain_dn: str, user_selector: str,
                               limit: int = 500) -> dict:
    """Report ACL ACEs for the user and known nested group SIDs.

    This is an ACL exposure review, not a full Windows AuthZ evaluation: object-specific
    GUIDs, conditional ACEs, dynamic token details and every inheritance nuance are not
    resolved. Review flagged entries manually before making security conclusions.
    """
    if SR_SECURITY_DESCRIPTOR is None or security_descriptor_control is None:
        raise RuntimeError("User ACL review needs impacket and ldap3 with security descriptor support. Install: pip install -U ldap3 impacket")
    user = resolve_check_user(conn, domain_dn, user_selector)
    user_dn = value(user, "distinguishedName", user.entry_dn)
    user_sid = sid_of(user)
    if not user_sid:
        raise RuntimeError("Resolved user has no readable objectSid.")
    sid_names = {user_sid: f"USER: {value(user, 'sAMAccountName', user_selector)}"}
    effective_sids = {user_sid}
    # Include transitive groups using AD's matching-rule-in-chain LDAP rule.
    escaped_dn = escape_filter_chars(user_dn)
    nested_filter = f"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={escaped_dn}))"
    try:
        groups = ldap_search(conn, domain_dn, nested_filter,
                             ["cn", "sAMAccountName", "objectSid", "distinguishedName"], max_entries=3000)
    except Exception as exc:
        groups = []
        say("!", f"Nested group expansion failed; direct user ACEs will still be checked: {exc}")
    graph_groups = []
    for g in groups:
        sid = sid_of(g)
        if sid:
            group_name = str(value(g, "sAMAccountName", value(g, "cn", sid)))
            group_dn = str(value(g, "distinguishedName", g.entry_dn))
            effective_sids.add(sid)
            sid_names[sid] = f"GROUP: {group_name}"
            graph_groups.append({"name": group_name, "dn": group_dn, "sid": sid})
    # Include the user's primary group (commonly Domain Users), which is not always in memberOf.
    try:
        base = ldap_search(conn, domain_dn, "(objectClass=domain)", ["objectSid"], max_entries=1)
        domain_sid = sid_of(base[0]) if base else None
        pgid = value(user, "primaryGroupID")
        if domain_sid and pgid is not None:
            primary_sid = f"{domain_sid}-{int(pgid)}"
            effective_sids.add(primary_sid)
            sid_names.setdefault(primary_sid, "PRIMARY GROUP (SID synthesized from primaryGroupID)")
    except Exception:
        pass

    say("*", f"Checking ACL entries for {value(user, 'sAMAccountName', user_selector)} and {len(effective_sids)-1} group SID(s) ...")
    controls = security_descriptor_control(sdflags=0x04)  # DACL only
    attrs = ["distinguishedName", "objectClass", "sAMAccountName", "cn", "nTSecurityDescriptor"]
    # Do not filter on nTSecurityDescriptor presence: some AD LDAP servers do not
    # support reliable presence filtering for this constructed/security-sensitive
    # attribute. Search directory objects and request the DACL via the SD control.
    entries = ldap_search(conn, domain_dn, "(objectClass=*)", attrs,
                          page_size=200, controls=controls, max_entries=limit)
    acl_hits, parse_errors = [], 0
    rights = [
        (0x10000000, "GENERIC_ALL"), (0x40000000, "GENERIC_WRITE"),
        (0x80000000, "GENERIC_READ"), (0x00040000, "WRITE_DAC"),
        (0x00080000, "WRITE_OWNER"), (0x00010000, "DELETE"),
        (0x00000001, "CREATE_CHILD"), (0x00000002, "DELETE_CHILD"),
        (0x00000004, "LIST_CHILDREN"), (0x00000008, "SELF"),
        (0x00000010, "READ_PROPERTY"), (0x00000020, "WRITE_PROPERTY"),
        (0x00000040, "DELETE_TREE"), (0x00000080, "LIST_OBJECT"),
        (0x00000100, "CONTROL_ACCESS"),
    ]
    for e in entries:
        blob = raw_value(e, "nTSecurityDescriptor")
        if not blob:
            continue
        try:
            sd = SR_SECURITY_DESCRIPTOR(data=blob)
            dacl = sd["Dacl"]
            if not dacl:
                continue
            for ace in dacl.aces:
                try:
                    ace_type = int(ace["AceType"])
                    ace_obj = ace["Ace"]
                    ace_sid = ace_obj["Sid"].formatCanonical()
                    if ace_sid not in effective_sids:
                        continue
                    mask = int(ace_obj["Mask"]["Mask"])
                    names = [n for bit, n in rights if mask & bit]
                    # AD commonly represents GenericWrite as an all-properties
                    # WRITE_PROPERTY ACE rather than retaining the generic mask bit.
                    # Label this as inferred, not as a raw GENERIC_WRITE mask.
                    object_specific = False
                    object_guid = None
                    try:
                        ace_flags_field = int(ace_obj["Flags"])
                        object_specific = bool(ace_flags_field & 0x1)  # ACE_OBJECT_TYPE_PRESENT
                        if object_specific:
                            raw_guid = ace_obj["ObjectType"]
                            if isinstance(raw_guid, (bytes, bytearray)) and len(raw_guid) == 16:
                                object_guid = str(uuid.UUID(bytes_le=bytes(raw_guid)))
                            else:
                                object_guid = str(raw_guid).strip("{}")
                    except Exception:
                        pass
                    # Attribute-specific property-write checks. GUID matching is a lead;
                    # validate ACE type, mask, inheritance and effective access manually.
                    if (mask & 0x00000020) and object_guid == "28630ebf-41d5-11d1-a9c1-0000f80367c1":
                        names.append("WRITE_SPN_ATTRIBUTE")
                    if (mask & 0x00000020) and object_guid == "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79":
                        names.append("WRITE_RBCD_ATTRIBUTE")
                    if (mask & 0x00000020) and not object_specific:
                        names.append("POTENTIAL_GENERIC_WRITE (all-properties WRITE_PROPERTY)")
                    if not names:
                        names = [f"ACCESS_MASK_0x{mask:08x}"]
                    flags = int(ace["AceFlags"])
                    deny_types = (1, 6, 10, 12)
                    allow_types = (0, 5, 9, 11)
                    effect = "Deny" if ace_type in deny_types else ("Allow" if ace_type in allow_types else "Other")
                    target = value(e, "distinguishedName", e.entry_dn)
                    object_class = ", ".join(map(str, as_list(value(e, "objectClass"))))
                    sam = value(e, "sAMAccountName")
                    cn = value(e, "cn")
                    object_name = sam or cn or target
                    high_impact = [r for r in names if r in ("GENERIC_ALL", "GENERIC_WRITE", "POTENTIAL_GENERIC_WRITE (all-properties WRITE_PROPERTY)", "WRITE_DAC", "WRITE_OWNER", "WRITE_PROPERTY", "WRITE_SPN_ATTRIBUTE", "WRITE_RBCD_ATTRIBUTE", "CREATE_CHILD", "DELETE_CHILD", "CONTROL_ACCESS")]
                    acl_hits.append({
                        "object": target, "object_name": object_name,
                        "object_class": object_class,
                        "trustee": sid_names.get(ace_sid, ace_sid), "sid": ace_sid,
                        "ace_type": ace_type, "effect": effect,
                        "rights": names, "high_impact_rights": high_impact,
                        "mask_hex": f"0x{mask:08x}",
                        "inherited": bool(flags & 0x10),
                        "object_specific_guid_present": object_specific,
                        "note": "Object-specific GUID rights may need interpretation" if ace_type in (5, 6, 7, 8, 11, 12) else ("WRITE_PROPERTY applies to all properties; review as potential GenericWrite" if "POTENTIAL_GENERIC_WRITE (all-properties WRITE_PROPERTY)" in names else ""),
                    })
                except Exception:
                    continue
        except Exception:
            parse_errors += 1
    acl_hits.sort(key=lambda x: (x["effect"] != "Allow", x["object"], x["trustee"]))
    # Summarize rights by name and list concrete objects with high-impact allow ACEs.
    right_counts = {}
    for hit in acl_hits:
        if hit["effect"] != "Allow":
            continue
        for right in hit["rights"]:
            right_counts[right] = right_counts.get(right, 0) + 1
    high_impact_entries = [
        hit for hit in acl_hits
        if hit["effect"] == "Allow" and any(
            right in hit["rights"] for right in
            ("GENERIC_ALL", "GENERIC_WRITE", "WRITE_DAC", "WRITE_OWNER", "WRITE_PROPERTY")
        )
    ]
    return {
        "selector": user_selector, "user": value(user, "sAMAccountName", user_selector),
        "user_dn": user_dn, "user_sid": user_sid,
        "matched_group_count": max(0, len(effective_sids) - 1),
        "groups": graph_groups,
        "checked_object_count": len(entries), "object_limit": limit,
        "truncated_possible": len(entries) >= limit, "parse_errors": parse_errors,
        "matched_acl_entries": acl_hits,
        "allow_right_counts": right_counts,
        "high_impact_entries": high_impact_entries,
        "allow_ace_count": sum(1 for hit in acl_hits if hit["effect"] == "Allow"),
        "deny_ace_count": sum(1 for hit in acl_hits if hit["effect"] == "Deny"),
        "method_note": "Shows DACL ACEs matching the user's SID, transitive group SIDs and synthesized primary-group SID. This is not a full Windows effective-access calculation; inherited ACLs, object-specific GUIDs, conditional ACEs, SIDHistory and token privileges can affect the real result.",
    }



def check_all_users_acl_permissions(conn: Connection, domain_dn: str, limit: int = 5000) -> dict:
    
    if SR_SECURITY_DESCRIPTOR is None or security_descriptor_control is None:
        raise RuntimeError("All-user ACL review needs impacket and ldap3 security-descriptor support. Install: pip install -U ldap3 impacket")

    users = ldap_search(conn, domain_dn, "(&(objectCategory=person)(objectClass=user))",
                        ["cn", "sAMAccountName", "distinguishedName", "objectSid", "primaryGroupID" ])
    domain_entries = ldap_search(conn, domain_dn, "(objectClass=domain)", ["objectSid"], max_entries=1)
    domain_sid = sid_of(domain_entries[0]) if domain_entries else None
    # Maps trustee SID -> user account names for direct and group-derived ACEs.
    sid_to_users: dict[str, set[str]] = {}
    user_sids: dict[str, str] = {}
    group_cache: dict[str, list[tuple[str, str]]] = {}
    for user in users:
        name = str(value(user, "sAMAccountName", value(user, "cn", user.entry_dn)))
        user_sid = sid_of(user)
        if not user_sid:
            continue
        user_sids[name] = user_sid
        sid_to_users.setdefault(user_sid, set()).add(name)
        dn = str(value(user, "distinguishedName", user.entry_dn))
        escaped_dn = escape_filter_chars(dn)
        try:
            groups = ldap_search(conn, domain_dn,
                f"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={escaped_dn}))",
                ["cn", "sAMAccountName", "objectSid"], max_entries=3000)
        except Exception as exc:
            groups = []
            say("!", f"Nested group lookup failed for {name}; direct ACEs still checked: {exc}")
        group_list = []
        for group in groups:
            gs = sid_of(group)
            if not gs:
                continue
            gname = str(value(group, "sAMAccountName", value(group, "cn", gs)))
            sid_to_users.setdefault(gs, set()).add(name)
            group_list.append((gs, gname))
        pgid = value(user, "primaryGroupID")
        if domain_sid and pgid is not None:
            psid = f"{domain_sid}-{int(pgid)}"
            sid_to_users.setdefault(psid, set()).add(name)
            group_list.append((psid, "PRIMARY_GROUP"))
        group_cache[name] = group_list

    say("*", f"Scanning ACLs once for {len(user_sids)} domain users (including known nested groups) ...")
    controls = security_descriptor_control(sdflags=0x04)
    attrs = ["distinguishedName", "objectClass", "sAMAccountName", "cn", "nTSecurityDescriptor"]
    entries = ldap_search(conn, domain_dn, "(objectClass=*)", attrs,
                          page_size=200, controls=controls, max_entries=limit)
    rights = [
        (0x10000000, "GENERIC_ALL"), (0x40000000, "GENERIC_WRITE"),
        (0x80000000, "GENERIC_READ"), (0x00040000, "WRITE_DAC"),
        (0x00080000, "WRITE_OWNER"), (0x00010000, "DELETE"),
        (0x00000001, "CREATE_CHILD"), (0x00000002, "DELETE_CHILD"),
        (0x00000004, "LIST_CHILDREN"), (0x00000008, "SELF"),
        (0x00000010, "READ_PROPERTY"), (0x00000020, "WRITE_PROPERTY"),
        (0x00000040, "DELETE_TREE"), (0x00000080, "LIST_OBJECT"),
        (0x00000100, "CONTROL_ACCESS"),
    ]
    # Schema attribute GUIDs in canonical UUID form.
    spn_guid = "28630ebf-41d5-11d1-a9c1-0000f80367c1"
    rbcd_guid = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
    hits, parse_errors = [], 0
    for entry in entries:
        blob = raw_value(entry, "nTSecurityDescriptor")
        if not blob:
            continue
        try:
            sd = SR_SECURITY_DESCRIPTOR(data=blob)
            dacl = sd["Dacl"]
            if not dacl:
                continue
            target = str(value(entry, "distinguishedName", entry.entry_dn))
            object_class = ", ".join(map(str, as_list(value(entry, "objectClass"))))
            object_name = str(value(entry, "sAMAccountName", value(entry, "cn", target)))
            for ace in dacl.aces:
                try:
                    ace_type = int(ace["AceType"])
                    ace_obj = ace["Ace"]
                    trustee_sid = ace_obj["Sid"].formatCanonical()
                    matched_users = sid_to_users.get(trustee_sid)
                    if not matched_users:
                        continue
                    mask = int(ace_obj["Mask"]["Mask"])
                    names = [n for bit, n in rights if mask & bit]
                    object_guid = None
                    object_specific = False
                    try:
                        obj_flags = int(ace_obj["Flags"])
                        object_specific = bool(obj_flags & 0x1)
                        if object_specific:
                            raw_guid = ace_obj["ObjectType"]
                            if isinstance(raw_guid, (bytes, bytearray)) and len(raw_guid) == 16:
                                object_guid = str(uuid.UUID(bytes_le=bytes(raw_guid)))
                            else:
                                object_guid = str(raw_guid).strip("{}")
                    except Exception:
                        pass
                    if mask & 0x20 and object_guid == spn_guid:
                        names.append("WRITE_SPN_ATTRIBUTE")
                    if mask & 0x20 and object_guid == rbcd_guid:
                        names.append("WRITE_RBCD_ATTRIBUTE")
                    if mask & 0x20 and not object_specific:
                        names.append("POTENTIAL_GENERIC_WRITE (all-properties WRITE_PROPERTY)")
                    if not names:
                        names = [f"ACCESS_MASK_0x{mask:08x}"]
                    flags = int(ace["AceFlags"])
                    effect = "Deny" if ace_type in (1, 6, 10, 12) else ("Allow" if ace_type in (0, 5, 9, 11) else "Other")
                    high = [r for r in names if r in (
                        "GENERIC_ALL", "GENERIC_WRITE", "POTENTIAL_GENERIC_WRITE (all-properties WRITE_PROPERTY)",
                        "WRITE_DAC", "WRITE_OWNER", "WRITE_PROPERTY", "WRITE_SPN_ATTRIBUTE",
                        "WRITE_RBCD_ATTRIBUTE", "CREATE_CHILD", "DELETE_CHILD", "CONTROL_ACCESS")]
                    for username in sorted(matched_users):
                        hits.append({
                            "user": username, "trustee_sid": trustee_sid,
                            "trustee_type": "direct or group-derived (see SID)",
                            "target_name": object_name, "object": target, "object_class": object_class,
                            "effect": effect, "rights": names, "high_impact_rights": high,
                            "mask_hex": f"0x{mask:08x}", "inherited": bool(flags & 0x10),
                            "object_specific_guid": object_guid,
                            "note": "Verify object-specific GUID and effective access; this report does not fully emulate Windows authorization." if object_specific else "",
                        })
                except Exception:
                    continue
        except Exception:
            parse_errors += 1
    hits.sort(key=lambda h: (h["user"].lower(), h["effect"] != "Allow", h["target_name"].lower()))
    return {
        "user_count": len(user_sids), "checked_object_count": len(entries),
        "object_limit": limit, "truncated_possible": len(entries) >= limit,
        "parse_errors": parse_errors, "entries": hits,
        "high_impact_entries": [h for h in hits if h["effect"] == "Allow" and h["high_impact_rights"]],
        "method_note": "One-pass DACL scan for all domain users, matching direct SIDs, nested group SIDs returned by AD matching-rule-in-chain, and synthesized primary-group SIDs. Not a complete effective-access or attack-path analysis; SIDHistory, conditional ACEs, deny evaluation, protected ACL nuances, and GUID semantics may affect results. Attribute GUID checks identify WriteSPN and RBCD-attribute writes when represented as object-specific WriteProperty ACEs."
    }

def summary(data: dict) -> dict:
    findings = data.get("findings", [])
    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ("Critical", "High", "Medium", "Low", "Info")}
    return {"users": len(data.get("users", [])), "groups": len(data.get("groups", [])),
            "computers": len(data.get("computers", [])), "trusts": len(data.get("trusts", [])),
            "gpos": len(data.get("gpos", [])), "findings": len(findings), "severity": counts}


def build_html(report: dict, out_path: Path) -> None:
    """Create a self-contained, dark-slate HTML report with client-side search/filter."""
    payload = json.dumps(safe_json(report), ensure_ascii=False).replace("</", "<\\/")
    title = html.escape(report.get("domain", "AD") + " — ADScope Report")
    document = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title><style>
:root{
 --bg:#10151d;--panel:#171f2a;--panel2:#1d2835;--line:#2d3a4a;--text:#e8eef6;--muted:#94a5b8;
 --cyan:#67d5e8;--blue:#8bb7ff;--green:#78d6a3;--amber:#f0c36d;--red:#ff8585;--purple:#c7a5ff;
 --shadow:0 14px 36px #0003;--radius:16px
 }
 *{box-sizing:border-box}
 html{scroll-behavior:smooth;scroll-padding-top:18px}
 body{margin:0;background:radial-gradient(ellipse at 8% 0%,#243446 0,transparent 36%),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
 a{color:var(--cyan)}
 .wrap{width:min(100% - 48px,1640px);margin:0 auto;padding:28px 0 36px}
 .hero{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:28px;padding:clamp(22px,3vw,36px);border:1px solid var(--line);border-radius:22px;background:linear-gradient(125deg,#202f3e 0%,#19222e 58%,#171f2a 100%);box-shadow:var(--shadow)}
 .eyebrow{text-transform:uppercase;letter-spacing:.16em;color:var(--cyan);font-size:11px;font-weight:800}
 .hero h1{font-size:clamp(27px,3.2vw,42px);line-height:1.12;margin:10px 0 8px;letter-spacing:-.045em}
 .sub{color:var(--muted);overflow-wrap:anywhere}
 .meta{text-align:right;color:var(--muted);font-size:12px;max-width:270px}
 .pill{display:inline-flex;align-items:center;max-width:100%;padding:6px 11px;border:1px solid #3b5264;border-radius:999px;background:#15232e;color:var(--cyan);font-size:11px;font-weight:750;overflow-wrap:anywhere}
 .nav{display:flex;gap:7px;flex-wrap:wrap;margin:18px 0 24px;padding:10px;border:1px solid var(--line);border-radius:14px;background:#141b24}
 .nav a{text-decoration:none;color:var(--muted);padding:8px 11px;border:1px solid transparent;border-radius:8px;background:transparent;font-size:12px;font-weight:650;white-space:nowrap}
 .nav a:hover,.nav a:focus-visible{color:var(--text);border-color:#3b596a;background:#20303c;outline:none}
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin:16px 0 24px}
 .card{min-width:0;padding:18px 20px;border:1px solid var(--line);border-radius:var(--radius);background:linear-gradient(145deg,#1b2531,#171f29);box-shadow:0 6px 18px #0002}
 .card .n{font-size:clamp(24px,2.1vw,32px);line-height:1.2;font-weight:800;letter-spacing:-.045em;overflow-wrap:anywhere}
 .card .k{color:var(--muted);font-size:12px;margin-top:5px}
 .section{margin:22px 0;padding:clamp(18px,2.2vw,28px);border:1px solid var(--line);border-radius:18px;background:linear-gradient(150deg,#19212b,#161d26 75%);box-shadow:0 8px 24px #0001;min-width:0}
 .section h2{margin:0 0 5px;font-size:clamp(18px,1.8vw,22px);line-height:1.3;letter-spacing:-.025em}
 .section h3{margin:20px 0 10px;font-size:15px}
 .section .desc{color:var(--muted);margin:0 0 18px;max-width:1000px}
 .tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:14px 0}
 .tools input,.tools select{min-height:40px;background:#101720;border:1px solid var(--line);border-radius:9px;color:var(--text);padding:9px 12px;outline:none;font:inherit}
 .tools input{flex:1 1 280px;min-width:min(220px,100%)}
 .tools select{flex:0 1 auto;max-width:100%}
 .tools input:focus,.tools select:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #67d5e81c}
 .tablewrap{max-width:100%;overflow:auto;border:1px solid var(--line);border-radius:12px;background:#141b24;scrollbar-color:#405164 #141b24}
 table{border-collapse:separate;border-spacing:0;width:100%;min-width:760px}
 th,td{text-align:left;vertical-align:top;padding:12px 14px;border-bottom:1px solid #2a3542;max-width:420px;overflow-wrap:anywhere}
 th{position:sticky;top:0;z-index:1;background:#222e3b;color:#b9c8d9;font-size:10px;text-transform:uppercase;letter-spacing:.075em;font-weight:800;cursor:pointer;white-space:nowrap}
 th:hover{color:var(--cyan)}
 tbody tr:last-child td{border-bottom:0}
 tbody tr:nth-child(even) td{background:#ffffff03}
 tbody tr:hover td{background:#263544}
 td{color:#dce5ef}
 td.mono{font:12px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;color:#b7c9dc;min-width:150px}
 .badge{display:inline-flex;align-items:center;white-space:nowrap;padding:4px 8px;border-radius:6px;font-size:10px;font-weight:850;letter-spacing:.02em;background:#343d49;color:#d9e2ed}
 .Critical,.High{background:#492b31;color:var(--red)}.Medium{background:#4a3b25;color:var(--amber)}.Low{background:#263d4a;color:var(--cyan)}.Info{background:#303244;color:var(--purple)}
 .notice{border:1px solid #594b31;border-left:3px solid var(--amber);background:#29271f;padding:13px 15px;color:#e6d8b8;border-radius:0 10px 10px 0;margin:14px 0;overflow-wrap:anywhere}
 .empty{padding:28px 18px;color:var(--muted);text-align:center;border:1px dashed var(--line);border-radius:10px;background:#141b24}
 .footer{color:var(--muted);font-size:12px;margin:28px 4px 0;padding-top:18px;border-top:1px solid var(--line)}
 .actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
 .btn{background:#263847;border:1px solid #496477;color:var(--text);border-radius:9px;padding:9px 13px;cursor:pointer;font:inherit;font-size:12px;font-weight:700;transition:background .15s,border-color .15s}
 .btn:hover{border-color:var(--cyan);background:#304858}
 .graph-shell{border:1px solid var(--line);border-radius:13px;overflow:hidden;background:#101720;margin:14px 0 20px}
 .graph-toolbar{display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap;padding:11px 13px;border-bottom:1px solid var(--line);background:#17212c}
 .graph-legend{display:flex;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:11px}.legend-item{display:flex;align-items:center;gap:6px}.legend-dot{width:9px;height:9px;border-radius:50%;display:inline-block}
 .graph-viewport{height:min(68vh,760px);min-height:430px;overflow:hidden;position:relative;cursor:grab;touch-action:none}.graph-viewport:active{cursor:grabbing}.graph-viewport svg{display:block;width:100%;height:100%;user-select:none}
 .graph-node{cursor:grab}.graph-node rect{stroke-width:1.5;filter:drop-shadow(0 5px 7px #0005)}.graph-node text{pointer-events:none;font-family:Inter,ui-sans-serif,system-ui,sans-serif}.graph-node .node-type{font-size:10px;letter-spacing:.09em;font-weight:800;fill:#9fb1c5}.graph-node .node-name{font-size:13px;font-weight:750;fill:#edf4fb}.graph-edge{fill:none;stroke-width:1.8;opacity:.78}.graph-edge-label{font-size:10px;fill:#d7e1eb;paint-order:stroke;stroke:#101720;stroke-width:4px;stroke-linejoin:round}.graph-details{padding:12px 14px;border-top:1px solid var(--line);color:var(--muted);font-size:12px;overflow-wrap:anywhere;min-height:42px}
 @media(min-width:1200px){.section{scroll-margin-top:16px}.section#alluseracls,.section#usercheck{padding:28px}}
 @media(max-width:900px){.wrap{width:min(100% - 32px,1640px);padding-top:16px}.hero{grid-template-columns:1fr;gap:18px}.meta{text-align:left;max-width:none}.actions{justify-content:flex-start}.nav{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:thin}.cards{grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}}
 @media(max-width:560px){.wrap{width:calc(100% - 22px);padding-top:11px}.hero{padding:20px;border-radius:16px}.hero h1{font-size:27px}.nav{margin:12px 0 18px;padding:7px;gap:4px}.nav a{padding:8px 9px}.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.card{padding:14px}.section{margin:14px 0;padding:16px;border-radius:14px}.tools{align-items:stretch}.tools input,.tools select{width:100%;flex-basis:100%}th,td{padding:10px 11px}}
 @media print{body{background:#fff;color:#111}.wrap{width:100%;padding:0}.hero,.section,.card,.nav{background:#fff;color:#111;box-shadow:none;border-color:#bbb}.nav,.actions,.tools{display:none!important}.sub,.desc,.footer{color:#444}.section{break-inside:avoid}.tablewrap{overflow:visible}table{min-width:0;font-size:9px}th,td{padding:5px;color:#111;max-width:none}.mono{color:#222!important}.notice{background:#fff;color:#333;border-color:#999}.cards{grid-template-columns:repeat(3,1fr)}}
</style></head><body><main class="wrap"><header class="hero"><div><div class="eyebrow">Read-only security assessment</div><h1>ADScope <span style="color:var(--cyan)">/</span> Domain Report</h1><div class="sub" id="subtitle"></div><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:14px"><span class="pill" id="connection"></span><span class="pill" id="created"></span></div></div><div class="meta"><div>LOCAL HTML REPORT</div><div class="actions" style="margin-top:14px"><button class="btn" onclick="downloadJSON()">Export JSON</button><button class="btn" onclick="window.print()">Print / PDF</button></div></div></header>
<nav class="nav"><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#usercheck">User permissions</a><a href="#alluseracls">All-user ACL audit</a><a href="#users">Users</a><a href="#groups">Groups</a><a href="#computers">Computers</a><a href="#trusts">Trusts</a><a href="#gpos">GPOs</a><a href="#diagnostics">Diagnostics</a></nav>
<div class="cards" id="cards"></div><section class="section" id="overview"><h2>Assessment overview</h2><div class="desc">Collected domain inventory and connection details.</div><div id="overviewContent"></div></section>
<section class="section" id="findings"><h2>Security findings</h2><div class="desc">Findings and observations from the assessment.</div><div class="tools"><input id="findingSearch" placeholder="Search findings by title, object, detail…" oninput="renderFindings()"><select id="severityFilter" onchange="renderFindings()"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select></div><div id="findingTable"></div></section>
<section class="section" id="alluseracls"><h2>All-users ACL audit</h2><div class="desc">Domain-wide DACL review.</div><div id="allAclSummary"></div><div id="allAclTable"></div></section><section class="section" id="usercheck"><h2>Specific-user permission review</h2><div class="desc">Permissions associated with the selected user and groups.</div><div id="aclSummary"></div><div id="aclGraph"></div><div id="aclTable"></div></section>
<section class="section" id="users"><h2>Users</h2><div class="desc">Account attributes and selected security-relevant flags.</div><div id="usersTable"></div></section><section class="section" id="groups"><h2>Groups</h2><div class="desc">Group inventory. Member values are distinguished names.</div><div id="groupsTable"></div></section><section class="section" id="computers"><h2>Computers</h2><div class="desc">Host inventory and delegation-related attributes.</div><div id="computersTable"></div></section><section class="section" id="trusts"><h2>Domain trusts</h2><div id="trustsTable"></div></section><section class="section" id="gpos"><h2>Group Policy Objects</h2><div id="gposTable"></div></section><section class="section" id="diagnostics"><h2>Connection diagnostics</h2><div class="desc">Failed connection methods can help distinguish TLS, network and bind problems.</div><div id="diagnosticsTable"></div></section><div class="footer">Generated by ADScope · AD reconnaissance & permission analysis · Treat this report as sensitive and store it securely.</div></main>
<script>
const R=__DATA__;
const $=id=>document.getElementById(id);
function esc(v){if(v===null||v===undefined)return '';if(typeof v==='object')return esc(JSON.stringify(v));return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function cell(v){if(v===null||v===undefined||v==='')return '<span style="color:var(--muted)">—</span>';if(typeof v==='object')v=JSON.stringify(v);return esc(v)}
function table(data,columns,empty='No data collected.'){if(!data||!data.length)return `<div class="empty">${esc(empty)}</div>`;return `<div class="tablewrap"><table><thead><tr>${columns.map(c=>`<th onclick="sortTable(this)">${esc(c.label)}</th>`).join('')}</tr></thead><tbody>${data.map(row=>`<tr>${columns.map(c=>`<td class="${c.mono?'mono':''}">${c.badge?`<span class="badge ${esc(row[c.key]||'Info')}">${cell(row[c.key])}</span>`:cell(row[c.key])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`}
function sortTable(th){const t=th.closest('table'),idx=[...th.parentNode.children].indexOf(th),body=t.tBodies[0],rows=[...body.rows],asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';rows.sort((a,b)=>a.cells[idx].innerText.localeCompare(b.cells[idx].innerText,undefined,{numeric:true})*(asc?1:-1));rows.forEach(r=>body.appendChild(r));}
function renderFindings(){let q=$('findingSearch').value.toLowerCase(),sev=$('severityFilter').value;let f=(R.data.findings||[]).filter(x=>(!sev||x.severity===sev)&&JSON.stringify(x).toLowerCase().includes(q));$('findingTable').innerHTML=table(f,[{key:'severity',label:'Severity',badge:true},{key:'category',label:'Category'},{key:'title',label:'Finding'},{key:'object',label:'Object',mono:true},{key:'detail',label:'Details'}],'No findings match this filter.');}
function downloadJSON(){const blob=new Blob([JSON.stringify(R,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='adscope-report.json';a.click();URL.revokeObjectURL(a.href)}
$('subtitle').textContent=`Domain: ${R.domain||'Unknown'} · DC: ${R.dc||'Unknown'}`;$('connection').textContent=`Connection: ${R.connection_mode||'Unknown'}`;$('created').textContent=`Generated: ${R.generated_at||'Unknown'}`;
const s=R.summary||{};$('cards').innerHTML=[['Users',s.users],['Groups',s.groups],['Computers',s.computers],['Trusts',s.trusts],['GPOs',s.gpos],['Findings',s.findings]].map(x=>`<div class="card"><div class="n">${esc(x[1]??0)}</div><div class="k">${esc(x[0])}</div></div>`).join('');
$('overviewContent').innerHTML=`<div class="cards" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr))">${Object.entries(s.severity||{}).map(([k,v])=>`<div class="card"><div class="n"><span class="badge ${esc(k)}">${esc(k)}</span></div><div class="k">${esc(v)} observation(s)</div></div>`).join('')}</div>`;
renderFindings();
if(R.all_user_permissions){const p=R.all_user_permissions;const entries=p.entries||[];const hi=p.high_impact_entries||[];
if(p.error){$('allAclSummary').innerHTML=`<div class="notice">All-user ACL audit failed: ${esc(p.error)}</div>`;$('allAclTable').innerHTML='';}else {
$('allAclSummary').innerHTML=`<p><b>Users checked: ${esc(p.user_count)}</b> · Directory objects checked: ${esc(p.checked_object_count)} · ACL findings: ${esc(entries.length)} · High-impact allow entries: ${esc(hi.length)}${p.truncated_possible?' · LIMIT REACHED — increase --acl-limit':''}</p><div class="notice">${esc(p.method_note||'')}</div>`;
$('allAclTable').innerHTML='<div class="tools"><input id="allAclSearch" placeholder="Search user, target, right, GUID…"><select id="allAclEffect"><option value="">Allow and deny</option><option>Allow</option><option>Deny</option><option>Other</option></select><select id="allAclRight"><option value="">All rights</option>'+[...new Set(entries.flatMap(x=>x.rights||[]))].sort().map(r=>`<option>${esc(r)}</option>`).join('')+'</select></div><div id="allAclRows"></div>';
function renderAllAcl(){const q=($('allAclSearch').value||'').toLowerCase(),ef=$('allAclEffect').value,ri=$('allAclRight').value;const rows=entries.filter(x=>(!ef||x.effect===ef)&&(!ri||(x.rights||[]).includes(ri))&&JSON.stringify(x).toLowerCase().includes(q));$('allAclRows').innerHTML=table(rows,[{key:'user',label:'User'},{key:'effect',label:'ACE effect'},{key:'rights',label:'Rights'},{key:'target_name',label:'Target object'},{key:'object_class',label:'Object class'},{key:'trustee_sid',label:'ACE trustee SID',mono:true},{key:'inherited',label:'Inherited'},{key:'object_specific_guid',label:'Object-type GUID',mono:true},{key:'mask_hex',label:'Mask'},{key:'note',label:'Notes'}],'No ACL entries match these filters.');}
$('allAclSearch').addEventListener('input',renderAllAcl);$('allAclEffect').addEventListener('change',renderAllAcl);$('allAclRight').addEventListener('change',renderAllAcl);renderAllAcl();}
}else{$('allAclSummary').innerHTML='<div class="empty">All-user ACL audit not requested. Run with --all-user-acls.</div>';}
function renderAclGraph(p){
 const host=$('aclGraph');if(!host)return;
 const highRights=new Set(['GENERIC_ALL','GENERIC_WRITE','POTENTIAL_GENERIC_WRITE (all-properties WRITE_PROPERTY)','WRITE_DAC','WRITE_OWNER','WRITE_PROPERTY','WRITE_SPN_ATTRIBUTE','WRITE_RBCD_ATTRIBUTE','CREATE_CHILD','DELETE_CHILD','CONTROL_ACCESS']);
 const hits=(p.matched_acl_entries||[]).filter(h=>h.effect==='Allow'&&Array.isArray(h.rights)&&h.rights.some(r=>highRights.has(r))&&h.object!==p.user_dn);
 const groups=(p.groups||[]).map(g=>({id:'g:'+g.sid,name:g.name,dn:g.dn,type:'GROUP',sid:g.sid}));
 const user={id:'user:'+p.user_sid,name:p.user,dn:p.user_dn,type:'SELECTED USER',sid:p.user_sid};
 const targetMap=new Map();
 hits.forEach(h=>{const id='t:'+h.object;if(!targetMap.has(id)){const cls=(h.object_class||'').toLowerCase();let type='OBJECT';if(cls.includes('computer'))type='COMPUTER';else if(cls.includes('group'))type='GROUP TARGET';else if(cls.includes('user')||cls.includes('person'))type='USER TARGET';targetMap.set(id,{id,name:h.object_name||h.object,dn:h.object,type,sid:'',className:h.object_class||''});}});
 const targets=[...targetMap.values()],edges=[];
 hits.forEach(h=>{const targetId='t:'+h.object,rights=h.rights.filter(r=>highRights.has(r));let source=user.id;const trustee=String(h.trustee||'');
   if(trustee.startsWith('GROUP:')){const gname=trustee.slice(6).trim();let g=groups.find(x=>x.name===gname);if(!g){g={id:'gx:'+gname,name:gname,dn:'',type:'GROUP',sid:''};groups.push(g);}source=g.id;}
   if(source!==targetId)edges.push({source,target:targetId,label:rights.join(' · '),inherited:!!h.inherited,mask:h.mask_hex,note:h.note||'',object:h.object,trustee});
 });
 const edgeMap=new Map();edges.forEach(e=>{const k=e.source+'|'+e.target+'|'+e.label;if(!edgeMap.has(k))edgeMap.set(k,e);});
 const aclEdges=[...edgeMap.values()];
 const memberEdges=groups.filter(g=>aclEdges.some(e=>e.source===g.id)).map(g=>({source:user.id,target:g.id,label:'MEMBER OF (transitive)',membership:true,inherited:false,object:g.dn||'',trustee:p.user}));
 const es=[...memberEdges,...aclEdges];
 const nodeMap=new Map([[user.id,user],...groups.map(g=>[g.id,g]),...targets.map(t=>[t.id,t])]);
 if(!es.length){host.innerHTML='<h3>BloodHound-style permission graph</h3><div class="empty">No high-impact permission entries found for this user or its resolved groups.</div>';return;}
 const usedGroups=groups.filter(g=>es.some(e=>e.source===g.id)),activeTargets=targets.filter(t=>es.some(e=>e.target===t.id));
 const H=Math.max(520,Math.max(usedGroups.length,activeTargets.length,1)*122+110),W=1320,pos=new Map();
 pos.set(user.id,{x:70,y:H/2-42,w:230,h:84});
 usedGroups.forEach((n,i)=>pos.set(n.id,{x:410,y:(H-(usedGroups.length*86+(usedGroups.length-1)*36))/2+i*122,w:240,h:86}));
 activeTargets.forEach((n,i)=>pos.set(n.id,{x:850,y:(H-(activeTargets.length*86+(activeTargets.length-1)*36))/2+i*122,w:330,h:86}));
 es.forEach(e=>{if(!pos.has(e.source)){const n=nodeMap.get(e.source);pos.set(e.source,{x:410,y:24+(pos.size%Math.max(1,Math.floor(H/122)))*122,w:240,h:86});}});
 const colors={'SELECTED USER':{fill:'#173746',stroke:'#58cbe0'},'GROUP':{fill:'#282344',stroke:'#ad92ff'},'USER TARGET':{fill:'#193b2e',stroke:'#67d5a1'},'COMPUTER':{fill:'#3a3020',stroke:'#e8bb68'},'GROUP TARGET':{fill:'#282344',stroke:'#ad92ff'},'OBJECT':{fill:'#263342',stroke:'#8ba6c3'}};
 const escA=v=>esc(v==null?'':String(v));
 const edgeMarkup=()=>es.map(e=>{const a=pos.get(e.source),b=pos.get(e.target);if(!a||!b)return '';const x1=a.x+a.w,y1=a.y+a.h/2,x2=b.x,y2=b.y+b.h/2,mx=(x1+x2)/2;const d=`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;const short=e.label.length>46?e.label.slice(0,43)+'…':e.label;return `<g><path class="graph-edge" d="${d}" stroke="${e.membership?'#58cbe0':(e.inherited?'#8a9bad':'#e7b86b')}" ${e.membership?'stroke-dasharray="5 5"':''} marker-end="url(#arrow)"/><text class="graph-edge-label" x="${mx}" y="${(y1+y2)/2-6}" text-anchor="middle">${escA(short)}</text></g>`;}).join('');
 const nodeMarkup=[...nodeMap.values()].filter(n=>pos.has(n.id)).map(n=>{const q=pos.get(n.id),c=colors[n.type]||colors.OBJECT,label=String(n.name||n.id),short=label.length>29?label.slice(0,26)+'…':label;return `<g class="graph-node" data-id="${escA(n.id)}" transform="translate(${q.x},${q.y})"><rect width="${q.w}" height="${q.h}" rx="12" fill="${c.fill}" stroke="${c.stroke}"/><text class="node-type" x="14" y="22">${escA(n.type)}</text><text class="node-name" x="14" y="47">${escA(short)}</text><text x="14" y="68" font-size="10" fill="#9fb1c5">${escA(n.dn?n.dn.split(',').slice(0,2).join(','):'Select for details')}</text></g>`;}).join('');
 host.innerHTML=`<h3>BloodHound-style permission graph</h3><div class="graph-shell"><div class="graph-toolbar"><div class="graph-legend"><span class="legend-item"><i class="legend-dot" style="background:#58cbe0"></i>Selected user</span><span class="legend-item"><i class="legend-dot" style="background:#ad92ff"></i>Group</span><span class="legend-item"><i class="legend-dot" style="background:#67d5a1"></i>User target</span><span class="legend-item"><i class="legend-dot" style="background:#e8bb68"></i>Computer / ACL edge</span></div><div class="actions"><button class="btn" id="graphZoomIn">＋ Zoom</button><button class="btn" id="graphZoomOut">− Zoom</button><button class="btn" id="graphReset">Reset view</button></div></div><div class="graph-viewport" id="aclGraphViewport"><svg id="aclGraphSvg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Selected user, group and target ACL relationships"><defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#e7b86b"/></marker></defs><g id="aclGraphScene">${edgeMarkup()}${nodeMarkup}</g></svg></div><div class="graph-details" id="aclGraphDetails">Select a node to view its distinguished name. Drag nodes to rearrange; scroll to zoom and drag the background to pan.</div></div>`;
 const svg=$('aclGraphSvg'),scene=$('aclGraphScene'),viewport=$('aclGraphViewport'),details=$('aclGraphDetails');let scale=1,tx=0,ty=0,drag=null,pan=null;
 function apply(){scene.setAttribute('transform',`translate(${tx} ${ty}) scale(${scale})`);}function zoom(f){scale=Math.max(.45,Math.min(2.5,scale*f));apply();}
 $('graphZoomIn').onclick=()=>zoom(1.15);$('graphZoomOut').onclick=()=>zoom(.87);$('graphReset').onclick=()=>{scale=1;tx=0;ty=0;apply();};
 function point(ev){const r=svg.getBoundingClientRect();return {x:(ev.clientX-r.left)*W/r.width,y:(ev.clientY-r.top)*H/r.height};}
 viewport.addEventListener('wheel',ev=>{ev.preventDefault();zoom(ev.deltaY<0?1.08:.92);},{passive:false});
 svg.querySelectorAll('.graph-node').forEach(el=>{el.addEventListener('pointerdown',ev=>{ev.stopPropagation();const pt=point(ev),id=el.getAttribute('data-id'),q=pos.get(id);drag={el,id,start:pt,orig:{x:q.x,y:q.y}};});el.addEventListener('click',()=>{const n=nodeMap.get(el.getAttribute('data-id'));if(n)details.innerHTML=`<b>${escA(n.type)}: ${escA(n.name)}</b><br>${escA(n.dn||'Distinguished name unavailable')}${n.sid?'<br>SID: '+escA(n.sid):''}`;});});
 svg.addEventListener('pointerdown',ev=>{if(ev.target.closest('.graph-node'))return;pan={start:point(ev),orig:{x:tx,y:ty}};});
 function redrawEdges(){scene.querySelectorAll('path.graph-edge,text.graph-edge-label').forEach(x=>x.remove());const layer=document.createElementNS('http://www.w3.org/2000/svg','g');layer.innerHTML=edgeMarkup();scene.insertBefore(layer,scene.firstChild);}
 svg.addEventListener('pointermove',ev=>{const pt=point(ev);if(drag){const q=pos.get(drag.id),dx=(pt.x-drag.start.x)/scale,dy=(pt.y-drag.start.y)/scale;q.x=drag.orig.x+dx;q.y=drag.orig.y+dy;drag.el.setAttribute('transform',`translate(${q.x},${q.y})`);redrawEdges();}else if(pan){tx=pan.orig.x+(pt.x-pan.start.x)/scale;ty=pan.orig.y+(pt.y-pan.start.y)/scale;apply();}});
 svg.addEventListener('pointerup',()=>{drag=null;pan=null;});svg.addEventListener('pointercancel',()=>{drag=null;pan=null;});
}
if(R.user_permissions){const p=R.user_permissions;if(p.error){$('aclSummary').innerHTML=`<div class="notice">ACL review failed: ${esc(p.error)}</div>`;$('aclTable').innerHTML='';$('aclGraph').innerHTML='';}else{
const counts=p.allow_right_counts||{};
const focus=['GENERIC_ALL','GENERIC_WRITE','WRITE_DAC','WRITE_OWNER','WRITE_PROPERTY','CREATE_CHILD','DELETE_CHILD','CONTROL_ACCESS'];
const cards=focus.map(r=>`<div class="card"><div class="n">${esc(counts[r]||0)}</div><div class="k">${esc(r)} allow ACE(s)</div></div>`).join('');
$('aclSummary').innerHTML=`<p><b>Selected account: ${esc(p.user)}</b> · ${esc(p.user_dn)}<br><span class="sub">SID: ${esc(p.user_sid)} · Group SIDs included: ${esc(p.matched_group_count)} · Directory objects checked: ${esc(p.checked_object_count)} · Matching allow ACEs: ${esc(p.allow_ace_count||0)} · Deny ACEs: ${esc(p.deny_ace_count||0)}${p.truncated_possible?' · LIMIT REACHED — increase --acl-limit to inspect more objects':''}</span></p><div class="cards" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr))">${cards}</div><h3>High-impact allow entries</h3><div id="aclHighImpact"></div><div class="notice">${esc(p.method_note||'')}</div>`;
$('aclHighImpact').innerHTML=table(p.high_impact_entries||[],[{key:'high_impact_rights',label:'Important rights'},{key:'trustee',label:'Granted through'},{key:'object_name',label:'Target account/object'},{key:'object_class',label:'Object type'},{key:'object',label:'Distinguished name',mono:true},{key:'inherited',label:'Inherited'},{key:'mask_hex',label:'Access mask'}],'No matching high-impact allow ACEs were found in the objects checked.');
renderAclGraph(p);
$('aclTable').innerHTML='<h3>All matching ACL entries</h3><div class="tools"><input id="aclSearch" placeholder="Search rights, trustee, object DN…" oninput="renderAclTable()"><select id="aclEffect" onchange="renderAclTable()"><option value="">Allow and deny</option><option>Allow</option><option>Deny</option><option>Other</option></select><select id="aclRight" onchange="renderAclTable()"><option value="">All rights</option>'+[...new Set((p.matched_acl_entries||[]).flatMap(x=>x.rights||[]))].sort().map(r=>`<option>${esc(r)}</option>`).join('')+'</select></div><div id="aclAllTable"></div>';
window.renderAclTable=function(){const q=($('aclSearch')?.value||'').toLowerCase(),effect=$('aclEffect')?.value||'',right=$('aclRight')?.value||'';const rows=(p.matched_acl_entries||[]).filter(x=>(!effect||x.effect===effect)&&(!right||(x.rights||[]).includes(right))&&JSON.stringify(x).toLowerCase().includes(q));$('aclAllTable').innerHTML=table(rows,[{key:'effect',label:'ACE effect'},{key:'trustee',label:'Matched trustee'},{key:'rights',label:'Rights'},{key:'object_name',label:'Target account/object'},{key:'inherited',label:'Inherited'},{key:'object',label:'Target DN',mono:true},{key:'mask_hex',label:'Mask'},{key:'note',label:'Notes'}],'No matching ACL entries for these filters.');};renderAclTable();
}}else{$('aclSummary').innerHTML='<div class="empty">No specific-user ACL review was requested. Run again with --check-user USERNAME.</div>';}
const common=[{key:'sAMAccountName',label:'Account'},{key:'cn',label:'Common name'},{key:'description',label:'Description'},{key:'distinguishedName',label:'Distinguished name',mono:true}];
$('usersTable').innerHTML=table(R.data.users||[],[{key:'sAMAccountName',label:'Account'},{key:'displayName',label:'Display name'},{key:'userPrincipalName',label:'UPN'},{key:'department',label:'Department'},{key:'userAccountControl',label:'Account flags'},{key:'servicePrincipalName',label:'SPNs'},{key:'adminCount',label:'adminCount'},{key:'distinguishedName',label:'DN',mono:true}]);
$('groupsTable').innerHTML=table(R.data.groups||[],[{key:'sAMAccountName',label:'Group'},{key:'description',label:'Description'},{key:'adminCount',label:'adminCount'},{key:'member',label:'Members'},{key:'distinguishedName',label:'DN',mono:true}]);
$('computersTable').innerHTML=table(R.data.computers||[],[{key:'cn',label:'Computer'},{key:'dNSHostName',label:'DNS hostname'},{key:'operatingSystem',label:'OS'},{key:'operatingSystemVersion',label:'OS version'},{key:'userAccountControl',label:'Account flags'},{key:'msDS-AllowedToDelegateTo',label:'Constrained delegation'},{key:'distinguishedName',label:'DN',mono:true}]);
$('trustsTable').innerHTML=table(R.data.trusts||[],[{key:'trustPartner',label:'Trust partner'},{key:'trustDirection',label:'Direction'},{key:'trustType',label:'Type'},{key:'trustAttributes',label:'Attributes'},{key:'distinguishedName',label:'DN',mono:true}]);
$('gposTable').innerHTML=table(R.data.gpos||[],[{key:'displayName',label:'GPO'},{key:'name',label:'GUID'},{key:'gPCFileSysPath',label:'SYSVOL path',mono:true},{key:'versionNumber',label:'Version'},{key:'whenChanged',label:'Changed'}]);
$('diagnosticsTable').innerHTML=table(R.connection_diagnostics||[],[{key:'mode',label:'Mode'},{key:'port',label:'Port'},{key:'success',label:'Success'},{key:'error',label:'Error'}]);
</script></body></html>'''
    document = document.replace("__TITLE__", title).replace("__DATA__", payload)
    out_path.write_text(document, encoding="utf-8")


def parse_args():
    p = argparse.ArgumentParser(description="ADScope: read-only Active Directory inventory and ACL review. NTLM is the default bind method.")
    p.add_argument("-t", "--dc", required=True, help="Domain controller hostname or IP")
    p.add_argument("-d", "--domain", required=True, help="AD DNS domain, e.g. corp.example")
    p.add_argument("-u", "--username", required=True, help="Account name or UPN")
    p.add_argument("-p", "--password", help="Password (prefer prompt or ADRECON_PASSWORD to avoid shell history)")
    p.add_argument("--auth", choices=["ntlm", "simple"], default="ntlm", help="Bind type (default: ntlm; use simple for a UPN/simple bind)")
    p.add_argument("--ldaps-port", type=int, default=636)
    p.add_argument("--ldap-port", type=int, default=389)
    p.add_argument("--plain", "--allow-plain-ldap", dest="allow_plain_ldap", action="store_true", help="Allow unencrypted LDAP fallback (lab use only)")
    p.add_argument("-k", "--insecure-tls", action="store_true", help="Skip TLS certificate validation (lab only)")
    p.add_argument("--timeout", type=int, default=6)
    p.add_argument("-c", "--check-user", help="Review ACLs for one user (sAMAccountName or UPN)")
    p.add_argument("-A", "--all-user-acls", action="store_true", help="Review ACL permissions for all domain users")
    p.add_argument("-L", "--acl-limit", type=int, default=5000, help="Maximum directory objects to inspect (default: 5000)")
    p.add_argument("-o", "--output", default="reports/adscope", help="Output path prefix, without extension (default: reports/adscope)")
    p.add_argument("--json-only", "--no-html", dest="no_html", action="store_true", help="Write JSON only; skip HTML dashboard")
    args = p.parse_args()
    if args.acl_limit < 1:
        p.error("--acl-limit must be at least 1")
    return args


def main() -> int:
    args = parse_args()
    banner()
    password = args.password or os.environ.get("ADRECON_PASSWORD") or getpass.getpass("LDAP password: ")
    if not password:
        say("x", "Empty password; aborting.")
        return 2
    if args.allow_plain_ldap:
        say("!", "Plain LDAP fallback is enabled. Credentials may be exposed if the connection falls back to port 389 without TLS.")
    if args.insecure_tls:
        say("!", "TLS certificate validation is disabled. Use only in a controlled lab.")
    conn = None
    try:
        conn, mode, diagnostics = bind_connection(args, password)
        # Read RootDSE without naming individual attributes in the search request.
        # Some LDAP servers / schema configurations reject explicit RootDSE attribute
        # names even though the attributes exist. Wildcards avoid that compatibility
        # issue; if RootDSE still cannot be read, fall back to the supplied DNS domain.
        domain_dn = ",".join("DC=" + part for part in args.domain.split("."))
        dc_name = args.dc
        try:
            root_ok = conn.search(
                search_base="", search_filter="(objectClass=*)",
                search_scope=BASE, attributes=["*", "+"]
            )
            if root_ok and conn.entries:
                root = conn.entries[0]
                domain_dn = value(root, "defaultNamingContext", domain_dn)
                dc_name = value(root, "dnsHostName", dc_name)
            else:
                say("!", f"RootDSE lookup unavailable ({conn.result}); using domain-derived DN: {domain_dn}")
        except Exception as root_exc:
            say("!", f"RootDSE lookup failed ({root_exc}); using domain-derived DN: {domain_dn}")
        say("+", f"Naming context: {domain_dn}")
        data = enumerate_domain(conn, domain_dn)
        user_permissions = None
        all_user_permissions = None
        if args.all_user_acls:
            try:
                all_user_permissions = check_all_users_acl_permissions(conn, domain_dn, args.acl_limit)
                say("+", f"All-user ACL review complete: {len(all_user_permissions['entries'])} user-to-ACE finding(s) across {all_user_permissions['checked_object_count']} objects.")
            except Exception as exc:
                say("!", f"All-user ACL review failed: {exc}")
                all_user_permissions = {"error": str(exc), "entries": [], "high_impact_entries": []}
        if args.check_user:
            try:
                user_permissions = check_user_acl_permissions(conn, domain_dn, args.check_user, args.acl_limit)
                say("+", f"ACL review complete: {len(user_permissions['matched_acl_entries'])} matching ACE(s) across {user_permissions['checked_object_count']} object(s).")
            except Exception as exc:
                say("!", f"Specific-user ACL review failed: {exc}")
                user_permissions = {"selector": args.check_user, "error": str(exc), "matched_acl_entries": []}
        report = {
            "tool": "ADScope", "version": "2.1", "generated_at": utc_now(),
            "domain": args.domain, "domain_dn": domain_dn, "dc": dc_name,
            "connection_mode": mode, "auth_type": args.auth,
            "tls_certificate_validation": "disabled" if args.insecure_tls else "required",
            "plain_ldap_allowed": bool(args.allow_plain_ldap),
            "scope": "LDAP-readable domain inventory; read-only; not a complete attack-path or effective-permissions analyzer.",
            "connection_diagnostics": diagnostics,
            "data": data, "user_permissions": user_permissions,
            "all_user_permissions": all_user_permissions,
        }
        report["summary"] = summary(data)
        prefix = Path(args.output)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        json_path = prefix.with_suffix(".json")
        json_path.write_text(json.dumps(safe_json(report), indent=2, ensure_ascii=False), encoding="utf-8")
        say("+", f"JSON report saved: {json_path}")
        if not args.no_html:
            html_path = prefix.with_suffix(".html")
            build_html(report, html_path)
            say("+", f"HTML dashboard saved: {html_path}")
        say("*", f"Finished: {report['summary']['users']} users, {report['summary']['groups']} groups, {report['summary']['computers']} computers, {report['summary']['findings']} observations.")
        return 0
    except KeyboardInterrupt:
        say("!", "Interrupted by user.")
        return 130
    except Exception as exc:
        say("x", str(exc))
        say("!", "If TLS fails, check the DC's certificate and LDAP policy. Plain LDAP is deliberately not tried unless --allow-plain-ldap is supplied.")
        return 1
    finally:
        if conn:
            try:
                conn.unbind()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
