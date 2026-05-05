#!/usr/bin/env python3
"""
ldap_to_sqlite.py — Export OpenLDAP users to SQLite.

Connects via ldapi:/// or ldaps://localhost:636 (tries in that order).
Writes a server overview, detects ppolicy, exports all user entries,
and — when ppolicy is absent — resets every password to an Argon2 hash
of the DEFAULT_PASSWORD constant.

Dependencies:
    pip install ldap3 argon2-cffi rich
"""

import argparse
import getpass
import json
import sqlite3
import ssl
import sys
from datetime import datetime, timezone
from typing import Optional

# ── optional-import guards ──────────────────────────────────────────────────

try:
    from ldap3 import (
        ALL,
        ALL_ATTRIBUTES,
        BASE,
        MODIFY_REPLACE,
        SASL,
        SUBTREE,
        Connection,
        Server,
        Tls,
    )
    from ldap3.core.exceptions import LDAPException, LDAPNoSuchObjectResult
except ImportError:
    sys.exit("ldap3 not installed — run: pip install ldap3")

try:
    from argon2 import PasswordHasher
except ImportError:
    sys.exit("argon2-cffi not installed — run: pip install argon2-cffi")

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()
    RICH = True
except ImportError:
    RICH = False

    class _FallbackConsole:
        def print(self, *args, **kwargs):
            # strip Rich markup tags for plain output
            import re
            text = " ".join(str(a) for a in args)
            text = re.sub(r"\[/?[^\]]*\]", "", text)
            print(text)

        def rule(self, title=""):
            print(f"\n{'─' * 60}  {title}")

    console = _FallbackConsole()

# ── constants ───────────────────────────────────────────────────────────────

DEFAULT_PASSWORD = "Changeme12345!"
PPOLICY_CONTROL_OID = "1.3.6.1.4.1.42.2.27.8.5.1"

# objectClass filter that catches the most common user entry types
USER_FILTER = (
    "(|"
    "(objectClass=inetOrgPerson)"
    "(objectClass=posixAccount)"
    "(objectClass=organizationalPerson)"
    "(objectClass=person)"
    ")"
)

# Attributes to fetch (best-effort; missing ones are silently skipped)
USER_ATTRS = [
    "uid", "cn", "sn", "givenName", "displayName", "mail",
    "userPassword",
    "uidNumber", "gidNumber", "homeDirectory", "loginShell",
    "shadowExpire", "shadowLastChange", "shadowMax", "shadowMin",
    "pwdAccountLockedTime", "pwdChangedTime", "pwdFailureTime",
    "pwdPolicySubentry",
    "memberOf", "description", "telephoneNumber", "mobile",
    "title", "departmentNumber", "employeeNumber", "employeeType",
    "objectClass", "createTimestamp", "modifyTimestamp",
    "gecos", "roomNumber", "labeledURI",
]


# ── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--uri",
        help="LDAP URI (default: try ldapi:/// then ldaps://localhost:636)",
    )
    p.add_argument("--bind-dn", help="Bind DN for simple auth")
    p.add_argument("--bind-pw", help="Bind password (prompted when omitted)")
    p.add_argument(
        "--base-dn",
        help="Search base DN (auto-detected from namingContexts if omitted)",
    )
    p.add_argument(
        "--db",
        default="ldap_export.sqlite",
        help="SQLite output file (default: ldap_export.sqlite)",
    )
    p.add_argument(
        "--no-reset",
        action="store_true",
        help="Never reset passwords, even when ppolicy is absent",
    )
    p.add_argument(
        "--ca-cert",
        help="CA certificate file for LDAPS TLS verification",
    )
    return p.parse_args()


# ── LDAP connection helpers ──────────────────────────────────────────────────

def _make_server(uri: str, ca_cert: Optional[str]) -> Server:
    if uri.startswith("ldaps://"):
        tls = Tls(
            validate=ssl.CERT_OPTIONAL if ca_cert else ssl.CERT_NONE,
            ca_certs_file=ca_cert,
        )
        return Server(uri, use_ssl=True, tls=tls, get_info=ALL)
    # ldapi:// or ldap://
    return Server(uri, get_info=ALL)


def _bind(server: Server, bind_dn: Optional[str], bind_pw: Optional[str],
          use_external_sasl: bool) -> Connection:
    if use_external_sasl:
        conn = Connection(
            server,
            authentication=SASL,
            sasl_mechanism="EXTERNAL",
            sasl_credentials="",
            auto_bind=True,
            raise_exceptions=True,
        )
    else:
        conn = Connection(
            server,
            user=bind_dn,
            password=bind_pw,
            auto_bind=True,
            raise_exceptions=True,
        )
    return conn


def connect(args: argparse.Namespace) -> tuple[Connection, str]:
    """Try URIs in priority order; return (conn, uri_used)."""
    bind_dn = args.bind_dn
    bind_pw = args.bind_pw

    if bind_dn and bind_pw is None:
        bind_pw = getpass.getpass(f"Password for {bind_dn}: ")

    uris = [args.uri] if args.uri else ["ldapi:///", "ldaps://localhost:636"]

    last_err: Optional[Exception] = None
    for uri in uris:
        console.print(f"  Trying [bold]{uri}[/bold] …", end=" ")
        server = _make_server(uri, args.ca_cert)

        # For ldapi without explicit credentials, try SASL EXTERNAL first
        attempts = []
        if uri.startswith("ldapi://") and not bind_dn:
            attempts.append((True, None, None))   # SASL EXTERNAL
        if bind_dn:
            attempts.append((False, bind_dn, bind_pw))
        else:
            attempts.append((False, None, None))   # anonymous

        for use_ext, dn, pw in attempts:
            try:
                conn = _bind(server, dn, pw, use_ext)
                auth_label = "SASL/EXTERNAL" if use_ext else (dn or "anonymous")
                console.print(f"[green]connected[/green] ({auth_label})")
                return conn, uri
            except LDAPException as e:
                last_err = e

        console.print(f"[yellow]failed[/yellow]")

    sys.exit(f"\nCould not connect to any LDAP URI.\nLast error: {last_err}")


# ── server overview ──────────────────────────────────────────────────────────

def _list(val) -> list[str]:
    """Normalise an ldap3 attribute value to a plain list of strings."""
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


def server_overview(conn: Connection) -> dict:
    """Return a dict of interesting root DSE / cn=config facts."""
    info = conn.server.info
    facts: dict = {}

    # Root DSE
    if info:
        facts["naming_contexts"]   = _list(getattr(info, "naming_contexts",   None))
        facts["supported_ldap_versions"] = _list(getattr(info, "supported_ldap_versions", None))
        facts["supported_sasl_mechanisms"] = _list(getattr(info, "supported_sasl_mechanisms", None))
        facts["supported_controls"] = _list(getattr(info, "supported_controls", None))
        facts["supported_extensions"] = _list(getattr(info, "supported_extensions", None))
        facts["supported_features"]  = _list(getattr(info, "supported_features",  None))
        facts["vendor_name"]    = str(getattr(info, "vendor_name",    "") or "")
        facts["vendor_version"] = str(getattr(info, "vendor_version", "") or "")
        facts["server_name"]    = str(getattr(info, "server_name",    "") or "")

        # alt: some servers expose these as other_info
        if hasattr(info, "other"):
            other = info.other or {}
            for key in ("objectClass", "configContext", "monitorContext"):
                if key in other:
                    facts.setdefault(key, _list(other[key]))

    # Try reading cn=config for overlay / module info
    overlay_info: dict = {}
    try:
        conn.search(
            "cn=config",
            "(objectClass=olcGlobal)",
            search_scope=BASE,
            attributes=["olcLogLevel", "olcTLSCipherSuite", "olcTLSProtocolMin",
                        "olcSizeLimit", "olcTimeLimit", "olcToolThreads",
                        "olcServerID"],
        )
        if conn.entries:
            e = conn.entries[0]
            for attr in ["olcLogLevel", "olcTLSCipherSuite", "olcTLSProtocolMin",
                         "olcSizeLimit", "olcTimeLimit"]:
                v = getattr(e, attr, None)
                if v and v.value:
                    overlay_info[attr] = str(v.value)
    except LDAPException:
        pass  # cn=config may not be readable without special access

    # List overlays across all databases
    try:
        conn.search(
            "cn=config",
            "(objectClass=olcOverlayConfig)",
            search_scope=SUBTREE,
            attributes=["olcOverlay", "objectClass"],
        )
        overlays = []
        for e in conn.entries:
            ov = getattr(e, "olcOverlay", None)
            if ov and ov.value:
                overlays.append(str(ov.value))
        if overlays:
            overlay_info["configured_overlays"] = overlays
    except LDAPException:
        pass

    # List loaded modules
    try:
        conn.search(
            "cn=config",
            "(objectClass=olcModuleList)",
            search_scope=SUBTREE,
            attributes=["olcModuleLoad"],
        )
        modules = []
        for e in conn.entries:
            ml = getattr(e, "olcModuleLoad", None)
            if ml:
                modules.extend(_list(ml.value))
        if modules:
            overlay_info["loaded_modules"] = modules
    except LDAPException:
        pass

    # List databases
    try:
        conn.search(
            "cn=config",
            "(|(objectClass=olcDatabaseConfig)(objectClass=olcHdbConfig)"
            "(objectClass=olcMdbConfig)(objectClass=olcBdbConfig))",
            search_scope=SUBTREE,
            attributes=["olcDatabase", "olcSuffix", "olcDbDirectory",
                        "objectClass"],
        )
        databases = []
        for e in conn.entries:
            db_type = str(getattr(e, "olcDatabase", None) and e.olcDatabase.value or "")
            suffix  = str(getattr(e, "olcSuffix",   None) and e.olcSuffix.value   or "")
            db_dir  = str(getattr(e, "olcDbDirectory", None) and e.olcDbDirectory.value or "")
            ocs     = _list(getattr(e, "objectClass", None) and e.objectClass.value or [])
            databases.append({
                "type": db_type,
                "suffix": suffix,
                "directory": db_dir,
                "objectClasses": ocs,
            })
        if databases:
            overlay_info["databases"] = databases
    except LDAPException:
        pass

    facts["config_details"] = overlay_info
    return facts


def print_overview(facts: dict, ppolicy_active: bool, base_dn: str) -> None:
    console.rule("[bold blue]OpenLDAP Installation Overview")
    console.print()

    tbl = Table(show_header=False, box=box.SIMPLE if RICH else None, expand=True)
    tbl.add_column("Key",   style="bold cyan", no_wrap=True)
    tbl.add_column("Value", style="white")

    def row(k, v):
        tbl.add_row(k, v if v else "[dim]—")

    row("Vendor",           facts.get("vendor_name", ""))
    row("Version",          facts.get("vendor_version", ""))
    row("Server Name",      facts.get("server_name", ""))
    row("LDAP Versions",    ", ".join(facts.get("supported_ldap_versions", [])))
    row("Naming Contexts",  "\n".join(facts.get("naming_contexts", [])))
    row("SASL Mechanisms",  ", ".join(facts.get("supported_sasl_mechanisms", [])))
    row("Export Base DN",   base_dn)

    cfg = facts.get("config_details", {})

    dbs = cfg.get("databases", [])
    if dbs:
        db_lines = []
        for db in dbs:
            parts = [db["type"] or "?"]
            if db["suffix"]:
                parts.append(f"suffix={db['suffix']}")
            if db["directory"]:
                parts.append(f"dir={db['directory']}")
            db_lines.append("  ".join(parts))
        row("Databases", "\n".join(db_lines))

    overlays = cfg.get("configured_overlays", [])
    row("Overlays", ", ".join(overlays) if overlays else "none detected")

    modules = cfg.get("loaded_modules", [])
    row("Loaded Modules", "\n".join(modules) if modules else "none detected / no access")

    for k in ("olcLogLevel", "olcTLSCipherSuite", "olcTLSProtocolMin",
              "olcSizeLimit", "olcTimeLimit"):
        if k in cfg:
            row(k, cfg[k])

    pp_text = "[green]YES — passwords are managed by ppolicy[/green]" if ppolicy_active \
        else "[red]NO  — passwords will be reset to Argon2 hash of DEFAULT_PASSWORD[/red]"
    row("ppolicy Active", pp_text)

    if RICH:
        console.print(tbl)
    else:
        for cell in tbl.columns[0]._cells:  # fallback plain print
            pass
        # plain fallback: just print key-value
        for k_cell, v_cell in zip(tbl.columns[0]._cells, tbl.columns[1]._cells):
            print(f"  {k_cell:<28} {v_cell}")

    console.print()


# ── ppolicy detection ────────────────────────────────────────────────────────

def check_ppolicy(conn: Connection, facts: dict) -> bool:
    """
    Return True if ppolicy is active.  Uses three independent signals:
      1. ppolicy control OID in root DSE supportedControls
      2. olcOverlay=ppolicy entries in cn=config
      3. Any user entry carrying pwdPolicySubentry or pwdAccountLockedTime
    """
    reasons: list[str] = []

    # 1. Root DSE controls
    controls = facts.get("supported_controls", [])
    if PPOLICY_CONTROL_OID in controls or any(
        PPOLICY_CONTROL_OID in c for c in controls
    ):
        reasons.append("ppolicy control OID present in root DSE supportedControls")

    # 2. cn=config overlays
    overlays = facts.get("config_details", {}).get("configured_overlays", [])
    if any("ppolicy" in o.lower() for o in overlays):
        reasons.append("ppolicy overlay configured in cn=config")

    # 3. Check loaded modules for argon2 / ppolicy
    modules = facts.get("config_details", {}).get("loaded_modules", [])
    if any("ppolicy" in m.lower() for m in modules):
        reasons.append("ppolicy module loaded (olcModuleLoad)")

    # 4. Live search: any user with ppolicy operational attributes
    if not reasons:
        try:
            conn.search(
                conn.server.info.naming_contexts[0]
                if conn.server.info and conn.server.info.naming_contexts
                else "",
                "(|(pwdPolicySubentry=*)(pwdAccountLockedTime=*))",
                search_scope=SUBTREE,
                attributes=["dn"],
                size_limit=1,
            )
            if conn.entries:
                reasons.append("user entries contain ppolicy operational attributes")
        except LDAPException:
            pass

    if reasons:
        console.print(
            f"[green]ppolicy detected[/green]: {'; '.join(reasons)}"
        )
    else:
        console.print(
            "[yellow]ppolicy NOT detected[/yellow] — no ppolicy signals found"
        )

    return bool(reasons)


# ── user search ──────────────────────────────────────────────────────────────

def resolve_base_dn(conn: Connection, args: argparse.Namespace) -> str:
    if args.base_dn:
        return args.base_dn
    info = conn.server.info
    if info and info.naming_contexts:
        base = str(info.naming_contexts[0])
        console.print(f"  Auto-detected base DN: [bold]{base}[/bold]")
        return base
    sys.exit("Cannot determine base DN — pass --base-dn explicitly.")


def fetch_users(conn: Connection, base_dn: str) -> list:
    console.print(f"\nSearching [bold]{base_dn}[/bold] for user entries …")
    conn.search(
        base_dn,
        USER_FILTER,
        search_scope=SUBTREE,
        attributes=USER_ATTRS,
    )
    users = list(conn.entries)
    console.print(f"  Found [bold]{len(users)}[/bold] user entr{'y' if len(users)==1 else 'ies'}.")
    return users


# ── SQLite schema ────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ldap_users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    dn                  TEXT    UNIQUE NOT NULL,
    uid                 TEXT,
    cn                  TEXT,
    sn                  TEXT,
    given_name          TEXT,
    display_name        TEXT,
    mail                TEXT,
    user_password       TEXT,
    uid_number          INTEGER,
    gid_number          INTEGER,
    home_directory      TEXT,
    login_shell         TEXT,
    shadow_expire       INTEGER,
    shadow_last_change  INTEGER,
    shadow_max          INTEGER,
    shadow_min          INTEGER,
    pwd_account_locked  TEXT,
    pwd_changed_time    TEXT,
    pwd_failure_time    TEXT,
    pwd_policy_subentry TEXT,
    member_of           TEXT,    -- JSON array
    description         TEXT,
    telephone_number    TEXT,
    mobile              TEXT,
    title               TEXT,
    department_number   TEXT,
    employee_number     TEXT,
    employee_type       TEXT,
    object_classes      TEXT,    -- JSON array
    create_timestamp    TEXT,
    modify_timestamp    TEXT,
    gecos               TEXT,
    room_number         TEXT,
    labeled_uri         TEXT,
    password_was_reset  INTEGER DEFAULT 0,   -- 1 = yes
    export_timestamp    TEXT
);

CREATE TABLE IF NOT EXISTS export_run (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT,
    ldap_uri        TEXT,
    base_dn         TEXT,
    total_users     INTEGER,
    passwords_reset INTEGER,
    ppolicy_active  INTEGER
);
"""


def init_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.executescript(SCHEMA_SQL)
    db.commit()
    return db


# ── attribute helpers ────────────────────────────────────────────────────────

def _str(entry, attr: str) -> Optional[str]:
    a = getattr(entry, attr, None)
    if a is None:
        return None
    v = a.value
    if v is None:
        return None
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v)


def _int(entry, attr: str) -> Optional[int]:
    s = _str(entry, attr)
    if s is None:
        return None
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _json_list(entry, attr: str) -> Optional[str]:
    a = getattr(entry, attr, None)
    if a is None:
        return None
    v = a.value
    if v is None:
        return None
    if not isinstance(v, (list, tuple)):
        v = [v]
    items = []
    for item in v:
        if isinstance(item, bytes):
            items.append(item.decode("utf-8", errors="replace"))
        else:
            items.append(str(item))
    return json.dumps(items) if items else None


def entry_to_row(entry, now: str) -> dict:
    return {
        "dn":                  str(entry.entry_dn),
        "uid":                 _str(entry, "uid"),
        "cn":                  _str(entry, "cn"),
        "sn":                  _str(entry, "sn"),
        "given_name":          _str(entry, "givenName"),
        "display_name":        _str(entry, "displayName"),
        "mail":                _str(entry, "mail"),
        "user_password":       _str(entry, "userPassword"),
        "uid_number":          _int(entry, "uidNumber"),
        "gid_number":          _int(entry, "gidNumber"),
        "home_directory":      _str(entry, "homeDirectory"),
        "login_shell":         _str(entry, "loginShell"),
        "shadow_expire":       _int(entry, "shadowExpire"),
        "shadow_last_change":  _int(entry, "shadowLastChange"),
        "shadow_max":          _int(entry, "shadowMax"),
        "shadow_min":          _int(entry, "shadowMin"),
        "pwd_account_locked":  _str(entry, "pwdAccountLockedTime"),
        "pwd_changed_time":    _str(entry, "pwdChangedTime"),
        "pwd_failure_time":    _str(entry, "pwdFailureTime"),
        "pwd_policy_subentry": _str(entry, "pwdPolicySubentry"),
        "member_of":           _json_list(entry, "memberOf"),
        "description":         _str(entry, "description"),
        "telephone_number":    _str(entry, "telephoneNumber"),
        "mobile":              _str(entry, "mobile"),
        "title":               _str(entry, "title"),
        "department_number":   _str(entry, "departmentNumber"),
        "employee_number":     _str(entry, "employeeNumber"),
        "employee_type":       _str(entry, "employeeType"),
        "object_classes":      _json_list(entry, "objectClass"),
        "create_timestamp":    _str(entry, "createTimestamp"),
        "modify_timestamp":    _str(entry, "modifyTimestamp"),
        "gecos":               _str(entry, "gecos"),
        "room_number":         _str(entry, "roomNumber"),
        "labeled_uri":         _str(entry, "labeledURI"),
        "password_was_reset":  0,
        "export_timestamp":    now,
    }


# ── password reset ───────────────────────────────────────────────────────────

_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def argon2_ldap_hash(password: str) -> str:
    """Return {ARGON2}<hash> — compatible with OpenLDAP's pw-argon2 module."""
    raw = _ph.hash(password)          # $argon2id$v=19$…
    return f"{{ARGON2}}{raw}"


def reset_password(conn: Connection, dn: str) -> bool:
    """Modify userPassword on *dn* in the live LDAP directory."""
    new_hash = argon2_ldap_hash(DEFAULT_PASSWORD)
    try:
        conn.modify(dn, {"userPassword": [(MODIFY_REPLACE, [new_hash])]})
        return conn.result["result"] == 0
    except LDAPException as e:
        console.print(f"  [red]LDAP modify failed for {dn}: {e}[/red]")
        return False


# ── progress table ────────────────────────────────────────────────────────────

def _make_progress_table() -> "Table":
    t = Table(
        "DN",
        "UID",
        "CN",
        "Mail",
        "Password",
        box=box.SIMPLE_HEAVY if RICH else None,
        show_lines=False,
        expand=True,
    )
    return t


# ── main export loop ─────────────────────────────────────────────────────────

def export(
    conn: Connection,
    db: sqlite3.Connection,
    users: list,
    uri: str,
    base_dn: str,
    ppolicy_active: bool,
    do_reset: bool,
) -> tuple[int, int]:
    """Insert users into SQLite, optionally reset passwords. Returns (total, resets)."""
    now = datetime.now(timezone.utc).isoformat()
    total = 0
    resets = 0

    console.rule("[bold blue]User Export")
    console.print()

    # Live-printed table for progress feedback
    if RICH:
        prog_table = _make_progress_table()

    plain_rows: list[tuple] = []

    for entry in users:
        row = entry_to_row(entry, now)
        dn  = row["dn"]
        uid = row["uid"] or "—"
        cn  = row["cn"]  or "—"
        mail= row["mail"] or "—"
        pw_status = "[dim]kept[/dim]"

        if do_reset:
            ok = reset_password(conn, dn)
            if ok:
                new_hash = argon2_ldap_hash(DEFAULT_PASSWORD)
                row["user_password"]    = new_hash
                row["password_was_reset"] = 1
                pw_status = "[green]RESET → Argon2[/green]"
                resets += 1
            else:
                pw_status = "[red]reset FAILED[/red]"

        # Upsert into SQLite
        placeholders = ", ".join([f":{k}" for k in row])
        cols         = ", ".join(row.keys())
        db.execute(
            f"INSERT OR REPLACE INTO ldap_users ({cols}) VALUES ({placeholders})",
            row,
        )

        total += 1
        plain_rows.append((dn[:60], uid, cn[:30], mail[:30], pw_status))

        if RICH:
            # strip markup for the display value
            clean_status = pw_status.replace("[green]", "").replace("[/green]", "") \
                                    .replace("[red]", "").replace("[/red]", "") \
                                    .replace("[dim]", "").replace("[/dim]", "")
            prog_table.add_row(
                Text(dn[:70], overflow="ellipsis"),
                uid[:20],
                cn[:30],
                mail[:30],
                Text(clean_status,
                     style="green" if "RESET" in clean_status
                     else ("red" if "FAILED" in clean_status else "dim")),
            )

    db.commit()

    if RICH:
        console.print(prog_table)
    else:
        # Plain fallback table
        header = f"{'DN':<62}  {'UID':<18}  {'CN':<30}  {'Mail':<30}  {'Password'}"
        print("\n" + header)
        print("─" * len(header))
        for r in plain_rows:
            # strip markup
            import re
            pw_clean = re.sub(r"\[/?[^\]]*\]", "", r[4])
            print(f"{r[0]:<62}  {r[1]:<18}  {r[2]:<30}  {r[3]:<30}  {pw_clean}")

    console.print()
    return total, resets


# ── final summary ─────────────────────────────────────────────────────────────

def print_summary(
    db_path: str,
    uri: str,
    base_dn: str,
    total: int,
    resets: int,
    ppolicy_active: bool,
) -> None:
    console.rule("[bold blue]Export Summary")
    console.print()
    lines = [
        ("SQLite file",       db_path),
        ("LDAP URI",          uri),
        ("Base DN",           base_dn),
        ("Users exported",    str(total)),
        ("Passwords reset",   str(resets)),
        ("ppolicy active",    "yes" if ppolicy_active else "no"),
        ("Default password",  DEFAULT_PASSWORD if resets else "—"),
    ]
    for k, v in lines:
        console.print(f"  [bold cyan]{k:<22}[/bold cyan]  {v}")
    console.print()


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    console.rule("[bold blue]OpenLDAP → SQLite Export")
    console.print(f"  Started at [bold]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold]")
    console.print()

    # ── 1. Connect ──────────────────────────────────────────────────────────
    console.rule("[bold]Step 1 — Connect")
    conn, uri = connect(args)

    # ── 2. Gather server info ────────────────────────────────────────────────
    console.rule("[bold]Step 2 — Gather server info")
    facts = server_overview(conn)

    # ── 3. Detect ppolicy ───────────────────────────────────────────────────
    console.rule("[bold]Step 3 — Detect ppolicy")
    ppolicy_active = check_ppolicy(conn, facts)
    do_reset = (not ppolicy_active) and (not args.no_reset)

    # ── 4. Print overview ────────────────────────────────────────────────────
    base_dn = resolve_base_dn(conn, args)
    print_overview(facts, ppolicy_active, base_dn)

    # ── 5. Fetch users ───────────────────────────────────────────────────────
    console.rule("[bold]Step 4 — Fetch users")
    users = fetch_users(conn, base_dn)
    if not users:
        console.print("[yellow]No user entries found — nothing to export.[/yellow]")
        sys.exit(0)

    # ── 6. Init SQLite ───────────────────────────────────────────────────────
    console.rule("[bold]Step 5 — Initialise SQLite")
    console.print(f"  Database: [bold]{args.db}[/bold]")
    db = init_db(args.db)

    # ── 7. Export + optional password reset ──────────────────────────────────
    total, resets = export(conn, db, users, uri, base_dn, ppolicy_active, do_reset)

    # ── 8. Record run metadata ────────────────────────────────────────────────
    db.execute(
        "INSERT INTO export_run (run_at, ldap_uri, base_dn, total_users, "
        "passwords_reset, ppolicy_active) VALUES (?,?,?,?,?,?)",
        (
            datetime.now(timezone.utc).isoformat(),
            uri, base_dn, total, resets,
            1 if ppolicy_active else 0,
        ),
    )
    db.commit()
    db.close()
    conn.unbind()

    # ── 9. Summary ────────────────────────────────────────────────────────────
    print_summary(args.db, uri, base_dn, total, resets, ppolicy_active)

    if do_reset and resets > 0:
        console.print(
            f"[bold yellow]NOTE[/bold yellow]: {resets} password(s) were reset in the live "
            f"LDAP directory to the Argon2 hash of \"{DEFAULT_PASSWORD}\".  "
            "Requires the [bold]pw-argon2[/bold] OpenLDAP module for authentication to work.\n"
        )


if __name__ == "__main__":
    main()
