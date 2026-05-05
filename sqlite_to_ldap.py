#!/usr/bin/env python3
"""
sqlite_to_ldap.py — Import users from an ldap_to_sqlite.py export into a target OpenLDAP.

Features
--------
- Auto-detects source base DN from the export_run table
- Rewrites DNs when the target base DN differs from the source
- Creates missing intermediate OUs before importing users
- Supports create (default), update (--update), or skip (--skip-existing) modes
- Dry-run support (--dry-run)
- Per-user progress table + final summary

Dependencies: pip install ldap3 rich
"""

import argparse
import getpass
import json
import re
import sqlite3
import ssl
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

try:
    from ldap3 import (
        ALL,
        BASE,
        MODIFY_REPLACE,
        SASL,
        SUBTREE,
        Connection,
        Server,
        Tls,
    )
    from ldap3.core.exceptions import (
        LDAPEntryAlreadyExistsResult,
        LDAPException,
        LDAPNoSuchObjectResult,
    )
except ImportError:
    sys.exit("ldap3 not installed — run: pip install ldap3")

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    console = Console()
    RICH = True
except ImportError:
    RICH = False

    class _Plain:
        def print(self, *a, **kw):
            import re as _re
            print(_re.sub(r"\[/?[^\]]*\]", "", " ".join(str(x) for x in a)))

        def rule(self, t=""):
            print(f"\n{'─'*60}  {t}")

    console = _Plain()


# ── attribute mapping: SQLite column → LDAP attribute name ──────────────────

# Columns that are stored as JSON arrays in SQLite
JSON_ARRAY_COLS = {"object_classes", "member_of"}

# Columns that are integers (avoid sending them as strings)
INT_COLS = {
    "uid_number", "gid_number",
    "shadow_expire", "shadow_last_change", "shadow_max", "shadow_min",
}

# Operational / meta columns — never sent to LDAP
SKIP_COLS = {
    "id", "dn", "object_classes", "password_was_reset",
    "export_timestamp", "create_timestamp", "modify_timestamp",
    # ppolicy operational attrs — skip unless explicitly requested
    "pwd_account_locked", "pwd_changed_time", "pwd_failure_time",
}

COLUMN_TO_ATTR: dict[str, str] = {
    "uid":               "uid",
    "cn":                "cn",
    "sn":                "sn",
    "given_name":        "givenName",
    "display_name":      "displayName",
    "mail":              "mail",
    "user_password":     "userPassword",
    "uid_number":        "uidNumber",
    "gid_number":        "gidNumber",
    "home_directory":    "homeDirectory",
    "login_shell":       "loginShell",
    "shadow_expire":     "shadowExpire",
    "shadow_last_change":"shadowLastChange",
    "shadow_max":        "shadowMax",
    "shadow_min":        "shadowMin",
    "description":       "description",
    "telephone_number":  "telephoneNumber",
    "mobile":            "mobile",
    "title":             "title",
    "department_number": "departmentNumber",
    "employee_number":   "employeeNumber",
    "employee_type":     "employeeType",
    "gecos":             "gecos",
    "room_number":       "roomNumber",
    "labeled_uri":       "labeledURI",
    "pwd_policy_subentry": "pwdPolicySubentry",
}


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("db", help="SQLite file produced by ldap_to_sqlite.py")
    p.add_argument(
        "--uri",
        help="Target LDAP URI (default: try ldapi:/// then ldaps://localhost:636)",
    )
    p.add_argument("--bind-dn",  help="Bind DN on the target server")
    p.add_argument("--bind-pw",  help="Bind password (prompted when omitted)")
    p.add_argument(
        "--target-base",
        help=(
            "Base DN on the target server.  When it differs from the source base DN "
            "all imported DNs are rewritten.  Auto-detected from the server if omitted."
        ),
    )
    p.add_argument(
        "--source-base",
        help=(
            "Override the source base DN (default: taken from export_run table). "
            "Only needed if the export_run table is missing."
        ),
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--update",
        action="store_true",
        help="Overwrite attributes of existing entries instead of erroring.",
    )
    mode.add_argument(
        "--skip-existing",
        action="store_true",
        help="Silently skip entries that already exist (default: error on conflict).",
    )

    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print every LDAP operation without executing it.",
    )
    p.add_argument(
        "--ca-cert",
        help="CA certificate file for LDAPS TLS verification",
    )
    p.add_argument(
        "--import-ppolicy-attrs",
        action="store_true",
        help="Also import pwdAccountLockedTime / pwdChangedTime / pwdFailureTime.",
    )
    return p.parse_args()


# ── LDAP connection ──────────────────────────────────────────────────────────

def connect(args: argparse.Namespace) -> tuple[Connection, str]:
    bind_dn = args.bind_dn
    bind_pw = args.bind_pw

    if bind_dn and bind_pw is None:
        bind_pw = getpass.getpass(f"Password for {bind_dn}: ")

    uris = [args.uri] if args.uri else ["ldapi:///", "ldaps://localhost:636"]

    last_err: Optional[Exception] = None
    for uri in uris:
        console.print(f"  Trying [bold]{uri}[/bold] …", end=" ")
        if uri.startswith("ldaps://"):
            tls = Tls(
                validate=ssl.CERT_OPTIONAL if args.ca_cert else ssl.CERT_NONE,
                ca_certs_file=args.ca_cert,
            )
            server = Server(uri, use_ssl=True, tls=tls, get_info=ALL)
        else:
            server = Server(uri, get_info=ALL)

        attempts = []
        if uri.startswith("ldapi://") and not bind_dn:
            attempts.append(("EXTERNAL", None, None))
        if bind_dn:
            attempts.append(("simple", bind_dn, bind_pw))
        else:
            attempts.append(("simple", None, None))

        for auth, dn, pw in attempts:
            try:
                if auth == "EXTERNAL":
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
                        user=dn,
                        password=pw,
                        auto_bind=True,
                        raise_exceptions=True,
                    )
                label = "SASL/EXTERNAL" if auth == "EXTERNAL" else (dn or "anonymous")
                console.print(f"[green]connected[/green] ({label})")
                return conn, uri
            except LDAPException as e:
                last_err = e

        console.print("[yellow]failed[/yellow]")

    sys.exit(f"\nCould not connect to any LDAP URI.\nLast error: {last_err}")


# ── SQLite helpers ───────────────────────────────────────────────────────────

def load_export_meta(db: sqlite3.Connection) -> dict:
    """Return the most recent export_run row, or {}."""
    try:
        row = db.execute(
            "SELECT * FROM export_run ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else {}
    except sqlite3.OperationalError:
        return {}


def load_users(db: sqlite3.Connection) -> list[dict]:
    db.row_factory = sqlite3.Row
    rows = db.execute("SELECT * FROM ldap_users ORDER BY dn").fetchall()
    return [dict(r) for r in rows]


# ── DN rewriting ─────────────────────────────────────────────────────────────

def _dn_suffix_lower(dn: str) -> str:
    return dn.strip().lower()


def rewrite_dn(dn: str, src_base: str, tgt_base: str) -> str:
    """Replace the trailing src_base suffix with tgt_base (case-insensitive)."""
    if src_base.lower() == tgt_base.lower():
        return dn
    low = dn.lower()
    sb  = src_base.lower()
    if low.endswith("," + sb):
        prefix = dn[: -(len(sb) + 1)]
        return f"{prefix},{tgt_base}"
    if low == sb:
        return tgt_base
    return dn   # no match — leave unchanged


# ── OU scaffolding ────────────────────────────────────────────────────────────

def _split_dn(dn: str) -> list[str]:
    """Split a DN into RDN components, respecting escaped commas."""
    return re.split(r"(?<!\\),", dn)


def intermediate_dns(dn: str, base_dn: str) -> list[str]:
    """
    Return the OUs between base_dn and dn that need to exist, ordered top-down.
    e.g. uid=jdoe,ou=people,ou=internal,dc=test,dc=local with base dc=test,dc=local
    → ['ou=internal,dc=test,dc=local', 'ou=people,ou=internal,dc=test,dc=local']
    """
    parts = _split_dn(dn)
    base_parts = _split_dn(base_dn)
    # strip the base suffix
    n_base = len(base_parts)
    middle = parts[1:-n_base]  # between the RDN and the base
    result = []
    for i in range(len(middle) - 1, -1, -1):
        # build from top (near base) down
        sub_parts = middle[i:] + base_parts
        result.append(",".join(sub_parts))
    return result


def ensure_dn_exists(
    conn: Connection, dn: str, dry_run: bool
) -> tuple[bool, str]:
    """
    Check whether *dn* exists; if not, create it as an OU (or dc object).
    Returns (created: bool, status_message: str).
    """
    try:
        conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["1.1"])
        if conn.entries:
            return False, "exists"
    except LDAPNoSuchObjectResult:
        pass

    # Derive the RDN type and value
    parts = _split_dn(dn)
    rdn   = parts[0]
    rtype, _, rval = rdn.partition("=")
    rtype = rtype.strip().lower()

    if rtype == "ou":
        attrs = {
            "objectClass": ["top", "organizationalUnit"],
            "ou": rval,
        }
    elif rtype == "dc":
        attrs = {
            "objectClass": ["top", "dcObject", "organization"],
            "dc": rval,
            "o":  rval,
        }
    elif rtype == "cn":
        attrs = {
            "objectClass": ["top", "organizationalRole"],
            "cn": rval,
        }
    else:
        attrs = {
            "objectClass": ["top", "organizationalUnit"],
            "ou": rval,
        }

    if dry_run:
        return True, "[dry-run] would create"

    conn.add(dn, attributes=attrs)
    if conn.result["result"] == 0:
        return True, "created"
    if conn.result["result"] == 68:   # entryAlreadyExists
        return False, "exists"
    return False, f"add failed: {conn.result['description']}"


def ensure_structure(
    conn: Connection,
    all_dns: list[str],
    target_base: str,
    dry_run: bool,
) -> None:
    """Ensure every intermediate OU that appears in any imported DN exists."""
    needed: dict[str, None] = {}   # ordered set
    for dn in all_dns:
        for ou_dn in intermediate_dns(dn, target_base):
            needed[ou_dn] = None

    if not needed:
        return

    console.print(f"\n  Scaffolding [bold]{len(needed)}[/bold] intermediate node(s):")
    for ou_dn in needed:
        created, status = ensure_dn_exists(conn, ou_dn, dry_run)
        icon = "[green]+[/green]" if created else "[dim]=[/dim]"
        console.print(f"    {icon}  {ou_dn}  [dim]{status}[/dim]")


# ── attribute builder ────────────────────────────────────────────────────────

def row_to_attrs(row: dict, import_ppolicy: bool) -> dict:
    """Convert a SQLite row to an ldap3 attribute dict."""
    extra_skip = set() if import_ppolicy else {
        "pwd_account_locked", "pwd_changed_time", "pwd_failure_time"
    }

    # objectClasses are mandatory — build them first
    oc_raw = row.get("object_classes")
    object_classes: list[str] = json.loads(oc_raw) if oc_raw else ["inetOrgPerson"]

    attrs: dict[str, object] = {"objectClass": object_classes}

    for col, ldap_attr in COLUMN_TO_ATTR.items():
        if col in SKIP_COLS or col in extra_skip:
            continue
        val = row.get(col)
        if val is None:
            continue

        if col in INT_COLS:
            attrs[ldap_attr] = int(val)
        else:
            attrs[ldap_attr] = str(val)

    # memberOf — JSON array
    mo_raw = row.get("member_of")
    if mo_raw:
        mo_list = json.loads(mo_raw)
        if mo_list:
            attrs["memberOf"] = mo_list

    # shadowAccount attrs require shadowAccount objectClass
    shadow_cols = {"shadowExpire", "shadowLastChange", "shadowMax", "shadowMin"}
    has_shadow = "shadowAccount" in object_classes
    if not has_shadow:
        for attr in shadow_cols:
            attrs.pop(attr, None)

    return attrs


# ── import a single user ─────────────────────────────────────────────────────

def import_user(
    conn: Connection,
    dn: str,
    attrs: dict,
    *,
    update: bool,
    skip_existing: bool,
    dry_run: bool,
) -> tuple[str, str]:
    """
    Add (or update) one user entry.
    Returns (status, detail) where status ∈ {added, updated, skipped, error, dry-run}.
    """
    if dry_run:
        exists = False
        try:
            conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["1.1"])
            exists = bool(conn.entries)
        except LDAPNoSuchObjectResult:
            pass
        action = "would update" if exists else "would add"
        return "dry-run", action

    # ── add ──
    try:
        conn.add(dn, attributes=attrs)
        if conn.result["result"] == 0:
            return "added", ""
        if conn.result["result"] != 68:   # not entryAlreadyExists
            return "error", conn.result["description"]
    except LDAPEntryAlreadyExistsResult:
        pass
    except LDAPException as e:
        return "error", str(e)

    # ── entry already exists ──
    if skip_existing:
        return "skipped", "already exists"

    if not update:
        return "error", "entry already exists (use --update or --skip-existing)"

    # ── update: replace every attribute we have ──
    changes = {
        attr: [(MODIFY_REPLACE, val if isinstance(val, list) else [val])]
        for attr, val in attrs.items()
        if attr != "objectClass"   # objectClass changes need careful handling
    }
    # objectClass: add missing classes, but don't remove existing ones
    try:
        conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["objectClass"])
        existing_oc = set(
            conn.entries[0].objectClass.values
            if conn.entries else []
        )
    except LDAPException:
        existing_oc = set()

    new_oc = set(attrs.get("objectClass", []))
    combined = list(existing_oc | new_oc)
    changes["objectClass"] = [(MODIFY_REPLACE, combined)]

    try:
        conn.modify(dn, changes)
        if conn.result["result"] == 0:
            return "updated", ""
        return "error", conn.result["description"]
    except LDAPException as e:
        return "error", str(e)


# ── progress table ────────────────────────────────────────────────────────────

_STATUS_STYLE = {
    "added":    "green",
    "updated":  "cyan",
    "skipped":  "dim",
    "dry-run":  "yellow",
    "error":    "red",
}


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    console.rule("[bold blue]SQLite → OpenLDAP Import")
    console.print(f"  Started at [bold]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold]")
    if args.dry_run:
        console.print("  [bold yellow]DRY-RUN mode — no changes will be made[/bold yellow]")
    console.print()

    # ── 1. Open SQLite ───────────────────────────────────────────────────────
    console.rule("[bold]Step 1 — Open SQLite")
    try:
        db = sqlite3.connect(args.db)
        db.row_factory = sqlite3.Row
    except sqlite3.Error as e:
        sys.exit(f"Cannot open {args.db}: {e}")

    meta  = load_export_meta(db)
    users = load_users(db)

    if not users:
        sys.exit("No users found in the database.")

    src_base = args.source_base or meta.get("base_dn", "")
    console.print(f"  File          : [bold]{args.db}[/bold]")
    console.print(f"  Users to import: [bold]{len(users)}[/bold]")
    if meta:
        console.print(f"  Exported from : {meta.get('ldap_uri','')}  at {meta.get('run_at','')}")
        console.print(f"  Source base DN: {src_base}")
        pp = "yes" if meta.get("ppolicy_active") else "no"
        console.print(f"  ppolicy was   : {pp}  |  passwords reset: {meta.get('passwords_reset',0)}")

    # ── 2. Connect to target ─────────────────────────────────────────────────
    console.print()
    console.rule("[bold]Step 2 — Connect to target")
    conn, uri = connect(args)

    # Resolve target base DN
    tgt_base = args.target_base
    if not tgt_base:
        info = conn.server.info
        if info and info.naming_contexts:
            tgt_base = str(info.naming_contexts[0])
            console.print(f"  Auto-detected target base DN: [bold]{tgt_base}[/bold]")
        elif src_base:
            tgt_base = src_base
            console.print(f"  Using source base DN as target: [bold]{tgt_base}[/bold]")
        else:
            sys.exit("Cannot determine target base DN — pass --target-base explicitly.")

    if src_base and src_base.lower() != tgt_base.lower():
        console.print(
            f"  [yellow]DN rewrite:[/yellow] …{src_base} → …{tgt_base}"
        )

    # ── 3. Rewrite DNs ───────────────────────────────────────────────────────
    rewritten: list[tuple[str, dict, dict]] = []   # (new_dn, attrs, original_row)
    for row in users:
        orig_dn = row["dn"]
        new_dn  = rewrite_dn(orig_dn, src_base, tgt_base) if src_base else orig_dn
        attrs   = row_to_attrs(row, args.import_ppolicy_attrs)
        rewritten.append((new_dn, attrs, row))

    # ── 4. Ensure target base + intermediate OUs ─────────────────────────────
    console.print()
    console.rule("[bold]Step 3 — Scaffold structure")

    # Ensure the base DN itself exists
    console.print(f"  Checking base DN [bold]{tgt_base}[/bold] …", end=" ")
    created, status = ensure_dn_exists(conn, tgt_base, args.dry_run)
    icon = "[green]created[/green]" if created else f"[dim]{status}[/dim]"
    console.print(icon)

    all_new_dns = [dn for dn, _, _ in rewritten]
    ensure_structure(conn, all_new_dns, tgt_base, args.dry_run)

    # ── 5. Import users ───────────────────────────────────────────────────────
    console.print()
    console.rule("[bold]Step 4 — Import users")
    console.print()

    counters: dict[str, int] = defaultdict(int)
    table_rows: list[tuple] = []

    for new_dn, attrs, row in rewritten:
        uid  = row.get("uid") or "—"
        cn   = row.get("cn")  or "—"
        mail = row.get("mail") or "—"
        pw_note = (
            "[yellow]Argon2[/yellow]" if row.get("password_was_reset")
            else "[dim]original hash[/dim]"
        )

        status, detail = import_user(
            conn, new_dn, attrs,
            update=args.update,
            skip_existing=args.skip_existing,
            dry_run=args.dry_run,
        )
        counters[status] += 1

        display = status + (f" — {detail}" if detail else "")
        table_rows.append((new_dn, uid, cn[:28], mail[:28], pw_note, status, display))

    # ── render progress table ─────────────────────────────────────────────────
    if RICH:
        tbl = Table(
            "DN", "UID", "CN", "Mail", "Password", "Result",
            box=box.SIMPLE_HEAVY,
            show_lines=False,
            expand=True,
        )
        for dn, uid, cn, mail, pw, status, display in table_rows:
            style = _STATUS_STYLE.get(status, "white")
            import re
            pw_plain = re.sub(r"\[/?[^\]]*\]", "", pw)
            tbl.add_row(
                Text(dn[:70], overflow="ellipsis"),
                uid[:18],
                cn,
                mail,
                Text(pw_plain, style="yellow" if "Argon2" in pw_plain else "dim"),
                Text(display, style=style),
            )
        console.print(tbl)
    else:
        import re
        hdr = f"{'DN':<55}  {'UID':<14}  {'CN':<28}  {'Result'}"
        print(hdr)
        print("─" * len(hdr))
        for dn, uid, cn, mail, pw, status, display in table_rows:
            clean = re.sub(r"\[/?[^\]]*\]", "", display)
            print(f"{dn[:55]:<55}  {uid:<14}  {cn:<28}  {clean}")

    # ── 6. Summary ────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold blue]Import Summary")
    console.print()
    totals = [
        ("Target URI",      uri),
        ("Target base DN",  tgt_base),
        ("Source file",     args.db),
        ("Total processed", str(len(users))),
        ("Added",           str(counters["added"])),
        ("Updated",         str(counters["updated"])),
        ("Skipped",         str(counters["skipped"])),
        ("Dry-run",         str(counters["dry-run"])),
        ("Errors",          str(counters["error"])),
    ]
    for k, v in totals:
        style = "red" if k == "Errors" and v != "0" else "white"
        console.print(f"  [bold cyan]{k:<22}[/bold cyan]  [{style}]{v}[/{style}]")
    console.print()

    if counters["error"]:
        console.print("[bold red]Some entries failed — review the Result column above.[/bold red]\n")
    elif args.dry_run:
        console.print("[yellow]Dry-run complete — rerun without --dry-run to apply.[/yellow]\n")
    else:
        console.print("[green]Import complete.[/green]\n")

    conn.unbind()
    db.close()


if __name__ == "__main__":
    main()
