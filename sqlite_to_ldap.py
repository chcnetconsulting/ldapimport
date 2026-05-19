#!/usr/bin/env python3
"""
Copyright Frequentis AG (c) 2026
import.py — Import users from an export.py export into a target OpenLDAP.

install requirements with pip install -r requirements.txt

Usage:
python3 import.py ldap_export.sqlite

ldap_export.sqlite from the previous export.py run must be present, user --dry-run for a test, whether all is correct, what would be imported.

connects via ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi and SASL Method EXTERNAL (required root privileges), or with user privileges as bind_dn user

required: ldap_export.sqlite3

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
# ldif3 is unmaintained and calls base64.decodestring / encodestring, which were
# removed in Python 3.9. Restore aliases before importing so the module loads
# under modern Python.
import base64 as _base64
if not hasattr(_base64, "decodestring"):
    _base64.decodestring = _base64.decodebytes
if not hasattr(_base64, "encodestring"):
    _base64.encodestring = _base64.encodebytes

try:
    from ldif3 import LDIFParser
    LDIF3 = True
except ImportError:
    LDIF3 = False  # only required when --ldif is used; checked in read_ldif_users()

try:
    from ldap3 import (
        ALL,
        BASE,
        MODIFY_ADD,
        MODIFY_REPLACE,
        SASL,
        SUBTREE,
        Connection,
        Server,
        Tls,
    )
    from ldap3.core.exceptions import (
        LDAPAttributeOrValueExistsResult,
        LDAPConstraintViolationResult,
        LDAPEntryAlreadyExistsResult,
        LDAPException,
        LDAPNoSuchObjectResult,
    )
except ImportError:
    sys.exit("ldap3 not installed — run: pip install ldap3")

try:
    from argon2 import PasswordHasher
    ARGON2 = True
except ImportError:
    ARGON2 = False  # only required when --reset-rejected-passwords is used

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


# Matches DEFAULT_PASSWORD in ldap_to_sqlite.py, so a round-trip "ppolicy
# absent → ppolicy present" import lands on the same plaintext.
DEFAULT_RESET_PASSWORD = "Changeme12345!"


def argon2_ldap_hash(password: str) -> str:
    """Return {ARGON2}<hash> in the form OpenLDAP's pw-argon2 module accepts."""
    if not ARGON2:
        sys.exit("argon2-cffi not installed — run: pip install argon2-cffi")
    return f"{{ARGON2}}{PasswordHasher().hash(password)}"


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
    "id", "dn", "object_classes", "member_of", "password_was_reset",
    "export_timestamp", "create_timestamp", "modify_timestamp",
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
    # ppolicy state — gated by --import-ppolicy-attrs (see row_to_attrs)
    "pwd_account_locked": "pwdAccountLockedTime",
    "pwd_changed_time":   "pwdChangedTime",
    "pwd_failure_time":   "pwdFailureTime",
}


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dbmode =  p.add_mutually_exclusive_group(required=True)
    dbmode.add_argument("--db", help="SQLite file produced by ldap_export.py")
    dbmode.add_argument("--ldif", help="Read users from domain.ldif file instead of former tmcs export script")

    p.add_argument(
        "--uri",
        help="Target LDAP URI (default: try ldapi://%%2Fvar%%2Frun%%2Fslapd%%2Fldapi then ldaps://localhost:636)",
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
    p.add_argument(
        "--reset-rejected-passwords",
        action="store_true",
        help=(
            "When the target ppolicy rejects a userPassword (constraintViolation),"
            " retry the operation with a strong Argon2-hashed default. Requires the"
            " OpenLDAP pw-argon2 module on the target server."
        ),
    )
    p.add_argument(
        "--reset-password-value",
        default=DEFAULT_RESET_PASSWORD,
        help="Plaintext used for the reset retry. Default: %(default)s.",
    )

    return p.parse_args()


# ── LDAP connection ──────────────────────────────────────────────────────────

def connect(args: argparse.Namespace) -> tuple[Connection, str]:
    bind_dn = args.bind_dn
    bind_pw = args.bind_pw

    if bind_dn and bind_pw is None:
        bind_pw = getpass.getpass(f"Password for {bind_dn}: ")

    uris = [args.uri] if args.uri else ["ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi", "ldaps://localhost:636"]

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

def _split_dn(dn: str) -> list[str]:
    """Split a DN into RDN strings, respecting escaped commas. Each RDN is
    stripped of surrounding whitespace so callers can compare DNs that differ
    only in cosmetic spacing (e.g. `uid=x, ou=u` vs `uid=x,ou=u`)."""
    return [p.strip() for p in re.split(r"(?<!\\),", dn)]


def _normalize_rdn(rdn: str) -> str:
    """Canonical, comparison-only form of an RDN: lower-case attribute type
    and value, whitespace trimmed. LDAP's distinguishedNameMatch is case-
    insensitive on the standard naming attributes (dc, ou, cn, …), so suffix
    matching here is too. The original RDN strings are still preserved for
    reconstruction — this output is only used for equality checks."""
    t, _, v = rdn.partition("=")
    return f"{t.strip().lower()}={v.strip().lower()}"


def _normalize_dn(dn: str) -> str:
    return ",".join(_normalize_rdn(p) for p in _split_dn(dn))


def rewrite_dn(dn: str, src_base: str, tgt_base: str) -> str:
    """Replace the trailing src_base suffix of dn with tgt_base. Attribute
    types match case-insensitively; whitespace around RDN separators is
    ignored. Returns dn unchanged if src_base isn't a suffix."""
    if not src_base or _normalize_dn(src_base) == _normalize_dn(tgt_base):
        return dn

    dn_rdns = _split_dn(dn)
    sb_rdns = _split_dn(src_base)

    if len(dn_rdns) < len(sb_rdns):
        return dn

    dn_tail_norm = [_normalize_rdn(r) for r in dn_rdns[-len(sb_rdns):]]
    sb_norm      = [_normalize_rdn(r) for r in sb_rdns]
    if dn_tail_norm != sb_norm:
        return dn

    prefix = dn_rdns[: -len(sb_rdns)]
    return f"{','.join(prefix)},{tgt_base}" if prefix else tgt_base


# ── OU scaffolding ────────────────────────────────────────────────────────────


def intermediate_dns(dn: str, base_dn: str) -> list[str]:
    """
    Return the OUs between base_dn and dn that need to exist, ordered top-down.
    e.g. uid=jdoe,ou=users,dc=frequentis,dc=frq with base dc=frequentis,dc=frq
    → ['ou=users,dc=frequentis,dc=frq']
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
            try:
                attrs[ldap_attr] = int(val)
            except (TypeError, ValueError):
                continue
        elif isinstance(val, (str, bytes)):
            # Pass str and bytes through unchanged. Critical for userPassword
            # binary hashes: str(b'{SSHA}…') would coerce to "b'{SSHA}…'".
            attrs[ldap_attr] = val
        else:
            attrs[ldap_attr] = str(val)

    # memberOf is operational (maintained by the memberof overlay from group
    # `member` attributes) and rejected on direct write. Group membership is
    # reconstructed by sync_group_memberships() after the user import.

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
    reset_password_hash: Optional[str] = None,
) -> tuple[str, str]:
    """
    Add (or update) one user entry.
    Returns (status, detail) where
    status ∈ {added, updated, reset, skipped, error, dry-run}.

    When reset_password_hash is set and the server rejects userPassword with a
    constraint violation, the operation is retried once with that hash
    substituted for the original userPassword.
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
    except LDAPConstraintViolationResult as e:
        if reset_password_hash and "userPassword" in attrs:
            retry = dict(attrs)
            retry["userPassword"] = reset_password_hash
            try:
                conn.add(dn, attributes=retry)
                if conn.result["result"] == 0:
                    return "reset", "added with reset password"
                return "error", f"reset-retry failed: {conn.result['description']}"
            except LDAPException as e2:
                return "error", f"reset-retry failed: {e2}"
        return "error", str(e)
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
    except LDAPConstraintViolationResult as e:
        if reset_password_hash and "userPassword" in changes:
            retry = dict(changes)
            retry["userPassword"] = [(MODIFY_REPLACE, [reset_password_hash])]
            try:
                conn.modify(dn, retry)
                if conn.result["result"] == 0:
                    return "reset", "updated with reset password"
                return "error", f"reset-retry failed: {conn.result['description']}"
            except LDAPException as e2:
                return "error", f"reset-retry failed: {e2}"
        return "error", str(e)
    except LDAPException as e:
        return "error", str(e)


# ── group-membership reconstruction ──────────────────────────────────────────

def sync_group_memberships(
    conn: Connection,
    rewritten: list[tuple[str, dict, dict]],
    src_base: str,
    tgt_base: str,
    dry_run: bool,
) -> dict[str, int]:
    """
    Reconstruct group membership on the target by adding each user's
    (rewritten) DN to the `member` attribute of every group named in the
    captured memberOf snapshot. Group DNs are rewritten src_base → tgt_base
    the same way user DNs are. Idempotent: already-member is silently OK,
    missing groups are warned and counted but not fatal.
    """
    counts: dict[str, int] = defaultdict(int)

    # (group_dn → list of user_dns) so we modify each group once.
    plan: dict[str, list[str]] = defaultdict(list)
    for user_dn, _attrs, row in rewritten:
        mo_raw = row.get("member_of")
        if not mo_raw:
            continue
        try:
            groups = json.loads(mo_raw)
        except (TypeError, ValueError):
            continue
        for g in groups or []:
            g_new = rewrite_dn(g, src_base, tgt_base) if src_base else g
            plan[g_new].append(user_dn)

    if not plan:
        console.print("  [dim]No memberOf data to apply.[/dim]")
        return counts

    pair_total = sum(len(v) for v in plan.values())
    console.print(
        f"  Applying [bold]{pair_total}[/bold] membership(s) "
        f"across [bold]{len(plan)}[/bold] group(s):"
    )

    for g_dn, user_dns in plan.items():
        if dry_run:
            for u_dn in user_dns:
                console.print(f"    [yellow][dry-run][/yellow] would add {u_dn} → {g_dn}")
                counts["dry-run"] += 1
            continue

        for u_dn in user_dns:
            try:
                conn.modify(g_dn, {"member": [(MODIFY_ADD, [u_dn])]})
                if conn.result["result"] == 0:
                    console.print(f"    [green]+[/green] {u_dn} → {g_dn}")
                    counts["added"] += 1
                else:
                    console.print(
                        f"    [red]![/red] {u_dn} → {g_dn}: {conn.result['description']}"
                    )
                    counts["error"] += 1
            except LDAPAttributeOrValueExistsResult:
                counts["already_member"] += 1
            except LDAPNoSuchObjectResult:
                console.print(f"    [yellow]?[/yellow] group missing: {g_dn}")
                counts["no_group"] += 1
            except LDAPException as e:
                console.print(f"    [red]![/red] {u_dn} → {g_dn}: {e}")
                counts["error"] += 1

    return counts


# ── LDIF reader ──────────────────────────────────────────────────────────────

USER_OBJECT_CLASSES = {"inetorgperson", "posixaccount", "shadowaccount", "person"}


def _decode_ldif_value(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return v


def _is_entry_block(lines: list[bytes]) -> bool:
    for l in lines:
        s = l.strip()
        if not s or s.startswith(b"#"):
            continue
        return s.lower().startswith(b"dn:")
    return False


def _strip_search_preamble(path: str) -> bytes:
    """
    The LDIF files we ingest may be raw `ldapsearch -LLL` output, which
    interleaves entry records with preamble/result blocks
    (`search: 2`, `result: 0 Success`, `# numResponses: …`). ldif3 rejects
    anything that isn't a clean record sequence, so drop the non-entry blocks
    here and feed the cleaned bytes to the parser.
    """
    out: list[bytes] = []
    block: list[bytes] = []
    with open(path, "rb") as f:
        for line in f:
            if not line.strip():
                if block and _is_entry_block(block):
                    out.extend(block)
                    out.append(b"\n")
                block = []
            else:
                block.append(line)
        if block and _is_entry_block(block):
            out.extend(block)
            out.append(b"\n")
    return b"".join(out)


def read_ldif_users(path: str) -> list[dict]:
    """
    Parse an LDIF export and return rows shaped like the SQLite ldap_users
    table, so the downstream pipeline (row_to_attrs, rewrite_dn,
    ensure_structure, import_user) works unchanged.
    """
    if not LDIF3:
        sys.exit("ldif3 not installed — run: pip install ldif3")

    # LDAP attribute (lower) → SQLite column
    attr_to_col = {ldap_attr.lower(): col for col, ldap_attr in COLUMN_TO_ATTR.items()}

    console.print(f"Reading LDIF file: [bold]{path}[/bold]")

    from io import BytesIO
    cleaned = _strip_search_preamble(path)

    users: list[dict] = []
    for dn, entry in LDIFParser(BytesIO(cleaned)).parse():
        norm = {k.lower(): v for k, v in entry.items()}

        object_classes = [_decode_ldif_value(v) for v in norm.get("objectclass", [])]
        if not ({c.lower() for c in object_classes} & USER_OBJECT_CLASSES):
            continue

        row: dict = {
            "dn": dn,
            "object_classes": json.dumps(object_classes),
        }

        for attr_lower, values in norm.items():
            if attr_lower == "objectclass" or not values:
                continue
            col = attr_to_col.get(attr_lower)
            if col is None:
                continue
            # Keep userPassword as raw bytes — utf-8 decoding with replacement
            # would corrupt binary hashes. Other attrs are text.
            row[col] = values[0] if col == "user_password" else _decode_ldif_value(values[0])

        mo = norm.get("memberof")
        if mo:
            row["member_of"] = json.dumps([_decode_ldif_value(v) for v in mo])

        users.append(row)

    console.print(f"  Parsed [bold]{len(users)}[/bold] user entries")
    return users

# ── progress table ────────────────────────────────────────────────────────────

_STATUS_STYLE = {
    "added":    "green",
    "updated":  "cyan",
    "reset":    "magenta",
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


    if args.ldif:
        console.rule("[bold]Step 1 — Read LDIF")
        users = read_ldif_users(args.ldif)
        meta = {}
        db = None
        source_label = args.ldif
        if not users:
            sys.exit("No user entries found in LDIF.")
    else:
        console.rule("[bold]Step 1 — Open SQLite")
        try:
            db = sqlite3.connect(args.db)
            db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            sys.exit(f"Cannot open {args.db}: {e}")

        meta  = load_export_meta(db)
        users = load_users(db)
        source_label = args.db
        if not users:
            sys.exit("No users found in the database.")

    src_base = args.source_base or meta.get("base_dn", "")
    console.print(f"  Source         : [bold]{source_label}[/bold]")
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

    reset_hash: Optional[str] = None
    if args.reset_rejected_passwords:
        reset_hash = argon2_ldap_hash(args.reset_password_value)
        console.print(
            f"  [magenta]Reset-on-reject enabled[/magenta] — rejected passwords will "
            f"be replaced with the Argon2 hash of [bold]{args.reset_password_value}[/bold]\n"
        )

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
            reset_password_hash=reset_hash,
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

    # ── 5. Reconstruct group membership ──────────────────────────────────────
    console.print()
    console.rule("[bold]Step 5 — Sync group membership")
    mb_counts = sync_group_memberships(
        conn, rewritten, src_base or "", tgt_base, args.dry_run
    )

    # ── 6. Summary ────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold blue]Import Summary")
    console.print()
    totals = [
        ("Target URI",      uri),
        ("Target base DN",  tgt_base),
        ("Source",          source_label),
        ("Total processed", str(len(users))),
        ("Added",           str(counters["added"])),
        ("Updated",         str(counters["updated"])),
        ("Passwords reset", str(counters["reset"])),
        ("Skipped",         str(counters["skipped"])),
        ("Dry-run",         str(counters["dry-run"])),
        ("Errors",          str(counters["error"])),
        ("Group links added",    str(mb_counts.get("added", 0))),
        ("Already member",       str(mb_counts.get("already_member", 0))),
        ("Group links (dry-run)", str(mb_counts.get("dry-run", 0))),
        ("Missing groups",       str(mb_counts.get("no_group", 0))),
        ("Group link errors",    str(mb_counts.get("error", 0))),
    ]
    for k, v in totals:
        style = "red" if k in ("Errors", "Group link errors") and v != "0" else "white"
        console.print(f"  [bold cyan]{k:<22}[/bold cyan]  [{style}]{v}[/{style}]")
    console.print()

    if counters["error"]:
        console.print("[bold red]Some entries failed — review the Result column above.[/bold red]\n")
    elif args.dry_run:
        console.print("[yellow]Dry-run complete — rerun without --dry-run to apply.[/yellow]\n")
    else:
        console.print("[green]Import complete.[/green]\n")

    conn.unbind()
    if db is not None:
        db.close()


if __name__ == "__main__":
    main()
