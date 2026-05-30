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
- Defaults to update mode (use --skip-existing to opt out)
- Imports the original userPassword and flags users with pwdReset=TRUE so
  they must change their password on next login (--no-force-password-change opts out)
- Protected uids (default: frquser, sut2k) are skipped entirely
- Dry-run support (--dry-run)
- Per-user progress table + final summary

Dependencies: pip install ldap3 rich
"""

import argparse
import base64
import getpass
import json
import re
import sqlite3
import ssl
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterator, Optional

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

# Service-account uids that must never be created or modified by the import.
# Override at the command line via --protect-uids.
DEFAULT_PROTECTED_UIDS = "frquser,sut2k"

# draft-zeilenga-ldap-relax: the Relax control tells the server "I'm a
# privileged admin doing a maintenance op, skip the usual checks." OpenLDAP's
# slapo-ppolicy honors it for both pre-hashed userPassword writes (no quality
# check on the supplied value) and for pwdReset (an operational attribute
# normally not writable from outside). criticality=False so servers that
# don't recognize the control still process the operation — the
# reset_password fallback handles any quality rejection that still occurs.
RELAX_RULES_CONTROL = ("1.3.6.1.4.1.4203.666.5.12", False, None)


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

    p.add_argument(
        "--skip-existing",
        action="store_true",
        help="Silently skip entries that already exist (default: update them).",
    )
    p.add_argument(
        "--no-force-password-change",
        action="store_true",
        help=(
            "Don't set pwdReset=TRUE on imported users. By default every"
            " added or updated user is flagged so they must change their"
            " password on next login (requires the ppolicy schema on the target)."
        ),
    )
    p.add_argument(
        "--protect-uids",
        default=DEFAULT_PROTECTED_UIDS,
        help=(
            "Comma-separated uids that must never be created or modified."
            " Matching source entries are skipped entirely. Default: %(default)s."
        ),
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
            "Fallback when ppolicy still rejects a userPassword even with the"
            " Relax control attached (e.g. the bind identity lacks Relax"
            " authority): retry with the plaintext default password so the"
            " server can run its own quality checks and hash it under"
            " olcPasswordHash."
        ),
    )
    p.add_argument(
        "--reset-password-value",
        default=DEFAULT_RESET_PASSWORD,
        help="Plaintext used for the reset retry. Default: %(default)s.",
    )
    p.add_argument(
        "--skip-argon2-check",
        action="store_true",
        help=(
            "Skip the preflight that verifies the target has the argon2"
            " password module loaded before importing {ARGON2} hashes."
        ),
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


def detect_source_base(dns: list[str]) -> str:
    """Best-effort source base DN inferred from a set of entry DNs.

    LDIF exports (unlike the SQLite path) carry no export_run table recording
    the base DN, so we derive it from the entries themselves. We take the
    longest trailing run of ``dc=`` components shared by every DN — the domain
    suffix in typical layouts (``uid=x,ou=users,dc=a,dc=b`` → ``dc=a,dc=b``).
    Intermediate org units (``ou=users``) are deliberately kept OUT of the
    base so they survive the rewrite onto the target base.

    Falls back to the longest common trailing RDN run for bases that use no
    ``dc=`` components (e.g. ``o=Acme,c=US``). Returns "" if nothing is shared.
    """
    if not dns:
        return ""

    def dc_suffix(dn: str) -> list[str]:
        rdns = _split_dn(dn)
        out: list[str] = []
        for rdn in reversed(rdns):
            if rdn.partition("=")[0].strip().lower() == "dc":
                out.insert(0, rdn)
            else:
                break
        return out

    suffixes = [dc_suffix(d) for d in dns]
    if all(suffixes) and len(
        {tuple(_normalize_rdn(r) for r in s) for s in suffixes}
    ) == 1:
        return ",".join(suffixes[0])

    # Fallback: longest common trailing RDN run across all DNs.
    common: list[str] = []
    for tail in zip(*(list(reversed(_split_dn(d))) for d in dns)):
        if len({_normalize_rdn(r) for r in tail}) == 1:
            common.insert(0, tail[0])
        else:
            break
    return ",".join(common)


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


# ── userPassword application ─────────────────────────────────────────────────

def _password_is_hashed(value: object) -> bool:
    """A captured userPassword is pre-hashed when it carries a `{SCHEME}` prefix.

    We only inspect the first value: ldap_users rows hold a single password
    and LDIF/SQLite paths both surface it as a single str/bytes value.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, bytes):
        return value.startswith(b"{")
    if isinstance(value, str):
        return value.startswith("{")
    return False


def _password_scheme(value: object) -> Optional[str]:
    """Return the upper-cased ``{SCHEME}`` name of a userPassword value
    (e.g. ``ARGON2``, ``CRYPT``, ``SSHA``), or None when it carries no scheme
    prefix (plaintext). Inspects only the first value, matching
    :func:`_password_is_hashed`."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")
    if not isinstance(value, str) or not value.startswith("{"):
        return None
    end = value.find("}")
    return value[1:end].upper() if end > 1 else None


def preflight_argon2(conn: Connection, users: list[dict], skip: bool) -> None:
    """Verify the target loads the argon2 module when any user carries an
    ``{ARGON2}`` userPassword.

    Argon2 hashes are stored verbatim under the Relax control, so the server
    must recognise the scheme. A server without ``pw-argon2`` rejects the
    MODIFY with a generic error (not a ppolicy constraint), so the
    reset-password fallback never fires and every Argon2 user fails to import
    while ``{CRYPT}``/``{SSHA}`` users still succeed — a confusing partial
    failure this check turns into one clear up-front error.

    Detection reads ``olcModuleLoad`` from ``cn=config`` (best-effort): when
    that subtree isn't readable by the bind identity — common for simple binds
    to the data backend — we can't confirm and only warn. Aborts only when the
    module is positively absent.
    """
    argon2_users = [
        u for u in users if _password_scheme(u.get("user_password")) == "ARGON2"
    ]
    if not argon2_users:
        return

    n = len(argon2_users)
    if skip:
        console.print(
            f"  [yellow]Skipping argon2 module preflight[/yellow] "
            f"({n} {{ARGON2}} user(s)) — --skip-argon2-check set."
        )
        return

    console.print(
        f"  {n} user(s) carry {{ARGON2}} hashes — checking target loads the "
        "argon2 module …",
        end=" ",
    )

    try:
        found = conn.search(
            "cn=config",
            "(olcModuleLoad=*)",
            search_scope=SUBTREE,
            attributes=["olcModuleLoad"],
        )
    except LDAPException as e:
        console.print(f"[yellow]could not verify[/yellow] ({e})")
        _warn_argon2_unverified()
        return

    if not found:
        console.print("[yellow]could not verify[/yellow] (cn=config not readable)")
        _warn_argon2_unverified()
        return

    loaded = any(
        "argon2" in str(v).lower()
        for entry in conn.entries
        for v in entry.olcModuleLoad.values
    )
    if loaded:
        console.print("[green]argon2 loaded[/green]")
        return

    console.print("[red]argon2 NOT loaded[/red]")
    sys.exit(
        f"\nThe target server does not have the argon2 password module loaded, "
        f"but {n} user(s) have {{ARGON2}} password hashes that would be stored "
        "verbatim.\nThose writes will fail. Load the module first, e.g.:\n\n"
        "  dn: cn=module{0},cn=config\n"
        "  changetype: modify\n"
        "  add: olcModuleLoad\n"
        "  olcModuleLoad: argon2\n\n"
        "Then re-run. Override this check with --skip-argon2-check."
    )


def _warn_argon2_unverified() -> None:
    console.print(
        "    [dim]Could not read cn=config to confirm the argon2 module. "
        "If {ARGON2} writes fail, load pw-argon2 on the target "
        "(olcModuleLoad: argon2).[/dim]"
    )


def _set_user_password(
    conn: Connection,
    dn: str,
    pw_value: object,
    reset_password: Optional[str],
) -> tuple[str, str]:
    """
    Apply userPassword via MODIFY_REPLACE on *dn*.

    Pre-hashed values are sent with the Relax control so OpenLDAP's ppolicy
    skips quality checking and stores the {SSHA}/{CRYPT}/… bytes verbatim;
    plaintext values are sent without Relax so the server runs olcPasswordHash
    and stores the resulting hash.

    When ppolicy still rejects (e.g. the bind identity has no Relax authority
    or the server doesn't honor the control) and ``reset_password`` is set,
    retries once with that plaintext.

    Returns one of:
      ("ok",    "")                          — password applied
      ("ok",    "password unchanged")        — target already held this value
      ("reset", "applied with reset password")
      ("reset", "already at reset password")
      ("error", "...")
    """
    pw_list = pw_value if isinstance(pw_value, list) else [pw_value]
    first = pw_list[0] if pw_list else None
    controls = [RELAX_RULES_CONTROL] if _password_is_hashed(first) else None

    try:
        conn.modify(
            dn,
            {"userPassword": [(MODIFY_REPLACE, pw_list)]},
            controls=controls,
        )
        if conn.result["result"] == 0:
            return "ok", ""
        return "error", conn.result["description"]
    except LDAPConstraintViolationResult as e:
        # ppolicy may reject because (a) it doesn't honor Relax for this
        # bind / value, or (b) the new value equals the stored one
        # ("not being changed"), which is benign.
        if "not being changed" in (e.message or "").lower():
            return "ok", "password unchanged"
        if not reset_password:
            return "error", str(e)
        try:
            conn.modify(dn, {"userPassword": [(MODIFY_REPLACE, [reset_password])]})
            if conn.result["result"] == 0:
                return "reset", "applied with reset password"
            return "error", f"reset-retry failed: {conn.result['description']}"
        except LDAPConstraintViolationResult as e2:
            # Re-imports land here: the target already holds the reset
            # plaintext, so a MODIFY_REPLACE to the same value trips
            # "not being changed". That's the state we want — surface it
            # as a successful reset.
            if "not being changed" in (e2.message or "").lower():
                return "reset", "already at reset password"
            return "error", f"reset-retry failed: {e2}"
        except LDAPException as e2:
            return "error", f"reset-retry failed: {e2}"
    except LDAPException as e:
        return "error", str(e)


# ── import a single user ─────────────────────────────────────────────────────

def import_user(
    conn: Connection,
    dn: str,
    attrs: dict,
    *,
    update: bool,
    skip_existing: bool,
    dry_run: bool,
    reset_password: Optional[str] = None,
) -> tuple[str, str]:
    """
    Add (or update) one user entry.
    Returns (status, detail) where
    status ∈ {added, updated, reset, skipped, error, dry-run}.

    userPassword is always applied via a separate MODIFY_REPLACE (with the
    Relax control for pre-hashed values, so ppolicy skips quality checking).
    Splitting it out of the add/bulk-update means a password rejection
    never blocks entry creation or rolls back other attribute changes —
    the entry lands first, and any password failure is reported per-user.

    When ``reset_password`` is set and ppolicy still rejects the supplied
    value, the password modify is retried once with that plaintext, which
    the server hashes via olcPasswordHash.
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

    pw_val = attrs.get("userPassword")
    attrs_no_pw = {k: v for k, v in attrs.items() if k != "userPassword"}

    # ── add (without userPassword — applied separately below) ──
    try:
        conn.add(dn, attributes=attrs_no_pw)
        if pw_val is None:
            return "added", ""
        pw_status, pw_detail = _set_user_password(conn, dn, pw_val, reset_password)
        if pw_status == "error":
            return "error", f"added; password: {pw_detail}"
        if pw_status == "reset":
            return "reset", pw_detail
        return "added", pw_detail
    except LDAPEntryAlreadyExistsResult:
        pass
    except LDAPException as e:
        return "error", str(e)

    # ── entry already exists ──
    if skip_existing:
        return "skipped", "already exists"
    if not update:
        return "error", "entry already exists (use --update or --skip-existing)"

    # ── update non-password attributes ──
    changes = {
        attr: [(MODIFY_REPLACE, val if isinstance(val, list) else [val])]
        for attr, val in attrs_no_pw.items()
        if attr != "objectClass"
    }
    # objectClass: union with existing, never shrink
    try:
        conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["objectClass"])
        existing_oc = set(
            conn.entries[0].objectClass.values if conn.entries else []
        )
    except LDAPException:
        existing_oc = set()
    combined = list(existing_oc | set(attrs.get("objectClass", [])))
    changes["objectClass"] = [(MODIFY_REPLACE, combined)]

    try:
        conn.modify(dn, changes)
        if conn.result["result"] != 0:
            return "error", conn.result["description"]
    except LDAPException as e:
        return "error", str(e)

    # ── update userPassword ──
    if pw_val is None:
        return "updated", ""
    pw_status, pw_detail = _set_user_password(conn, dn, pw_val, reset_password)
    if pw_status == "error":
        return "error", f"password: {pw_detail}"
    if pw_status == "reset":
        return "reset", pw_detail
    return "updated", pw_detail


# ── pwdReset (force password change on next login) ───────────────────────────

def force_password_change(
    conn: Connection, dn: str, dry_run: bool
) -> tuple[bool, str]:
    """Set pwdReset=TRUE so the user must change password on next login.

    pwdReset is a ppolicy operational attribute — external writes to it
    require the Relax control, which we attach. The modify still fails
    with 'undefined attribute type' if the ppolicy schema isn't loaded
    on the target; the caller surfaces that per-user without aborting.
    """
    if dry_run:
        return True, "would set pwdReset=TRUE"
    try:
        conn.modify(
            dn,
            {"pwdReset": [(MODIFY_REPLACE, ["TRUE"])]},
            controls=[RELAX_RULES_CONTROL],
        )
        if conn.result["result"] == 0:
            return True, "pwdReset=TRUE"
        return False, conn.result["description"]
    except LDAPException as e:
        return False, str(e)


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
# Minimal RFC 2849 reader extracted from ldif3 (MIT-licensed, abandoned upstream).
# Only the entry-record subset we need: line folding, blank-line record split,
# `attr: text` / `attr:: base64`. `attr:< url` references are not consumed
# (we never emit them) and the entire `changetype:` machinery is omitted.

USER_OBJECT_CLASSES = {"inetorgperson", "posixaccount", "shadowaccount", "person"}


def _iter_ldif_blocks(path: str) -> Iterator[list[bytes]]:
    """Yield non-empty blocks of unfolded, comment-free logical lines.
    A block is a maximal run separated by blank lines. Continuation lines
    (a leading space, per RFC 2849 §2.2) are appended to the previous line."""
    block: list[bytes] = []
    logical: Optional[bytes] = None

    def flush_logical():
        if logical is not None and not logical.startswith(b"#"):
            block.append(logical)

    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if line.startswith(b" ") and logical is not None:
                logical += line[1:]
                continue
            flush_logical()
            logical = None
            if not line:
                if block:
                    yield block
                    block = []
            else:
                logical = line
        flush_logical()
        if block:
            yield block


def _parse_ldif_attr(line: bytes) -> tuple[str, bytes]:
    """Parse one `attr: value` / `attr:: base64` line. Returns the attribute
    name (original case) and the raw byte value. Raises ValueError if there
    is no colon (caller treats that as a non-attribute line)."""
    colon = line.index(b":")
    attr = line[:colon].decode("ascii")
    rest = line[colon + 1:]
    if rest.startswith(b":"):
        return attr, base64.b64decode(rest[1:].strip())
    if rest.startswith(b"<"):
        return attr, b""  # URL references unsupported — same default as ldif3
    return attr, rest.lstrip(b" ")


def _decode_ldif_value(v: bytes) -> str:
    return v.decode("utf-8", errors="replace")


def read_ldif_users(path: str) -> list[dict]:
    """
    Parse an LDIF export and return rows shaped like the SQLite ldap_users
    table, so the downstream pipeline (row_to_attrs, rewrite_dn,
    ensure_structure, import_user) works unchanged.

    Tolerates raw `ldapsearch -LLL` output: blocks without a `dn:` line
    (search/result preamble, `# numResponses: …`) are skipped silently.
    """
    attr_to_col = {ldap_attr.lower(): col for col, ldap_attr in COLUMN_TO_ATTR.items()}

    console.print(f"Reading LDIF file: [bold]{path}[/bold]")

    users: list[dict] = []
    for block in _iter_ldif_blocks(path):
        dn: Optional[str] = None
        entry: dict[str, list[bytes]] = {}
        for line in block:
            try:
                attr, val = _parse_ldif_attr(line)
            except ValueError:
                continue
            if attr.lower() == "dn":
                dn = _decode_ldif_value(val)
            else:
                entry.setdefault(attr.lower(), []).append(val)

        if dn is None:
            continue  # ldapsearch preamble/result block

        object_classes = [_decode_ldif_value(v) for v in entry.get("objectclass", [])]
        if not ({c.lower() for c in object_classes} & USER_OBJECT_CLASSES):
            continue

        row: dict = {
            "dn": dn,
            "object_classes": json.dumps(object_classes),
        }

        for attr_lower, values in entry.items():
            if attr_lower == "objectclass" or not values:
                continue
            col = attr_to_col.get(attr_lower)
            if col is None:
                continue
            # userPassword keeps raw bytes — utf-8 decode-with-replace would
            # corrupt {SSHA}/{CRYPT} binary hashes. Other attrs are text.
            row[col] = values[0] if col == "user_password" else _decode_ldif_value(values[0])

        mo = entry.get("memberof")
        if mo:
            row["member_of"] = json.dumps([_decode_ldif_value(v) for v in mo])

        users.append(row)

    console.print(f"  Parsed [bold]{len(users)}[/bold] user entries")
    return users

# ── progress table ────────────────────────────────────────────────────────────

_STATUS_STYLE = {
    "added":     "green",
    "updated":   "cyan",
    "reset":     "magenta",
    "skipped":   "dim",
    "protected": "blue",
    "dry-run":   "yellow",
    "error":     "red",
}


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    protected_uids = {
        u.strip().lower() for u in args.protect_uids.split(",") if u.strip()
    }

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
    if not src_base and args.ldif:
        src_base = detect_source_base([u["dn"] for u in users])
        if src_base:
            console.print(
                f"  Auto-detected source base DN: [bold]{src_base}[/bold]"
            )
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

    # Fail fast if {ARGON2} hashes are present but the module is missing.
    preflight_argon2(conn, users, args.skip_argon2_check)

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

    # Protected users are skipped entirely, so don't scaffold OUs that exist
    # only to host one.
    all_new_dns = [
        dn for dn, _, row in rewritten
        if (row.get("uid") or "").strip().lower() not in protected_uids
    ]
    ensure_structure(conn, all_new_dns, tgt_base, args.dry_run)

    # ── 5. Import users ───────────────────────────────────────────────────────
    console.print()
    console.rule("[bold]Step 4 — Import users")
    console.print()

    reset_plaintext: Optional[str] = None
    if args.reset_rejected_passwords:
        reset_plaintext = args.reset_password_value
        console.print(
            f"  [magenta]Reset-on-reject enabled[/magenta] — rejected passwords will "
            f"be replaced with the plaintext [bold]{args.reset_password_value}[/bold] "
            f"(server will hash it via olcPasswordHash)"
        )
    if protected_uids:
        console.print(
            f"  [blue]Protected uids (never touched):[/blue] "
            f"{', '.join(sorted(protected_uids))}"
        )
    if not args.no_force_password_change:
        console.print(
            "  [cyan]Force password change[/cyan] — pwdReset=TRUE will be set on"
            " every imported user (requires ppolicy schema on the target)"
        )
    console.print()

    counters: dict[str, int] = defaultdict(int)
    table_rows: list[tuple] = []

    for new_dn, attrs, row in rewritten:
        uid  = row.get("uid") or "—"
        uid_key = (row.get("uid") or "").strip().lower()
        cn   = row.get("cn")  or "—"
        mail = row.get("mail") or "—"
        pw_note = (
            "[yellow]Argon2[/yellow]" if row.get("password_was_reset")
            else "[dim]original hash[/dim]"
        )

        if uid_key in protected_uids:
            status, detail = "protected", "uid is protected, untouched"
            counters[status] += 1
            display = f"{status} — {detail}"
            table_rows.append((new_dn, uid, cn[:28], mail[:28], pw_note, status, display))
            continue

        status, detail = import_user(
            conn, new_dn, attrs,
            update=not args.skip_existing,
            skip_existing=args.skip_existing,
            dry_run=args.dry_run,
            reset_password=reset_plaintext,
        )
        counters[status] += 1

        if (
            status in ("added", "updated", "reset", "dry-run")
            and not args.no_force_password_change
        ):
            ok, fdetail = force_password_change(conn, new_dn, args.dry_run)
            counters["pwdreset_ok" if ok else "pwdreset_failed"] += 1
            tag = fdetail if ok else f"pwdReset failed: {fdetail}"
            detail = f"{detail}; {tag}" if detail else tag

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
    importable = [
        (dn, attrs, row) for dn, attrs, row in rewritten
        if (row.get("uid") or "").strip().lower() not in protected_uids
    ]
    mb_counts = sync_group_memberships(
        conn, importable, src_base or "", tgt_base, args.dry_run
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
        ("Protected",       str(counters["protected"])),
        ("Dry-run",         str(counters["dry-run"])),
        ("Errors",          str(counters["error"])),
        ("pwdReset set",    str(counters["pwdreset_ok"])),
        ("pwdReset failed", str(counters["pwdreset_failed"])),
        ("Group links added",    str(mb_counts.get("added", 0))),
        ("Already member",       str(mb_counts.get("already_member", 0))),
        ("Group links (dry-run)", str(mb_counts.get("dry-run", 0))),
        ("Missing groups",       str(mb_counts.get("no_group", 0))),
        ("Group link errors",    str(mb_counts.get("error", 0))),
    ]
    for k, v in totals:
        red_keys = ("Errors", "Group link errors", "pwdReset failed")
        style = "red" if k in red_keys and v != "0" else "white"
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
