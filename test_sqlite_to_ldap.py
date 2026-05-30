"""
Tests for sqlite_to_ldap.py.

Run with: pytest test_sqlite_to_ldap.py -v

Uses ldap3's MOCK_SYNC strategy, so no real LDAP server is required.
"""

import base64
import json
import sqlite3
import sys
from pathlib import Path

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_SLAPD_2_4, Connection, Server
from ldap3.core.exceptions import (
    LDAPConstraintViolationResult,
    LDAPNoSuchObjectResult,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlite_to_ldap as s2l


# ── DN helpers ───────────────────────────────────────────────────────────────


class TestSplitDN:
    def test_simple(self):
        assert s2l._split_dn("uid=alice,ou=users,dc=test,dc=local") == [
            "uid=alice", "ou=users", "dc=test", "dc=local",
        ]

    def test_whitespace_around_separators_trimmed(self):
        assert s2l._split_dn("uid=alice, ou=users, dc=test, dc=local") == [
            "uid=alice", "ou=users", "dc=test", "dc=local",
        ]

    def test_escaped_comma_kept_inside_rdn(self):
        assert s2l._split_dn(r"cn=Doe\, John,ou=users,dc=t,dc=l") == [
            r"cn=Doe\, John", "ou=users", "dc=t", "dc=l",
        ]


class TestNormalizeDN:
    def test_lower_cases_attribute_types_and_values(self):
        assert s2l._normalize_dn("UID=Alice,OU=Users") == "uid=alice,ou=users"

    def test_strips_separator_whitespace(self):
        assert s2l._normalize_dn("uid=alice, ou=users") == "uid=alice,ou=users"


class TestRewriteDN:
    def test_replaces_source_suffix_with_target(self):
        assert s2l.rewrite_dn(
            "uid=alice,ou=users,dc=source,dc=org",
            "dc=source,dc=org",
            "dc=target,dc=com",
        ) == "uid=alice,ou=users,dc=target,dc=com"

    def test_suffix_match_is_case_insensitive(self):
        assert s2l.rewrite_dn(
            "uid=alice,ou=users,DC=Source,DC=Org",
            "dc=source,dc=org",
            "dc=target,dc=com",
        ) == "uid=alice,ou=users,dc=target,dc=com"

    def test_noop_when_bases_are_equal(self):
        dn = "uid=alice,ou=users,dc=t,dc=l"
        assert s2l.rewrite_dn(dn, "dc=t,dc=l", "dc=t,dc=l") == dn
        assert s2l.rewrite_dn(dn, "dc=t, dc=l", "dc=t,dc=l") == dn  # cosmetic-only diff

    def test_noop_when_suffix_does_not_match(self):
        dn = "uid=alice,ou=users,dc=other,dc=org"
        assert s2l.rewrite_dn(dn, "dc=source,dc=org", "dc=target,dc=com") == dn

    def test_dn_equal_to_source_base_becomes_target_base(self):
        assert s2l.rewrite_dn(
            "dc=source,dc=org", "dc=source,dc=org", "dc=target,dc=com",
        ) == "dc=target,dc=com"

    def test_empty_source_base_returns_dn_unchanged(self):
        dn = "uid=alice,ou=users,dc=t,dc=l"
        assert s2l.rewrite_dn(dn, "", "dc=anything") == dn


class TestIntermediateDNs:
    def test_single_intermediate_ou(self):
        assert s2l.intermediate_dns(
            "uid=jdoe,ou=users,dc=t,dc=l", "dc=t,dc=l",
        ) == ["ou=users,dc=t,dc=l"]

    def test_nested_ous_returned_top_down(self):
        # Closest to the base first, so callers can create parents before children.
        assert s2l.intermediate_dns(
            "uid=jdoe,ou=eng,ou=people,dc=t,dc=l", "dc=t,dc=l",
        ) == ["ou=people,dc=t,dc=l", "ou=eng,ou=people,dc=t,dc=l"]

    def test_no_intermediates_when_user_sits_directly_on_base(self):
        assert s2l.intermediate_dns("uid=jdoe,dc=t,dc=l", "dc=t,dc=l") == []


# ── row_to_attrs ─────────────────────────────────────────────────────────────


def _row(**overrides):
    """A minimal-but-realistic ldap_users row, customisable via kwargs."""
    base = {
        "id": 1,
        "dn": "uid=alice,ou=users,dc=t,dc=l",
        "uid": "alice",
        "cn": "Alice Smith",
        "sn": "Smith",
        "given_name": "Alice",
        "mail": "alice@t.l",
        "user_password": "{SSHA}abc",
        "uid_number": 1001,
        "gid_number": 1001,
        "home_directory": "/home/alice",
        "login_shell": "/bin/bash",
        "object_classes": json.dumps(["inetOrgPerson", "posixAccount"]),
        "export_timestamp": "2026-05-20T00:00:00+00:00",
        "create_timestamp": "2026-05-20 00:00:00+00:00",
        "modify_timestamp": "2026-05-20 00:00:00+00:00",
        "password_was_reset": 0,
    }
    base.update(overrides)
    return base


class TestRowToAttrs:
    def test_columns_mapped_to_ldap_attribute_names(self):
        attrs = s2l.row_to_attrs(_row(), import_ppolicy=False)
        assert attrs["uid"] == "alice"
        assert attrs["givenName"] == "Alice"
        assert attrs["homeDirectory"] == "/home/alice"
        assert attrs["objectClass"] == ["inetOrgPerson", "posixAccount"]

    def test_int_columns_emitted_as_int(self):
        attrs = s2l.row_to_attrs(_row(), import_ppolicy=False)
        assert attrs["uidNumber"] == 1001 and isinstance(attrs["uidNumber"], int)
        assert attrs["gidNumber"] == 1001 and isinstance(attrs["gidNumber"], int)

    def test_skip_cols_never_emitted(self):
        attrs = s2l.row_to_attrs(_row(), import_ppolicy=False)
        # `dn` names the entry; member_of is reapplied via sync_group_memberships.
        assert "dn" not in attrs
        assert "memberOf" not in attrs
        # Audit columns must not leak into the LDAP write.
        assert "exportTimestamp" not in attrs
        assert "createTimestamp" not in attrs

    def test_none_values_are_dropped(self):
        attrs = s2l.row_to_attrs(_row(mail=None), import_ppolicy=False)
        assert "mail" not in attrs

    def test_shadow_attrs_dropped_without_shadowaccount_class(self):
        row = _row(
            object_classes=json.dumps(["inetOrgPerson", "posixAccount"]),
            shadow_min=0, shadow_max=99999, shadow_expire=-1, shadow_last_change=20000,
        )
        attrs = s2l.row_to_attrs(row, import_ppolicy=False)
        for a in ("shadowMin", "shadowMax", "shadowExpire", "shadowLastChange"):
            assert a not in attrs

    def test_shadow_attrs_kept_with_shadowaccount_class(self):
        row = _row(
            object_classes=json.dumps(
                ["inetOrgPerson", "posixAccount", "shadowAccount"],
            ),
            shadow_min=0, shadow_max=99999,
        )
        attrs = s2l.row_to_attrs(row, import_ppolicy=False)
        assert attrs["shadowMin"] == 0
        assert attrs["shadowMax"] == 99999

    def test_ppolicy_attrs_gated_off_by_default(self):
        row = _row(
            pwd_account_locked="000001Z",
            pwd_changed_time="20260101000000Z",
            pwd_failure_time="20260102000000Z",
        )
        attrs = s2l.row_to_attrs(row, import_ppolicy=False)
        assert "pwdAccountLockedTime" not in attrs
        assert "pwdChangedTime" not in attrs
        assert "pwdFailureTime" not in attrs

    def test_ppolicy_attrs_emitted_when_enabled(self):
        row = _row(
            pwd_account_locked="000001Z",
            pwd_changed_time="20260101000000Z",
        )
        attrs = s2l.row_to_attrs(row, import_ppolicy=True)
        assert attrs["pwdAccountLockedTime"] == "000001Z"
        assert attrs["pwdChangedTime"] == "20260101000000Z"

    def test_userpassword_bytes_passed_through_unchanged(self):
        # str(b'…') would corrupt {SSHA}/{CRYPT} binary hashes.
        raw = b"{SSHA}\x00\x01raw-binary"
        attrs = s2l.row_to_attrs(_row(user_password=raw), import_ppolicy=False)
        assert attrs["userPassword"] == raw
        assert isinstance(attrs["userPassword"], bytes)

    def test_default_object_classes_when_missing(self):
        attrs = s2l.row_to_attrs(_row(object_classes=None), import_ppolicy=False)
        assert attrs["objectClass"] == ["inetOrgPerson"]


# ── SQLite loader ────────────────────────────────────────────────────────────


@pytest.fixture
def sqlite_db(tmp_path):
    path = tmp_path / "users.sqlite"
    db = sqlite3.connect(path)
    db.execute(
        """
        CREATE TABLE ldap_users (
            id INTEGER PRIMARY KEY,
            dn TEXT,
            uid TEXT,
            cn TEXT,
            object_classes TEXT
        )
        """,
    )
    db.execute(
        """
        CREATE TABLE export_run (
            id INTEGER PRIMARY KEY,
            base_dn TEXT,
            ldap_uri TEXT,
            run_at TEXT,
            ppolicy_active INTEGER,
            passwords_reset INTEGER
        )
        """,
    )
    db.executemany(
        "INSERT INTO ldap_users (dn, uid, cn, object_classes) VALUES (?, ?, ?, ?)",
        [
            ("uid=bob,ou=users,dc=t,dc=l",   "bob",   "Bob B",   '["inetOrgPerson"]'),
            ("uid=alice,ou=users,dc=t,dc=l", "alice", "Alice A", '["inetOrgPerson"]'),
        ],
    )
    db.execute(
        "INSERT INTO export_run "
        "(base_dn, ldap_uri, run_at, ppolicy_active, passwords_reset) "
        "VALUES (?, ?, ?, ?, ?)",
        ("dc=t,dc=l", "ldaps://example", "2026-05-20", 1, 0),
    )
    db.commit()
    db.row_factory = sqlite3.Row
    yield db
    db.close()


class TestSqliteLoader:
    def test_load_users_sorted_by_dn(self, sqlite_db):
        users = s2l.load_users(sqlite_db)
        assert [u["uid"] for u in users] == ["alice", "bob"]

    def test_load_export_meta_returns_latest_row(self, sqlite_db):
        meta = s2l.load_export_meta(sqlite_db)
        assert meta["base_dn"] == "dc=t,dc=l"
        assert meta["ppolicy_active"] == 1
        assert meta["passwords_reset"] == 0

    def test_load_export_meta_tolerates_missing_table(self, tmp_path):
        path = tmp_path / "noexport.sqlite"
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE ldap_users (id INTEGER)")
        db.row_factory = sqlite3.Row
        assert s2l.load_export_meta(db) == {}
        db.close()


# ── LDIF reader ──────────────────────────────────────────────────────────────


LDIF_SAMPLE = b"""\
# leading comment must be ignored - ascii only here
dn: uid=alice,ou=users,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
uid: alice
cn: Alice Smith
sn: Smith
givenName: Alice
mail: alice@test.local
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/alice
loginShell: /bin/bash
description: Continuation
 line is folded back
memberOf: cn=admins,ou=groups,dc=test,dc=local

dn: uid=bob,ou=users,dc=test,dc=local
objectClass: inetOrgPerson
uid: bob
cn: Bob Brown
sn: Brown
mail:: Ym9iQHRlc3QubG9jYWw=

dn: cn=admins,ou=groups,dc=test,dc=local
objectClass: groupOfNames
cn: admins
member: uid=alice,ou=users,dc=test,dc=local

# ldapsearch preamble - no dn line, should be skipped
search: 2
result: 0 Success
"""


@pytest.fixture
def ldif_file(tmp_path):
    p = tmp_path / "domain.ldif"
    p.write_bytes(LDIF_SAMPLE)
    return str(p)


class TestLdifReader:
    def test_extracts_only_user_entries(self, ldif_file):
        users = s2l.read_ldif_users(ldif_file)
        assert [u["uid"] for u in users] == ["alice", "bob"]

    def test_group_entries_excluded(self, ldif_file):
        users = s2l.read_ldif_users(ldif_file)
        assert all("cn=admins" not in u["dn"] for u in users)

    def test_base64_value_decoded(self, ldif_file):
        bob = next(u for u in s2l.read_ldif_users(ldif_file) if u["uid"] == "bob")
        assert bob["mail"] == "bob@test.local"

    def test_continuation_lines_joined(self, ldif_file):
        alice = next(u for u in s2l.read_ldif_users(ldif_file) if u["uid"] == "alice")
        # The leading single space of the wrapped line is stripped per RFC 2849;
        # the rest is appended verbatim.
        assert alice["description"] == "Continuationline is folded back"

    def test_memberof_serialised_as_json_array(self, ldif_file):
        alice = next(u for u in s2l.read_ldif_users(ldif_file) if u["uid"] == "alice")
        assert json.loads(alice["member_of"]) == [
            "cn=admins,ou=groups,dc=test,dc=local",
        ]

    def test_object_classes_serialised_as_json(self, ldif_file):
        alice = next(u for u in s2l.read_ldif_users(ldif_file) if u["uid"] == "alice")
        assert json.loads(alice["object_classes"]) == [
            "inetOrgPerson", "posixAccount",
        ]

    def test_userpassword_kept_as_bytes(self, tmp_path):
        ldif = (
            b"dn: uid=carol,ou=users,dc=test,dc=local\n"
            b"objectClass: inetOrgPerson\n"
            b"uid: carol\n"
            b"cn: Carol\n"
            b"sn: C\n"
            b"userPassword:: " + base64.b64encode(b"{SSHA}\x00binary") + b"\n"
        )
        p = tmp_path / "carol.ldif"
        p.write_bytes(ldif)
        users = s2l.read_ldif_users(str(p))
        assert len(users) == 1
        assert users[0]["user_password"] == b"{SSHA}\x00binary"

    def test_blocks_without_dn_are_ignored(self, tmp_path):
        p = tmp_path / "only_preamble.ldif"
        p.write_bytes(b"search: 2\nresult: 0 Success\n")
        assert s2l.read_ldif_users(str(p)) == []


# ── ldap3 MOCK_SYNC integration ──────────────────────────────────────────────


@pytest.fixture
def ldap_conn():
    """Fresh in-memory ldap3 server with the base DN pre-created."""
    server = Server("mock_server", get_info=OFFLINE_SLAPD_2_4)
    conn = Connection(
        server,
        user="cn=admin,dc=test,dc=local",
        password="admin",
        client_strategy=MOCK_SYNC,
        raise_exceptions=True,
    )
    conn.strategy.add_entry(
        "cn=admin,dc=test,dc=local",
        {"objectClass": ["inetOrgPerson"], "sn": "admin", "userPassword": "admin"},
    )
    conn.strategy.add_entry(
        "dc=test,dc=local",
        {"objectClass": ["top", "domain"], "dc": "test"},
    )
    conn.bind()
    yield conn
    conn.unbind()


class TestEnsureDNExists:
    def test_creates_missing_ou(self, ldap_conn):
        created, status = s2l.ensure_dn_exists(
            ldap_conn, "ou=users,dc=test,dc=local", dry_run=False,
        )
        assert created is True
        assert status == "created"
        ldap_conn.search("ou=users,dc=test,dc=local", "(objectClass=*)", attributes=["ou"])
        assert ldap_conn.entries

    def test_idempotent_when_already_present(self, ldap_conn):
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        created, status = s2l.ensure_dn_exists(
            ldap_conn, "ou=users,dc=test,dc=local", dry_run=False,
        )
        assert created is False
        assert status == "exists"

    def test_dry_run_writes_nothing(self, ldap_conn):
        created, status = s2l.ensure_dn_exists(
            ldap_conn, "ou=virtual,dc=test,dc=local", dry_run=True,
        )
        assert created is True
        assert "dry-run" in status
        # Confirm the entry was not actually persisted.
        try:
            ldap_conn.search(
                "ou=virtual,dc=test,dc=local", "(objectClass=*)", attributes=["1.1"],
            )
            assert not ldap_conn.entries
        except LDAPNoSuchObjectResult:
            pass


class TestEnsureStructure:
    def test_scaffolds_nested_ous_in_parent_first_order(self, ldap_conn):
        dns = ["uid=jdoe,ou=eng,ou=people,dc=test,dc=local"]
        s2l.ensure_structure(ldap_conn, dns, "dc=test,dc=local", dry_run=False)
        for ou_dn in (
            "ou=people,dc=test,dc=local",
            "ou=eng,ou=people,dc=test,dc=local",
        ):
            ldap_conn.search(ou_dn, "(objectClass=*)", attributes=["ou"])
            assert ldap_conn.entries, f"{ou_dn} was not created"


def _user_attrs():
    return {
        "objectClass": ["inetOrgPerson"],
        "uid": "jdoe",
        "cn": "John Doe",
        "sn": "Doe",
    }


class TestImportUser:
    def test_added_when_entry_is_new(self, ldap_conn):
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        status, _ = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )
        assert status == "added"

    def test_error_on_conflict_without_flag(self, ldap_conn):
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )
        status, detail = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )
        assert status == "error"
        assert "exist" in detail.lower()

    def test_skipped_when_skip_existing(self, ldap_conn):
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )
        status, _ = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=True, dry_run=False,
        )
        assert status == "skipped"

    def test_update_replaces_attributes(self, ldap_conn):
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )
        new_attrs = _user_attrs()
        new_attrs["cn"] = "Johnathan Doe"
        status, _ = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", new_attrs,
            update=True, skip_existing=False, dry_run=False,
        )
        assert status == "updated"
        ldap_conn.search(
            "uid=jdoe,ou=users,dc=test,dc=local",
            "(objectClass=*)", attributes=["cn"],
        )
        assert "Johnathan Doe" in ldap_conn.entries[0].cn.values

    def test_dry_run_reports_would_add_for_new_entry(self, ldap_conn):
        status, detail = s2l.import_user(
            ldap_conn, "uid=ghost,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=True,
        )
        assert status == "dry-run"
        assert "add" in detail

    def test_dry_run_reports_would_update_for_existing_entry(self, ldap_conn):
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )
        status, detail = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=True,
        )
        assert status == "dry-run"
        assert "update" in detail

    def test_reset_password_retry_on_constraint_violation(
        self, ldap_conn, monkeypatch,
    ):
        """ADD path: entry is created without userPassword (Relax-and-split),
        then the separate password MODIFY is rejected by (simulated) ppolicy
        and the reset-retry sends the plaintext."""
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        real_modify = ldap_conn.modify
        seen = []

        def flaky_modify(dn, changes, **kw):
            if "userPassword" in changes:
                seen.append(changes["userPassword"][0][1][0])
                if len(seen) == 1:
                    raise LDAPConstraintViolationResult()
            return real_modify(dn, changes, **kw)

        monkeypatch.setattr(ldap_conn, "modify", flaky_modify)

        attrs = _user_attrs()
        attrs["userPassword"] = b"{SSHA}rejected-by-policy"
        status, detail = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", attrs,
            update=False, skip_existing=False, dry_run=False,
            reset_password="Changeme12345!",
        )
        assert status == "reset"
        assert "reset" in detail.lower()
        # First password modify sent the source hash; reset-retry sent the
        # plaintext so the server runs its quality checks and hashes it itself.
        assert seen == [b"{SSHA}rejected-by-policy", "Changeme12345!"]
        # Entry was created regardless of the password rejection.
        ldap_conn.search(
            "uid=jdoe,ou=users,dc=test,dc=local",
            "(objectClass=*)", attributes=["cn", "userPassword"],
        )
        assert ldap_conn.entries
        assert b"Changeme12345!" in ldap_conn.entries[0].userPassword.raw_values

    def test_update_with_ppolicy_rejection_when_entry_already_exists(
        self, ldap_conn, monkeypatch,
    ):
        """UPDATE path: ppolicy rejects the source hash on the password
        modify; reset-retry with the plaintext succeeds. Other attribute
        changes from the earlier bulk modify must still land."""
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )

        real_modify = ldap_conn.modify
        pw_attempts = []

        def flaky_modify(dn, changes, **kw):
            if "userPassword" in changes:
                pw_attempts.append(changes["userPassword"][0][1][0])
                if len(pw_attempts) == 1:
                    raise LDAPConstraintViolationResult()
            return real_modify(dn, changes, **kw)

        monkeypatch.setattr(ldap_conn, "modify", flaky_modify)

        attrs = _user_attrs()
        attrs["userPassword"] = b"{SSHA}rejected-by-policy"
        attrs["cn"] = "Updated Name"
        status, detail = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", attrs,
            update=True, skip_existing=False, dry_run=False,
            reset_password="Changeme12345!",
        )
        assert status == "reset", f"expected reset, got {status}: {detail}"
        # First pw attempt sent the source hash; reset-retry sent the plaintext.
        assert pw_attempts == [b"{SSHA}rejected-by-policy", "Changeme12345!"]
        ldap_conn.search(
            "uid=jdoe,ou=users,dc=test,dc=local",
            "(objectClass=*)", attributes=["cn", "userPassword"],
        )
        assert "Updated Name" in ldap_conn.entries[0].cn.values
        assert b"Changeme12345!" in ldap_conn.entries[0].userPassword.raw_values

    def test_update_password_unchanged_treated_as_success(
        self, ldap_conn, monkeypatch,
    ):
        """First userPassword modify fails with "Password is not being
        changed from existing value" — the source hash already matches
        what the target holds. Not an error: surface as "updated /
        password unchanged" and confirm the other attribute changes
        landed via the earlier (separate) modify."""
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )

        real_modify = ldap_conn.modify

        def flaky_modify(dn, changes, **kw):
            if "userPassword" in changes:
                raise LDAPConstraintViolationResult(
                    message="Password is not being changed from existing value",
                )
            return real_modify(dn, changes, **kw)

        monkeypatch.setattr(ldap_conn, "modify", flaky_modify)

        attrs = _user_attrs()
        attrs["userPassword"] = b"{SSHA}same-as-existing"
        attrs["cn"] = "Updated Name"
        status, detail = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", attrs,
            update=True, skip_existing=False, dry_run=False,
        )
        assert status == "updated", f"got {status}: {detail}"
        assert "unchanged" in detail.lower()
        # Non-password attrs landed via the earlier (separate) modify.
        ldap_conn.search(
            "uid=jdoe,ou=users,dc=test,dc=local",
            "(objectClass=*)", attributes=["cn"],
        )
        assert "Updated Name" in ldap_conn.entries[0].cn.values

    def test_update_reset_retry_finds_password_already_reset(
        self, ldap_conn, monkeypatch,
    ):
        """Update path: ppolicy rejects the source hash, then the reset-retry
        sends the plaintext but the target already holds exactly that value
        ("not being changed"). Treat as a successful reset rather than an
        error, and verify other attribute changes still landed."""
        s2l.ensure_dn_exists(ldap_conn, "ou=users,dc=test,dc=local", dry_run=False)
        s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", _user_attrs(),
            update=False, skip_existing=False, dry_run=False,
        )

        real_modify = ldap_conn.modify
        pw_attempts = []

        def flaky_modify(dn, changes, **kw):
            if "userPassword" in changes:
                pw_attempts.append(changes["userPassword"][0][1][0])
                if len(pw_attempts) == 1:
                    # First attempt: ppolicy rejects the supplied hash.
                    raise LDAPConstraintViolationResult(
                        message="Password fails quality checking policy",
                    )
                # Reset-retry: target already holds the reset plaintext.
                raise LDAPConstraintViolationResult(
                    message="Password is not being changed from existing value",
                )
            return real_modify(dn, changes, **kw)

        monkeypatch.setattr(ldap_conn, "modify", flaky_modify)

        attrs = _user_attrs()
        attrs["userPassword"] = b"{SSHA}rejected-by-policy"
        attrs["cn"] = "Updated Name"
        status, detail = s2l.import_user(
            ldap_conn, "uid=jdoe,ou=users,dc=test,dc=local", attrs,
            update=True, skip_existing=False, dry_run=False,
            reset_password="Changeme12345!",
        )
        assert status == "reset", f"got {status}: {detail}"
        assert "already at reset" in detail.lower()
        # First pw attempt sent the source hash; reset-retry sent the plaintext.
        assert pw_attempts == [b"{SSHA}rejected-by-policy", "Changeme12345!"]
        ldap_conn.search(
            "uid=jdoe,ou=users,dc=test,dc=local",
            "(objectClass=*)", attributes=["cn"],
        )
        assert "Updated Name" in ldap_conn.entries[0].cn.values


class TestSyncGroupMemberships:
    def _setup_group_and_user(self, conn):
        s2l.ensure_dn_exists(conn, "ou=groups,dc=test,dc=local", dry_run=False)
        s2l.ensure_dn_exists(conn, "ou=users,dc=test,dc=local", dry_run=False)
        conn.add(
            "cn=admins,ou=groups,dc=test,dc=local",
            attributes={
                "objectClass": ["top", "groupOfNames"],
                "cn": "admins",
                # groupOfNames requires at least one member; placeholder used.
                "member": ["cn=placeholder,dc=test,dc=local"],
            },
        )
        s2l.import_user(
            conn, "uid=alice,ou=users,dc=test,dc=local",
            {"objectClass": ["inetOrgPerson"], "uid": "alice", "cn": "Alice", "sn": "A"},
            update=False, skip_existing=False, dry_run=False,
        )

    def test_user_added_to_existing_group(self, ldap_conn):
        self._setup_group_and_user(ldap_conn)
        rewritten = [(
            "uid=alice,ou=users,dc=test,dc=local",
            {},
            {"member_of": json.dumps(["cn=admins,ou=groups,dc=test,dc=local"])},
        )]
        counts = s2l.sync_group_memberships(
            ldap_conn, rewritten,
            "dc=test,dc=local", "dc=test,dc=local",
            dry_run=False,
        )
        assert counts.get("added") == 1
        ldap_conn.search(
            "cn=admins,ou=groups,dc=test,dc=local",
            "(objectClass=*)", attributes=["member"],
        )
        assert (
            "uid=alice,ou=users,dc=test,dc=local"
            in ldap_conn.entries[0].member.values
        )

    def test_missing_group_counted_not_fatal(self, ldap_conn):
        rewritten = [(
            "uid=alice,ou=users,dc=test,dc=local",
            {},
            {"member_of": json.dumps(["cn=ghost,ou=groups,dc=test,dc=local"])},
        )]
        counts = s2l.sync_group_memberships(
            ldap_conn, rewritten,
            "dc=test,dc=local", "dc=test,dc=local",
            dry_run=False,
        )
        assert counts.get("no_group") == 1

    def test_dry_run_does_not_modify(self, ldap_conn):
        self._setup_group_and_user(ldap_conn)
        rewritten = [(
            "uid=alice,ou=users,dc=test,dc=local",
            {},
            {"member_of": json.dumps(["cn=admins,ou=groups,dc=test,dc=local"])},
        )]
        counts = s2l.sync_group_memberships(
            ldap_conn, rewritten,
            "dc=test,dc=local", "dc=test,dc=local",
            dry_run=True,
        )
        assert counts.get("dry-run") == 1
        ldap_conn.search(
            "cn=admins,ou=groups,dc=test,dc=local",
            "(objectClass=*)", attributes=["member"],
        )
        assert (
            "uid=alice,ou=users,dc=test,dc=local"
            not in ldap_conn.entries[0].member.values
        )

    def test_group_dn_rewritten_between_bases(self, ldap_conn):
        """memberOf DNs from the source base get rewritten to the target base
        the same way user DNs are, so the membership lookup hits the
        already-created group on the target server."""
        self._setup_group_and_user(ldap_conn)
        rewritten = [(
            "uid=alice,ou=users,dc=test,dc=local",
            {},
            # Captured memberOf still uses the source base DN.
            {"member_of": json.dumps(["cn=admins,ou=groups,dc=source,dc=org"])},
        )]
        counts = s2l.sync_group_memberships(
            ldap_conn, rewritten,
            "dc=source,dc=org", "dc=test,dc=local",
            dry_run=False,
        )
        assert counts.get("added") == 1
