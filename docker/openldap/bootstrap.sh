#!/bin/bash
# Build-time bootstrap: reconfigure slapd for the local.test domain, load the
# argon2 password module, and let the data admin read cn=config (so the
# import's argon2 preflight can positively confirm the module).
set -eux

ADMIN_PW="${LDAP_ADMIN_PASSWORD:-admin}"

# Drop the default database/config the package created on install.
rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*

debconf-set-selections <<EOF
slapd slapd/password1 password ${ADMIN_PW}
slapd slapd/password2 password ${ADMIN_PW}
slapd slapd/domain string local.test
slapd shared/organization string local.test
slapd slapd/backend select MDB
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/no_configuration boolean false
EOF
dpkg-reconfigure -f noninteractive slapd

# slapd needs its runtime dir for the ldapi socket + pid file.
mkdir -p /var/run/slapd
chown openldap:openldap /var/run/slapd

# Start slapd on the local socket only, long enough to apply cn=config changes.
slapd -h "ldapi:///" -u openldap -g openldap
for i in $(seq 1 30); do
    ldapsearch -Y EXTERNAL -H ldapi:/// -b "" -s base >/dev/null 2>&1 && break
    sleep 0.5
done

# Locate the argon2 contrib module (filename differs across releases).
ARGON_FILE="$(ls /usr/lib/ldap/ | grep -iE 'argon2.*\.(la|so)$' | head -1)"
: "${ARGON_FILE:?argon2 module not found in /usr/lib/ldap — is slapd-contrib installed?}"

# Adding the olcModuleLoad value loads the module immediately; a bad filename
# makes this ldapadd fail, so the build stops loudly rather than shipping a
# server that silently can't store {ARGON2}.
ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: ${ARGON_FILE}
EOF

# Grant the data admin read on the config DB so a network bind as
# cn=admin,dc=local,dc=test can see olcModuleLoad (the preflight's check).
ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcAccess
olcAccess: to * by dn.exact="cn=admin,dc=local,dc=test" read by * break
EOF

# Confirm the scheme is actually registered before we finish the build.
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config '(olcModuleLoad=*)' olcModuleLoad

# Stop the temporary instance; the container CMD starts the real one.
PID="$(cat /var/run/slapd/slapd.pid 2>/dev/null || pgrep -x slapd || true)"
[ -n "${PID}" ] && kill "${PID}" || true
for i in $(seq 1 20); do pgrep -x slapd >/dev/null || break; sleep 0.5; done
