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

# The slapd package's default config already ships cn=module{0},cn=config
# (it loads back_mdb), so we MODIFY that entry rather than add a new one —
# re-adding the same RDN fails with a naming violation. Adding the
# olcModuleLoad values loads the modules immediately; a bad filename makes this
# ldapmodify fail, so the build stops loudly rather than shipping a server that
# silently can't store {ARGON2} or enforce ppolicy. Loading the ppolicy module
# (OpenLDAP 2.5+) also registers its schema (pwdPolicy object class, pwdReset
# operational attr) — no separate schema load needed.
ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: ${ARGON_FILE}
olcModuleLoad: ppolicy
EOF

# Load the openssh-lpk schema (ldapPublicKey / sshPublicKey). Source exports
# routinely carry SSH keys on user entries; without this schema those adds fail
# with "invalid object class ldapPublicKey" and the import can't land users.
ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
dn: cn=openssh-lpk,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: openssh-lpk
olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey' DESC 'MANDATORY: OpenSSH Public key' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' DESC 'MANDATORY: OpenSSH LPK objectclass' SUP top AUXILIARY MAY ( sshPublicKey \$ uid ) )
EOF

# Grant the data admin read on the config DB so a network bind as
# cn=admin,dc=local,dc=test can see olcModuleLoad (the preflight's check).
ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcAccess
olcAccess: to * by dn.exact="cn=admin,dc=local,dc=test" read by * break
EOF

# Enable the ppolicy overlay on the data DB so the import can write pwdReset
# and so pre-hashed userPassword values (sent with the Relax control) are
# accepted without a quality check. olcPPolicyHashCleartext lets the server
# hash any cleartext fallback password the import sends.
ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcOverlay=ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: ppolicy
olcPPolicyDefault: cn=default,ou=policies,dc=local,dc=test
olcPPolicyHashCleartext: TRUE
olcPPolicyUseLockout: TRUE
EOF

# Create the policy subtree + default policy in the data DB. pwdMustChange
# makes pwdReset=TRUE actually force a change on next login.
ldapadd -x -D "cn=admin,dc=local,dc=test" -w "${ADMIN_PW}" -H ldapi:/// <<EOF
dn: ou=policies,dc=local,dc=test
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,dc=local,dc=test
objectClass: pwdPolicy
objectClass: device
cn: default
pwdAttribute: userPassword
pwdMustChange: TRUE
EOF

# Confirm the modules and overlay are actually registered before finishing.
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config '(olcModuleLoad=*)' olcModuleLoad
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config '(olcOverlay=ppolicy)' olcOverlay olcPPolicyDefault

# Stop the temporary instance; the container CMD starts the real one.
PID="$(cat /var/run/slapd/slapd.pid 2>/dev/null || pgrep -x slapd || true)"
[ -n "${PID}" ] && kill "${PID}" || true
for i in $(seq 1 20); do pgrep -x slapd >/dev/null || break; sleep 0.5; done
