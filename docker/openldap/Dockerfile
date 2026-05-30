FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# slapd-contrib ships the pw-argon2 password module we need for {ARGON2} hashes.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        slapd ldap-utils slapd-contrib procps && \
    rm -rf /var/lib/apt/lists/*

COPY bootstrap.sh /bootstrap.sh
RUN chmod +x /bootstrap.sh && /bootstrap.sh

EXPOSE 389
# A -d argument keeps slapd in the foreground (required for a container PID 1).
CMD ["slapd", "-h", "ldap:/// ldapi:///", "-u", "openldap", "-g", "openldap", "-d", "0"]
