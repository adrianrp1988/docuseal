# LDAP integration RFC

Goal
- Optional LDAP authentication backend for enterprise customers.
- When enabled (LDAP_ENABLED=true), attempt LDAP authentication for sign-in.
- On first successful LDAP login, auto-provision a User record (unless disabled).

Configuration (environment variables)
- LDAP_ENABLED=true|false
- LDAP_HOST
- LDAP_PORT (default: 389)
- LDAP_ENCRYPTION: 'start_tls' | 'simple_tls' | 'none' (default: none)
- LDAP_BASE_DN
- LDAP_BIND_DN (optional, for searching)
- LDAP_BIND_PASSWORD (optional)
- LDAP_UID_ATTRIBUTE (default: uid or mail)
- LDAP_CREATE_USERS=true|false (auto-provision)
- LDAP_FALLBACK=true|false (allow local DB fallback)

Behavior
- If LDAP_ENABLED is false: existing behavior unchanged.
- If LDAP_ENABLED is true: login attempts will first try LDAP auth for matching account/user.
  - On success: find or create user (depending on LDAP_CREATE_USERS)
  - On failure: fall back to local authentication (controlled by LDAP_FALLBACK)

Local development
- A docker-compose LDAP service (osixia/openldap) can be used for testing. See docker-compose.ldap.yml.

Security
- Do not log passwords or LDAP bind details.
- Use TLS in production (start_tls or simple_tls).
- Store bind credentials in environment variables or Rails encrypted credentials.

Notes
- You must decide account mapping for auto-provisioned users (e.g., map by email domain to a tenant/account).
- Consider disabling password resets and local password changes for LDAP users.
