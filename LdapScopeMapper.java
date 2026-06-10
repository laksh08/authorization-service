package com.oauth.ldap.service;

import com.oauth.ldap.config.LdapProperties;
import com.oauth.ldap.mapper.LdapClientEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Converts LDAP group memberships (memberOf attribute) into OAuth 2 scopes.
 *
 * Convention: any group whose CN starts with the configured scopeGroupPrefix
 * (default: "oauth-") contributes a scope.
 *
 * Examples:
 *   Group CN = "oauth-read"   → scope "read"
 *   Group CN = "oauth-write"  → scope "write"
 *   Group CN = "oauth-admin"  → scope "admin"
 *   Group CN = "it-team"      → ignored (no prefix match)
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "ldap.enabled", havingValue = "true")
public class LdapScopeMapper {

    private final LdapProperties ldapProperties;

    /**
     * Derives scopes from the entry's memberOf attribute.
     * Falls back to the configured default scopes if nothing maps.
     */
    public Set<String> deriveScopes(LdapClientEntry entry) {
        Set<String> scopes     = new HashSet<>();
        String      prefix     = ldapProperties.getScopeGroupPrefix();
        Set<String> memberOf   = entry.getMemberOf();

        if (memberOf != null && !memberOf.isEmpty()) {
            for (String groupDn : memberOf) {
                String cn = extractCn(groupDn);
                if (cn != null && cn.toLowerCase().startsWith(prefix.toLowerCase())) {
                    String scope = cn.substring(prefix.length()).toLowerCase().trim();
                    if (!scope.isBlank()) {
                        scopes.add(scope);
                        log.debug("Mapped group '{}' → scope '{}'", cn, scope);
                    }
                }
            }
        }

        if (scopes.isEmpty()) {
            log.debug("No scope-mapped groups found for '{}', using defaults", entry.toClientId());
            scopes.addAll(ldapProperties.getDefaultScopes());
        }

        return scopes;
    }

    /**
     * Extracts the CN value from a full DN string.
     * e.g. "CN=oauth-read,OU=Groups,DC=example,DC=com" → "oauth-read"
     */
    private String extractCn(String dn) {
        if (dn == null) return null;
        String[] parts = dn.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase().startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }
}