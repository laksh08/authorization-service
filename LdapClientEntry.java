package com.oauth.ldap.mapper;

import lombok.Builder;
import lombok.Data;

import java.util.Set;

/**
 * Value object representing an LDAP entry for a service account / OAuth client.
 */
@Data
@Builder
public class LdapClientEntry {

    private String dn;              // Distinguished Name
    private String cn;              // Common Name — used as client name
    private String uid;             // uid or sAMAccountName — used as client ID
    private String mail;
    private String description;
    private String department;
    private String organization;
    private Set<String> memberOf;   // Group memberships — mapped to scopes

    /**
     * Derives a safe client ID from the LDAP uid.
     */
    public String toClientId() {
        return (uid != null ? uid : cn)
            .toLowerCase()
            .replaceAll("[^a-z0-9\\-]", "-")
            .replaceAll("-{2,}", "-");
    }

    /**
     * Derives a human-readable client name from CN.
     */
    public String toClientName() {
        return cn != null ? cn : uid;
    }
}