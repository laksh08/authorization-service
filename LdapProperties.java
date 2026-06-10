package com.oauth.ldap.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Data
@Configuration
@ConfigurationProperties(prefix = "ldap")
public class LdapProperties {

    /** Whether LDAP integration is enabled */
    private boolean enabled = false;

    /** LDAP server URL, e.g. ldap://ad.example.com:389 */
    private String url = "ldap://localhost:389";

    /** Base DN for all searches */
    private String baseDn = "dc=example,dc=com";

    /** Bind DN for authentication */
    private String username = "cn=admin,dc=example,dc=com";

    /** Bind password */
    private String password = "admin";

    /** Sub-tree under baseDn where service accounts live */
    private String userSearchBase = "ou=serviceaccounts";

    /**
     * LDAP filter for service accounts to import as OAuth clients.
     * Active Directory example: (&(objectClass=user)(servicePrincipalName=*))
     * OpenLDAP example: (objectClass=inetOrgPerson)
     */
    private String userSearchFilter = "(objectClass=person)";

    /** Cron expression for the scheduled LDAP → DB sync job */
    private String syncCron = "0 0 * * * *"; // every hour

    /** Tenant to assign to all LDAP-synced clients */
    private String defaultTenant = "default";

    /** Default scopes to assign to LDAP-synced clients */
    private Set<String> defaultScopes = Set.of("read");

    /** Default grant types to assign to LDAP-synced clients */
    private Set<String> defaultGrantTypes = Set.of("client_credentials");

    /** LDAP attributes to fetch on each search */
    private String[] searchAttributes = {
        "cn", "uid", "sAMAccountName", "mail",
        "description", "department", "o", "memberOf"
    };

    /** Group DN prefix whose CN maps to an OAuth scope (e.g. "cn=oauth-read,..." → scope "read") */
    private String scopeGroupPrefix = "oauth-";

    private Pool pool = new Pool();

    @Data
    public static class Pool {
        private int maxActive  = 8;
        private int minIdle    = 1;
        private int maxIdle    = 8;
        private long maxWaitMs = 3000;
    }
}