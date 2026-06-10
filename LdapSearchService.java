package com.oauth.ldap.service;

import com.oauth.ldap.config.LdapProperties;
import com.oauth.ldap.mapper.LdapClientAttributeMapper;
import com.oauth.ldap.mapper.LdapClientEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.filter.LikeFilter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.query.SearchScope;
import org.springframework.stereotype.Service;

import javax.naming.Name;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Performs LDAP searches for service accounts / OAuth client candidates.
 * All queries use the configured baseDn and userSearchBase.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "ldap.enabled", havingValue = "true")
public class LdapSearchService {

    private final LdapTemplate    ldapTemplate;
    private final LdapProperties  ldapProperties;

    /**
     * Fetches all service-account entries matching the configured filter.
     * Returns an empty list (never throws) on LDAP connectivity failure.
     */
    public List<LdapClientEntry> findAllServiceAccounts() {
        try {
            LdapQuery query = LdapQueryBuilder.query()
                    .base(ldapProperties.getUserSearchBase())
                    .searchScope(SearchScope.SUBTREE)
                    .countLimit(10_000)
                    .timeLimit(30_000)
                    .attributes(ldapProperties.getSearchAttributes())
                    .filter(ldapProperties.getUserSearchFilter());

            List<LdapClientEntry> results = ldapTemplate.search(
                    query, new LdapClientAttributeMapper());

            log.info("LDAP search returned {} service account entries", results.size());
            return results;

        } catch (Exception e) {
            log.error("LDAP search failed: {}", e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Looks up a single LDAP entry by uid or sAMAccountName.
     */
    public Optional<LdapClientEntry> findByUid(String uid) {
        try {
            LdapQuery query = LdapQueryBuilder.query()
                    .base(ldapProperties.getUserSearchBase())
                    .searchScope(SearchScope.SUBTREE)
                    .attributes(ldapProperties.getSearchAttributes())
                    .where("uid").is(uid)
                    .or("sAMAccountName").is(uid);

            List<LdapClientEntry> results = ldapTemplate.search(
                    query, new LdapClientAttributeMapper());

            return results.isEmpty() ? Optional.empty() : Optional.of(results.get(0));

        } catch (Exception e) {
            log.error("LDAP lookup by uid '{}' failed: {}", uid, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Verifies that the LDAP connection is healthy.
     */
    public boolean isHealthy() {
        try {
            ldapTemplate.lookup(ldapProperties.getUserSearchBase());
            return true;
        } catch (Exception e) {
            log.warn("LDAP health check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Lists all LDAP groups that contain the given DN as a member.
     * Used for scope derivation.
     */
    public List<String> getGroupsForDn(String memberDn) {
        try {
            LdapQuery query = LdapQueryBuilder.query()
                    .searchScope(SearchScope.SUBTREE)
                    .where("member").is(memberDn);

            return ldapTemplate.search(query, attrs -> {
                Object cn = attrs.get("cn");
                return cn != null ? cn.get().toString() : null;
            });
        } catch (Exception e) {
            log.warn("Could not fetch groups for DN '{}': {}", memberDn, e.getMessage());
            return Collections.emptyList();
        }
    }
}