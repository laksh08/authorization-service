package com.oauth.ldap.mapper;

import org.springframework.ldap.core.AttributesMapper;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.HashSet;
import java.util.Set;

/**
 * Maps raw LDAP attributes to LdapClientEntry.
 * Handles both standard LDAP (uid, cn) and Active Directory (sAMAccountName) attributes.
 */
public class LdapClientAttributeMapper implements AttributesMapper<LdapClientEntry> {

    @Override
    public LdapClientEntry mapFromAttributes(Attributes attrs) throws NamingException {
        return LdapClientEntry.builder()
                .cn(getString(attrs, "cn"))
                .uid(getUid(attrs))
                .mail(getString(attrs, "mail"))
                .description(getString(attrs, "description"))
                .department(getString(attrs, "department"))
                .organization(getString(attrs, "o"))
                .memberOf(getMultiValue(attrs, "memberOf"))
                .build();
    }

    private String getUid(Attributes attrs) throws NamingException {
        // Try AD sAMAccountName first, then standard uid
        String sam = getString(attrs, "sAMAccountName");
        if (sam != null) return sam;
        return getString(attrs, "uid");
    }

    private String getString(Attributes attrs, String attrName) throws NamingException {
        Attribute attr = attrs.get(attrName);
        if (attr == null) return null;
        Object value = attr.get();
        return value != null ? value.toString() : null;
    }

    private Set<String> getMultiValue(Attributes attrs, String attrName) throws NamingException {
        Set<String> result = new HashSet<>();
        Attribute attr = attrs.get(attrName);
        if (attr == null) return result;

        NamingEnumeration<?> en = attr.getAll();
        while (en.hasMore()) {
            result.add(en.next().toString());
        }
        return result;
    }
}