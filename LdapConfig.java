package com.oauth.ldap.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.pool2.factory.PooledContextSource;
import org.springframework.ldap.pool2.validation.DefaultDirContextValidator;

@Slf4j
@Configuration
@ConditionalOnProperty(name = "ldap.enabled", havingValue = "true")
public class LdapConfig {

    @Value("${ldap.url}")
    private String ldapUrl;

    @Value("${ldap.base-dn}")
    private String baseDn;

    @Value("${ldap.username}")
    private String username;

    @Value("${ldap.password}")
    private String password;

    @Value("${ldap.pool.max-active:8}")
    private int poolMaxActive;

    @Value("${ldap.pool.min-idle:1}")
    private int poolMinIdle;

    @Bean
    public LdapContextSource ldapContextSource() {
        LdapContextSource source = new LdapContextSource();
        source.setUrl(ldapUrl);
        source.setBase(baseDn);
        source.setUserDn(username);
        source.setPassword(password);
        source.setPooled(false); // We pool manually via PooledContextSource
        source.afterPropertiesSet();
        log.info("LDAP context source configured: url={}, base={}", ldapUrl, baseDn);
        return source;
    }

    @Bean
    public LdapTemplate ldapTemplate(LdapContextSource contextSource) {
        LdapTemplate template = new LdapTemplate(contextSource);
        template.setIgnorePartialResultException(true); // Needed for AD
        template.setIgnoreNameNotFoundException(true);
        return template;
    }
}