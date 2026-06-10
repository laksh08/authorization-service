package com.oauth.ldap.service;

import com.oauth.core.domain.OAuthClient;
import com.oauth.core.event.ClientDomainEvent;
import com.oauth.core.exception.OAuthExceptions;
import com.oauth.core.service.PasswordGeneratorService;
import com.oauth.core.tenant.TenantContext;
import com.oauth.infra.repository.OAuthClientRepository;
import com.oauth.ldap.config.LdapProperties;
import com.oauth.ldap.dto.LdapSyncResult;
import com.oauth.ldap.mapper.LdapClientEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

/**
 * Upserts OAuthClient rows from LDAP search results.
 *
 * Strategy:
 *  - NEW entry   → create client with auto-generated secret
 *  - EXISTING    → update name, scopes, description; preserve secret
 *  - DELETED     → no automatic deletion (manual admin action required)
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "ldap.enabled", havingValue = "true")
public class LdapClientSyncService {

    private final OAuthClientRepository   clientRepository;
    private final PasswordGeneratorService passwordGenerator;
    private final PasswordEncoder          passwordEncoder;
    private final LdapScopeMapper          scopeMapper;
    private final LdapProperties           ldapProperties;
    private final ApplicationEventPublisher eventPublisher;

    /**
     * Processes a list of LDAP entries, upserting each into oauth_clients.
     * Returns a detailed sync result.
     */
    @Transactional
    public LdapSyncResult syncEntries(List<LdapClientEntry> entries, String triggeredBy) {

        Instant startedAt = Instant.now();

        LdapSyncResult.LdapSyncResultBuilder result = LdapSyncResult.builder()
                .startedAt(startedAt)
                .triggeredBy(triggeredBy)
                .totalLdapEntries(entries.size());

        List<String> createdIds   = new ArrayList<>();
        List<String> updatedIds   = new ArrayList<>();
        List<String> errorMsgs    = new ArrayList<>();
        int created = 0, updated = 0, skipped = 0, errors = 0;

        for (LdapClientEntry entry : entries) {
            try {
                String clientId = entry.toClientId();

                if (clientId == null || clientId.isBlank()) {
                    log.warn("LDAP entry has no usable uid/cn, skipping DN: {}", entry.getDn());
                    skipped++;
                    continue;
                }

                Optional<OAuthClient> existing = clientRepository.findByClientId(clientId);

                if (existing.isPresent()) {
                    updateExistingClient(existing.get(), entry);
                    updatedIds.add(clientId);
                    updated++;
                } else {
                    createClientFromLdap(entry, clientId);
                    createdIds.add(clientId);
                    created++;
                }

            } catch (Exception e) {
                String msg = "Failed to sync LDAP entry uid='" + entry.getUid() + "': " + e.getMessage();
                log.error(msg, e);
                errorMsgs.add(msg);
                errors++;
            }
        }

        Instant completedAt = Instant.now();

        LdapSyncResult syncResult = result
                .completedAt(completedAt)
                .created(created)
                .updated(updated)
                .skipped(skipped)
                .errors(errors)
                .createdClientIds(createdIds)
                .updatedClientIds(updatedIds)
                .errorMessages(errorMsgs)
                .build();

        log.info("LDAP sync complete [{}]: total={}, created={}, updated={}, skipped={}, errors={}, duration={}ms",
                triggeredBy,
                entries.size(), created, updated, skipped, errors,
                syncResult.durationMs());

        return syncResult;
    }

    // ─── Private Helpers ─────────────────────────────────────────────────────────

    private void createClientFromLdap(LdapClientEntry entry, String clientId) {
        String tenant    = ldapProperties.getDefaultTenant();
        Set<String> scopes = scopeMapper.deriveScopes(entry);

        String rawSecret = passwordGenerator.generateClientSecret();

        OAuthClient client = OAuthClient.builder()
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(rawSecret))
                .clientName(entry.toClientName())
                .tenantId(tenant)
                .description(entry.getDescription())
                .scopes(scopes)
                .authorizedGrantTypes(new HashSet<>(ldapProperties.getDefaultGrantTypes()))
                .ldapSynced(true)
                .ldapDn(entry.getDn())
                .ldapLastSyncAt(Instant.now())
                .status(OAuthClient.ClientStatus.ACTIVE)
                .build();

        clientRepository.save(client);
        log.info("LDAP-sync CREATED client '{}' in tenant '{}' with scopes {}", clientId, tenant, scopes);

        eventPublisher.publishEvent(
            new ClientDomainEvent(this, ClientDomainEvent.EventType.LDAP_SYNCED, client));
    }

    private void updateExistingClient(OAuthClient client, LdapClientEntry entry) {
        boolean changed = false;

        // Update name if changed
        String newName = entry.toClientName();
        if (newName != null && !newName.equals(client.getClientName())) {
            client.setClientName(newName);
            changed = true;
        }

        // Update description
        if (entry.getDescription() != null && !entry.getDescription().equals(client.getDescription())) {
            client.setDescription(entry.getDescription());
            changed = true;
        }

        // Re-derive scopes from LDAP groups
        Set<String> newScopes = scopeMapper.deriveScopes(entry);
        if (!newScopes.equals(client.getScopes())) {
            client.setScopes(newScopes);
            changed = true;
        }

        // Update LDAP metadata always
        client.setLdapDn(entry.getDn());
        client.setLdapLastSyncAt(Instant.now());

        // Reactivate if it was suspended but LDAP entry still exists
        if (OAuthClient.ClientStatus.SUSPENDED.equals(client.getStatus())) {
            client.setStatus(OAuthClient.ClientStatus.ACTIVE);
            changed = true;
        }

        clientRepository.save(client);

        if (changed) {
            log.info("LDAP-sync UPDATED client '{}'", client.getClientId());
            eventPublisher.publishEvent(
                new ClientDomainEvent(this, ClientDomainEvent.EventType.LDAP_SYNCED, client));
        } else {
            log.debug("LDAP-sync: no changes for client '{}'", client.getClientId());
        }
    }
}