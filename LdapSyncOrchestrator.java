package com.oauth.ldap.sync;

import com.oauth.ldap.dto.LdapSyncResult;
import com.oauth.ldap.mapper.LdapClientEntry;
import com.oauth.ldap.service.LdapClientSyncService;
import com.oauth.ldap.service.LdapSearchService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Orchestrates the full LDAP → OAuth sync pipeline:
 *   1. Search LDAP for all service accounts
 *   2. Hand results to LdapClientSyncService for upsert
 *
 * Guards against concurrent execution with an atomic flag.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "ldap.enabled", havingValue = "true")
public class LdapSyncOrchestrator {

    private final LdapSearchService     searchService;
    private final LdapClientSyncService syncService;

    private final AtomicBoolean running = new AtomicBoolean(false);

    /**
     * Executes a full sync run. Returns a result summary.
     * If a sync is already in progress, returns an error result immediately.
     *
     * @param triggeredBy "SCHEDULER" | "MANUAL" | principal name
     */
    public LdapSyncResult runSync(String triggeredBy) {
        if (!running.compareAndSet(false, true)) {
            log.warn("LDAP sync requested by '{}' but a sync is already running", triggeredBy);
            return LdapSyncResult.builder()
                    .triggeredBy(triggeredBy)
                    .errorMessages(List.of("A sync is already in progress"))
                    .errors(1)
                    .build();
        }

        try {
            log.info("Starting LDAP sync [triggeredBy={}]", triggeredBy);

            // Phase 1 – search LDAP
            List<LdapClientEntry> entries = searchService.findAllServiceAccounts();
            if (entries.isEmpty()) {
                log.warn("LDAP search returned no entries. Verify ldap.user-search-base and filter.");
            }

            // Phase 2 – upsert into OAuth DB
            LdapSyncResult result = syncService.syncEntries(entries, triggeredBy);
            return result;

        } catch (Exception e) {
            log.error("LDAP sync failed unexpectedly: {}", e.getMessage(), e);
            return LdapSyncResult.builder()
                    .triggeredBy(triggeredBy)
                    .errorMessages(List.of("Sync failed: " + e.getMessage()))
                    .errors(1)
                    .build();
        } finally {
            running.set(false);
        }
    }

    /**
     * Returns true if a sync is currently running.
     */
    public boolean isSyncRunning() {
        return running.get();
    }
}