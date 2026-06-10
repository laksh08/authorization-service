package com.oauth.ldap.sync;

import com.oauth.ldap.config.LdapProperties;
import com.oauth.ldap.dto.LdapSyncResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled LDAP → OAuth sync job.
 *
 * The cron expression is driven by ldap.sync-cron (default: every hour).
 * Set ldap.enabled=false to disable all LDAP functionality entirely.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "ldap.enabled", havingValue = "true")
public class LdapScheduledSyncJob {

    private final LdapSyncOrchestrator orchestrator;
    private final LdapProperties       ldapProperties;

    /**
     * Runs on the configured cron schedule.
     * fixedDelayString used as a safe fallback; the real schedule comes from the
     * @Scheduled cron expression read at runtime via SpEL.
     */
    @Scheduled(cron = "${ldap.sync-cron:0 0 * * * *}")
    public void scheduledSync() {
        log.info("LDAP scheduled sync triggered [cron={}]", ldapProperties.getSyncCron());

        LdapSyncResult result = orchestrator.runSync("SCHEDULER");

        if (result.isSuccessful()) {
            log.info("Scheduled LDAP sync completed successfully: created={}, updated={}, duration={}ms",
                    result.getCreated(), result.getUpdated(), result.durationMs());
        } else {
            log.error("Scheduled LDAP sync completed with {} error(s): {}",
                    result.getErrors(), result.getErrorMessages());
        }
    }
}