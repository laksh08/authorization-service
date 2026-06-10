package com.oauth.ldap.controller;

import com.oauth.ldap.dto.LdapSyncResult;
import com.oauth.ldap.mapper.LdapClientEntry;
import com.oauth.ldap.service.LdapSearchService;
import com.oauth.ldap.sync.LdapSyncOrchestrator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/admin/ldap")
@RequiredArgsConstructor
@Tag(name = "Admin - LDAP Sync", description = "LDAP integration and manual sync endpoints")
@SecurityRequirement(name = "bearerAuth")
@PreAuthorize("hasAuthority('SCOPE_admin')")
@ConditionalOnProperty(name = "ldap.enabled", havingValue = "true")
public class LdapSyncController {

    private final LdapSyncOrchestrator orchestrator;
    private final LdapSearchService    searchService;

    /**
     * Manually triggers a full LDAP → OAuth DB sync.
     */
    @PostMapping("/sync")
    @Operation(summary = "Trigger a manual LDAP sync",
               description = "Searches LDAP and upserts matching service accounts as OAuth clients. " +
                             "Returns 409 if a sync is already running.")
    public ResponseEntity<LdapSyncResult> triggerSync(
            @AuthenticationPrincipal Jwt jwt) {

        if (orchestrator.isSyncRunning()) {
            return ResponseEntity.status(409)
                    .body(LdapSyncResult.builder()
                            .errorMessages(List.of("A sync is already in progress"))
                            .errors(1)
                            .build());
        }

        String principal = jwt != null ? jwt.getSubject() : "MANUAL";
        log.info("Manual LDAP sync triggered by: {}", principal);

        LdapSyncResult result = orchestrator.runSync(principal);

        return result.isSuccessful()
            ? ResponseEntity.ok(result)
            : ResponseEntity.status(207).body(result); // 207 Multi-Status for partial failures
    }

    /**
     * Shows the current sync status (running or idle).
     */
    @GetMapping("/sync/status")
    @Operation(summary = "Get current LDAP sync status")
    public ResponseEntity<Map<String, Object>> getSyncStatus() {
        return ResponseEntity.ok(Map.of(
            "running", orchestrator.isSyncRunning(),
            "message", orchestrator.isSyncRunning()
                ? "Sync is currently in progress"
                : "No sync running"
        ));
    }

    /**
     * Checks LDAP connectivity health.
     */
    @GetMapping("/health")
    @Operation(summary = "Check LDAP server connectivity")
    public ResponseEntity<Map<String, Object>> checkLdapHealth() {
        boolean healthy = searchService.isHealthy();
        return ResponseEntity.status(healthy ? 200 : 503)
                .body(Map.of(
                    "status",  healthy ? "UP" : "DOWN",
                    "message", healthy ? "LDAP connection OK" : "LDAP unreachable"
                ));
    }

    /**
     * Preview LDAP entries without syncing — useful for validation before committing.
     */
    @GetMapping("/preview")
    @Operation(summary = "Preview LDAP entries that would be synced (dry run)",
               description = "Returns the raw LDAP entries without creating/updating any clients.")
    public ResponseEntity<Map<String, Object>> previewLdapEntries() {
        List<LdapClientEntry> entries = searchService.findAllServiceAccounts();
        return ResponseEntity.ok(Map.of(
            "count",   entries.size(),
            "entries", entries
        ));
    }

    /**
     * Look up a specific LDAP entry by uid without syncing.
     */
    @GetMapping("/entry/{uid}")
    @Operation(summary = "Fetch a single LDAP entry by uid / sAMAccountName")
    public ResponseEntity<?> getLdapEntry(@PathVariable String uid) {
        return searchService.findByUid(uid)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}