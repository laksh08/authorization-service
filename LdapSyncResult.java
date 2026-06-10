package com.oauth.ldap.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class LdapSyncResult {

    private Instant startedAt;
    private Instant completedAt;

    @Builder.Default
    private int totalLdapEntries  = 0;

    @Builder.Default
    private int created           = 0;

    @Builder.Default
    private int updated           = 0;

    @Builder.Default
    private int skipped           = 0;

    @Builder.Default
    private int errors            = 0;

    @Builder.Default
    private List<String> createdClientIds = new ArrayList<>();

    @Builder.Default
    private List<String> updatedClientIds = new ArrayList<>();

    @Builder.Default
    private List<String> errorMessages    = new ArrayList<>();

    private String triggeredBy;    // "SCHEDULER" | "MANUAL"

    public long durationMs() {
        if (startedAt == null || completedAt == null) return -1;
        return completedAt.toEpochMilli() - startedAt.toEpochMilli();
    }

    public boolean isSuccessful() {
        return errors == 0;
    }
}