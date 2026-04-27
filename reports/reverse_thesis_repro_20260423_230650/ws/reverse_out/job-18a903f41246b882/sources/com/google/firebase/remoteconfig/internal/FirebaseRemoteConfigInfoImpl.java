package com.google.firebase.remoteconfig.internal;

import com.google.firebase.remoteconfig.FirebaseRemoteConfigInfo;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigSettings;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class FirebaseRemoteConfigInfoImpl implements FirebaseRemoteConfigInfo {
    private final FirebaseRemoteConfigSettings configSettings;
    private final int lastFetchStatus;
    private final long lastSuccessfulFetchTimeInMillis;

    private FirebaseRemoteConfigInfoImpl(long lastSuccessfulFetchTimeInMillis, int lastFetchStatus, FirebaseRemoteConfigSettings configSettings) {
        this.lastSuccessfulFetchTimeInMillis = lastSuccessfulFetchTimeInMillis;
        this.lastFetchStatus = lastFetchStatus;
        this.configSettings = configSettings;
    }

    @Override // com.google.firebase.remoteconfig.FirebaseRemoteConfigInfo
    public long getFetchTimeMillis() {
        return this.lastSuccessfulFetchTimeInMillis;
    }

    @Override // com.google.firebase.remoteconfig.FirebaseRemoteConfigInfo
    public int getLastFetchStatus() {
        return this.lastFetchStatus;
    }

    @Override // com.google.firebase.remoteconfig.FirebaseRemoteConfigInfo
    public FirebaseRemoteConfigSettings getConfigSettings() {
        return this.configSettings;
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static class Builder {
        private FirebaseRemoteConfigSettings builderConfigSettings;
        private int builderLastFetchStatus;
        private long builderLastSuccessfulFetchTimeInMillis;

        private Builder() {
        }

        public Builder withLastSuccessfulFetchTimeInMillis(long fetchTimeInMillis) {
            this.builderLastSuccessfulFetchTimeInMillis = fetchTimeInMillis;
            return this;
        }

        Builder withLastFetchStatus(int lastFetchStatus) {
            this.builderLastFetchStatus = lastFetchStatus;
            return this;
        }

        Builder withConfigSettings(FirebaseRemoteConfigSettings configSettings) {
            this.builderConfigSettings = configSettings;
            return this;
        }

        public FirebaseRemoteConfigInfoImpl build() {
            return new FirebaseRemoteConfigInfoImpl(this.builderLastSuccessfulFetchTimeInMillis, this.builderLastFetchStatus, this.builderConfigSettings);
        }
    }

    static Builder newBuilder() {
        return new Builder();
    }
}
