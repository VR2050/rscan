package com.google.firebase.remoteconfig;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class FirebaseRemoteConfigFetchThrottledException extends FirebaseRemoteConfigFetchException {
    private final long throttleEndTimeMillis;

    public FirebaseRemoteConfigFetchThrottledException(long throttleEndTimeMillis) {
        this("Fetch was throttled.", throttleEndTimeMillis);
    }

    public FirebaseRemoteConfigFetchThrottledException(String message, long throttledEndTimeInMillis) {
        super(message);
        this.throttleEndTimeMillis = throttledEndTimeInMillis;
    }

    public long getThrottleEndTimeMillis() {
        return this.throttleEndTimeMillis;
    }
}
