package com.google.firebase.remoteconfig;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class FirebaseRemoteConfigServerException extends FirebaseRemoteConfigException {
    private final int httpStatusCode;

    public FirebaseRemoteConfigServerException(int httpStatusCode, String detailMessage) {
        super(detailMessage);
        this.httpStatusCode = httpStatusCode;
    }

    public FirebaseRemoteConfigServerException(int httpStatusCode, String detailMessage, Throwable cause) {
        super(detailMessage, cause);
        this.httpStatusCode = httpStatusCode;
    }

    public int getHttpStatusCode() {
        return this.httpStatusCode;
    }
}
