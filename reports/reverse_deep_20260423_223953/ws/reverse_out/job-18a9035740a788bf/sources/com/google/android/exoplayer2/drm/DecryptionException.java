package com.google.android.exoplayer2.drm;

/* JADX INFO: loaded from: classes2.dex */
public class DecryptionException extends Exception {
    public final int errorCode;

    public DecryptionException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}
