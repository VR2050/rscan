package com.google.android.gms.wearable;

import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public class ChannelIOException extends IOException {
    private final int zzg;
    private final int zzh;

    public ChannelIOException(String str, int i, int i2) {
        super(str);
        this.zzg = i;
        this.zzh = i2;
    }

    public int getCloseReason() {
        return this.zzg;
    }

    public int getAppSpecificErrorCode() {
        return this.zzh;
    }
}
