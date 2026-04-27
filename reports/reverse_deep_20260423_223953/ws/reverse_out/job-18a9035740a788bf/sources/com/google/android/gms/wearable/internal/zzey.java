package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.MessageApi;

/* JADX INFO: loaded from: classes.dex */
public final class zzey implements MessageApi.SendMessageResult {
    private final int zzeh;
    private final Status zzp;

    public zzey(Status status, int i) {
        this.zzp = status;
        this.zzeh = i;
    }

    @Override // com.google.android.gms.common.api.Result
    public final Status getStatus() {
        return this.zzp;
    }

    @Override // com.google.android.gms.wearable.MessageApi.SendMessageResult
    public final int getRequestId() {
        return this.zzeh;
    }
}
