package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.DataApi;

/* JADX INFO: loaded from: classes.dex */
public final class zzch implements DataApi.DeleteDataItemsResult {
    private final int zzdh;
    private final Status zzp;

    public zzch(Status status, int i) {
        this.zzp = status;
        this.zzdh = i;
    }

    @Override // com.google.android.gms.common.api.Result
    public final Status getStatus() {
        return this.zzp;
    }

    @Override // com.google.android.gms.wearable.DataApi.DeleteDataItemsResult
    public final int getNumDeleted() {
        return this.zzdh;
    }
}
