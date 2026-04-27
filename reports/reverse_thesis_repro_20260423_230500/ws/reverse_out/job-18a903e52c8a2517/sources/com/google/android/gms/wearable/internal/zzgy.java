package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.NodeApi;

/* JADX INFO: loaded from: classes.dex */
final class zzgy extends zzgm<NodeApi.GetLocalNodeResult> {
    public zzgy(BaseImplementation.ResultHolder<NodeApi.GetLocalNodeResult> resultHolder) {
        super(resultHolder);
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzeg zzegVar) {
        zza(new zzfk(zzgd.zzb(zzegVar.statusCode), zzegVar.zzea));
    }
}
