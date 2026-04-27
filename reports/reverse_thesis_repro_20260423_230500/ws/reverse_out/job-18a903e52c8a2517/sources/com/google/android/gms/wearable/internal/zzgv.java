package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.DataApi;

/* JADX INFO: loaded from: classes.dex */
final class zzgv extends zzgm<DataApi.DataItemResult> {
    public zzgv(BaseImplementation.ResultHolder<DataApi.DataItemResult> resultHolder) {
        super(resultHolder);
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzec zzecVar) {
        zza(new zzcg(zzgd.zzb(zzecVar.statusCode), zzecVar.zzdy));
    }
}
