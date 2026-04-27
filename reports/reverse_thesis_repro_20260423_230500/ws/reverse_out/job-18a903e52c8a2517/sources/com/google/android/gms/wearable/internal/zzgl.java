package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.CapabilityApi;

/* JADX INFO: loaded from: classes.dex */
final class zzgl extends zzgm<CapabilityApi.AddLocalCapabilityResult> {
    public zzgl(BaseImplementation.ResultHolder<CapabilityApi.AddLocalCapabilityResult> resultHolder) {
        super(resultHolder);
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzf zzfVar) {
        zza(new zzu(zzgd.zzb(zzfVar.statusCode)));
    }
}
