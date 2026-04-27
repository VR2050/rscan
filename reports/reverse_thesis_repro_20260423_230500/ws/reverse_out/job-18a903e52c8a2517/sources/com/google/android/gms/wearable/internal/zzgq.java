package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.CapabilityApi;

/* JADX INFO: loaded from: classes.dex */
final class zzgq extends zzgm<CapabilityApi.GetAllCapabilitiesResult> {
    public zzgq(BaseImplementation.ResultHolder<CapabilityApi.GetAllCapabilitiesResult> resultHolder) {
        super(resultHolder);
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzdi zzdiVar) {
        zza(new zzx(zzgd.zzb(zzdiVar.statusCode), zzgk.zza(zzdiVar.zzdp)));
    }
}
