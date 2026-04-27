package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.ChannelApi;

/* JADX INFO: loaded from: classes.dex */
final class zzha extends zzgm<ChannelApi.OpenChannelResult> {
    public zzha(BaseImplementation.ResultHolder<ChannelApi.OpenChannelResult> resultHolder) {
        super(resultHolder);
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzfq zzfqVar) {
        zza(new zzam(zzgd.zzb(zzfqVar.statusCode), zzfqVar.zzck));
    }
}
