package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.DataApi;

/* JADX INFO: loaded from: classes.dex */
final class zzgp extends zzgm<DataApi.DeleteDataItemsResult> {
    public zzgp(BaseImplementation.ResultHolder<DataApi.DeleteDataItemsResult> resultHolder) {
        super(resultHolder);
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzdg zzdgVar) {
        zza(new zzch(zzgd.zzb(zzdgVar.statusCode), zzdgVar.zzdh));
    }
}
