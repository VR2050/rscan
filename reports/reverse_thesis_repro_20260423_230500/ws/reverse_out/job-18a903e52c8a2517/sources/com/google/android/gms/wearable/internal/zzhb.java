package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.DataApi;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.FutureTask;

/* JADX INFO: loaded from: classes.dex */
final class zzhb extends zzgm<DataApi.DataItemResult> {
    private final List<FutureTask<Boolean>> zzev;

    zzhb(BaseImplementation.ResultHolder<DataApi.DataItemResult> resultHolder, List<FutureTask<Boolean>> list) {
        super(resultHolder);
        this.zzev = list;
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzfu zzfuVar) {
        zza(new zzcg(zzgd.zzb(zzfuVar.statusCode), zzfuVar.zzdy));
        if (zzfuVar.statusCode != 0) {
            Iterator<FutureTask<Boolean>> it = this.zzev.iterator();
            while (it.hasNext()) {
                it.next().cancel(true);
            }
        }
    }
}
