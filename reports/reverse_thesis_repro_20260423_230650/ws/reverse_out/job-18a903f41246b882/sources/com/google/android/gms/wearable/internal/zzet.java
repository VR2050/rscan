package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation;
import java.lang.ref.WeakReference;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzet<T> extends zzgm<Status> {
    private WeakReference<Map<T, zzhk<T>>> zzec;
    private WeakReference<T> zzed;

    zzet(Map<T, zzhk<T>> map, T t, BaseImplementation.ResultHolder<Status> resultHolder) {
        super(resultHolder);
        this.zzec = new WeakReference<>(map);
        this.zzed = new WeakReference<>(t);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(Status status) {
        Map<T, zzhk<T>> map = this.zzec.get();
        T t = this.zzed.get();
        if (status.getStatus().getStatusCode() == 4002 && map != null && t != null) {
            synchronized (map) {
                zzhk<T> zzhkVarRemove = map.remove(t);
                if (zzhkVarRemove != null) {
                    zzhkVarRemove.clear();
                }
            }
        }
        zza(status);
    }
}
