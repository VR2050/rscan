package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcl;
import java.io.IOException;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
abstract class zzcg<T extends zzcl<T>> {
    zzcg() {
    }

    abstract int zza(Map.Entry<?, ?> entry);

    abstract void zza(zzfz zzfzVar, Map.Entry<?, ?> entry) throws IOException;

    abstract void zza(Object obj, zzcj<T> zzcjVar);

    abstract zzcj<T> zzb(Object obj);

    abstract zzcj<T> zzc(Object obj);

    abstract void zzd(Object obj);

    abstract boolean zze(zzdx zzdxVar);
}
