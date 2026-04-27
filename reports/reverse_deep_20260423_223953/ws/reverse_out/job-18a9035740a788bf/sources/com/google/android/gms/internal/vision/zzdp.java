package com.google.android.gms.internal.vision;

import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public final class zzdp<K, V> {
    static <K, V> int zza(zzdq<K, V> zzdqVar, K k, V v) {
        return zzcj.zza(zzdqVar.zzmw, 1, k) + zzcj.zza(zzdqVar.zzmy, 2, v);
    }

    static <K, V> void zza(zzca zzcaVar, zzdq<K, V> zzdqVar, K k, V v) throws IOException {
        zzcj.zza(zzcaVar, zzdqVar.zzmw, 1, k);
        zzcj.zza(zzcaVar, zzdqVar.zzmy, 2, v);
    }
}
