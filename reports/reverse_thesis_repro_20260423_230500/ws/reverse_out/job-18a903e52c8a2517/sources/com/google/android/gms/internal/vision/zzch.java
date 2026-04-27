package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcr;
import java.io.IOException;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzch extends zzcg<Object> {
    zzch() {
    }

    @Override // com.google.android.gms.internal.vision.zzcg
    final int zza(Map.Entry<?, ?> entry) {
        entry.getKey();
        throw new NoSuchMethodError();
    }

    @Override // com.google.android.gms.internal.vision.zzcg
    final void zza(zzfz zzfzVar, Map.Entry<?, ?> entry) throws IOException {
        entry.getKey();
        throw new NoSuchMethodError();
    }

    @Override // com.google.android.gms.internal.vision.zzcg
    final void zza(Object obj, zzcj<Object> zzcjVar) {
        ((zzcr.zzc) obj).zzkx = zzcjVar;
    }

    @Override // com.google.android.gms.internal.vision.zzcg
    final zzcj<Object> zzb(Object obj) {
        return ((zzcr.zzc) obj).zzkx;
    }

    @Override // com.google.android.gms.internal.vision.zzcg
    final zzcj<Object> zzc(Object obj) {
        zzcj<Object> zzcjVarZzb = zzb(obj);
        if (!zzcjVarZzb.isImmutable()) {
            return zzcjVarZzb;
        }
        zzcj<Object> zzcjVar = (zzcj) zzcjVarZzb.clone();
        zza(obj, zzcjVar);
        return zzcjVar;
    }

    @Override // com.google.android.gms.internal.vision.zzcg
    final void zzd(Object obj) {
        zzb(obj).zzao();
    }

    @Override // com.google.android.gms.internal.vision.zzcg
    final boolean zze(zzdx zzdxVar) {
        return zzdxVar instanceof zzcr.zzc;
    }
}
