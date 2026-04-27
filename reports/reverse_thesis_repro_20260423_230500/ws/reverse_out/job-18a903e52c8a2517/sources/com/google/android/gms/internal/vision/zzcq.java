package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcr;

/* JADX INFO: loaded from: classes.dex */
final class zzcq implements zzdw {
    private static final zzcq zzkq = new zzcq();

    private zzcq() {
    }

    public static zzcq zzbs() {
        return zzkq;
    }

    @Override // com.google.android.gms.internal.vision.zzdw
    public final boolean zza(Class<?> cls) {
        return zzcr.class.isAssignableFrom(cls);
    }

    @Override // com.google.android.gms.internal.vision.zzdw
    public final zzdv zzb(Class<?> cls) {
        if (!zzcr.class.isAssignableFrom(cls)) {
            String strValueOf = String.valueOf(cls.getName());
            throw new IllegalArgumentException(strValueOf.length() != 0 ? "Unsupported message type: ".concat(strValueOf) : new String("Unsupported message type: "));
        }
        try {
            return (zzdv) zzcr.zzc(cls.asSubclass(zzcr.class)).zza(zzcr.zzd.zzla, (Object) null, (Object) null);
        } catch (Exception e) {
            String strValueOf2 = String.valueOf(cls.getName());
            throw new RuntimeException(strValueOf2.length() != 0 ? "Unable to get message info for ".concat(strValueOf2) : new String("Unable to get message info for "), e);
        }
    }
}
