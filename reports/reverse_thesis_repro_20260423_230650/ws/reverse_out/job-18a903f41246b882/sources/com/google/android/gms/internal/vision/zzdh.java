package com.google.android.gms.internal.vision;

/* JADX INFO: loaded from: classes.dex */
abstract class zzdh {
    private static final zzdh zzmo;
    private static final zzdh zzmp;

    static {
        zzdi zzdiVar = null;
        zzmo = new zzdj();
        zzmp = new zzdk();
    }

    private zzdh() {
    }

    static zzdh zzcm() {
        return zzmo;
    }

    static zzdh zzcn() {
        return zzmp;
    }

    abstract void zza(Object obj, long j);

    abstract <L> void zza(Object obj, Object obj2, long j);
}
