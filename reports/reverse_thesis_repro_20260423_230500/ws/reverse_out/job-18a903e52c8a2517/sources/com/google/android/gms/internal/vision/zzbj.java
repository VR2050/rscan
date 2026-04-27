package com.google.android.gms.internal.vision;

/* JADX INFO: loaded from: classes.dex */
final class zzbj {
    private static final Class<?> zzgm = zzf("libcore.io.Memory");
    private static final boolean zzgn;

    static {
        zzgn = zzf("org.robolectric.Robolectric") != null;
    }

    static boolean zzaq() {
        return (zzgm == null || zzgn) ? false : true;
    }

    static Class<?> zzar() {
        return zzgm;
    }

    private static <T> Class<T> zzf(String str) {
        try {
            return (Class<T>) Class.forName(str);
        } catch (Throwable th) {
            return null;
        }
    }
}
