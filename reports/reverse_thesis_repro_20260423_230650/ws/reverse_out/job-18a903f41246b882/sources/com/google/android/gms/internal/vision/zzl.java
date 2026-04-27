package com.google.android.gms.internal.vision;

import android.content.Context;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.dynamite.DynamiteModule;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzl<T> {
    private static String PREFIX = "com.google.android.gms.vision.dynamite";
    private final String tag;
    private final String zzci;
    private final String zzcj;
    private T zzcl;
    private final Context zze;
    private final Object lock = new Object();
    private boolean zzck = false;

    public zzl(Context context, String str, String str2) {
        this.zze = context;
        this.tag = str;
        String str3 = PREFIX;
        StringBuilder sb = new StringBuilder(String.valueOf(str3).length() + 1 + String.valueOf(str2).length());
        sb.append(str3);
        sb.append(".");
        sb.append(str2);
        this.zzci = sb.toString();
        this.zzcj = PREFIX;
    }

    public final boolean isOperational() {
        return zzp() != null;
    }

    protected abstract T zza(DynamiteModule dynamiteModule, Context context) throws RemoteException, DynamiteModule.LoadingException;

    protected abstract void zzm() throws RemoteException;

    public final void zzo() {
        synchronized (this.lock) {
            if (this.zzcl == null) {
                return;
            }
            try {
                zzm();
            } catch (RemoteException e) {
                Log.e(this.tag, "Could not finalize native handle", e);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x005a A[Catch: all -> 0x006d, TryCatch #3 {, blocks: (B:4:0x0003, B:6:0x0007, B:7:0x0009, B:10:0x000c, B:21:0x0036, B:25:0x0047, B:27:0x004b, B:29:0x004f, B:35:0x0069, B:36:0x006b, B:30:0x005a, B:32:0x005e, B:34:0x0062, B:24:0x0040, B:15:0x001a, B:16:0x0021, B:19:0x002d), top: B:47:0x0003 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected final T zzp() {
        /*
            r5 = this;
            java.lang.Object r0 = r5.lock
            monitor-enter(r0)
            T r1 = r5.zzcl     // Catch: java.lang.Throwable -> L6d
            if (r1 == 0) goto Lb
            T r1 = r5.zzcl     // Catch: java.lang.Throwable -> L6d
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L6d
            return r1
        Lb:
            r1 = 0
            android.content.Context r2 = r5.zze     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L19 java.lang.Throwable -> L6d
            com.google.android.gms.dynamite.DynamiteModule$VersionPolicy r3 = com.google.android.gms.dynamite.DynamiteModule.PREFER_HIGHEST_OR_REMOTE_VERSION     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L19 java.lang.Throwable -> L6d
            java.lang.String r4 = r5.zzci     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L19 java.lang.Throwable -> L6d
            com.google.android.gms.dynamite.DynamiteModule r1 = com.google.android.gms.dynamite.DynamiteModule.load(r2, r3, r4)     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L19 java.lang.Throwable -> L6d
            goto L34
        L17:
            r1 = move-exception
            goto L40
        L19:
            r2 = move-exception
            java.lang.String r2 = r5.tag     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L3f java.lang.Throwable -> L6d
            java.lang.String r3 = "Cannot load feature, fall back to load whole module."
            android.util.Log.d(r2, r3)     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L3f java.lang.Throwable -> L6d
            android.content.Context r2 = r5.zze     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L2c java.lang.Throwable -> L6d
            com.google.android.gms.dynamite.DynamiteModule$VersionPolicy r3 = com.google.android.gms.dynamite.DynamiteModule.PREFER_HIGHEST_OR_REMOTE_VERSION     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L2c java.lang.Throwable -> L6d
            java.lang.String r4 = r5.zzcj     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L2c java.lang.Throwable -> L6d
            com.google.android.gms.dynamite.DynamiteModule r1 = com.google.android.gms.dynamite.DynamiteModule.load(r2, r3, r4)     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L2c java.lang.Throwable -> L6d
            goto L34
        L2c:
            r2 = move-exception
            java.lang.String r3 = r5.tag     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L3f java.lang.Throwable -> L6d
            java.lang.String r4 = "Error Loading module"
            android.util.Log.e(r3, r4, r2)     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L3f java.lang.Throwable -> L6d
        L34:
            if (r1 == 0) goto L47
            android.content.Context r2 = r5.zze     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L3f java.lang.Throwable -> L6d
            java.lang.Object r1 = r5.zza(r1, r2)     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L3f java.lang.Throwable -> L6d
            r5.zzcl = r1     // Catch: android.os.RemoteException -> L17 com.google.android.gms.dynamite.DynamiteModule.LoadingException -> L3f java.lang.Throwable -> L6d
            goto L47
        L3f:
            r1 = move-exception
        L40:
            java.lang.String r2 = r5.tag     // Catch: java.lang.Throwable -> L6d
            java.lang.String r3 = "Error creating remote native handle"
            android.util.Log.e(r2, r3, r1)     // Catch: java.lang.Throwable -> L6d
        L47:
            boolean r1 = r5.zzck     // Catch: java.lang.Throwable -> L6d
            if (r1 != 0) goto L5a
            T r1 = r5.zzcl     // Catch: java.lang.Throwable -> L6d
            if (r1 != 0) goto L5a
            java.lang.String r1 = r5.tag     // Catch: java.lang.Throwable -> L6d
            java.lang.String r2 = "Native handle not yet available. Reverting to no-op handle."
            android.util.Log.w(r1, r2)     // Catch: java.lang.Throwable -> L6d
            r1 = 1
            r5.zzck = r1     // Catch: java.lang.Throwable -> L6d
            goto L69
        L5a:
            boolean r1 = r5.zzck     // Catch: java.lang.Throwable -> L6d
            if (r1 == 0) goto L69
            T r1 = r5.zzcl     // Catch: java.lang.Throwable -> L6d
            if (r1 == 0) goto L69
            java.lang.String r1 = r5.tag     // Catch: java.lang.Throwable -> L6d
            java.lang.String r2 = "Native handle is now available."
            android.util.Log.w(r1, r2)     // Catch: java.lang.Throwable -> L6d
        L69:
            T r1 = r5.zzcl     // Catch: java.lang.Throwable -> L6d
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L6d
            return r1
        L6d:
            r1 = move-exception
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L6d
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzl.zzp():java.lang.Object");
    }
}
