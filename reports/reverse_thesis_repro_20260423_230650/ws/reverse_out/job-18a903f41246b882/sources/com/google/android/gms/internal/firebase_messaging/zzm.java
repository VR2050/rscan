package com.google.android.gms.internal.firebase_messaging;

/* JADX INFO: compiled from: com.google.firebase:firebase-iid@@20.0.2 */
/* JADX INFO: loaded from: classes.dex */
public final class zzm {
    private static final zzp zza;
    private static final int zzb;

    /* JADX INFO: compiled from: com.google.firebase:firebase-iid@@20.0.2 */
    static final class zza extends zzp {
        zza() {
        }

        @Override // com.google.android.gms.internal.firebase_messaging.zzp
        public final void zza(Throwable th, Throwable th2) {
        }
    }

    public static void zza(Throwable th, Throwable th2) {
        zza.zza(th, th2);
    }

    private static Integer zza() {
        try {
            return (Integer) Class.forName("android.os.Build$VERSION").getField("SDK_INT").get(null);
        } catch (Exception e) {
            System.err.println("Failed to retrieve value from android.os.Build$VERSION.SDK_INT due to the following exception.");
            e.printStackTrace(System.err);
            return null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0016 A[Catch: all -> 0x002b, TryCatch #0 {all -> 0x002b, blocks: (B:5:0x0008, B:7:0x0010, B:8:0x0016, B:10:0x001f, B:11:0x0025), top: B:25:0x0008 }] */
    static {
        /*
            r0 = 1
            java.lang.Integer r1 = zza()     // Catch: java.lang.Throwable -> L2d
            if (r1 == 0) goto L16
            int r2 = r1.intValue()     // Catch: java.lang.Throwable -> L2b
            r3 = 19
            if (r2 < r3) goto L16
            com.google.android.gms.internal.firebase_messaging.zzs r2 = new com.google.android.gms.internal.firebase_messaging.zzs     // Catch: java.lang.Throwable -> L2b
            r2.<init>()     // Catch: java.lang.Throwable -> L2b
            goto L65
        L16:
            java.lang.String r2 = "com.google.devtools.build.android.desugar.runtime.twr_disable_mimic"
            boolean r2 = java.lang.Boolean.getBoolean(r2)     // Catch: java.lang.Throwable -> L2b
            r2 = r2 ^ r0
            if (r2 == 0) goto L25
            com.google.android.gms.internal.firebase_messaging.zzq r2 = new com.google.android.gms.internal.firebase_messaging.zzq     // Catch: java.lang.Throwable -> L2b
            r2.<init>()     // Catch: java.lang.Throwable -> L2b
            goto L65
        L25:
            com.google.android.gms.internal.firebase_messaging.zzm$zza r2 = new com.google.android.gms.internal.firebase_messaging.zzm$zza     // Catch: java.lang.Throwable -> L2b
            r2.<init>()     // Catch: java.lang.Throwable -> L2b
            goto L65
        L2b:
            r2 = move-exception
            goto L2f
        L2d:
            r2 = move-exception
            r1 = 0
        L2f:
            java.io.PrintStream r3 = java.lang.System.err
            java.lang.Class<com.google.android.gms.internal.firebase_messaging.zzm$zza> r4 = com.google.android.gms.internal.firebase_messaging.zzm.zza.class
            java.lang.String r4 = r4.getName()
            java.lang.String r5 = java.lang.String.valueOf(r4)
            int r5 = r5.length()
            int r5 = r5 + 133
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            r6.<init>(r5)
            java.lang.String r5 = "An error has occurred when initializing the try-with-resources desuguring strategy. The default strategy "
            r6.append(r5)
            r6.append(r4)
            java.lang.String r4 = "will be used. The error is: "
            r6.append(r4)
            java.lang.String r4 = r6.toString()
            r3.println(r4)
            java.io.PrintStream r3 = java.lang.System.err
            r2.printStackTrace(r3)
            com.google.android.gms.internal.firebase_messaging.zzm$zza r2 = new com.google.android.gms.internal.firebase_messaging.zzm$zza
            r2.<init>()
        L65:
            com.google.android.gms.internal.firebase_messaging.zzm.zza = r2
            if (r1 != 0) goto L6a
            goto L6e
        L6a:
            int r0 = r1.intValue()
        L6e:
            com.google.android.gms.internal.firebase_messaging.zzm.zzb = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.firebase_messaging.zzm.<clinit>():void");
    }
}
