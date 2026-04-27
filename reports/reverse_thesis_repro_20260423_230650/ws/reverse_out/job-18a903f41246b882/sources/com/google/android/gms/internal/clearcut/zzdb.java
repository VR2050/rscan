package com.google.android.gms.internal.clearcut;

/* JADX INFO: loaded from: classes.dex */
final class zzdb extends zzcy {
    private zzdb() {
        super();
    }

    private static <E> zzcn<E> zzc(Object obj, long j) {
        return (zzcn) zzfd.zzo(obj, j);
    }

    @Override // com.google.android.gms.internal.clearcut.zzcy
    final void zza(Object obj, long j) {
        zzc(obj, j).zzv();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1 */
    /* JADX WARN: Type inference failed for: r0v2, types: [com.google.android.gms.internal.clearcut.zzcn] */
    /* JADX WARN: Type inference failed for: r0v4 */
    /* JADX WARN: Type inference failed for: r0v5 */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r6v1, types: [com.google.android.gms.internal.clearcut.zzcn, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r6v2, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v3 */
    @Override // com.google.android.gms.internal.clearcut.zzcy
    final <E> void zza(Object obj, Object obj2, long j) {
        zzcn zzcnVarZzc = zzc(obj, j);
        ?? Zzc = zzc(obj2, j);
        int size = zzcnVarZzc.size();
        int size2 = Zzc.size();
        ?? r0 = zzcnVarZzc;
        r0 = zzcnVarZzc;
        if (size > 0 && size2 > 0) {
            boolean zZzu = zzcnVarZzc.zzu();
            ?? Zzi = zzcnVarZzc;
            if (!zZzu) {
                Zzi = zzcnVarZzc.zzi(size2 + size);
            }
            Zzi.addAll(Zzc);
            r0 = Zzi;
        }
        if (size > 0) {
            Zzc = r0;
        }
        zzfd.zza(obj, j, (Object) Zzc);
    }
}
