package com.google.android.gms.internal.vision;

/* JADX INFO: loaded from: classes.dex */
final class zzdk extends zzdh {
    private zzdk() {
        super();
    }

    private static <E> zzcw<E> zzc(Object obj, long j) {
        return (zzcw) zzfl.zzo(obj, j);
    }

    @Override // com.google.android.gms.internal.vision.zzdh
    final void zza(Object obj, long j) {
        zzc(obj, j).zzao();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1 */
    /* JADX WARN: Type inference failed for: r0v2, types: [com.google.android.gms.internal.vision.zzcw] */
    /* JADX WARN: Type inference failed for: r0v4 */
    /* JADX WARN: Type inference failed for: r0v5 */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r6v1, types: [com.google.android.gms.internal.vision.zzcw, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r6v2, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v3 */
    @Override // com.google.android.gms.internal.vision.zzdh
    final <E> void zza(Object obj, Object obj2, long j) {
        zzcw zzcwVarZzc = zzc(obj, j);
        ?? Zzc = zzc(obj2, j);
        int size = zzcwVarZzc.size();
        int size2 = Zzc.size();
        ?? r0 = zzcwVarZzc;
        r0 = zzcwVarZzc;
        if (size > 0 && size2 > 0) {
            boolean zZzan = zzcwVarZzc.zzan();
            ?? Zzk = zzcwVarZzc;
            if (!zZzan) {
                Zzk = zzcwVarZzc.zzk(size2 + size);
            }
            Zzk.addAll(Zzc);
            r0 = Zzk;
        }
        if (size > 0) {
            Zzc = r0;
        }
        zzfl.zza(obj, j, (Object) Zzc);
    }
}
