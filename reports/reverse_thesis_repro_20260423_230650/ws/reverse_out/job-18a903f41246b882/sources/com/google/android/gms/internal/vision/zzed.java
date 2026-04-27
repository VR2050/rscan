package com.google.android.gms.internal.vision;

import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
final class zzed<T> implements zzen<T> {
    private final zzdx zzni;
    private final boolean zznj;
    private final zzff<?, ?> zzns;
    private final zzcg<?> zznt;

    private zzed(zzff<?, ?> zzffVar, zzcg<?> zzcgVar, zzdx zzdxVar) {
        this.zzns = zzffVar;
        this.zznj = zzcgVar.zze(zzdxVar);
        this.zznt = zzcgVar;
        this.zzni = zzdxVar;
    }

    static <T> zzed<T> zza(zzff<?, ?> zzffVar, zzcg<?> zzcgVar, zzdx zzdxVar) {
        return new zzed<>(zzffVar, zzcgVar, zzdxVar);
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final boolean equals(T t, T t2) {
        if (!this.zzns.zzr(t).equals(this.zzns.zzr(t2))) {
            return false;
        }
        if (this.zznj) {
            return this.zznt.zzb(t).equals(this.zznt.zzb(t2));
        }
        return true;
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final int hashCode(T t) {
        int iHashCode = this.zzns.zzr(t).hashCode();
        return this.zznj ? (iHashCode * 53) + this.zznt.zzb(t).hashCode() : iHashCode;
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final T newInstance() {
        return (T) this.zzni.zzbv().zzbz();
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final void zza(T t, zzfz zzfzVar) throws IOException {
        for (T t2 : this.zznt.zzb(t)) {
            zzcl zzclVar = (zzcl) t2.getKey();
            if (zzclVar.zzbp() != zzfy.MESSAGE || zzclVar.zzbq() || zzclVar.zzbr()) {
                throw new IllegalStateException("Found invalid MessageSet item.");
            }
            zzfzVar.zza(zzclVar.zzbn(), t2 instanceof zzdc ? ((zzdc) t2).zzcj().zzak() : t2.getValue());
        }
        zzff<?, ?> zzffVar = this.zzns;
        zzffVar.zzc(zzffVar.zzr(t), zzfzVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:26:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0061 A[EDGE_INSN: B:49:0x0061->B:27:0x0061 BREAK  A[LOOP:1: B:14:0x0032->B:52:0x0032], SYNTHETIC] */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zza(T r8, byte[] r9, int r10, int r11, com.google.android.gms.internal.vision.zzbl r12) throws java.io.IOException {
        /*
            r7 = this;
            com.google.android.gms.internal.vision.zzcr r8 = (com.google.android.gms.internal.vision.zzcr) r8
            com.google.android.gms.internal.vision.zzfg r0 = r8.zzkr
            com.google.android.gms.internal.vision.zzfg r1 = com.google.android.gms.internal.vision.zzfg.zzdu()
            if (r0 != r1) goto L10
            com.google.android.gms.internal.vision.zzfg r0 = com.google.android.gms.internal.vision.zzfg.zzdv()
            r8.zzkr = r0
        L10:
            r8 = r0
        L11:
            if (r10 >= r11) goto L6b
            int r2 = com.google.android.gms.internal.vision.zzbk.zza(r9, r10, r12)
            int r0 = r12.zzgo
            r10 = 11
            r1 = 2
            if (r0 == r10) goto L30
            r10 = r0 & 7
            if (r10 != r1) goto L2b
            r1 = r9
            r3 = r11
            r4 = r8
            r5 = r12
            int r10 = com.google.android.gms.internal.vision.zzbk.zza(r0, r1, r2, r3, r4, r5)
            goto L11
        L2b:
            int r10 = com.google.android.gms.internal.vision.zzbk.zza(r0, r9, r2, r11, r12)
            goto L11
        L30:
            r10 = 0
            r0 = 0
        L32:
            if (r2 >= r11) goto L61
            int r2 = com.google.android.gms.internal.vision.zzbk.zza(r9, r2, r12)
            int r3 = r12.zzgo
            int r4 = r3 >>> 3
            r5 = r3 & 7
            if (r4 == r1) goto L4f
            r6 = 3
            if (r4 == r6) goto L44
            goto L58
        L44:
            if (r5 != r1) goto L58
            int r2 = com.google.android.gms.internal.vision.zzbk.zze(r9, r2, r12)
            java.lang.Object r0 = r12.zzgq
            com.google.android.gms.internal.vision.zzbo r0 = (com.google.android.gms.internal.vision.zzbo) r0
            goto L32
        L4f:
            if (r5 != 0) goto L58
            int r2 = com.google.android.gms.internal.vision.zzbk.zza(r9, r2, r12)
            int r10 = r12.zzgo
            goto L32
        L58:
            r4 = 12
            if (r3 == r4) goto L61
            int r2 = com.google.android.gms.internal.vision.zzbk.zza(r3, r9, r2, r11, r12)
            goto L32
        L61:
            if (r0 == 0) goto L69
            int r10 = r10 << 3
            r10 = r10 | r1
            r8.zzb(r10, r0)
        L69:
            r10 = r2
            goto L11
        L6b:
            if (r10 != r11) goto L6e
            return
        L6e:
            com.google.android.gms.internal.vision.zzcx r8 = com.google.android.gms.internal.vision.zzcx.zzcf()
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzed.zza(java.lang.Object, byte[], int, int, com.google.android.gms.internal.vision.zzbl):void");
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final void zzc(T t, T t2) {
        zzep.zza(this.zzns, t, t2);
        if (this.zznj) {
            zzep.zza(this.zznt, t, t2);
        }
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final void zzd(T t) {
        this.zzns.zzd(t);
        this.zznt.zzd(t);
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final int zzn(T t) {
        zzff<?, ?> zzffVar = this.zzns;
        int iZzs = zzffVar.zzs(zzffVar.zzr(t)) + 0;
        return this.zznj ? iZzs + this.zznt.zzb(t).zzbm() : iZzs;
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final boolean zzp(T t) {
        return this.zznt.zzb(t).isInitialized();
    }
}
