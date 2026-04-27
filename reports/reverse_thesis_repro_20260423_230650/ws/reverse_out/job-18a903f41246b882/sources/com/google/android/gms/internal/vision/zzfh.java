package com.google.android.gms.internal.vision;

import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
final class zzfh extends zzff<zzfg, zzfg> {
    zzfh() {
    }

    private static void zza(Object obj, zzfg zzfgVar) {
        ((zzcr) obj).zzkr = zzfgVar;
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ void zza(zzfg zzfgVar, int i, long j) {
        zzfgVar.zzb(i << 3, Long.valueOf(j));
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ void zza(zzfg zzfgVar, int i, zzbo zzboVar) {
        zzfgVar.zzb((i << 3) | 2, zzboVar);
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ void zza(zzfg zzfgVar, zzfz zzfzVar) throws IOException {
        zzfgVar.zzb(zzfzVar);
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ void zzc(zzfg zzfgVar, zzfz zzfzVar) throws IOException {
        zzfgVar.zza(zzfzVar);
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final void zzd(Object obj) {
        ((zzcr) obj).zzkr.zzao();
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ zzfg zzdt() {
        return zzfg.zzdv();
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ void zze(Object obj, zzfg zzfgVar) {
        zza(obj, zzfgVar);
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ void zzf(Object obj, zzfg zzfgVar) {
        zza(obj, zzfgVar);
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ zzfg zzg(zzfg zzfgVar, zzfg zzfgVar2) {
        zzfg zzfgVar3 = zzfgVar;
        zzfg zzfgVar4 = zzfgVar2;
        return zzfgVar4.equals(zzfg.zzdu()) ? zzfgVar3 : zzfg.zza(zzfgVar3, zzfgVar4);
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ int zzn(zzfg zzfgVar) {
        return zzfgVar.zzbl();
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ zzfg zzr(Object obj) {
        return ((zzcr) obj).zzkr;
    }

    @Override // com.google.android.gms.internal.vision.zzff
    final /* synthetic */ int zzs(zzfg zzfgVar) {
        return zzfgVar.zzdw();
    }
}
