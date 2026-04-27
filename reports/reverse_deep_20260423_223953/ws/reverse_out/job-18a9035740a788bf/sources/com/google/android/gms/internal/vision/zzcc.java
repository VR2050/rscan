package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcr;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzcc implements zzfz {
    private final zzca zzgz;

    private zzcc(zzca zzcaVar) {
        zzca zzcaVar2 = (zzca) zzct.zza(zzcaVar, "output");
        this.zzgz = zzcaVar2;
        zzcaVar2.zzhk = this;
    }

    public static zzcc zza(zzca zzcaVar) {
        return zzcaVar.zzhk != null ? zzcaVar.zzhk : new zzcc(zzcaVar);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, double d) throws IOException {
        this.zzgz.zza(i, d);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, float f) throws IOException {
        this.zzgz.zza(i, f);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, long j) throws IOException {
        this.zzgz.zza(i, j);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, zzbo zzboVar) throws IOException {
        this.zzgz.zza(i, zzboVar);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final <K, V> void zza(int i, zzdq<K, V> zzdqVar, Map<K, V> map) throws IOException {
        for (Map.Entry<K, V> entry : map.entrySet()) {
            this.zzgz.zzd(i, 2);
            this.zzgz.zzq(zzdp.zza(zzdqVar, entry.getKey(), entry.getValue()));
            zzdp.zza(this.zzgz, zzdqVar, entry.getKey(), entry.getValue());
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, Object obj) throws IOException {
        if (obj instanceof zzbo) {
            this.zzgz.zzb(i, (zzbo) obj);
        } else {
            this.zzgz.zza(i, (zzdx) obj);
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, Object obj, zzen zzenVar) throws IOException {
        this.zzgz.zza(i, (zzdx) obj, zzenVar);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, String str) throws IOException {
        this.zzgz.zza(i, str);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, List<String> list) throws IOException {
        int i2 = 0;
        if (!(list instanceof zzdg)) {
            while (i2 < list.size()) {
                this.zzgz.zza(i, list.get(i2));
                i2++;
            }
            return;
        }
        zzdg zzdgVar = (zzdg) list;
        while (i2 < list.size()) {
            Object raw = zzdgVar.getRaw(i2);
            if (raw instanceof String) {
                this.zzgz.zza(i, (String) raw);
            } else {
                this.zzgz.zza(i, (zzbo) raw);
            }
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, List<?> list, zzen zzenVar) throws IOException {
        for (int i2 = 0; i2 < list.size(); i2++) {
            zza(i, list.get(i2), zzenVar);
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zza(int i, List<Integer> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zze(i, list.get(i2).intValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzu = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzu += zzca.zzu(list.get(i3).intValue());
        }
        this.zzgz.zzq(iZzu);
        while (i2 < list.size()) {
            this.zzgz.zzp(list.get(i2).intValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzac(int i) throws IOException {
        this.zzgz.zzd(i, 3);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzad(int i) throws IOException {
        this.zzgz.zzd(i, 4);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzb(int i, long j) throws IOException {
        this.zzgz.zzb(i, j);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzb(int i, Object obj, zzen zzenVar) throws IOException {
        zzca zzcaVar = this.zzgz;
        zzcaVar.zzd(i, 3);
        zzenVar.zza((zzdx) obj, zzcaVar.zzhk);
        zzcaVar.zzd(i, 4);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzb(int i, List<zzbo> list) throws IOException {
        for (int i2 = 0; i2 < list.size(); i2++) {
            this.zzgz.zza(i, list.get(i2));
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzb(int i, List<?> list, zzen zzenVar) throws IOException {
        for (int i2 = 0; i2 < list.size(); i2++) {
            zzb(i, list.get(i2), zzenVar);
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzb(int i, List<Integer> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzh(i, list.get(i2).intValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzx = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzx += zzca.zzx(list.get(i3).intValue());
        }
        this.zzgz.zzq(iZzx);
        while (i2 < list.size()) {
            this.zzgz.zzs(list.get(i2).intValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzb(int i, boolean z) throws IOException {
        this.zzgz.zzb(i, z);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final int zzbc() {
        return zzcr.zzd.zzlj;
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzc(int i, long j) throws IOException {
        this.zzgz.zzc(i, j);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzc(int i, List<Long> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zza(i, list.get(i2).longValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZze = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZze += zzca.zze(list.get(i3).longValue());
        }
        this.zzgz.zzq(iZze);
        while (i2 < list.size()) {
            this.zzgz.zzb(list.get(i2).longValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzd(int i, List<Long> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zza(i, list.get(i2).longValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzf = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzf += zzca.zzf(list.get(i3).longValue());
        }
        this.zzgz.zzq(iZzf);
        while (i2 < list.size()) {
            this.zzgz.zzb(list.get(i2).longValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zze(int i, int i2) throws IOException {
        this.zzgz.zze(i, i2);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zze(int i, List<Long> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzc(i, list.get(i2).longValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzh = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzh += zzca.zzh(list.get(i3).longValue());
        }
        this.zzgz.zzq(iZzh);
        while (i2 < list.size()) {
            this.zzgz.zzd(list.get(i2).longValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzf(int i, int i2) throws IOException {
        this.zzgz.zzf(i, i2);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzf(int i, List<Float> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zza(i, list.get(i2).floatValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzd = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzd += zzca.zzd(list.get(i3).floatValue());
        }
        this.zzgz.zzq(iZzd);
        while (i2 < list.size()) {
            this.zzgz.zzc(list.get(i2).floatValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzg(int i, int i2) throws IOException {
        this.zzgz.zzg(i, i2);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzg(int i, List<Double> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zza(i, list.get(i2).doubleValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzb = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzb += zzca.zzb(list.get(i3).doubleValue());
        }
        this.zzgz.zzq(iZzb);
        while (i2 < list.size()) {
            this.zzgz.zza(list.get(i2).doubleValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzh(int i, int i2) throws IOException {
        this.zzgz.zzh(i, i2);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzh(int i, List<Integer> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zze(i, list.get(i2).intValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzz = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzz += zzca.zzz(list.get(i3).intValue());
        }
        this.zzgz.zzq(iZzz);
        while (i2 < list.size()) {
            this.zzgz.zzp(list.get(i2).intValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzi(int i, long j) throws IOException {
        this.zzgz.zza(i, j);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzi(int i, List<Boolean> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzb(i, list.get(i2).booleanValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzb = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzb += zzca.zzb(list.get(i3).booleanValue());
        }
        this.zzgz.zzq(iZzb);
        while (i2 < list.size()) {
            this.zzgz.zza(list.get(i2).booleanValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzj(int i, long j) throws IOException {
        this.zzgz.zzc(i, j);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzj(int i, List<Integer> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzf(i, list.get(i2).intValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzv = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzv += zzca.zzv(list.get(i3).intValue());
        }
        this.zzgz.zzq(iZzv);
        while (i2 < list.size()) {
            this.zzgz.zzq(list.get(i2).intValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzk(int i, List<Integer> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzh(i, list.get(i2).intValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzy = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzy += zzca.zzy(list.get(i3).intValue());
        }
        this.zzgz.zzq(iZzy);
        while (i2 < list.size()) {
            this.zzgz.zzs(list.get(i2).intValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzl(int i, List<Long> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzc(i, list.get(i2).longValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzi = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzi += zzca.zzi(list.get(i3).longValue());
        }
        this.zzgz.zzq(iZzi);
        while (i2 < list.size()) {
            this.zzgz.zzd(list.get(i2).longValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzm(int i, List<Integer> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzg(i, list.get(i2).intValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzw = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzw += zzca.zzw(list.get(i3).intValue());
        }
        this.zzgz.zzq(iZzw);
        while (i2 < list.size()) {
            this.zzgz.zzr(list.get(i2).intValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzn(int i, List<Long> list, boolean z) throws IOException {
        int i2 = 0;
        if (!z) {
            while (i2 < list.size()) {
                this.zzgz.zzb(i, list.get(i2).longValue());
                i2++;
            }
            return;
        }
        this.zzgz.zzd(i, 2);
        int iZzg = 0;
        for (int i3 = 0; i3 < list.size(); i3++) {
            iZzg += zzca.zzg(list.get(i3).longValue());
        }
        this.zzgz.zzq(iZzg);
        while (i2 < list.size()) {
            this.zzgz.zzc(list.get(i2).longValue());
            i2++;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzo(int i, int i2) throws IOException {
        this.zzgz.zzh(i, i2);
    }

    @Override // com.google.android.gms.internal.vision.zzfz
    public final void zzp(int i, int i2) throws IOException {
        this.zzgz.zze(i, i2);
    }
}
