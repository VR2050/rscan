package com.google.android.gms.internal.vision;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.RandomAccess;

/* JADX INFO: loaded from: classes.dex */
final class zzep {
    private static final Class<?> zzob = zzdj();
    private static final zzff<?, ?> zzoc = zzd(false);
    private static final zzff<?, ?> zzod = zzd(true);
    private static final zzff<?, ?> zzoe = new zzfh();

    static int zza(List<Long> list) {
        int iZze;
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (list instanceof zzdl) {
            zzdl zzdlVar = (zzdl) list;
            iZze = 0;
            while (i < size) {
                iZze += zzca.zze(zzdlVar.getLong(i));
                i++;
            }
        } else {
            iZze = 0;
            while (i < size) {
                iZze += zzca.zze(list.get(i).longValue());
                i++;
            }
        }
        return iZze;
    }

    private static <UT, UB> UB zza(int i, int i2, UB ub, zzff<UT, UB> zzffVar) {
        if (ub == null) {
            ub = zzffVar.zzdt();
        }
        zzffVar.zza(ub, i, i2);
        return ub;
    }

    static <UT, UB> UB zza(int i, List<Integer> list, zzcv<?> zzcvVar, UB ub, zzff<UT, UB> zzffVar) {
        if (zzcvVar == null) {
            return ub;
        }
        if (list instanceof RandomAccess) {
            int size = list.size();
            int i2 = 0;
            for (int i3 = 0; i3 < size; i3++) {
                int iIntValue = list.get(i3).intValue();
                if (zzcvVar.zzaf(iIntValue) != null) {
                    if (i3 != i2) {
                        list.set(i2, Integer.valueOf(iIntValue));
                    }
                    i2++;
                } else {
                    ub = (UB) zza(i, iIntValue, ub, zzffVar);
                }
            }
            if (i2 != size) {
                list.subList(i2, size).clear();
            }
        } else {
            Iterator<Integer> it = list.iterator();
            while (it.hasNext()) {
                int iIntValue2 = it.next().intValue();
                if (zzcvVar.zzaf(iIntValue2) == null) {
                    ub = (UB) zza(i, iIntValue2, ub, zzffVar);
                    it.remove();
                }
            }
        }
        return ub;
    }

    public static void zza(int i, List<String> list, zzfz zzfzVar) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zza(i, list);
    }

    public static void zza(int i, List<?> list, zzfz zzfzVar, zzen zzenVar) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zza(i, list, zzenVar);
    }

    public static void zza(int i, List<Double> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzg(i, list, z);
    }

    /* JADX WARN: Multi-variable type inference failed */
    static <T, FT extends zzcl<FT>> void zza(zzcg<FT> zzcgVar, T t, T t2) {
        zzcj<T> zzcjVarZzb = zzcgVar.zzb(t2);
        if (zzcjVarZzb.isEmpty()) {
            return;
        }
        zzcgVar.zzc(t).zza(zzcjVarZzb);
    }

    static <T> void zza(zzds zzdsVar, T t, T t2, long j) {
        zzfl.zza(t, j, zzdsVar.zzb(zzfl.zzo(t, j), zzfl.zzo(t2, j)));
    }

    static <T, UT, UB> void zza(zzff<UT, UB> zzffVar, T t, T t2) {
        zzffVar.zze(t, zzffVar.zzg(zzffVar.zzr(t), zzffVar.zzr(t2)));
    }

    static int zzb(List<Long> list) {
        int iZzf;
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (list instanceof zzdl) {
            zzdl zzdlVar = (zzdl) list;
            iZzf = 0;
            while (i < size) {
                iZzf += zzca.zzf(zzdlVar.getLong(i));
                i++;
            }
        } else {
            iZzf = 0;
            while (i < size) {
                iZzf += zzca.zzf(list.get(i).longValue());
                i++;
            }
        }
        return iZzf;
    }

    public static void zzb(int i, List<zzbo> list, zzfz zzfzVar) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzb(i, list);
    }

    public static void zzb(int i, List<?> list, zzfz zzfzVar, zzen zzenVar) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzb(i, list, zzenVar);
    }

    public static void zzb(int i, List<Float> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzf(i, list, z);
    }

    static int zzc(int i, Object obj, zzen zzenVar) {
        return obj instanceof zzde ? zzca.zza(i, (zzde) obj) : zzca.zzb(i, (zzdx) obj, zzenVar);
    }

    static int zzc(int i, List<?> list) {
        int size = list.size();
        int i2 = 0;
        if (size == 0) {
            return 0;
        }
        int iZzt = zzca.zzt(i) * size;
        if (list instanceof zzdg) {
            zzdg zzdgVar = (zzdg) list;
            while (i2 < size) {
                Object raw = zzdgVar.getRaw(i2);
                iZzt += raw instanceof zzbo ? zzca.zzb((zzbo) raw) : zzca.zzi((String) raw);
                i2++;
            }
        } else {
            while (i2 < size) {
                Object obj = list.get(i2);
                iZzt += obj instanceof zzbo ? zzca.zzb((zzbo) obj) : zzca.zzi((String) obj);
                i2++;
            }
        }
        return iZzt;
    }

    static int zzc(int i, List<?> list, zzen zzenVar) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iZzt = zzca.zzt(i) * size;
        for (int i2 = 0; i2 < size; i2++) {
            Object obj = list.get(i2);
            iZzt += obj instanceof zzde ? zzca.zza((zzde) obj) : zzca.zza((zzdx) obj, zzenVar);
        }
        return iZzt;
    }

    static int zzc(List<Long> list) {
        int iZzg;
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (list instanceof zzdl) {
            zzdl zzdlVar = (zzdl) list;
            iZzg = 0;
            while (i < size) {
                iZzg += zzca.zzg(zzdlVar.getLong(i));
                i++;
            }
        } else {
            iZzg = 0;
            while (i < size) {
                iZzg += zzca.zzg(list.get(i).longValue());
                i++;
            }
        }
        return iZzg;
    }

    public static void zzc(int i, List<Long> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzc(i, list, z);
    }

    static int zzd(int i, List<zzbo> list) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iZzt = size * zzca.zzt(i);
        for (int i2 = 0; i2 < list.size(); i2++) {
            iZzt += zzca.zzb(list.get(i2));
        }
        return iZzt;
    }

    static int zzd(int i, List<zzdx> list, zzen zzenVar) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        int iZzc = 0;
        for (int i2 = 0; i2 < size; i2++) {
            iZzc += zzca.zzc(i, list.get(i2), zzenVar);
        }
        return iZzc;
    }

    static int zzd(List<Integer> list) {
        int iZzz;
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (list instanceof zzcs) {
            zzcs zzcsVar = (zzcs) list;
            iZzz = 0;
            while (i < size) {
                iZzz += zzca.zzz(zzcsVar.getInt(i));
                i++;
            }
        } else {
            iZzz = 0;
            while (i < size) {
                iZzz += zzca.zzz(list.get(i).intValue());
                i++;
            }
        }
        return iZzz;
    }

    private static zzff<?, ?> zzd(boolean z) {
        try {
            Class<?> clsZzdk = zzdk();
            if (clsZzdk == null) {
                return null;
            }
            return (zzff) clsZzdk.getConstructor(Boolean.TYPE).newInstance(Boolean.valueOf(z));
        } catch (Throwable th) {
            return null;
        }
    }

    public static void zzd(int i, List<Long> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzd(i, list, z);
    }

    static boolean zzd(Object obj, Object obj2) {
        if (obj != obj2) {
            return obj != null && obj.equals(obj2);
        }
        return true;
    }

    public static zzff<?, ?> zzdg() {
        return zzoc;
    }

    public static zzff<?, ?> zzdh() {
        return zzod;
    }

    public static zzff<?, ?> zzdi() {
        return zzoe;
    }

    private static Class<?> zzdj() {
        try {
            return Class.forName("com.google.protobuf.GeneratedMessage");
        } catch (Throwable th) {
            return null;
        }
    }

    private static Class<?> zzdk() {
        try {
            return Class.forName("com.google.protobuf.UnknownFieldSetSchema");
        } catch (Throwable th) {
            return null;
        }
    }

    static int zze(List<Integer> list) {
        int iZzu;
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (list instanceof zzcs) {
            zzcs zzcsVar = (zzcs) list;
            iZzu = 0;
            while (i < size) {
                iZzu += zzca.zzu(zzcsVar.getInt(i));
                i++;
            }
        } else {
            iZzu = 0;
            while (i < size) {
                iZzu += zzca.zzu(list.get(i).intValue());
                i++;
            }
        }
        return iZzu;
    }

    public static void zze(int i, List<Long> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzn(i, list, z);
    }

    static int zzf(List<Integer> list) {
        int iZzv;
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (list instanceof zzcs) {
            zzcs zzcsVar = (zzcs) list;
            iZzv = 0;
            while (i < size) {
                iZzv += zzca.zzv(zzcsVar.getInt(i));
                i++;
            }
        } else {
            iZzv = 0;
            while (i < size) {
                iZzv += zzca.zzv(list.get(i).intValue());
                i++;
            }
        }
        return iZzv;
    }

    public static void zzf(int i, List<Long> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zze(i, list, z);
    }

    public static void zzf(Class<?> cls) {
        Class<?> cls2;
        if (!zzcr.class.isAssignableFrom(cls) && (cls2 = zzob) != null && !cls2.isAssignableFrom(cls)) {
            throw new IllegalArgumentException("Message classes must extend GeneratedMessage or GeneratedMessageLite");
        }
    }

    static int zzg(List<Integer> list) {
        int iZzw;
        int size = list.size();
        int i = 0;
        if (size == 0) {
            return 0;
        }
        if (list instanceof zzcs) {
            zzcs zzcsVar = (zzcs) list;
            iZzw = 0;
            while (i < size) {
                iZzw += zzca.zzw(zzcsVar.getInt(i));
                i++;
            }
        } else {
            iZzw = 0;
            while (i < size) {
                iZzw += zzca.zzw(list.get(i).intValue());
                i++;
            }
        }
        return iZzw;
    }

    public static void zzg(int i, List<Long> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzl(i, list, z);
    }

    static int zzh(List<?> list) {
        return list.size() << 2;
    }

    public static void zzh(int i, List<Integer> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zza(i, list, z);
    }

    static int zzi(List<?> list) {
        return list.size() << 3;
    }

    public static void zzi(int i, List<Integer> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzj(i, list, z);
    }

    static int zzj(List<?> list) {
        return list.size();
    }

    public static void zzj(int i, List<Integer> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzm(i, list, z);
    }

    public static void zzk(int i, List<Integer> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzb(i, list, z);
    }

    public static void zzl(int i, List<Integer> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzk(i, list, z);
    }

    public static void zzm(int i, List<Integer> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzh(i, list, z);
    }

    public static void zzn(int i, List<Boolean> list, zzfz zzfzVar, boolean z) throws IOException {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzfzVar.zzi(i, list, z);
    }

    static int zzo(int i, List<Long> list, boolean z) {
        if (list.size() == 0) {
            return 0;
        }
        return zza(list) + (list.size() * zzca.zzt(i));
    }

    static int zzp(int i, List<Long> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return zzb(list) + (size * zzca.zzt(i));
    }

    static int zzq(int i, List<Long> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return zzc(list) + (size * zzca.zzt(i));
    }

    static int zzr(int i, List<Integer> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return zzd(list) + (size * zzca.zzt(i));
    }

    static int zzs(int i, List<Integer> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return zze(list) + (size * zzca.zzt(i));
    }

    static int zzt(int i, List<Integer> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return zzf(list) + (size * zzca.zzt(i));
    }

    static int zzu(int i, List<Integer> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return zzg(list) + (size * zzca.zzt(i));
    }

    static int zzv(int i, List<?> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return size * zzca.zzl(i, 0);
    }

    static int zzw(int i, List<?> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return size * zzca.zzg(i, 0L);
    }

    static int zzx(int i, List<?> list, boolean z) {
        int size = list.size();
        if (size == 0) {
            return 0;
        }
        return size * zzca.zzc(i, true);
    }
}
