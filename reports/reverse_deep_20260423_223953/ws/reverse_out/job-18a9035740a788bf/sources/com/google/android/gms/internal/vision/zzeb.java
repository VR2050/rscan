package com.google.android.gms.internal.vision;

import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import sun.misc.Unsafe;

/* JADX INFO: loaded from: classes.dex */
final class zzeb<T> implements zzen<T> {
    private static final int[] zznc = new int[0];
    private static final Unsafe zznd = zzfl.zzdz();
    private final int[] zzne;
    private final Object[] zznf;
    private final int zzng;
    private final int zznh;
    private final zzdx zzni;
    private final boolean zznj;
    private final boolean zznk;
    private final boolean zznl;
    private final boolean zznm;
    private final int[] zznn;
    private final int zzno;
    private final int zznp;
    private final zzef zznq;
    private final zzdh zznr;
    private final zzff<?, ?> zzns;
    private final zzcg<?> zznt;
    private final zzds zznu;

    private zzeb(int[] iArr, Object[] objArr, int i, int i2, zzdx zzdxVar, boolean z, boolean z2, int[] iArr2, int i3, int i4, zzef zzefVar, zzdh zzdhVar, zzff<?, ?> zzffVar, zzcg<?> zzcgVar, zzds zzdsVar) {
        this.zzne = iArr;
        this.zznf = objArr;
        this.zzng = i;
        this.zznh = i2;
        this.zznk = zzdxVar instanceof zzcr;
        this.zznl = z;
        this.zznj = zzcgVar != null && zzcgVar.zze(zzdxVar);
        this.zznm = false;
        this.zznn = iArr2;
        this.zzno = i3;
        this.zznp = i4;
        this.zznq = zzefVar;
        this.zznr = zzdhVar;
        this.zzns = zzffVar;
        this.zznt = zzcgVar;
        this.zzni = zzdxVar;
        this.zznu = zzdsVar;
    }

    private static int zza(int i, byte[] bArr, int i2, int i3, Object obj, zzbl zzblVar) throws IOException {
        return zzbk.zza(i, bArr, i2, i3, zzo(obj), zzblVar);
    }

    private static int zza(zzen<?> zzenVar, int i, byte[] bArr, int i2, int i3, zzcw<?> zzcwVar, zzbl zzblVar) throws IOException {
        int iZza = zza((zzen) zzenVar, bArr, i2, i3, zzblVar);
        while (true) {
            zzcwVar.add(zzblVar.zzgq);
            if (iZza >= i3) {
                break;
            }
            int iZza2 = zzbk.zza(bArr, iZza, zzblVar);
            if (i != zzblVar.zzgo) {
                break;
            }
            iZza = zza((zzen) zzenVar, bArr, iZza2, i3, zzblVar);
        }
        return iZza;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static int zza(zzen zzenVar, byte[] bArr, int i, int i2, int i3, zzbl zzblVar) throws IOException {
        zzeb zzebVar = (zzeb) zzenVar;
        Object objNewInstance = zzebVar.newInstance();
        int iZza = zzebVar.zza(objNewInstance, bArr, i, i2, i3, zzblVar);
        zzebVar.zzd(objNewInstance);
        zzblVar.zzgq = objNewInstance;
        return iZza;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static int zza(zzen zzenVar, byte[] bArr, int i, int i2, zzbl zzblVar) throws IOException {
        int iZza = i + 1;
        int i3 = bArr[i];
        if (i3 < 0) {
            iZza = zzbk.zza(i3, bArr, iZza, zzblVar);
            i3 = zzblVar.zzgo;
        }
        int i4 = iZza;
        if (i3 < 0 || i3 > i2 - i4) {
            throw zzcx.zzcb();
        }
        Object objNewInstance = zzenVar.newInstance();
        int i5 = i3 + i4;
        zzenVar.zza(objNewInstance, bArr, i4, i5, zzblVar);
        zzenVar.zzd(objNewInstance);
        zzblVar.zzgq = objNewInstance;
        return i5;
    }

    private static <UT, UB> int zza(zzff<UT, UB> zzffVar, T t) {
        return zzffVar.zzn(zzffVar.zzr(t));
    }

    private final int zza(T t, byte[] bArr, int i, int i2, int i3, int i4, int i5, int i6, int i7, long j, int i8, zzbl zzblVar) throws IOException {
        Object objValueOf;
        Object objValueOf2;
        int iZzb;
        long jZza;
        int iZzo;
        Object objValueOf3;
        int i9;
        Unsafe unsafe = zznd;
        long j2 = this.zzne[i8 + 2] & 1048575;
        switch (i7) {
            case 51:
                if (i5 != 1) {
                    return i;
                }
                objValueOf = Double.valueOf(zzbk.zzc(bArr, i));
                unsafe.putObject(t, j, objValueOf);
                iZzb = i + 8;
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 52:
                if (i5 != 5) {
                    return i;
                }
                objValueOf2 = Float.valueOf(zzbk.zzd(bArr, i));
                unsafe.putObject(t, j, objValueOf2);
                iZzb = i + 4;
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 53:
            case 54:
                if (i5 != 0) {
                    return i;
                }
                iZzb = zzbk.zzb(bArr, i, zzblVar);
                jZza = zzblVar.zzgp;
                objValueOf3 = Long.valueOf(jZza);
                unsafe.putObject(t, j, objValueOf3);
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 55:
            case 62:
                if (i5 != 0) {
                    return i;
                }
                iZzb = zzbk.zza(bArr, i, zzblVar);
                iZzo = zzblVar.zzgo;
                objValueOf3 = Integer.valueOf(iZzo);
                unsafe.putObject(t, j, objValueOf3);
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 56:
            case 65:
                if (i5 != 1) {
                    return i;
                }
                objValueOf = Long.valueOf(zzbk.zzb(bArr, i));
                unsafe.putObject(t, j, objValueOf);
                iZzb = i + 8;
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 57:
            case 64:
                if (i5 != 5) {
                    return i;
                }
                objValueOf2 = Integer.valueOf(zzbk.zza(bArr, i));
                unsafe.putObject(t, j, objValueOf2);
                iZzb = i + 4;
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 58:
                if (i5 != 0) {
                    return i;
                }
                iZzb = zzbk.zzb(bArr, i, zzblVar);
                objValueOf3 = Boolean.valueOf(zzblVar.zzgp != 0);
                unsafe.putObject(t, j, objValueOf3);
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 59:
                if (i5 != 2) {
                    return i;
                }
                iZzb = zzbk.zza(bArr, i, zzblVar);
                i9 = zzblVar.zzgo;
                if (i9 == 0) {
                    objValueOf3 = "";
                    unsafe.putObject(t, j, objValueOf3);
                    unsafe.putInt(t, j2, i4);
                    return iZzb;
                }
                if ((i6 & 536870912) != 0 && !zzfn.zze(bArr, iZzb, iZzb + i9)) {
                    throw zzcx.zzcg();
                }
                unsafe.putObject(t, j, new String(bArr, iZzb, i9, zzct.UTF_8));
                iZzb += i9;
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 60:
                if (i5 != 2) {
                    return i;
                }
                iZzb = zza(zzag(i8), bArr, i, i2, zzblVar);
                Object object = unsafe.getInt(t, j2) == i4 ? unsafe.getObject(t, j) : null;
                objValueOf3 = zzblVar.zzgq;
                if (object != null) {
                    objValueOf3 = zzct.zza(object, objValueOf3);
                }
                unsafe.putObject(t, j, objValueOf3);
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 61:
                if (i5 != 2) {
                    return i;
                }
                iZzb = zzbk.zza(bArr, i, zzblVar);
                i9 = zzblVar.zzgo;
                if (i9 == 0) {
                    objValueOf3 = zzbo.zzgt;
                    unsafe.putObject(t, j, objValueOf3);
                    unsafe.putInt(t, j2, i4);
                    return iZzb;
                }
                unsafe.putObject(t, j, zzbo.zzb(bArr, iZzb, i9));
                iZzb += i9;
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 63:
                if (i5 != 0) {
                    return i;
                }
                int iZza = zzbk.zza(bArr, i, zzblVar);
                int i10 = zzblVar.zzgo;
                zzcv<?> zzcvVarZzai = zzai(i8);
                if (zzcvVarZzai != null && zzcvVarZzai.zzaf(i10) == null) {
                    zzo(t).zzb(i3, Long.valueOf(i10));
                    return iZza;
                }
                unsafe.putObject(t, j, Integer.valueOf(i10));
                iZzb = iZza;
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 66:
                if (i5 != 0) {
                    return i;
                }
                iZzb = zzbk.zza(bArr, i, zzblVar);
                iZzo = zzbx.zzo(zzblVar.zzgo);
                objValueOf3 = Integer.valueOf(iZzo);
                unsafe.putObject(t, j, objValueOf3);
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 67:
                if (i5 != 0) {
                    return i;
                }
                iZzb = zzbk.zzb(bArr, i, zzblVar);
                jZza = zzbx.zza(zzblVar.zzgp);
                objValueOf3 = Long.valueOf(jZza);
                unsafe.putObject(t, j, objValueOf3);
                unsafe.putInt(t, j2, i4);
                return iZzb;
            case 68:
                if (i5 != 3) {
                    return i;
                }
                iZzb = zza(zzag(i8), bArr, i, i2, (i3 & (-8)) | 4, zzblVar);
                Object object2 = unsafe.getInt(t, j2) == i4 ? unsafe.getObject(t, j) : null;
                objValueOf3 = zzblVar.zzgq;
                if (object2 != null) {
                    objValueOf3 = zzct.zza(object2, objValueOf3);
                }
                unsafe.putObject(t, j, objValueOf3);
                unsafe.putInt(t, j2, i4);
                return iZzb;
            default:
                return i;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x025c, code lost:
    
        if (r30.zzgp != 0) goto L143;
     */
    /* JADX WARN: Code restructure failed: missing block: B:143:0x025e, code lost:
    
        r6 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x0260, code lost:
    
        r6 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x0261, code lost:
    
        r11.addBoolean(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x0264, code lost:
    
        if (r4 >= r20) goto L266;
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x0266, code lost:
    
        r6 = com.google.android.gms.internal.vision.zzbk.zza(r18, r4, r30);
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x026c, code lost:
    
        if (r21 != r30.zzgo) goto L267;
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x026e, code lost:
    
        r4 = com.google.android.gms.internal.vision.zzbk.zzb(r18, r6, r30);
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x0276, code lost:
    
        if (r30.zzgp == 0) goto L144;
     */
    /* JADX WARN: Code restructure failed: missing block: B:233:0x014c, code lost:
    
        r11.add(com.google.android.gms.internal.vision.zzbo.zzb(r18, r1, r4));
        r1 = r1 + r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:236:0x0261, code lost:
    
        r6 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:301:?, code lost:
    
        return r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:302:?, code lost:
    
        return r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x013c, code lost:
    
        if (r4 == 0) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x013e, code lost:
    
        r11.add(com.google.android.gms.internal.vision.zzbo.zzgt);
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0144, code lost:
    
        r11.add(com.google.android.gms.internal.vision.zzbo.zzb(r18, r1, r4));
        r1 = r1 + r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x014c, code lost:
    
        if (r1 >= r20) goto L247;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x014e, code lost:
    
        r4 = com.google.android.gms.internal.vision.zzbk.zza(r18, r1, r30);
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0154, code lost:
    
        if (r21 != r30.zzgo) goto L248;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0156, code lost:
    
        r1 = com.google.android.gms.internal.vision.zzbk.zza(r18, r4, r30);
        r4 = r30.zzgo;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x015c, code lost:
    
        if (r4 < 0) goto L249;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x015e, code lost:
    
        if (r4 != 0) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0165, code lost:
    
        throw com.google.android.gms.internal.vision.zzcx.zzcc();
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:110:0x01f1  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x01ad  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:114:0x0201 -> B:104:0x01d8). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:150:0x0276 -> B:143:0x025e). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:72:0x015e -> B:65:0x013e). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:94:0x01bd -> B:86:0x019c). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final int zza(T r17, byte[] r18, int r19, int r20, int r21, int r22, int r23, int r24, long r25, int r27, long r28, com.google.android.gms.internal.vision.zzbl r30) throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 1036
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zza(java.lang.Object, byte[], int, int, int, int, int, int, long, int, long, com.google.android.gms.internal.vision.zzbl):int");
    }

    private final <K, V> int zza(T t, byte[] bArr, int i, int i2, int i3, long j, zzbl zzblVar) throws IOException {
        Unsafe unsafe = zznd;
        Object objZzah = zzah(i3);
        Object object = unsafe.getObject(t, j);
        if (this.zznu.zzj(object)) {
            Object objZzl = this.zznu.zzl(objZzah);
            this.zznu.zzb(objZzl, object);
            unsafe.putObject(t, j, objZzl);
            object = objZzl;
        }
        zzdq<?, ?> zzdqVarZzm = this.zznu.zzm(objZzah);
        Map<?, ?> mapZzh = this.zznu.zzh(object);
        int iZza = zzbk.zza(bArr, i, zzblVar);
        int i4 = zzblVar.zzgo;
        if (i4 < 0 || i4 > i2 - iZza) {
            throw zzcx.zzcb();
        }
        int i5 = i4 + iZza;
        K k = zzdqVarZzm.zzmx;
        V v = zzdqVarZzm.zzew;
        while (iZza < i5) {
            int iZza2 = iZza + 1;
            int i6 = bArr[iZza];
            if (i6 < 0) {
                iZza2 = zzbk.zza(i6, bArr, iZza2, zzblVar);
                i6 = zzblVar.zzgo;
            }
            int i7 = iZza2;
            int i8 = i6 >>> 3;
            int i9 = i6 & 7;
            if (i8 != 1) {
                if (i8 == 2 && i9 == zzdqVarZzm.zzmy.zzee()) {
                    iZza = zza(bArr, i7, i2, zzdqVarZzm.zzmy, zzdqVarZzm.zzew.getClass(), zzblVar);
                    v = zzblVar.zzgq;
                } else {
                    iZza = zzbk.zza(i6, bArr, i7, i2, zzblVar);
                }
            } else if (i9 == zzdqVarZzm.zzmw.zzee()) {
                iZza = zza(bArr, i7, i2, zzdqVarZzm.zzmw, (Class<?>) null, zzblVar);
                k = (K) zzblVar.zzgq;
            } else {
                iZza = zzbk.zza(i6, bArr, i7, i2, zzblVar);
            }
        }
        if (iZza != i5) {
            throw zzcx.zzcf();
        }
        mapZzh.put(k, v);
        return i5;
    }

    /* JADX WARN: Failed to find 'out' block for switch in B:24:0x007f. Please report as an issue. */
    private final int zza(T t, byte[] bArr, int i, int i2, int i3, zzbl zzblVar) throws IOException {
        Unsafe unsafe;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        T t2;
        zzcv<?> zzcvVarZzai;
        int i9;
        int iZza;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        zzbl zzblVar2;
        zzbl zzblVar3;
        long j;
        int iZzb;
        long jZza;
        long j2;
        int iZzo;
        long j3;
        Object objZza;
        int i16;
        int i17;
        int i18;
        int i19;
        zzeb<T> zzebVar = this;
        T t3 = t;
        byte[] bArr2 = bArr;
        int i20 = i2;
        int i21 = i3;
        zzbl zzblVar4 = zzblVar;
        Unsafe unsafe2 = zznd;
        int iZza2 = i;
        int i22 = -1;
        int i23 = 0;
        int i24 = 0;
        int i25 = 0;
        int i26 = -1;
        while (true) {
            if (iZza2 < i20) {
                int i27 = iZza2 + 1;
                byte b = bArr2[iZza2];
                if (b < 0) {
                    iZza = zzbk.zza(b, bArr2, i27, zzblVar4);
                    i9 = zzblVar4.zzgo;
                } else {
                    i9 = b;
                    iZza = i27;
                }
                int i28 = i9 >>> 3;
                int i29 = i9 & 7;
                int iZzr = i28 > i22 ? zzebVar.zzr(i28, i23 / 3) : zzebVar.zzal(i28);
                if (iZzr == -1) {
                    i10 = i28;
                    i11 = iZza;
                    i6 = i9;
                    unsafe = unsafe2;
                    i4 = i21;
                    i12 = 0;
                } else {
                    int[] iArr = zzebVar.zzne;
                    int i30 = iArr[iZzr + 1];
                    int i31 = (i30 & 267386880) >>> 20;
                    int i32 = i9;
                    long j4 = i30 & 1048575;
                    if (i31 <= 17) {
                        int i33 = iArr[iZzr + 2];
                        int i34 = 1 << (i33 >>> 20);
                        int i35 = i33 & 1048575;
                        if (i35 != i26) {
                            if (i26 != -1) {
                                unsafe2.putInt(t3, i26, i25);
                            }
                            i25 = unsafe2.getInt(t3, i35);
                            i26 = i35;
                        }
                        switch (i31) {
                            case 0:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                i15 = i32;
                                bArr2 = bArr;
                                i14 = iZza;
                                if (i29 == 1) {
                                    zzfl.zza(t3, j4, zzbk.zzc(bArr2, i14));
                                    iZza2 = i14 + 8;
                                    i25 |= i34;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 1:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                i15 = i32;
                                bArr2 = bArr;
                                i14 = iZza;
                                if (i29 == 5) {
                                    zzfl.zza((Object) t3, j4, zzbk.zzd(bArr2, i14));
                                    iZza2 = i14 + 4;
                                    i25 |= i34;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 2:
                            case 3:
                                zzblVar3 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                j = j4;
                                i15 = i32;
                                bArr2 = bArr;
                                i14 = iZza;
                                if (i29 == 0) {
                                    iZzb = zzbk.zzb(bArr2, i14, zzblVar3);
                                    jZza = zzblVar3.zzgp;
                                    unsafe2.putLong(t, j, jZza);
                                    i25 |= i34;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar3;
                                    iZza2 = iZzb;
                                    i22 = i10;
                                    i20 = i2;
                                    i21 = i3;
                                } else {
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 4:
                            case 11:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                j2 = j4;
                                i15 = i32;
                                bArr2 = bArr;
                                i14 = iZza;
                                if (i29 == 0) {
                                    iZza2 = zzbk.zza(bArr2, i14, zzblVar2);
                                    iZzo = zzblVar2.zzgo;
                                    unsafe2.putInt(t3, j2, iZzo);
                                    i25 |= i34;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 5:
                            case 14:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                i15 = i32;
                                bArr2 = bArr;
                                if (i29 == 1) {
                                    i14 = iZza;
                                    unsafe2.putLong(t, j4, zzbk.zzb(bArr2, iZza));
                                    iZza2 = i14 + 8;
                                    i25 |= i34;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 6:
                            case 13:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                i15 = i32;
                                bArr2 = bArr;
                                i20 = i2;
                                if (i29 == 5) {
                                    unsafe2.putInt(t3, j4, zzbk.zza(bArr2, iZza));
                                    iZza2 = iZza + 4;
                                    i25 |= i34;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 7:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                i15 = i32;
                                bArr2 = bArr;
                                i20 = i2;
                                if (i29 == 0) {
                                    iZza2 = zzbk.zzb(bArr2, iZza, zzblVar2);
                                    zzfl.zza(t3, j4, zzblVar2.zzgp != 0);
                                    i25 |= i34;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 8:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                j3 = j4;
                                i15 = i32;
                                bArr2 = bArr;
                                i20 = i2;
                                if (i29 == 2) {
                                    iZza2 = (i30 & 536870912) == 0 ? zzbk.zzc(bArr2, iZza, zzblVar2) : zzbk.zzd(bArr2, iZza, zzblVar2);
                                    objZza = zzblVar2.zzgq;
                                    unsafe2.putObject(t3, j3, objZza);
                                    i25 |= i34;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 9:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                j3 = j4;
                                i15 = i32;
                                bArr2 = bArr;
                                if (i29 == 2) {
                                    i20 = i2;
                                    iZza2 = zza(zzebVar.zzag(i13), bArr2, iZza, i20, zzblVar2);
                                    objZza = (i25 & i34) == 0 ? zzblVar2.zzgq : zzct.zza(unsafe2.getObject(t3, j3), zzblVar2.zzgq);
                                    unsafe2.putObject(t3, j3, objZza);
                                    i25 |= i34;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 10:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                i15 = i32;
                                bArr2 = bArr;
                                if (i29 == 2) {
                                    iZza2 = zzbk.zze(bArr2, iZza, zzblVar2);
                                    unsafe2.putObject(t3, j4, zzblVar2.zzgq);
                                    i25 |= i34;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 12:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                j2 = j4;
                                i15 = i32;
                                bArr2 = bArr;
                                if (i29 == 0) {
                                    iZza2 = zzbk.zza(bArr2, iZza, zzblVar2);
                                    iZzo = zzblVar2.zzgo;
                                    zzcv<?> zzcvVarZzai2 = zzebVar.zzai(i13);
                                    if (zzcvVarZzai2 != null && zzcvVarZzai2.zzaf(iZzo) == null) {
                                        zzo(t).zzb(i15, Long.valueOf(iZzo));
                                        i20 = i2;
                                        i24 = i15;
                                        i23 = i13;
                                        zzblVar4 = zzblVar2;
                                        i22 = i10;
                                        i21 = i3;
                                    }
                                    unsafe2.putInt(t3, j2, iZzo);
                                    i25 |= i34;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 15:
                                zzblVar2 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                j2 = j4;
                                i15 = i32;
                                bArr2 = bArr;
                                if (i29 == 0) {
                                    iZza2 = zzbk.zza(bArr2, iZza, zzblVar2);
                                    iZzo = zzbx.zzo(zzblVar2.zzgo);
                                    unsafe2.putInt(t3, j2, iZzo);
                                    i25 |= i34;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 16:
                                zzblVar3 = zzblVar;
                                i13 = iZzr;
                                i10 = i28;
                                i15 = i32;
                                if (i29 == 0) {
                                    j = j4;
                                    bArr2 = bArr;
                                    iZzb = zzbk.zzb(bArr2, iZza, zzblVar3);
                                    jZza = zzbx.zza(zzblVar3.zzgp);
                                    unsafe2.putLong(t, j, jZza);
                                    i25 |= i34;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar3;
                                    iZza2 = iZzb;
                                    i22 = i10;
                                    i20 = i2;
                                    i21 = i3;
                                } else {
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            case 17:
                                if (i29 == 3) {
                                    i13 = iZzr;
                                    i10 = i28;
                                    i15 = i32;
                                    iZza2 = zza(zzebVar.zzag(iZzr), bArr, iZza, i2, (i28 << 3) | 4, zzblVar);
                                    zzblVar2 = zzblVar;
                                    unsafe2.putObject(t3, j4, (i25 & i34) == 0 ? zzblVar2.zzgq : zzct.zza(unsafe2.getObject(t3, j4), zzblVar2.zzgq));
                                    i25 |= i34;
                                    bArr2 = bArr;
                                    i20 = i2;
                                    i24 = i15;
                                    i23 = i13;
                                    zzblVar4 = zzblVar2;
                                    i22 = i10;
                                    i21 = i3;
                                } else {
                                    i13 = iZzr;
                                    i10 = i28;
                                    i15 = i32;
                                    i14 = iZza;
                                    i12 = i13;
                                    unsafe = unsafe2;
                                    i11 = i14;
                                    i6 = i15;
                                    i4 = i3;
                                }
                                break;
                            default:
                                i13 = iZzr;
                                i10 = i28;
                                i14 = iZza;
                                i15 = i32;
                                i12 = i13;
                                unsafe = unsafe2;
                                i11 = i14;
                                i6 = i15;
                                i4 = i3;
                                break;
                        }
                    } else {
                        i10 = i28;
                        bArr2 = bArr;
                        int i36 = iZza;
                        if (i31 != 27) {
                            i16 = i25;
                            if (i31 <= 49) {
                                i17 = i26;
                                i18 = i32;
                                i12 = iZzr;
                                unsafe = unsafe2;
                                iZza2 = zza(t, bArr, i36, i2, i32, i10, i29, iZzr, i30, i31, j4, zzblVar);
                                if (iZza2 == i36) {
                                    i4 = i3;
                                    i11 = iZza2;
                                    i25 = i16;
                                    i26 = i17;
                                    i6 = i18;
                                } else {
                                    zzebVar = this;
                                    t3 = t;
                                    bArr2 = bArr;
                                    i20 = i2;
                                    i21 = i3;
                                    zzblVar4 = zzblVar;
                                    i25 = i16;
                                    i23 = i12;
                                    i26 = i17;
                                    i22 = i10;
                                    i24 = i18;
                                    unsafe2 = unsafe;
                                }
                            } else {
                                i17 = i26;
                                i18 = i32;
                                i12 = iZzr;
                                unsafe = unsafe2;
                                i19 = i36;
                                if (i31 != 50) {
                                    iZza2 = zza(t, bArr, i19, i2, i18, i10, i29, i30, i31, j4, i12, zzblVar);
                                    if (iZza2 != i19) {
                                        zzebVar = this;
                                        t3 = t;
                                        bArr2 = bArr;
                                        i20 = i2;
                                        i21 = i3;
                                        i24 = i18;
                                        i25 = i16;
                                        i23 = i12;
                                        i26 = i17;
                                        i22 = i10;
                                        unsafe2 = unsafe;
                                    }
                                } else if (i29 == 2) {
                                    iZza2 = zza(t, bArr, i19, i2, i12, j4, zzblVar);
                                    if (iZza2 != i19) {
                                        zzebVar = this;
                                        t3 = t;
                                        bArr2 = bArr;
                                        i20 = i2;
                                        i21 = i3;
                                        zzblVar4 = zzblVar;
                                        i25 = i16;
                                        i23 = i12;
                                        i26 = i17;
                                        i22 = i10;
                                        i24 = i18;
                                        unsafe2 = unsafe;
                                    }
                                }
                                i4 = i3;
                                i11 = iZza2;
                                i25 = i16;
                                i26 = i17;
                                i6 = i18;
                            }
                        } else if (i29 == 2) {
                            zzcw zzcwVarZzk = (zzcw) unsafe2.getObject(t3, j4);
                            if (!zzcwVarZzk.zzan()) {
                                int size = zzcwVarZzk.size();
                                zzcwVarZzk = zzcwVarZzk.zzk(size == 0 ? 10 : size << 1);
                                unsafe2.putObject(t3, j4, zzcwVarZzk);
                            }
                            iZza2 = zza((zzen<?>) zzebVar.zzag(iZzr), i32, bArr, i36, i2, (zzcw<?>) zzcwVarZzk, zzblVar);
                            i20 = i2;
                            i21 = i3;
                            i24 = i32;
                            i23 = iZzr;
                            i25 = i25;
                            i22 = i10;
                        } else {
                            i16 = i25;
                            i17 = i26;
                            i18 = i32;
                            i12 = iZzr;
                            unsafe = unsafe2;
                            i19 = i36;
                        }
                        i4 = i3;
                        i11 = i19;
                        i25 = i16;
                        i26 = i17;
                        i6 = i18;
                    }
                    zzblVar4 = zzblVar;
                }
                if (i6 != i4 || i4 == 0) {
                    iZza2 = zza(i6, bArr, i11, i2, t, zzblVar);
                    zzebVar = this;
                    t3 = t;
                    bArr2 = bArr;
                    i20 = i2;
                    i21 = i4;
                    i24 = i6;
                    i23 = i12;
                    i22 = i10;
                    unsafe2 = unsafe;
                    zzblVar4 = zzblVar;
                } else {
                    i7 = i26;
                    i8 = -1;
                    i5 = i11;
                }
            } else {
                int i37 = i26;
                unsafe = unsafe2;
                i4 = i21;
                i5 = iZza2;
                i6 = i24;
                i7 = i37;
                i8 = -1;
            }
        }
        if (i7 != i8) {
            t2 = t;
            unsafe.putInt(t2, i7, i25);
        } else {
            t2 = t;
        }
        Object objZza2 = null;
        for (int i38 = this.zzno; i38 < this.zznp; i38++) {
            int i39 = this.zznn[i38];
            zzff zzffVar = this.zzns;
            int i40 = this.zzne[i39];
            Object objZzo = zzfl.zzo(t2, zzaj(i39) & 1048575);
            if (objZzo != null && (zzcvVarZzai = zzai(i39)) != null) {
                objZza2 = zza(i39, i40, this.zznu.zzh(objZzo), zzcvVarZzai, objZza2, (zzff<UT, Object>) zzffVar);
            }
            objZza2 = (zzfg) objZza2;
        }
        if (objZza2 != null) {
            this.zzns.zzf(t2, objZza2);
        }
        if (i4 == 0) {
            if (i5 != i2) {
                throw zzcx.zzcf();
            }
        } else if (i5 > i2 || i6 != i4) {
            throw zzcx.zzcf();
        }
        return i5;
    }

    private static int zza(byte[] bArr, int i, int i2, zzft zzftVar, Class<?> cls, zzbl zzblVar) throws IOException {
        int iZzb;
        Object objValueOf;
        Object objValueOf2;
        Object objValueOf3;
        int iZzo;
        long jZza;
        switch (zzec.zzhz[zzftVar.ordinal()]) {
            case 1:
                iZzb = zzbk.zzb(bArr, i, zzblVar);
                objValueOf = Boolean.valueOf(zzblVar.zzgp != 0);
                zzblVar.zzgq = objValueOf;
                return iZzb;
            case 2:
                return zzbk.zze(bArr, i, zzblVar);
            case 3:
                objValueOf2 = Double.valueOf(zzbk.zzc(bArr, i));
                zzblVar.zzgq = objValueOf2;
                return i + 8;
            case 4:
            case 5:
                objValueOf3 = Integer.valueOf(zzbk.zza(bArr, i));
                zzblVar.zzgq = objValueOf3;
                return i + 4;
            case 6:
            case 7:
                objValueOf2 = Long.valueOf(zzbk.zzb(bArr, i));
                zzblVar.zzgq = objValueOf2;
                return i + 8;
            case 8:
                objValueOf3 = Float.valueOf(zzbk.zzd(bArr, i));
                zzblVar.zzgq = objValueOf3;
                return i + 4;
            case 9:
            case 10:
            case 11:
                iZzb = zzbk.zza(bArr, i, zzblVar);
                iZzo = zzblVar.zzgo;
                objValueOf = Integer.valueOf(iZzo);
                zzblVar.zzgq = objValueOf;
                return iZzb;
            case 12:
            case 13:
                iZzb = zzbk.zzb(bArr, i, zzblVar);
                jZza = zzblVar.zzgp;
                objValueOf = Long.valueOf(jZza);
                zzblVar.zzgq = objValueOf;
                return iZzb;
            case 14:
                return zza((zzen) zzek.zzdc().zze(cls), bArr, i, i2, zzblVar);
            case 15:
                iZzb = zzbk.zza(bArr, i, zzblVar);
                iZzo = zzbx.zzo(zzblVar.zzgo);
                objValueOf = Integer.valueOf(iZzo);
                zzblVar.zzgq = objValueOf;
                return iZzb;
            case 16:
                iZzb = zzbk.zzb(bArr, i, zzblVar);
                jZza = zzbx.zza(zzblVar.zzgp);
                objValueOf = Long.valueOf(jZza);
                zzblVar.zzgq = objValueOf;
                return iZzb;
            case 17:
                return zzbk.zzd(bArr, i, zzblVar);
            default:
                throw new RuntimeException("unsupported field type.");
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:169:0x03a0  */
    /* JADX WARN: Removed duplicated region for block: B:192:0x041f  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x0422  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x0427  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x042a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static <T> com.google.android.gms.internal.vision.zzeb<T> zza(java.lang.Class<T> r33, com.google.android.gms.internal.vision.zzdv r34, com.google.android.gms.internal.vision.zzef r35, com.google.android.gms.internal.vision.zzdh r36, com.google.android.gms.internal.vision.zzff<?, ?> r37, com.google.android.gms.internal.vision.zzcg<?> r38, com.google.android.gms.internal.vision.zzds r39) {
        /*
            Method dump skipped, instruction units count: 1152
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zza(java.lang.Class, com.google.android.gms.internal.vision.zzdv, com.google.android.gms.internal.vision.zzef, com.google.android.gms.internal.vision.zzdh, com.google.android.gms.internal.vision.zzff, com.google.android.gms.internal.vision.zzcg, com.google.android.gms.internal.vision.zzds):com.google.android.gms.internal.vision.zzeb");
    }

    private final <K, V, UT, UB> UB zza(int i, int i2, Map<K, V> map, zzcv<?> zzcvVar, UB ub, zzff<UT, UB> zzffVar) {
        zzdq<?, ?> zzdqVarZzm = this.zznu.zzm(zzah(i));
        Iterator<Map.Entry<K, V>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<K, V> next = it.next();
            if (zzcvVar.zzaf(((Integer) next.getValue()).intValue()) == null) {
                if (ub == null) {
                    ub = zzffVar.zzdt();
                }
                zzbt zzbtVarZzm = zzbo.zzm(zzdp.zza(zzdqVarZzm, next.getKey(), next.getValue()));
                try {
                    zzdp.zza(zzbtVarZzm.zzax(), zzdqVarZzm, next.getKey(), next.getValue());
                    zzffVar.zza(ub, i2, zzbtVarZzm.zzaw());
                    it.remove();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return ub;
    }

    private static Field zza(Class<?> cls, String str) {
        try {
            return cls.getDeclaredField(str);
        } catch (NoSuchFieldException e) {
            Field[] declaredFields = cls.getDeclaredFields();
            for (Field field : declaredFields) {
                if (str.equals(field.getName())) {
                    return field;
                }
            }
            String name = cls.getName();
            String string = Arrays.toString(declaredFields);
            StringBuilder sb = new StringBuilder(String.valueOf(str).length() + 40 + String.valueOf(name).length() + String.valueOf(string).length());
            sb.append("Field ");
            sb.append(str);
            sb.append(" for ");
            sb.append(name);
            sb.append(" not found. Known fields are ");
            sb.append(string);
            throw new RuntimeException(sb.toString());
        }
    }

    private static void zza(int i, Object obj, zzfz zzfzVar) throws IOException {
        if (obj instanceof String) {
            zzfzVar.zza(i, (String) obj);
        } else {
            zzfzVar.zza(i, (zzbo) obj);
        }
    }

    private static <UT, UB> void zza(zzff<UT, UB> zzffVar, T t, zzfz zzfzVar) throws IOException {
        zzffVar.zza(zzffVar.zzr(t), zzfzVar);
    }

    private final <K, V> void zza(zzfz zzfzVar, int i, Object obj, int i2) throws IOException {
        if (obj != null) {
            zzfzVar.zza(i, this.zznu.zzm(zzah(i2)), this.zznu.zzi(obj));
        }
    }

    private final void zza(T t, T t2, int i) {
        long jZzaj = zzaj(i) & 1048575;
        if (zza(t2, i)) {
            Object objZzo = zzfl.zzo(t, jZzaj);
            Object objZzo2 = zzfl.zzo(t2, jZzaj);
            if (objZzo != null && objZzo2 != null) {
                zzfl.zza(t, jZzaj, zzct.zza(objZzo, objZzo2));
                zzb(t, i);
            } else if (objZzo2 != null) {
                zzfl.zza(t, jZzaj, objZzo2);
                zzb(t, i);
            }
        }
    }

    private final boolean zza(T t, int i) {
        if (!this.zznl) {
            int iZzak = zzak(i);
            return (zzfl.zzj(t, (long) (iZzak & 1048575)) & (1 << (iZzak >>> 20))) != 0;
        }
        int iZzaj = zzaj(i);
        long j = iZzaj & 1048575;
        switch ((iZzaj & 267386880) >>> 20) {
            case 0:
                return zzfl.zzn(t, j) != FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
            case 1:
                return zzfl.zzm(t, j) != 0.0f;
            case 2:
                return zzfl.zzk(t, j) != 0;
            case 3:
                return zzfl.zzk(t, j) != 0;
            case 4:
                return zzfl.zzj(t, j) != 0;
            case 5:
                return zzfl.zzk(t, j) != 0;
            case 6:
                return zzfl.zzj(t, j) != 0;
            case 7:
                return zzfl.zzl(t, j);
            case 8:
                Object objZzo = zzfl.zzo(t, j);
                if (objZzo instanceof String) {
                    return !((String) objZzo).isEmpty();
                }
                if (objZzo instanceof zzbo) {
                    return !zzbo.zzgt.equals(objZzo);
                }
                throw new IllegalArgumentException();
            case 9:
                return zzfl.zzo(t, j) != null;
            case 10:
                return !zzbo.zzgt.equals(zzfl.zzo(t, j));
            case 11:
                return zzfl.zzj(t, j) != 0;
            case 12:
                return zzfl.zzj(t, j) != 0;
            case 13:
                return zzfl.zzj(t, j) != 0;
            case 14:
                return zzfl.zzk(t, j) != 0;
            case 15:
                return zzfl.zzj(t, j) != 0;
            case 16:
                return zzfl.zzk(t, j) != 0;
            case 17:
                return zzfl.zzo(t, j) != null;
            default:
                throw new IllegalArgumentException();
        }
    }

    private final boolean zza(T t, int i, int i2) {
        return zzfl.zzj(t, (long) (zzak(i2) & 1048575)) == i;
    }

    private final boolean zza(T t, int i, int i2, int i3) {
        return this.zznl ? zza(t, i) : (i2 & i3) != 0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static boolean zza(Object obj, int i, zzen zzenVar) {
        return zzenVar.zzp(zzfl.zzo(obj, i & 1048575));
    }

    private final zzen zzag(int i) {
        int i2 = (i / 3) << 1;
        zzen zzenVar = (zzen) this.zznf[i2];
        if (zzenVar != null) {
            return zzenVar;
        }
        zzen<T> zzenVarZze = zzek.zzdc().zze((Class) this.zznf[i2 + 1]);
        this.zznf[i2] = zzenVarZze;
        return zzenVarZze;
    }

    private final Object zzah(int i) {
        return this.zznf[(i / 3) << 1];
    }

    private final zzcv<?> zzai(int i) {
        return (zzcv) this.zznf[((i / 3) << 1) + 1];
    }

    private final int zzaj(int i) {
        return this.zzne[i + 1];
    }

    private final int zzak(int i) {
        return this.zzne[i + 2];
    }

    private final int zzal(int i) {
        if (i < this.zzng || i > this.zznh) {
            return -1;
        }
        return zzs(i, 0);
    }

    private final void zzb(T t, int i) {
        if (this.zznl) {
            return;
        }
        int iZzak = zzak(i);
        long j = iZzak & 1048575;
        zzfl.zza((Object) t, j, zzfl.zzj(t, j) | (1 << (iZzak >>> 20)));
    }

    private final void zzb(T t, int i, int i2) {
        zzfl.zza((Object) t, zzak(i2) & 1048575, i);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0021  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void zzb(T r19, com.google.android.gms.internal.vision.zzfz r20) throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 1342
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zzb(java.lang.Object, com.google.android.gms.internal.vision.zzfz):void");
    }

    private final void zzb(T t, T t2, int i) {
        int iZzaj = zzaj(i);
        int i2 = this.zzne[i];
        long j = iZzaj & 1048575;
        if (zza(t2, i2, i)) {
            Object objZzo = zzfl.zzo(t, j);
            Object objZzo2 = zzfl.zzo(t2, j);
            if (objZzo != null && objZzo2 != null) {
                zzfl.zza(t, j, zzct.zza(objZzo, objZzo2));
                zzb(t, i2, i);
            } else if (objZzo2 != null) {
                zzfl.zza(t, j, objZzo2);
                zzb(t, i2, i);
            }
        }
    }

    private final boolean zzc(T t, T t2, int i) {
        return zza(t, i) == zza(t2, i);
    }

    private static <E> List<E> zzd(Object obj, long j) {
        return (List) zzfl.zzo(obj, j);
    }

    private static <T> double zze(T t, long j) {
        return ((Double) zzfl.zzo(t, j)).doubleValue();
    }

    private static <T> float zzf(T t, long j) {
        return ((Float) zzfl.zzo(t, j)).floatValue();
    }

    private static <T> int zzg(T t, long j) {
        return ((Integer) zzfl.zzo(t, j)).intValue();
    }

    private static <T> long zzh(T t, long j) {
        return ((Long) zzfl.zzo(t, j)).longValue();
    }

    private static <T> boolean zzi(T t, long j) {
        return ((Boolean) zzfl.zzo(t, j)).booleanValue();
    }

    private static zzfg zzo(Object obj) {
        zzcr zzcrVar = (zzcr) obj;
        zzfg zzfgVar = zzcrVar.zzkr;
        if (zzfgVar != zzfg.zzdu()) {
            return zzfgVar;
        }
        zzfg zzfgVarZzdv = zzfg.zzdv();
        zzcrVar.zzkr = zzfgVarZzdv;
        return zzfgVarZzdv;
    }

    private final int zzr(int i, int i2) {
        if (i < this.zzng || i > this.zznh) {
            return -1;
        }
        return zzs(i, i2);
    }

    private final int zzs(int i, int i2) {
        int length = (this.zzne.length / 3) - 1;
        while (i2 <= length) {
            int i3 = (length + i2) >>> 1;
            int i4 = i3 * 3;
            int i5 = this.zzne[i4];
            if (i == i5) {
                return i4;
            }
            if (i < i5) {
                length = i3 - 1;
            } else {
                i2 = i3 + 1;
            }
        }
        return -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:103:0x01a2  */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean equals(T r10, T r11) {
        /*
            Method dump skipped, instruction units count: 610
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.equals(java.lang.Object, java.lang.Object):boolean");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00e2 A[PHI: r3
      0x00e2: PHI (r3v13 java.lang.Object) = (r3v11 java.lang.Object), (r3v14 java.lang.Object) binds: [B:67:0x00e0, B:62:0x00ce] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int hashCode(T r9) {
        /*
            Method dump skipped, instruction units count: 476
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.hashCode(java.lang.Object):int");
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final T newInstance() {
        return (T) this.zznq.newInstance(this.zzni);
    }

    /* JADX WARN: Removed duplicated region for block: B:112:0x0385  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0400  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0413  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0428  */
    /* JADX WARN: Removed duplicated region for block: B:192:0x04ee  */
    /* JADX WARN: Removed duplicated region for block: B:295:0x0842  */
    /* JADX WARN: Removed duplicated region for block: B:322:0x08bd  */
    /* JADX WARN: Removed duplicated region for block: B:325:0x08d0  */
    /* JADX WARN: Removed duplicated region for block: B:328:0x08e5  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0030  */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zza(T r14, com.google.android.gms.internal.vision.zzfz r15) throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 2736
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zza(java.lang.Object, com.google.android.gms.internal.vision.zzfz):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:100:0x01f5, code lost:
    
        if (r0 == r15) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x0212, code lost:
    
        if (r0 == r15) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x0214, code lost:
    
        r2 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0090, code lost:
    
        if (r6 == 0) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x0107, code lost:
    
        if (r6 == 0) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0109, code lost:
    
        r0 = com.google.android.gms.internal.vision.zzbk.zza(r12, r8, r11);
        r1 = r11.zzgo;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x01c8, code lost:
    
        if (r0 == r15) goto L105;
     */
    /* JADX WARN: Failed to find 'out' block for switch in B:20:0x0061. Please report as an issue. */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zza(T r28, byte[] r29, int r30, int r31, com.google.android.gms.internal.vision.zzbl r32) throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 632
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zza(java.lang.Object, byte[], int, int, com.google.android.gms.internal.vision.zzbl):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0031  */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zzc(T r7, T r8) {
        /*
            Method dump skipped, instruction units count: 406
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zzc(java.lang.Object, java.lang.Object):void");
    }

    @Override // com.google.android.gms.internal.vision.zzen
    public final void zzd(T t) {
        int i;
        int i2 = this.zzno;
        while (true) {
            i = this.zznp;
            if (i2 >= i) {
                break;
            }
            long jZzaj = zzaj(this.zznn[i2]) & 1048575;
            Object objZzo = zzfl.zzo(t, jZzaj);
            if (objZzo != null) {
                zzfl.zza(t, jZzaj, this.zznu.zzk(objZzo));
            }
            i2++;
        }
        int length = this.zznn.length;
        while (i < length) {
            this.zznr.zza(t, this.zznn[i]);
            i++;
        }
        this.zzns.zzd(t);
        if (this.zznj) {
            this.zznt.zzd(t);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:248:0x0414, code lost:
    
        if (zza(r20, r15, r5) != false) goto L394;
     */
    /* JADX WARN: Code restructure failed: missing block: B:257:0x0434, code lost:
    
        if (zza(r20, r15, r5) != false) goto L405;
     */
    /* JADX WARN: Code restructure failed: missing block: B:260:0x043c, code lost:
    
        if (zza(r20, r15, r5) != false) goto L408;
     */
    /* JADX WARN: Code restructure failed: missing block: B:269:0x045c, code lost:
    
        if (zza(r20, r15, r5) != false) goto L420;
     */
    /* JADX WARN: Code restructure failed: missing block: B:272:0x0464, code lost:
    
        if (zza(r20, r15, r5) != false) goto L424;
     */
    /* JADX WARN: Code restructure failed: missing block: B:280:0x047c, code lost:
    
        if (zza(r20, r15, r5) != false) goto L433;
     */
    /* JADX WARN: Code restructure failed: missing block: B:393:0x06b4, code lost:
    
        if ((r12 & r18) != 0) goto L394;
     */
    /* JADX WARN: Code restructure failed: missing block: B:394:0x06b6, code lost:
    
        r4 = com.google.android.gms.internal.vision.zzca.zzc(r15, (com.google.android.gms.internal.vision.zzdx) r2.getObject(r20, r10), zzag(r5));
     */
    /* JADX WARN: Code restructure failed: missing block: B:404:0x06e1, code lost:
    
        if ((r12 & r18) != 0) goto L405;
     */
    /* JADX WARN: Code restructure failed: missing block: B:405:0x06e3, code lost:
    
        r4 = com.google.android.gms.internal.vision.zzca.zzh(r15, 0L);
     */
    /* JADX WARN: Code restructure failed: missing block: B:407:0x06ec, code lost:
    
        if ((r12 & r18) != 0) goto L408;
     */
    /* JADX WARN: Code restructure failed: missing block: B:408:0x06ee, code lost:
    
        r9 = com.google.android.gms.internal.vision.zzca.zzm(r15, 0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:419:0x0711, code lost:
    
        if ((r12 & r18) != 0) goto L420;
     */
    /* JADX WARN: Code restructure failed: missing block: B:420:0x0713, code lost:
    
        r4 = r2.getObject(r20, r10);
     */
    /* JADX WARN: Code restructure failed: missing block: B:423:0x0720, code lost:
    
        if ((r12 & r18) != 0) goto L424;
     */
    /* JADX WARN: Code restructure failed: missing block: B:424:0x0722, code lost:
    
        r4 = com.google.android.gms.internal.vision.zzep.zzc(r15, r2.getObject(r20, r10), zzag(r5));
     */
    /* JADX WARN: Code restructure failed: missing block: B:432:0x0747, code lost:
    
        if ((r12 & r18) != 0) goto L433;
     */
    /* JADX WARN: Code restructure failed: missing block: B:433:0x0749, code lost:
    
        r4 = com.google.android.gms.internal.vision.zzca.zzc(r15, true);
     */
    /* JADX WARN: Removed duplicated region for block: B:142:0x020d A[PHI: r5
      0x020d: PHI (r5v71 int) = 
      (r5v34 int)
      (r5v37 int)
      (r5v40 int)
      (r5v43 int)
      (r5v46 int)
      (r5v49 int)
      (r5v52 int)
      (r5v55 int)
      (r5v58 int)
      (r5v61 int)
      (r5v64 int)
      (r5v67 int)
      (r5v70 int)
      (r5v75 int)
     binds: [B:141:0x020b, B:136:0x01fa, B:131:0x01e9, B:126:0x01d8, B:121:0x01c7, B:116:0x01b6, B:111:0x01a5, B:106:0x0193, B:101:0x0181, B:96:0x016f, B:91:0x015d, B:86:0x014b, B:81:0x0139, B:76:0x0127] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:186:0x030a A[PHI: r5
      0x030a: PHI (r5v94 java.lang.Object) = (r5v12 java.lang.Object), (r5v92 java.lang.Object), (r5v96 java.lang.Object) binds: [B:193:0x0331, B:45:0x00ab, B:185:0x0306] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:195:0x0334 A[PHI: r5
      0x0334: PHI (r5v90 java.lang.Object) = (r5v12 java.lang.Object), (r5v92 java.lang.Object) binds: [B:193:0x0331, B:45:0x00ab] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:374:0x05fa A[PHI: r4
      0x05fa: PHI (r4v105 int) = 
      (r4v68 int)
      (r4v71 int)
      (r4v74 int)
      (r4v77 int)
      (r4v80 int)
      (r4v83 int)
      (r4v86 int)
      (r4v89 int)
      (r4v92 int)
      (r4v95 int)
      (r4v98 int)
      (r4v101 int)
      (r4v104 int)
      (r4v109 int)
     binds: [B:373:0x05f8, B:368:0x05e7, B:363:0x05d6, B:358:0x05c5, B:353:0x05b4, B:348:0x05a3, B:343:0x0592, B:338:0x0580, B:333:0x056e, B:328:0x055c, B:323:0x054a, B:318:0x0538, B:313:0x0526, B:308:0x0514] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:390:0x06aa A[PHI: r6
      0x06aa: PHI (r6v4 int) = 
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v13 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v1 int)
      (r6v14 int)
      (r6v1 int)
     binds: [B:245:0x040b, B:435:0x0751, B:432:0x0747, B:426:0x0732, B:423:0x0720, B:419:0x0711, B:415:0x0704, B:411:0x06f7, B:407:0x06ec, B:404:0x06e1, B:400:0x06d4, B:396:0x06c7, B:393:0x06b4, B:371:0x05f4, B:366:0x05e3, B:361:0x05d2, B:356:0x05c1, B:351:0x05b0, B:346:0x059f, B:341:0x058e, B:336:0x057c, B:331:0x056a, B:326:0x0558, B:321:0x0546, B:316:0x0534, B:311:0x0522, B:306:0x0510, B:301:0x04dc, B:298:0x04cf, B:295:0x04bf, B:292:0x04af, B:289:0x049f, B:286:0x0491, B:283:0x0484, B:280:0x047c, B:275:0x046c, B:272:0x0464, B:269:0x045c, B:266:0x0450, B:263:0x0444, B:409:0x06f3, B:260:0x043c, B:257:0x0434, B:254:0x0428, B:251:0x041c, B:389:0x06a9, B:248:0x0414] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:421:0x0717 A[PHI: r4
      0x0717: PHI (r4v140 java.lang.Object) = (r4v14 java.lang.Object), (r4v136 java.lang.Object), (r4v143 java.lang.Object) binds: [B:428:0x073a, B:277:0x0474, B:420:0x0713] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:430:0x073d A[PHI: r4
      0x073d: PHI (r4v132 java.lang.Object) = (r4v14 java.lang.Object), (r4v136 java.lang.Object) binds: [B:428:0x073a, B:277:0x0474] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int zzn(T r20) {
        /*
            Method dump skipped, instruction units count: 2290
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zzn(java.lang.Object):int");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ca  */
    /* JADX WARN: Type inference failed for: r4v12 */
    /* JADX WARN: Type inference failed for: r4v13 */
    /* JADX WARN: Type inference failed for: r4v14, types: [com.google.android.gms.internal.vision.zzen] */
    /* JADX WARN: Type inference failed for: r4v17 */
    /* JADX WARN: Type inference failed for: r4v18 */
    /* JADX WARN: Type inference failed for: r4v5, types: [com.google.android.gms.internal.vision.zzen] */
    @Override // com.google.android.gms.internal.vision.zzen
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean zzp(T r14) {
        /*
            Method dump skipped, instruction units count: 285
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzeb.zzp(java.lang.Object):boolean");
    }
}
