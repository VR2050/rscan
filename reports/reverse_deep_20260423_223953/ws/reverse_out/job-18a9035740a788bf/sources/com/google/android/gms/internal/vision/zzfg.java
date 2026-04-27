package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcr;
import java.io.IOException;
import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public final class zzfg {
    private static final zzfg zzot = new zzfg(0, new int[0], new Object[0], false);
    private int count;
    private boolean zzgl;
    private int zzks;
    private Object[] zznf;
    private int[] zzou;

    private zzfg() {
        this(0, new int[8], new Object[8], true);
    }

    private zzfg(int i, int[] iArr, Object[] objArr, boolean z) {
        this.zzks = -1;
        this.count = i;
        this.zzou = iArr;
        this.zznf = objArr;
        this.zzgl = z;
    }

    static zzfg zza(zzfg zzfgVar, zzfg zzfgVar2) {
        int i = zzfgVar.count + zzfgVar2.count;
        int[] iArrCopyOf = Arrays.copyOf(zzfgVar.zzou, i);
        System.arraycopy(zzfgVar2.zzou, 0, iArrCopyOf, zzfgVar.count, zzfgVar2.count);
        Object[] objArrCopyOf = Arrays.copyOf(zzfgVar.zznf, i);
        System.arraycopy(zzfgVar2.zznf, 0, objArrCopyOf, zzfgVar.count, zzfgVar2.count);
        return new zzfg(i, iArrCopyOf, objArrCopyOf, true);
    }

    private static void zzb(int i, Object obj, zzfz zzfzVar) throws IOException {
        int i2 = i >>> 3;
        int i3 = i & 7;
        if (i3 == 0) {
            zzfzVar.zzi(i2, ((Long) obj).longValue());
            return;
        }
        if (i3 == 1) {
            zzfzVar.zzc(i2, ((Long) obj).longValue());
            return;
        }
        if (i3 == 2) {
            zzfzVar.zza(i2, (zzbo) obj);
            return;
        }
        if (i3 != 3) {
            if (i3 != 5) {
                throw new RuntimeException(zzcx.zzce());
            }
            zzfzVar.zzh(i2, ((Integer) obj).intValue());
        } else if (zzfzVar.zzbc() == zzcr.zzd.zzlj) {
            zzfzVar.zzac(i2);
            ((zzfg) obj).zzb(zzfzVar);
            zzfzVar.zzad(i2);
        } else {
            zzfzVar.zzad(i2);
            ((zzfg) obj).zzb(zzfzVar);
            zzfzVar.zzac(i2);
        }
    }

    public static zzfg zzdu() {
        return zzot;
    }

    static zzfg zzdv() {
        return new zzfg();
    }

    public final boolean equals(Object obj) {
        boolean z;
        boolean z2;
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof zzfg)) {
            return false;
        }
        zzfg zzfgVar = (zzfg) obj;
        int i = this.count;
        if (i == zzfgVar.count) {
            int[] iArr = this.zzou;
            int[] iArr2 = zzfgVar.zzou;
            int i2 = 0;
            while (true) {
                if (i2 >= i) {
                    z = true;
                    break;
                }
                if (iArr[i2] != iArr2[i2]) {
                    z = false;
                    break;
                }
                i2++;
            }
            if (z) {
                Object[] objArr = this.zznf;
                Object[] objArr2 = zzfgVar.zznf;
                int i3 = this.count;
                int i4 = 0;
                while (true) {
                    if (i4 >= i3) {
                        z2 = true;
                        break;
                    }
                    if (!objArr[i4].equals(objArr2[i4])) {
                        z2 = false;
                        break;
                    }
                    i4++;
                }
                if (z2) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.count;
        int i2 = (i + 527) * 31;
        int[] iArr = this.zzou;
        int iHashCode = 17;
        int i3 = 17;
        for (int i4 = 0; i4 < i; i4++) {
            i3 = (i3 * 31) + iArr[i4];
        }
        int i5 = (i2 + i3) * 31;
        Object[] objArr = this.zznf;
        int i6 = this.count;
        for (int i7 = 0; i7 < i6; i7++) {
            iHashCode = (iHashCode * 31) + objArr[i7].hashCode();
        }
        return i5 + iHashCode;
    }

    final void zza(zzfz zzfzVar) throws IOException {
        if (zzfzVar.zzbc() == zzcr.zzd.zzlk) {
            for (int i = this.count - 1; i >= 0; i--) {
                zzfzVar.zza(this.zzou[i] >>> 3, this.zznf[i]);
            }
            return;
        }
        for (int i2 = 0; i2 < this.count; i2++) {
            zzfzVar.zza(this.zzou[i2] >>> 3, this.zznf[i2]);
        }
    }

    final void zza(StringBuilder sb, int i) {
        for (int i2 = 0; i2 < this.count; i2++) {
            zzea.zza(sb, i, String.valueOf(this.zzou[i2] >>> 3), this.zznf[i2]);
        }
    }

    public final void zzao() {
        this.zzgl = false;
    }

    final void zzb(int i, Object obj) {
        if (!this.zzgl) {
            throw new UnsupportedOperationException();
        }
        int i2 = this.count;
        if (i2 == this.zzou.length) {
            int i3 = this.count + (i2 < 4 ? 8 : i2 >> 1);
            this.zzou = Arrays.copyOf(this.zzou, i3);
            this.zznf = Arrays.copyOf(this.zznf, i3);
        }
        int[] iArr = this.zzou;
        int i4 = this.count;
        iArr[i4] = i;
        this.zznf[i4] = obj;
        this.count = i4 + 1;
    }

    public final void zzb(zzfz zzfzVar) throws IOException {
        if (this.count == 0) {
            return;
        }
        if (zzfzVar.zzbc() == zzcr.zzd.zzlj) {
            for (int i = 0; i < this.count; i++) {
                zzb(this.zzou[i], this.zznf[i], zzfzVar);
            }
            return;
        }
        for (int i2 = this.count - 1; i2 >= 0; i2--) {
            zzb(this.zzou[i2], this.zznf[i2], zzfzVar);
        }
    }

    public final int zzbl() {
        int iZze;
        int i = this.zzks;
        if (i != -1) {
            return i;
        }
        int i2 = 0;
        for (int i3 = 0; i3 < this.count; i3++) {
            int i4 = this.zzou[i3];
            int i5 = i4 >>> 3;
            int i6 = i4 & 7;
            if (i6 == 0) {
                iZze = zzca.zze(i5, ((Long) this.zznf[i3]).longValue());
            } else if (i6 == 1) {
                iZze = zzca.zzg(i5, ((Long) this.zznf[i3]).longValue());
            } else if (i6 == 2) {
                iZze = zzca.zzc(i5, (zzbo) this.zznf[i3]);
            } else if (i6 == 3) {
                iZze = (zzca.zzt(i5) << 1) + ((zzfg) this.zznf[i3]).zzbl();
            } else {
                if (i6 != 5) {
                    throw new IllegalStateException(zzcx.zzce());
                }
                iZze = zzca.zzl(i5, ((Integer) this.zznf[i3]).intValue());
            }
            i2 += iZze;
        }
        this.zzks = i2;
        return i2;
    }

    public final int zzdw() {
        int i = this.zzks;
        if (i != -1) {
            return i;
        }
        int iZzd = 0;
        for (int i2 = 0; i2 < this.count; i2++) {
            iZzd += zzca.zzd(this.zzou[i2] >>> 3, (zzbo) this.zznf[i2]);
        }
        this.zzks = iZzd;
        return iZzd;
    }
}
