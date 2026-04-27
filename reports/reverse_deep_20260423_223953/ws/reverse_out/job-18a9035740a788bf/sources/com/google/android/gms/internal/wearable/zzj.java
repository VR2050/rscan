package com.google.android.gms.internal.wearable;

import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import java.io.IOException;
import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public final class zzj extends zzn<zzj> {
    public byte[] zzgd = zzw.zzhy;
    public String zzge = "";
    public double zzgf = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
    public float zzgg = 0.0f;
    public long zzgh = 0;
    public int zzgi = 0;
    public int zzgj = 0;
    public boolean zzgk = false;
    public zzh[] zzgl = zzh.zzh();
    public zzi[] zzgm = zzi.zzi();
    public String[] zzgn = zzw.zzhw;
    public long[] zzgo = zzw.zzhs;
    public float[] zzgp = zzw.zzht;
    public long zzgq = 0;

    public zzj() {
        this.zzhc = null;
        this.zzhl = -1;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof zzj)) {
            return false;
        }
        zzj zzjVar = (zzj) obj;
        if (!Arrays.equals(this.zzgd, zzjVar.zzgd)) {
            return false;
        }
        String str = this.zzge;
        if (str == null) {
            if (zzjVar.zzge != null) {
                return false;
            }
        } else if (!str.equals(zzjVar.zzge)) {
            return false;
        }
        if (Double.doubleToLongBits(this.zzgf) != Double.doubleToLongBits(zzjVar.zzgf) || Float.floatToIntBits(this.zzgg) != Float.floatToIntBits(zzjVar.zzgg) || this.zzgh != zzjVar.zzgh || this.zzgi != zzjVar.zzgi || this.zzgj != zzjVar.zzgj || this.zzgk != zzjVar.zzgk || !zzr.equals(this.zzgl, zzjVar.zzgl) || !zzr.equals(this.zzgm, zzjVar.zzgm) || !zzr.equals(this.zzgn, zzjVar.zzgn) || !zzr.equals(this.zzgo, zzjVar.zzgo) || !zzr.equals(this.zzgp, zzjVar.zzgp) || this.zzgq != zzjVar.zzgq) {
            return false;
        }
        if (this.zzhc == null || this.zzhc.isEmpty()) {
            return zzjVar.zzhc == null || zzjVar.zzhc.isEmpty();
        }
        return this.zzhc.equals(zzjVar.zzhc);
    }

    public final int hashCode() {
        int iHashCode = (((getClass().getName().hashCode() + 527) * 31) + Arrays.hashCode(this.zzgd)) * 31;
        String str = this.zzge;
        int iHashCode2 = 0;
        int iHashCode3 = str == null ? 0 : str.hashCode();
        long jDoubleToLongBits = Double.doubleToLongBits(this.zzgf);
        int iFloatToIntBits = (((((iHashCode + iHashCode3) * 31) + ((int) (jDoubleToLongBits ^ (jDoubleToLongBits >>> 32)))) * 31) + Float.floatToIntBits(this.zzgg)) * 31;
        long j = this.zzgh;
        int iHashCode4 = (((((((((((((((((iFloatToIntBits + ((int) (j ^ (j >>> 32)))) * 31) + this.zzgi) * 31) + this.zzgj) * 31) + (this.zzgk ? 1231 : 1237)) * 31) + zzr.hashCode(this.zzgl)) * 31) + zzr.hashCode(this.zzgm)) * 31) + zzr.hashCode(this.zzgn)) * 31) + zzr.hashCode(this.zzgo)) * 31) + zzr.hashCode(this.zzgp)) * 31;
        long j2 = this.zzgq;
        int i = (iHashCode4 + ((int) (j2 ^ (j2 >>> 32)))) * 31;
        if (this.zzhc != null && !this.zzhc.isEmpty()) {
            iHashCode2 = this.zzhc.hashCode();
        }
        return i + iHashCode2;
    }

    @Override // com.google.android.gms.internal.wearable.zzn, com.google.android.gms.internal.wearable.zzt
    public final void zza(zzl zzlVar) throws IOException {
        if (!Arrays.equals(this.zzgd, zzw.zzhy)) {
            byte[] bArr = this.zzgd;
            zzlVar.zzf(1, 2);
            zzlVar.zzl(bArr.length);
            zzlVar.zzc(bArr);
        }
        String str = this.zzge;
        if (str != null && !str.equals("")) {
            zzlVar.zza(2, this.zzge);
        }
        if (Double.doubleToLongBits(this.zzgf) != Double.doubleToLongBits(FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE)) {
            double d = this.zzgf;
            zzlVar.zzf(3, 1);
            zzlVar.zzb(Double.doubleToLongBits(d));
        }
        if (Float.floatToIntBits(this.zzgg) != Float.floatToIntBits(0.0f)) {
            zzlVar.zza(4, this.zzgg);
        }
        long j = this.zzgh;
        if (j != 0) {
            zzlVar.zza(5, j);
        }
        int i = this.zzgi;
        if (i != 0) {
            zzlVar.zzd(6, i);
        }
        int i2 = this.zzgj;
        int i3 = 0;
        if (i2 != 0) {
            zzlVar.zzf(7, 0);
            zzlVar.zzl(zzl.zzn(i2));
        }
        boolean z = this.zzgk;
        if (z) {
            zzlVar.zzf(8, 0);
            zzlVar.zza(z ? (byte) 1 : (byte) 0);
        }
        zzh[] zzhVarArr = this.zzgl;
        if (zzhVarArr != null && zzhVarArr.length > 0) {
            int i4 = 0;
            while (true) {
                zzh[] zzhVarArr2 = this.zzgl;
                if (i4 >= zzhVarArr2.length) {
                    break;
                }
                zzh zzhVar = zzhVarArr2[i4];
                if (zzhVar != null) {
                    zzlVar.zza(9, zzhVar);
                }
                i4++;
            }
        }
        zzi[] zziVarArr = this.zzgm;
        if (zziVarArr != null && zziVarArr.length > 0) {
            int i5 = 0;
            while (true) {
                zzi[] zziVarArr2 = this.zzgm;
                if (i5 >= zziVarArr2.length) {
                    break;
                }
                zzi zziVar = zziVarArr2[i5];
                if (zziVar != null) {
                    zzlVar.zza(10, zziVar);
                }
                i5++;
            }
        }
        String[] strArr = this.zzgn;
        if (strArr != null && strArr.length > 0) {
            int i6 = 0;
            while (true) {
                String[] strArr2 = this.zzgn;
                if (i6 >= strArr2.length) {
                    break;
                }
                String str2 = strArr2[i6];
                if (str2 != null) {
                    zzlVar.zza(11, str2);
                }
                i6++;
            }
        }
        long[] jArr = this.zzgo;
        if (jArr != null && jArr.length > 0) {
            int i7 = 0;
            while (true) {
                long[] jArr2 = this.zzgo;
                if (i7 >= jArr2.length) {
                    break;
                }
                zzlVar.zza(12, jArr2[i7]);
                i7++;
            }
        }
        long j2 = this.zzgq;
        if (j2 != 0) {
            zzlVar.zza(13, j2);
        }
        float[] fArr = this.zzgp;
        if (fArr != null && fArr.length > 0) {
            while (true) {
                float[] fArr2 = this.zzgp;
                if (i3 >= fArr2.length) {
                    break;
                }
                zzlVar.zza(14, fArr2[i3]);
                i3++;
            }
        }
        super.zza(zzlVar);
    }

    @Override // com.google.android.gms.internal.wearable.zzn, com.google.android.gms.internal.wearable.zzt
    protected final int zzg() {
        long[] jArr;
        int i;
        int iZzg = super.zzg();
        if (!Arrays.equals(this.zzgd, zzw.zzhy)) {
            byte[] bArr = this.zzgd;
            iZzg += zzl.zzk(1) + zzl.zzm(bArr.length) + bArr.length;
        }
        String str = this.zzge;
        if (str != null && !str.equals("")) {
            iZzg += zzl.zzb(2, this.zzge);
        }
        if (Double.doubleToLongBits(this.zzgf) != Double.doubleToLongBits(FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE)) {
            iZzg += zzl.zzk(3) + 8;
        }
        if (Float.floatToIntBits(this.zzgg) != Float.floatToIntBits(0.0f)) {
            iZzg += zzl.zzk(4) + 4;
        }
        long j = this.zzgh;
        if (j != 0) {
            iZzg += zzl.zzb(5, j);
        }
        int i2 = this.zzgi;
        if (i2 != 0) {
            iZzg += zzl.zze(6, i2);
        }
        int i3 = this.zzgj;
        if (i3 != 0) {
            iZzg += zzl.zzk(7) + zzl.zzm(zzl.zzn(i3));
        }
        if (this.zzgk) {
            iZzg += zzl.zzk(8) + 1;
        }
        zzh[] zzhVarArr = this.zzgl;
        int i4 = 0;
        if (zzhVarArr != null && zzhVarArr.length > 0) {
            int i5 = 0;
            while (true) {
                zzh[] zzhVarArr2 = this.zzgl;
                if (i5 >= zzhVarArr2.length) {
                    break;
                }
                zzh zzhVar = zzhVarArr2[i5];
                if (zzhVar != null) {
                    iZzg += zzl.zzb(9, zzhVar);
                }
                i5++;
            }
        }
        zzi[] zziVarArr = this.zzgm;
        if (zziVarArr != null && zziVarArr.length > 0) {
            int i6 = 0;
            while (true) {
                zzi[] zziVarArr2 = this.zzgm;
                if (i6 >= zziVarArr2.length) {
                    break;
                }
                zzi zziVar = zziVarArr2[i6];
                if (zziVar != null) {
                    iZzg += zzl.zzb(10, zziVar);
                }
                i6++;
            }
        }
        String[] strArr = this.zzgn;
        if (strArr != null && strArr.length > 0) {
            int i7 = 0;
            int iZzg2 = 0;
            int i8 = 0;
            while (true) {
                String[] strArr2 = this.zzgn;
                if (i7 >= strArr2.length) {
                    break;
                }
                String str2 = strArr2[i7];
                if (str2 != null) {
                    i8++;
                    iZzg2 += zzl.zzg(str2);
                }
                i7++;
            }
            iZzg = iZzg + iZzg2 + (i8 * 1);
        }
        long[] jArr2 = this.zzgo;
        if (jArr2 != null && jArr2.length > 0) {
            int i9 = 0;
            while (true) {
                jArr = this.zzgo;
                if (i4 >= jArr.length) {
                    break;
                }
                long j2 = jArr[i4];
                if ((j2 & (-128)) == 0) {
                    i = 1;
                } else if ((j2 & (-16384)) == 0) {
                    i = 2;
                } else if ((j2 & (-2097152)) == 0) {
                    i = 3;
                } else if ((j2 & (-268435456)) == 0) {
                    i = 4;
                } else if ((j2 & (-34359738368L)) == 0) {
                    i = 5;
                } else if ((j2 & (-4398046511104L)) == 0) {
                    i = 6;
                } else if ((j2 & (-562949953421312L)) == 0) {
                    i = 7;
                } else if ((j2 & (-72057594037927936L)) == 0) {
                    i = 8;
                } else {
                    i = (j2 & Long.MIN_VALUE) == 0 ? 9 : 10;
                }
                i9 += i;
                i4++;
            }
            iZzg = iZzg + i9 + (jArr.length * 1);
        }
        long j3 = this.zzgq;
        if (j3 != 0) {
            iZzg += zzl.zzb(13, j3);
        }
        float[] fArr = this.zzgp;
        if (fArr != null && fArr.length > 0) {
            return iZzg + (fArr.length * 4) + (fArr.length * 1);
        }
        return iZzg;
    }

    @Override // com.google.android.gms.internal.wearable.zzt
    public final /* synthetic */ zzt zza(zzk zzkVar) throws IOException {
        while (true) {
            int iZzj = zzkVar.zzj();
            switch (iZzj) {
                case 0:
                    return this;
                case 10:
                    this.zzgd = zzkVar.readBytes();
                    break;
                case 18:
                    this.zzge = zzkVar.readString();
                    break;
                case 25:
                    this.zzgf = Double.longBitsToDouble(zzkVar.zzn());
                    break;
                case 37:
                    this.zzgg = Float.intBitsToFloat(zzkVar.zzm());
                    break;
                case 40:
                    this.zzgh = zzkVar.zzl();
                    break;
                case 48:
                    this.zzgi = zzkVar.zzk();
                    break;
                case 56:
                    int iZzk = zzkVar.zzk();
                    this.zzgj = (-(iZzk & 1)) ^ (iZzk >>> 1);
                    break;
                case 64:
                    this.zzgk = zzkVar.zzk() != 0;
                    break;
                case 74:
                    int iZzb = zzw.zzb(zzkVar, 74);
                    zzh[] zzhVarArr = this.zzgl;
                    int length = zzhVarArr == null ? 0 : zzhVarArr.length;
                    int i = iZzb + length;
                    zzh[] zzhVarArr2 = new zzh[i];
                    if (length != 0) {
                        System.arraycopy(this.zzgl, 0, zzhVarArr2, 0, length);
                    }
                    while (length < i - 1) {
                        zzhVarArr2[length] = new zzh();
                        zzkVar.zza(zzhVarArr2[length]);
                        zzkVar.zzj();
                        length++;
                    }
                    zzhVarArr2[length] = new zzh();
                    zzkVar.zza(zzhVarArr2[length]);
                    this.zzgl = zzhVarArr2;
                    break;
                case 82:
                    int iZzb2 = zzw.zzb(zzkVar, 82);
                    zzi[] zziVarArr = this.zzgm;
                    int length2 = zziVarArr == null ? 0 : zziVarArr.length;
                    int i2 = iZzb2 + length2;
                    zzi[] zziVarArr2 = new zzi[i2];
                    if (length2 != 0) {
                        System.arraycopy(this.zzgm, 0, zziVarArr2, 0, length2);
                    }
                    while (length2 < i2 - 1) {
                        zziVarArr2[length2] = new zzi();
                        zzkVar.zza(zziVarArr2[length2]);
                        zzkVar.zzj();
                        length2++;
                    }
                    zziVarArr2[length2] = new zzi();
                    zzkVar.zza(zziVarArr2[length2]);
                    this.zzgm = zziVarArr2;
                    break;
                case 90:
                    int iZzb3 = zzw.zzb(zzkVar, 90);
                    String[] strArr = this.zzgn;
                    int length3 = strArr == null ? 0 : strArr.length;
                    int i3 = iZzb3 + length3;
                    String[] strArr2 = new String[i3];
                    if (length3 != 0) {
                        System.arraycopy(this.zzgn, 0, strArr2, 0, length3);
                    }
                    while (length3 < i3 - 1) {
                        strArr2[length3] = zzkVar.readString();
                        zzkVar.zzj();
                        length3++;
                    }
                    strArr2[length3] = zzkVar.readString();
                    this.zzgn = strArr2;
                    break;
                case 96:
                    int iZzb4 = zzw.zzb(zzkVar, 96);
                    long[] jArr = this.zzgo;
                    int length4 = jArr == null ? 0 : jArr.length;
                    int i4 = iZzb4 + length4;
                    long[] jArr2 = new long[i4];
                    if (length4 != 0) {
                        System.arraycopy(this.zzgo, 0, jArr2, 0, length4);
                    }
                    while (length4 < i4 - 1) {
                        jArr2[length4] = zzkVar.zzl();
                        zzkVar.zzj();
                        length4++;
                    }
                    jArr2[length4] = zzkVar.zzl();
                    this.zzgo = jArr2;
                    break;
                case 98:
                    int iZze = zzkVar.zze(zzkVar.zzk());
                    int position = zzkVar.getPosition();
                    int i5 = 0;
                    while (zzkVar.zzp() > 0) {
                        zzkVar.zzl();
                        i5++;
                    }
                    zzkVar.zzg(position);
                    long[] jArr3 = this.zzgo;
                    int length5 = jArr3 == null ? 0 : jArr3.length;
                    int i6 = i5 + length5;
                    long[] jArr4 = new long[i6];
                    if (length5 != 0) {
                        System.arraycopy(this.zzgo, 0, jArr4, 0, length5);
                    }
                    while (length5 < i6) {
                        jArr4[length5] = zzkVar.zzl();
                        length5++;
                    }
                    this.zzgo = jArr4;
                    zzkVar.zzf(iZze);
                    break;
                case 104:
                    this.zzgq = zzkVar.zzl();
                    break;
                case 114:
                    int iZzk2 = zzkVar.zzk();
                    int iZze2 = zzkVar.zze(iZzk2);
                    int i7 = iZzk2 / 4;
                    float[] fArr = this.zzgp;
                    int length6 = fArr == null ? 0 : fArr.length;
                    int i8 = i7 + length6;
                    float[] fArr2 = new float[i8];
                    if (length6 != 0) {
                        System.arraycopy(this.zzgp, 0, fArr2, 0, length6);
                    }
                    while (length6 < i8) {
                        fArr2[length6] = Float.intBitsToFloat(zzkVar.zzm());
                        length6++;
                    }
                    this.zzgp = fArr2;
                    zzkVar.zzf(iZze2);
                    break;
                case 117:
                    int iZzb5 = zzw.zzb(zzkVar, 117);
                    float[] fArr3 = this.zzgp;
                    int length7 = fArr3 == null ? 0 : fArr3.length;
                    int i9 = iZzb5 + length7;
                    float[] fArr4 = new float[i9];
                    if (length7 != 0) {
                        System.arraycopy(this.zzgp, 0, fArr4, 0, length7);
                    }
                    while (length7 < i9 - 1) {
                        fArr4[length7] = Float.intBitsToFloat(zzkVar.zzm());
                        zzkVar.zzj();
                        length7++;
                    }
                    fArr4[length7] = Float.intBitsToFloat(zzkVar.zzm());
                    this.zzgp = fArr4;
                    break;
                default:
                    if (!super.zza(zzkVar, iZzj)) {
                        return this;
                    }
                    break;
                    break;
            }
        }
    }
}
