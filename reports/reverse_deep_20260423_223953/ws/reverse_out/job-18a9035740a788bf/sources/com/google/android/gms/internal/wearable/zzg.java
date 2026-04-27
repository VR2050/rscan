package com.google.android.gms.internal.wearable;

import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public final class zzg extends zzn<zzg> {
    public zzh[] zzfy = zzh.zzh();

    public zzg() {
        this.zzhc = null;
        this.zzhl = -1;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof zzg)) {
            return false;
        }
        zzg zzgVar = (zzg) obj;
        if (!zzr.equals(this.zzfy, zzgVar.zzfy)) {
            return false;
        }
        if (this.zzhc == null || this.zzhc.isEmpty()) {
            return zzgVar.zzhc == null || zzgVar.zzhc.isEmpty();
        }
        return this.zzhc.equals(zzgVar.zzhc);
    }

    public final int hashCode() {
        int iHashCode;
        int iHashCode2 = (((getClass().getName().hashCode() + 527) * 31) + zzr.hashCode(this.zzfy)) * 31;
        if (this.zzhc == null || this.zzhc.isEmpty()) {
            iHashCode = 0;
        } else {
            iHashCode = this.zzhc.hashCode();
        }
        return iHashCode2 + iHashCode;
    }

    @Override // com.google.android.gms.internal.wearable.zzn, com.google.android.gms.internal.wearable.zzt
    public final void zza(zzl zzlVar) throws IOException {
        zzh[] zzhVarArr = this.zzfy;
        if (zzhVarArr != null && zzhVarArr.length > 0) {
            int i = 0;
            while (true) {
                zzh[] zzhVarArr2 = this.zzfy;
                if (i >= zzhVarArr2.length) {
                    break;
                }
                zzh zzhVar = zzhVarArr2[i];
                if (zzhVar != null) {
                    zzlVar.zza(1, zzhVar);
                }
                i++;
            }
        }
        super.zza(zzlVar);
    }

    @Override // com.google.android.gms.internal.wearable.zzn, com.google.android.gms.internal.wearable.zzt
    protected final int zzg() {
        int iZzg = super.zzg();
        zzh[] zzhVarArr = this.zzfy;
        if (zzhVarArr != null && zzhVarArr.length > 0) {
            int i = 0;
            while (true) {
                zzh[] zzhVarArr2 = this.zzfy;
                if (i >= zzhVarArr2.length) {
                    break;
                }
                zzh zzhVar = zzhVarArr2[i];
                if (zzhVar != null) {
                    iZzg += zzl.zzb(1, zzhVar);
                }
                i++;
            }
        }
        return iZzg;
    }

    public static zzg zza(byte[] bArr) throws zzs {
        return (zzg) zzt.zza(new zzg(), bArr, 0, bArr.length);
    }

    @Override // com.google.android.gms.internal.wearable.zzt
    public final /* synthetic */ zzt zza(zzk zzkVar) throws IOException {
        while (true) {
            int iZzj = zzkVar.zzj();
            if (iZzj == 0) {
                return this;
            }
            if (iZzj != 10) {
                if (!super.zza(zzkVar, iZzj)) {
                    return this;
                }
            } else {
                int iZzb = zzw.zzb(zzkVar, 10);
                zzh[] zzhVarArr = this.zzfy;
                int length = zzhVarArr == null ? 0 : zzhVarArr.length;
                int i = iZzb + length;
                zzh[] zzhVarArr2 = new zzh[i];
                if (length != 0) {
                    System.arraycopy(this.zzfy, 0, zzhVarArr2, 0, length);
                }
                while (length < i - 1) {
                    zzhVarArr2[length] = new zzh();
                    zzkVar.zza(zzhVarArr2[length]);
                    zzkVar.zzj();
                    length++;
                }
                zzhVarArr2[length] = new zzh();
                zzkVar.zza(zzhVarArr2[length]);
                this.zzfy = zzhVarArr2;
            }
        }
    }
}
