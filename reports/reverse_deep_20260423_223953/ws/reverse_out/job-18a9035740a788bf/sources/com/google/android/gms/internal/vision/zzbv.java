package com.google.android.gms.internal.vision;

import java.io.IOException;
import java.nio.charset.Charset;

/* JADX INFO: loaded from: classes.dex */
class zzbv extends zzbu {
    protected final byte[] zzha;

    zzbv(byte[] bArr) {
        this.zzha = bArr;
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof zzbo) || size() != ((zzbo) obj).size()) {
            return false;
        }
        if (size() == 0) {
            return true;
        }
        if (!(obj instanceof zzbv)) {
            return obj.equals(this);
        }
        zzbv zzbvVar = (zzbv) obj;
        int iZzau = zzau();
        int iZzau2 = zzbvVar.zzau();
        if (iZzau == 0 || iZzau2 == 0 || iZzau == iZzau2) {
            return zza(zzbvVar, 0, size());
        }
        return false;
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    public int size() {
        return this.zzha.length;
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    protected final int zza(int i, int i2, int i3) {
        return zzct.zza(i, this.zzha, zzav(), i3);
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    protected final String zza(Charset charset) {
        return new String(this.zzha, zzav(), size(), charset);
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    final void zza(zzbn zzbnVar) throws IOException {
        zzbnVar.zza(this.zzha, zzav(), size());
    }

    @Override // com.google.android.gms.internal.vision.zzbu
    final boolean zza(zzbo zzboVar, int i, int i2) {
        if (i2 > zzboVar.size()) {
            int size = size();
            StringBuilder sb = new StringBuilder(40);
            sb.append("Length too large: ");
            sb.append(i2);
            sb.append(size);
            throw new IllegalArgumentException(sb.toString());
        }
        if (i2 > zzboVar.size()) {
            int size2 = zzboVar.size();
            StringBuilder sb2 = new StringBuilder(59);
            sb2.append("Ran off end of other: 0, ");
            sb2.append(i2);
            sb2.append(", ");
            sb2.append(size2);
            throw new IllegalArgumentException(sb2.toString());
        }
        if (!(zzboVar instanceof zzbv)) {
            return zzboVar.zzc(0, i2).equals(zzc(0, i2));
        }
        zzbv zzbvVar = (zzbv) zzboVar;
        byte[] bArr = this.zzha;
        byte[] bArr2 = zzbvVar.zzha;
        int iZzav = zzav() + i2;
        int iZzav2 = zzav();
        int iZzav3 = zzbvVar.zzav();
        while (iZzav2 < iZzav) {
            if (bArr[iZzav2] != bArr2[iZzav3]) {
                return false;
            }
            iZzav2++;
            iZzav3++;
        }
        return true;
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    public final boolean zzat() {
        int iZzav = zzav();
        return zzfn.zze(this.zzha, iZzav, size() + iZzav);
    }

    protected int zzav() {
        return 0;
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    public final zzbo zzc(int i, int i2) {
        int iZzb = zzb(0, i2, size());
        return iZzb == 0 ? zzbo.zzgt : new zzbr(this.zzha, zzav(), iZzb);
    }

    @Override // com.google.android.gms.internal.vision.zzbo
    public byte zzl(int i) {
        return this.zzha[i];
    }
}
