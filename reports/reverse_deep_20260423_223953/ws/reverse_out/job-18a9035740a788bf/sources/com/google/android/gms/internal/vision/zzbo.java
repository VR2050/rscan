package com.google.android.gms.internal.vision;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzbo implements Serializable, Iterable<Byte> {
    public static final zzbo zzgt = new zzbv(zzct.zzlo);
    private static final zzbs zzgu;
    private int zzgv = 0;

    static {
        zzbp zzbpVar = null;
        zzgu = zzbj.zzaq() ? new zzbw(zzbpVar) : new zzbq(zzbpVar);
    }

    zzbo() {
    }

    static int zzb(int i, int i2, int i3) {
        int i4 = i2 - i;
        if ((i | i2 | i4 | (i3 - i2)) >= 0) {
            return i4;
        }
        if (i < 0) {
            StringBuilder sb = new StringBuilder(32);
            sb.append("Beginning index: ");
            sb.append(i);
            sb.append(" < 0");
            throw new IndexOutOfBoundsException(sb.toString());
        }
        if (i2 < i) {
            StringBuilder sb2 = new StringBuilder(66);
            sb2.append("Beginning index larger than ending index: ");
            sb2.append(i);
            sb2.append(", ");
            sb2.append(i2);
            throw new IndexOutOfBoundsException(sb2.toString());
        }
        StringBuilder sb3 = new StringBuilder(37);
        sb3.append("End index: ");
        sb3.append(i2);
        sb3.append(" >= ");
        sb3.append(i3);
        throw new IndexOutOfBoundsException(sb3.toString());
    }

    public static zzbo zzb(byte[] bArr, int i, int i2) {
        return new zzbv(zzgu.zzc(bArr, i, i2));
    }

    public static zzbo zzg(String str) {
        return new zzbv(str.getBytes(zzct.UTF_8));
    }

    static zzbt zzm(int i) {
        return new zzbt(i, null);
    }

    public abstract boolean equals(Object obj);

    public final int hashCode() {
        int iZza = this.zzgv;
        if (iZza == 0) {
            int size = size();
            iZza = zza(size, 0, size);
            if (iZza == 0) {
                iZza = 1;
            }
            this.zzgv = iZza;
        }
        return iZza;
    }

    @Override // java.lang.Iterable
    public /* synthetic */ Iterator<Byte> iterator() {
        return new zzbp(this);
    }

    public abstract int size();

    public final String toString() {
        return String.format("<ByteString@%s size=%d>", Integer.toHexString(System.identityHashCode(this)), Integer.valueOf(size()));
    }

    protected abstract int zza(int i, int i2, int i3);

    protected abstract String zza(Charset charset);

    abstract void zza(zzbn zzbnVar) throws IOException;

    public final String zzas() {
        return size() == 0 ? "" : zza(zzct.UTF_8);
    }

    public abstract boolean zzat();

    protected final int zzau() {
        return this.zzgv;
    }

    public abstract zzbo zzc(int i, int i2);

    public abstract byte zzl(int i);
}
