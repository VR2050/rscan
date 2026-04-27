package com.google.android.gms.internal.wearable;

import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
final class zzv {
    final int tag;
    final byte[] zzhm;

    zzv(int i, byte[] bArr) {
        this.tag = i;
        this.zzhm = bArr;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof zzv)) {
            return false;
        }
        zzv zzvVar = (zzv) obj;
        return this.tag == zzvVar.tag && Arrays.equals(this.zzhm, zzvVar.zzhm);
    }

    public final int hashCode() {
        return ((this.tag + 527) * 31) + Arrays.hashCode(this.zzhm);
    }
}
