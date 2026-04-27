package com.google.android.gms.internal.vision;

import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
final class zzbq implements zzbs {
    private zzbq() {
    }

    /* synthetic */ zzbq(zzbp zzbpVar) {
        this();
    }

    @Override // com.google.android.gms.internal.vision.zzbs
    public final byte[] zzc(byte[] bArr, int i, int i2) {
        return Arrays.copyOfRange(bArr, i, i2 + i);
    }
}
