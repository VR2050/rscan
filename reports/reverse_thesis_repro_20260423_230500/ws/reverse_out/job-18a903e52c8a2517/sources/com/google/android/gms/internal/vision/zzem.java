package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcr;

/* JADX INFO: loaded from: classes.dex */
final class zzem implements zzdv {
    private final int flags;
    private final String info;
    private final Object[] zznf;
    private final zzdx zzni;

    zzem(zzdx zzdxVar, String str, Object[] objArr) {
        this.zzni = zzdxVar;
        this.info = str;
        this.zznf = objArr;
        char cCharAt = str.charAt(0);
        if (cCharAt < 55296) {
            this.flags = cCharAt;
            return;
        }
        int i = cCharAt & 8191;
        int i2 = 13;
        int i3 = 1;
        while (true) {
            int i4 = i3 + 1;
            char cCharAt2 = str.charAt(i3);
            if (cCharAt2 < 55296) {
                this.flags = i | (cCharAt2 << i2);
                return;
            } else {
                i |= (cCharAt2 & 8191) << i2;
                i2 += 13;
                i3 = i4;
            }
        }
    }

    @Override // com.google.android.gms.internal.vision.zzdv
    public final int zzcv() {
        return (this.flags & 1) == 1 ? zzcr.zzd.zzlg : zzcr.zzd.zzlh;
    }

    @Override // com.google.android.gms.internal.vision.zzdv
    public final boolean zzcw() {
        return (this.flags & 2) == 2;
    }

    @Override // com.google.android.gms.internal.vision.zzdv
    public final zzdx zzcx() {
        return this.zzni;
    }

    final String zzde() {
        return this.info;
    }

    final Object[] zzdf() {
        return this.zznf;
    }
}
