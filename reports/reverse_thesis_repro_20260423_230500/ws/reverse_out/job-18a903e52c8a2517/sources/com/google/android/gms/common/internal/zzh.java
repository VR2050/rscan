package com.google.android.gms.common.internal;

import com.google.android.exoplayer2.extractor.ts.TsExtractor;

/* JADX INFO: loaded from: classes.dex */
public final class zzh {
    private final String mPackageName;
    private final int zzdt = TsExtractor.TS_STREAM_TYPE_AC3;
    private final String zzej;
    private final boolean zzek;

    public zzh(String str, String str2, boolean z, int i) {
        this.mPackageName = str;
        this.zzej = str2;
        this.zzek = z;
    }

    final String zzt() {
        return this.zzej;
    }

    final String getPackageName() {
        return this.mPackageName;
    }

    final int zzq() {
        return this.zzdt;
    }
}
