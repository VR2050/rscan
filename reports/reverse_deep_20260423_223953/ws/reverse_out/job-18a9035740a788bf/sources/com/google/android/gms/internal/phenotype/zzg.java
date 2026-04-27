package com.google.android.gms.internal.phenotype;

import android.database.ContentObserver;
import android.os.Handler;

/* JADX INFO: loaded from: classes.dex */
final class zzg extends ContentObserver {
    zzg(Handler handler) {
        super(null);
    }

    @Override // android.database.ContentObserver
    public final void onChange(boolean z) {
        zzf.zzbh.set(true);
    }
}
