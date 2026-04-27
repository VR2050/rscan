package com.google.android.gms.wearable;

import com.google.android.gms.wearable.WearableListenerService;
import com.google.android.gms.wearable.internal.zzfo;

/* JADX INFO: loaded from: classes.dex */
final class zzn implements Runnable {
    private final /* synthetic */ WearableListenerService.zzd zzao;
    private final /* synthetic */ zzfo zzaq;

    zzn(WearableListenerService.zzd zzdVar, zzfo zzfoVar) {
        this.zzao = zzdVar;
        this.zzaq = zzfoVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        WearableListenerService.this.onPeerConnected(this.zzaq);
    }
}
