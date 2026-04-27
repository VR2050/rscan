package com.google.android.gms.wearable;

import com.google.android.gms.wearable.WearableListenerService;
import com.google.android.gms.wearable.internal.zzfe;

/* JADX INFO: loaded from: classes.dex */
final class zzm implements Runnable {
    private final /* synthetic */ WearableListenerService.zzd zzao;
    private final /* synthetic */ zzfe zzap;

    zzm(WearableListenerService.zzd zzdVar, zzfe zzfeVar) {
        this.zzao = zzdVar;
        this.zzap = zzfeVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        WearableListenerService.this.onMessageReceived(this.zzap);
    }
}
