package com.google.android.gms.wearable;

import com.google.android.gms.wearable.WearableListenerService;
import com.google.android.gms.wearable.internal.zzaw;

/* JADX INFO: loaded from: classes.dex */
final class zzt implements Runnable {
    private final /* synthetic */ WearableListenerService.zzd zzao;
    private final /* synthetic */ zzaw zzav;

    zzt(WearableListenerService.zzd zzdVar, zzaw zzawVar) {
        this.zzao = zzdVar;
        this.zzav = zzawVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zzav.zza(WearableListenerService.this);
        this.zzav.zza(WearableListenerService.this.zzaj);
    }
}
