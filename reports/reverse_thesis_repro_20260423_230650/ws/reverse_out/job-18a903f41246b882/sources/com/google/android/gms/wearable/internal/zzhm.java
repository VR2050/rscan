package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.wearable.MessageApi;

/* JADX INFO: loaded from: classes.dex */
final class zzhm implements ListenerHolder.Notifier<MessageApi.MessageListener> {
    private final /* synthetic */ zzfe zzap;

    zzhm(zzfe zzfeVar) {
        this.zzap = zzfeVar;
    }

    @Override // com.google.android.gms.common.api.internal.ListenerHolder.Notifier
    public final void onNotifyListenerFailed() {
    }

    @Override // com.google.android.gms.common.api.internal.ListenerHolder.Notifier
    public final /* synthetic */ void notifyListener(MessageApi.MessageListener messageListener) {
        messageListener.onMessageReceived(this.zzap);
    }
}
