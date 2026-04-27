package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.wearable.ChannelApi;

/* JADX INFO: loaded from: classes.dex */
final class zzhn implements ListenerHolder.Notifier<ChannelApi.ChannelListener> {
    private final /* synthetic */ zzaw zzav;

    zzhn(zzaw zzawVar) {
        this.zzav = zzawVar;
    }

    @Override // com.google.android.gms.common.api.internal.ListenerHolder.Notifier
    public final void onNotifyListenerFailed() {
    }

    @Override // com.google.android.gms.common.api.internal.ListenerHolder.Notifier
    public final /* synthetic */ void notifyListener(ChannelApi.ChannelListener channelListener) {
        this.zzav.zza(channelListener);
    }
}
