package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;

/* JADX INFO: loaded from: classes.dex */
final class zzgc implements ChannelApi.ChannelListener {
    private final String zzce;
    private final ChannelApi.ChannelListener zzeq;

    zzgc(String str, ChannelApi.ChannelListener channelListener) {
        this.zzce = (String) Preconditions.checkNotNull(str);
        this.zzeq = (ChannelApi.ChannelListener) Preconditions.checkNotNull(channelListener);
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public final void onChannelOpened(Channel channel) {
        this.zzeq.onChannelOpened(channel);
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public final void onChannelClosed(Channel channel, int i, int i2) {
        this.zzeq.onChannelClosed(channel, i, i2);
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public final void onInputClosed(Channel channel, int i, int i2) {
        this.zzeq.onInputClosed(channel, i, i2);
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public final void onOutputClosed(Channel channel, int i, int i2) {
        this.zzeq.onOutputClosed(channel, i, i2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof zzgc)) {
            return false;
        }
        zzgc zzgcVar = (zzgc) obj;
        return this.zzeq.equals(zzgcVar.zzeq) && this.zzce.equals(zzgcVar.zzce);
    }

    public final int hashCode() {
        return (this.zzce.hashCode() * 31) + this.zzeq.hashCode();
    }
}
