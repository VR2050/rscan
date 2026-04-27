package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes.dex */
final class zzam implements ChannelApi.OpenChannelResult {
    private final Channel zzcd;
    private final Status zzp;

    zzam(Status status, @Nullable Channel channel) {
        this.zzp = (Status) Preconditions.checkNotNull(status);
        this.zzcd = channel;
    }

    @Override // com.google.android.gms.common.api.Result
    public final Status getStatus() {
        return this.zzp;
    }

    @Override // com.google.android.gms.wearable.ChannelApi.OpenChannelResult
    @Nullable
    public final Channel getChannel() {
        return this.zzcd;
    }
}
