package com.google.android.gms.wearable.internal;

import android.content.IntentFilter;
import android.os.RemoteException;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.common.api.internal.RegisterListenerMethod;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.ChannelClient;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes.dex */
final class zzat extends RegisterListenerMethod<zzhg, ChannelClient.ChannelCallback> {
    private final IntentFilter[] zzba;

    @Nullable
    private final String zzce;
    private final ChannelApi.ChannelListener zzcf;
    private final ListenerHolder<ChannelApi.ChannelListener> zzci;

    zzat(ChannelApi.ChannelListener channelListener, @Nullable String str, IntentFilter[] intentFilterArr, ListenerHolder<ChannelClient.ChannelCallback> listenerHolder, ListenerHolder<ChannelApi.ChannelListener> listenerHolder2) {
        super(listenerHolder);
        this.zzcf = channelListener;
        this.zzba = intentFilterArr;
        this.zzce = str;
        this.zzci = listenerHolder2;
    }

    @Override // com.google.android.gms.common.api.internal.RegisterListenerMethod
    protected final /* synthetic */ void registerListener(Api.AnyClient anyClient, TaskCompletionSource taskCompletionSource) throws RemoteException {
        ((zzhg) anyClient).zza(new zzgh(taskCompletionSource), this.zzcf, this.zzci, this.zzce, this.zzba);
    }
}
