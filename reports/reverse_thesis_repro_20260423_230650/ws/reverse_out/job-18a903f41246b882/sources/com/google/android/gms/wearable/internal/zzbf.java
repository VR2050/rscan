package com.google.android.gms.wearable.internal;

import android.content.IntentFilter;
import android.os.RemoteException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.wearable.ChannelApi;

/* JADX INFO: loaded from: classes.dex */
final class zzbf implements zzc<ChannelApi.ChannelListener> {
    private final /* synthetic */ IntentFilter[] zzbr;
    private final /* synthetic */ String zzcs;

    zzbf(String str, IntentFilter[] intentFilterArr) {
        this.zzcs = str;
        this.zzbr = intentFilterArr;
    }

    @Override // com.google.android.gms.wearable.internal.zzc
    public final /* synthetic */ void zza(zzhg zzhgVar, BaseImplementation.ResultHolder resultHolder, ChannelApi.ChannelListener channelListener, ListenerHolder<ChannelApi.ChannelListener> listenerHolder) throws RemoteException {
        zzhgVar.zza((BaseImplementation.ResultHolder<Status>) resultHolder, channelListener, listenerHolder, this.zzcs, this.zzbr);
    }
}
