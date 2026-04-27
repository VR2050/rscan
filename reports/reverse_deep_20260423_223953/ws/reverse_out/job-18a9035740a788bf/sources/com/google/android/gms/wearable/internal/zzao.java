package com.google.android.gms.wearable.internal;

import android.app.Activity;
import android.content.Context;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Looper;
import com.google.android.gms.common.api.GoogleApi;
import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.common.api.internal.ListenerHolders;
import com.google.android.gms.common.internal.PendingResultUtil;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelClient;
import java.io.InputStream;
import java.io.OutputStream;

/* JADX INFO: loaded from: classes.dex */
public final class zzao extends ChannelClient {
    private final zzaj zzcg;

    public zzao(Context context, GoogleApi.Settings settings) {
        super(context, settings);
        this.zzcg = new zzaj();
    }

    public zzao(Activity activity, GoogleApi.Settings settings) {
        super(activity, settings);
        this.zzcg = new zzaj();
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<ChannelClient.Channel> openChannel(String str, String str2) {
        return PendingResultUtil.toTask(this.zzcg.openChannel(asGoogleApiClient(), str, str2), zzap.zzbx);
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Void> registerChannelCallback(ChannelClient.ChannelCallback channelCallback) {
        Preconditions.checkNotNull(channelCallback, "listener is null");
        ListenerHolder listenerHolderCreateListenerHolder = ListenerHolders.createListenerHolder(channelCallback, getLooper(), "ChannelListener");
        IntentFilter[] intentFilterArr = {zzgj.zzc("com.google.android.gms.wearable.CHANNEL_EVENT")};
        zzas zzasVar = new zzas(channelCallback);
        return doRegisterEventListener(new zzat(zzasVar, null, intentFilterArr, listenerHolderCreateListenerHolder, ListenerHolders.createListenerHolder(zzasVar, getLooper(), "ChannelListener")), new zzau(zzasVar, null, listenerHolderCreateListenerHolder.getListenerKey()));
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Boolean> unregisterChannelCallback(ChannelClient.ChannelCallback channelCallback) {
        return doUnregisterEventListener(ListenerHolders.createListenerHolder(channelCallback, getLooper(), "ChannelListener").getListenerKey());
    }

    private static zzay zza(ChannelClient.Channel channel) {
        Preconditions.checkNotNull(channel, "channel must not be null");
        return (zzay) channel;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static zzay zza(Channel channel) {
        Preconditions.checkNotNull(channel, "channel must not be null");
        return (zzay) channel;
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Void> close(ChannelClient.Channel channel) {
        return PendingResultUtil.toVoidTask(zza(channel).close(asGoogleApiClient()));
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Void> close(ChannelClient.Channel channel, int i) {
        return PendingResultUtil.toVoidTask(zza(channel).close(asGoogleApiClient(), i));
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<InputStream> getInputStream(ChannelClient.Channel channel) {
        return PendingResultUtil.toTask(zza(channel).getInputStream(asGoogleApiClient()), zzaq.zzbx);
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<OutputStream> getOutputStream(ChannelClient.Channel channel) {
        return PendingResultUtil.toTask(zza(channel).getOutputStream(asGoogleApiClient()), zzar.zzbx);
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Void> receiveFile(ChannelClient.Channel channel, Uri uri, boolean z) {
        return PendingResultUtil.toVoidTask(zza(channel).receiveFile(asGoogleApiClient(), uri, z));
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Void> sendFile(ChannelClient.Channel channel, Uri uri) {
        return PendingResultUtil.toVoidTask(zza(channel).sendFile(asGoogleApiClient(), uri));
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Void> sendFile(ChannelClient.Channel channel, Uri uri, long j, long j2) {
        return PendingResultUtil.toVoidTask(zza(channel).sendFile(asGoogleApiClient(), uri, j, j2));
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Void> registerChannelCallback(ChannelClient.Channel channel, ChannelClient.ChannelCallback channelCallback) {
        String strZzc = ((zzay) channel).zzc();
        Preconditions.checkNotNull(channelCallback, "listener is null");
        Looper looper = getLooper();
        String strValueOf = String.valueOf(strZzc);
        ListenerHolder listenerHolderCreateListenerHolder = ListenerHolders.createListenerHolder(channelCallback, looper, strValueOf.length() != 0 ? "ChannelListener:".concat(strValueOf) : new String("ChannelListener:"));
        IntentFilter[] intentFilterArr = {zzgj.zzc("com.google.android.gms.wearable.CHANNEL_EVENT")};
        zzas zzasVar = new zzas(channelCallback);
        return doRegisterEventListener(new zzat(zzasVar, strZzc, intentFilterArr, listenerHolderCreateListenerHolder, ListenerHolders.createListenerHolder(zzasVar, getLooper(), "ChannelListener")), new zzau(zzasVar, strZzc, listenerHolderCreateListenerHolder.getListenerKey()));
    }

    @Override // com.google.android.gms.wearable.ChannelClient
    public final Task<Boolean> unregisterChannelCallback(ChannelClient.Channel channel, ChannelClient.ChannelCallback channelCallback) {
        String strZzc = zza(channel).zzc();
        Looper looper = getLooper();
        String strValueOf = String.valueOf(strZzc);
        return doUnregisterEventListener(ListenerHolders.createListenerHolder(channelCallback, looper, strValueOf.length() != 0 ? "ChannelListener:".concat(strValueOf) : new String("ChannelListener:")).getListenerKey());
    }
}
