package com.google.android.gms.wearable.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.common.api.internal.UnregisterListenerMethod;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.wearable.MessageClient;

/* JADX INFO: loaded from: classes.dex */
final class zzfd extends UnregisterListenerMethod<zzhg, MessageClient.OnMessageReceivedListener> {
    private final MessageClient.OnMessageReceivedListener zzej;

    private zzfd(MessageClient.OnMessageReceivedListener onMessageReceivedListener, ListenerHolder.ListenerKey<MessageClient.OnMessageReceivedListener> listenerKey) {
        super(listenerKey);
        this.zzej = onMessageReceivedListener;
    }

    @Override // com.google.android.gms.common.api.internal.UnregisterListenerMethod
    protected final /* synthetic */ void unregisterListener(Api.AnyClient anyClient, TaskCompletionSource taskCompletionSource) throws RemoteException {
        ((zzhg) anyClient).zza(new zzgg(taskCompletionSource), this.zzej);
    }
}
