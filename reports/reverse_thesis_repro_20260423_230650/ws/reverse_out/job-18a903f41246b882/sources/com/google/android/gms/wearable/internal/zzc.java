package com.google.android.gms.wearable.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.common.api.internal.ListenerHolder;

/* JADX INFO: loaded from: classes.dex */
interface zzc<T> {
    void zza(zzhg zzhgVar, BaseImplementation.ResultHolder<Status> resultHolder, T t, ListenerHolder<T> listenerHolder) throws RemoteException;
}
