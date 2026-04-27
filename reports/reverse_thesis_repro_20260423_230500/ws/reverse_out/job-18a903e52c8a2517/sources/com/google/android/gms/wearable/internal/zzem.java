package com.google.android.gms.wearable.internal;

import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.common.data.DataHolder;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public interface zzem extends IInterface {
    void onConnectedNodes(List<zzfo> list) throws RemoteException;

    void zza(DataHolder dataHolder) throws RemoteException;

    void zza(zzah zzahVar) throws RemoteException;

    void zza(zzaw zzawVar) throws RemoteException;

    void zza(zzfe zzfeVar) throws RemoteException;

    void zza(zzfo zzfoVar) throws RemoteException;

    void zza(zzi zziVar) throws RemoteException;

    void zza(zzl zzlVar) throws RemoteException;

    void zzb(zzfo zzfoVar) throws RemoteException;
}
