package com.google.android.gms.wearable.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.common.data.DataHolder;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class zzeo extends com.google.android.gms.internal.wearable.zza implements zzem {
    zzeo(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.wearable.internal.IWearableListener");
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(DataHolder dataHolder) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, dataHolder);
        transactOneway(1, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzfe zzfeVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzfeVar);
        transactOneway(2, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzfo zzfoVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzfoVar);
        transactOneway(3, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zzb(zzfo zzfoVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzfoVar);
        transactOneway(4, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void onConnectedNodes(List<zzfo> list) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        parcelObtainAndWriteInterfaceToken.writeTypedList(list);
        transactOneway(5, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzl zzlVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzlVar);
        transactOneway(6, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzaw zzawVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzawVar);
        transactOneway(7, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzah zzahVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzahVar);
        transactOneway(8, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzi zziVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zziVar);
        transactOneway(9, parcelObtainAndWriteInterfaceToken);
    }
}
