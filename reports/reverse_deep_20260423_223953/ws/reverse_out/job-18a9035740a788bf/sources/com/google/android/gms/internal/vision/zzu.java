package com.google.android.gms.internal.vision;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;

/* JADX INFO: loaded from: classes.dex */
public final class zzu extends zza implements zzt {
    zzu(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.vision.text.internal.client.INativeTextRecognizer");
    }

    @Override // com.google.android.gms.internal.vision.zzt
    public final zzx[] zza(IObjectWrapper iObjectWrapper, zzm zzmVar, zzz zzzVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        zzc.zza(parcelObtainAndWriteInterfaceToken, iObjectWrapper);
        zzc.zza(parcelObtainAndWriteInterfaceToken, zzmVar);
        zzc.zza(parcelObtainAndWriteInterfaceToken, zzzVar);
        Parcel parcelTransactAndReadException = transactAndReadException(3, parcelObtainAndWriteInterfaceToken);
        zzx[] zzxVarArr = (zzx[]) parcelTransactAndReadException.createTypedArray(zzx.CREATOR);
        parcelTransactAndReadException.recycle();
        return zzxVarArr;
    }

    @Override // com.google.android.gms.internal.vision.zzt
    public final void zzq() throws RemoteException {
        transactAndReadExceptionReturnVoid(2, obtainAndWriteInterfaceToken());
    }
}
