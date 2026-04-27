package com.google.android.gms.internal.vision;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.vision.barcode.Barcode;

/* JADX INFO: loaded from: classes.dex */
public final class zzi extends zza implements zzh {
    zzi(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.vision.barcode.internal.client.INativeBarcodeDetector");
    }

    @Override // com.google.android.gms.internal.vision.zzh
    public final Barcode[] zza(IObjectWrapper iObjectWrapper, zzm zzmVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        zzc.zza(parcelObtainAndWriteInterfaceToken, iObjectWrapper);
        zzc.zza(parcelObtainAndWriteInterfaceToken, zzmVar);
        Parcel parcelTransactAndReadException = transactAndReadException(1, parcelObtainAndWriteInterfaceToken);
        Barcode[] barcodeArr = (Barcode[]) parcelTransactAndReadException.createTypedArray(Barcode.CREATOR);
        parcelTransactAndReadException.recycle();
        return barcodeArr;
    }

    @Override // com.google.android.gms.internal.vision.zzh
    public final Barcode[] zzb(IObjectWrapper iObjectWrapper, zzm zzmVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        zzc.zza(parcelObtainAndWriteInterfaceToken, iObjectWrapper);
        zzc.zza(parcelObtainAndWriteInterfaceToken, zzmVar);
        Parcel parcelTransactAndReadException = transactAndReadException(2, parcelObtainAndWriteInterfaceToken);
        Barcode[] barcodeArr = (Barcode[]) parcelTransactAndReadException.createTypedArray(Barcode.CREATOR);
        parcelTransactAndReadException.recycle();
        return barcodeArr;
    }

    @Override // com.google.android.gms.internal.vision.zzh
    public final void zzn() throws RemoteException {
        transactAndReadExceptionReturnVoid(3, obtainAndWriteInterfaceToken());
    }
}
