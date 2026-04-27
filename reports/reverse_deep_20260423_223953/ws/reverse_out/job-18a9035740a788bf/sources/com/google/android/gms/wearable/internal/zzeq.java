package com.google.android.gms.wearable.internal;

import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import com.google.android.gms.wearable.Asset;
import com.google.android.gms.wearable.PutDataRequest;

/* JADX INFO: loaded from: classes.dex */
public final class zzeq extends com.google.android.gms.internal.wearable.zza implements zzep {
    zzeq(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.wearable.internal.IWearableService");
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, PutDataRequest putDataRequest) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, putDataRequest);
        transactAndReadExceptionReturnVoid(6, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, Uri uri) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, uri);
        transactAndReadExceptionReturnVoid(7, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        transactAndReadExceptionReturnVoid(8, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, Uri uri, int i) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, uri);
        parcelObtainAndWriteInterfaceToken.writeInt(i);
        transactAndReadExceptionReturnVoid(40, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zzb(zzek zzekVar, Uri uri, int i) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, uri);
        parcelObtainAndWriteInterfaceToken.writeInt(i);
        transactAndReadExceptionReturnVoid(41, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, String str, String str2, byte[] bArr) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        parcelObtainAndWriteInterfaceToken.writeString(str2);
        parcelObtainAndWriteInterfaceToken.writeByteArray(bArr);
        transactAndReadExceptionReturnVoid(12, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, Asset asset) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, asset);
        transactAndReadExceptionReturnVoid(13, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zzb(zzek zzekVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        transactAndReadExceptionReturnVoid(14, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zzc(zzek zzekVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        transactAndReadExceptionReturnVoid(15, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, String str, int i) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        parcelObtainAndWriteInterfaceToken.writeInt(i);
        transactAndReadExceptionReturnVoid(42, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, int i) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeInt(i);
        transactAndReadExceptionReturnVoid(43, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, String str) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        transactAndReadExceptionReturnVoid(46, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zzb(zzek zzekVar, String str) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        transactAndReadExceptionReturnVoid(47, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, zzd zzdVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzdVar);
        transactAndReadExceptionReturnVoid(16, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, zzfw zzfwVar) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzfwVar);
        transactAndReadExceptionReturnVoid(17, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, String str, String str2) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        parcelObtainAndWriteInterfaceToken.writeString(str2);
        transactAndReadExceptionReturnVoid(31, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zzc(zzek zzekVar, String str) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        transactAndReadExceptionReturnVoid(32, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zzb(zzek zzekVar, String str, int i) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        parcelObtainAndWriteInterfaceToken.writeInt(i);
        transactAndReadExceptionReturnVoid(33, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, zzei zzeiVar, String str) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzeiVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        transactAndReadExceptionReturnVoid(34, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zzb(zzek zzekVar, zzei zzeiVar, String str) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzeiVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        transactAndReadExceptionReturnVoid(35, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, String str, ParcelFileDescriptor parcelFileDescriptor) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, parcelFileDescriptor);
        transactAndReadExceptionReturnVoid(38, parcelObtainAndWriteInterfaceToken);
    }

    @Override // com.google.android.gms.wearable.internal.zzep
    public final void zza(zzek zzekVar, String str, ParcelFileDescriptor parcelFileDescriptor, long j, long j2) throws RemoteException {
        Parcel parcelObtainAndWriteInterfaceToken = obtainAndWriteInterfaceToken();
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, zzekVar);
        parcelObtainAndWriteInterfaceToken.writeString(str);
        com.google.android.gms.internal.wearable.zzc.zza(parcelObtainAndWriteInterfaceToken, parcelFileDescriptor);
        parcelObtainAndWriteInterfaceToken.writeLong(j);
        parcelObtainAndWriteInterfaceToken.writeLong(j2);
        transactAndReadExceptionReturnVoid(39, parcelObtainAndWriteInterfaceToken);
    }
}
