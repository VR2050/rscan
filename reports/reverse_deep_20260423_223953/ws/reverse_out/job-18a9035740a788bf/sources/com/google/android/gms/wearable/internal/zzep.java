package com.google.android.gms.wearable.internal;

import android.net.Uri;
import android.os.IInterface;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import com.google.android.gms.wearable.Asset;
import com.google.android.gms.wearable.PutDataRequest;

/* JADX INFO: loaded from: classes.dex */
public interface zzep extends IInterface {
    void zza(zzek zzekVar) throws RemoteException;

    void zza(zzek zzekVar, int i) throws RemoteException;

    void zza(zzek zzekVar, Uri uri) throws RemoteException;

    void zza(zzek zzekVar, Uri uri, int i) throws RemoteException;

    void zza(zzek zzekVar, Asset asset) throws RemoteException;

    void zza(zzek zzekVar, PutDataRequest putDataRequest) throws RemoteException;

    void zza(zzek zzekVar, zzd zzdVar) throws RemoteException;

    void zza(zzek zzekVar, zzei zzeiVar, String str) throws RemoteException;

    void zza(zzek zzekVar, zzfw zzfwVar) throws RemoteException;

    void zza(zzek zzekVar, String str) throws RemoteException;

    void zza(zzek zzekVar, String str, int i) throws RemoteException;

    void zza(zzek zzekVar, String str, ParcelFileDescriptor parcelFileDescriptor) throws RemoteException;

    void zza(zzek zzekVar, String str, ParcelFileDescriptor parcelFileDescriptor, long j, long j2) throws RemoteException;

    void zza(zzek zzekVar, String str, String str2) throws RemoteException;

    void zza(zzek zzekVar, String str, String str2, byte[] bArr) throws RemoteException;

    void zzb(zzek zzekVar) throws RemoteException;

    void zzb(zzek zzekVar, Uri uri, int i) throws RemoteException;

    void zzb(zzek zzekVar, zzei zzeiVar, String str) throws RemoteException;

    void zzb(zzek zzekVar, String str) throws RemoteException;

    void zzb(zzek zzekVar, String str, int i) throws RemoteException;

    void zzc(zzek zzekVar) throws RemoteException;

    void zzc(zzek zzekVar, String str) throws RemoteException;
}
