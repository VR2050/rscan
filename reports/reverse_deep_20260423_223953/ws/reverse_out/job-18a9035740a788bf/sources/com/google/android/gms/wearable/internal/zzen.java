package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.common.data.DataHolder;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzen extends com.google.android.gms.internal.wearable.zzb implements zzem {
    public zzen() {
        super("com.google.android.gms.wearable.internal.IWearableListener");
    }

    @Override // com.google.android.gms.internal.wearable.zzb
    protected final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        switch (i) {
            case 1:
                zza((DataHolder) com.google.android.gms.internal.wearable.zzc.zza(parcel, DataHolder.CREATOR));
                return true;
            case 2:
                zza((zzfe) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzfe.CREATOR));
                return true;
            case 3:
                zza((zzfo) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzfo.CREATOR));
                return true;
            case 4:
                zzb((zzfo) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzfo.CREATOR));
                return true;
            case 5:
                onConnectedNodes(parcel.createTypedArrayList(zzfo.CREATOR));
                return true;
            case 6:
                zza((zzl) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzl.CREATOR));
                return true;
            case 7:
                zza((zzaw) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzaw.CREATOR));
                return true;
            case 8:
                zza((zzah) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzah.CREATOR));
                return true;
            case 9:
                zza((zzi) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzi.CREATOR));
                return true;
            default:
                return false;
        }
    }
}
