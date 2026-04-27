package com.google.android.gms.maps.internal;

import android.os.Parcel;
import android.os.RemoteException;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzaa extends com.google.android.gms.internal.maps.zzb implements zzz {
    public zzaa() {
        super("com.google.android.gms.maps.internal.IOnIndoorStateChangeListener");
    }

    @Override // com.google.android.gms.internal.maps.zzb
    protected final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i == 1) {
            onIndoorBuildingFocused();
        } else if (i == 2) {
            zza(com.google.android.gms.internal.maps.zzo.zze(parcel.readStrongBinder()));
        } else {
            return false;
        }
        parcel2.writeNoException();
        return true;
    }
}
