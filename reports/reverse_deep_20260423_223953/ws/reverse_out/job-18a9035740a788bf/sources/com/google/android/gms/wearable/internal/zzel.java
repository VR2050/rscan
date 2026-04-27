package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.data.DataHolder;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzel extends com.google.android.gms.internal.wearable.zzb implements zzek {
    public zzel() {
        super("com.google.android.gms.wearable.internal.IWearableCallbacks");
    }

    @Override // com.google.android.gms.internal.wearable.zzb
    protected final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        switch (i) {
            case 2:
                zza((zzdw) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdw.CREATOR));
                break;
            case 3:
                zza((zzfu) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzfu.CREATOR));
                break;
            case 4:
                zza((zzec) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzec.CREATOR));
                break;
            case 5:
                zzb((DataHolder) com.google.android.gms.internal.wearable.zzc.zza(parcel, DataHolder.CREATOR));
                break;
            case 6:
                zza((zzdg) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdg.CREATOR));
                break;
            case 7:
                zza((zzga) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzga.CREATOR));
                break;
            case 8:
                zza((zzee) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzee.CREATOR));
                break;
            case 9:
                zza((zzeg) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzeg.CREATOR));
                break;
            case 10:
                zza((zzea) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzea.CREATOR));
                break;
            case 11:
                zza((Status) com.google.android.gms.internal.wearable.zzc.zza(parcel, Status.CREATOR));
                break;
            case 12:
                zza((zzge) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzge.CREATOR));
                break;
            case 13:
                zza((zzdy) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdy.CREATOR));
                break;
            case 14:
                zza((zzfq) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzfq.CREATOR));
                break;
            case 15:
                zza((zzbt) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzbt.CREATOR));
                break;
            case 16:
                zzb((zzbt) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzbt.CREATOR));
                break;
            case 17:
                zza((zzdm) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdm.CREATOR));
                break;
            case 18:
                zza((zzdo) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdo.CREATOR));
                break;
            case 19:
                zza((zzbn) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzbn.CREATOR));
                break;
            case 20:
                zza((zzbp) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzbp.CREATOR));
                break;
            case 21:
            case 24:
            case 25:
            default:
                return false;
            case 22:
                zza((zzdk) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdk.CREATOR));
                break;
            case 23:
                zza((zzdi) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdi.CREATOR));
                break;
            case 26:
                zza((zzf) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzf.CREATOR));
                break;
            case 27:
                zza((zzfy) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzfy.CREATOR));
                break;
            case 28:
                zza((zzdr) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdr.CREATOR));
                break;
            case 29:
                zza((zzdv) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdv.CREATOR));
                break;
            case 30:
                zza((zzdt) com.google.android.gms.internal.wearable.zzc.zza(parcel, zzdt.CREATOR));
                break;
        }
        parcel2.writeNoException();
        return true;
    }
}
