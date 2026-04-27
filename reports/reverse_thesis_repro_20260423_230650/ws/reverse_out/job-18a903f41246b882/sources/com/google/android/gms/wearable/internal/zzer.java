package com.google.android.gms.wearable.internal;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.wearable.WearableStatusCodes;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzer<T> {
    private final Map<T, zzhk<T>> zzeb = new HashMap();

    zzer() {
    }

    public final void zza(IBinder iBinder) {
        zzep zzeqVar;
        synchronized (this.zzeb) {
            if (iBinder == null) {
                zzeqVar = null;
            } else {
                IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.wearable.internal.IWearableService");
                if (iInterfaceQueryLocalInterface instanceof zzep) {
                    zzeqVar = (zzep) iInterfaceQueryLocalInterface;
                } else {
                    zzeqVar = new zzeq(iBinder);
                }
            }
            zzgz zzgzVar = new zzgz();
            for (Map.Entry<T, zzhk<T>> entry : this.zzeb.entrySet()) {
                zzhk<T> value = entry.getValue();
                try {
                    zzeqVar.zza(zzgzVar, new zzd(value));
                    if (Log.isLoggable("WearableClient", 3)) {
                        String strValueOf = String.valueOf(entry.getKey());
                        String strValueOf2 = String.valueOf(value);
                        StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 27 + String.valueOf(strValueOf2).length());
                        sb.append("onPostInitHandler: added: ");
                        sb.append(strValueOf);
                        sb.append("/");
                        sb.append(strValueOf2);
                        Log.d("WearableClient", sb.toString());
                    }
                } catch (RemoteException e) {
                    String strValueOf3 = String.valueOf(entry.getKey());
                    String strValueOf4 = String.valueOf(value);
                    StringBuilder sb2 = new StringBuilder(String.valueOf(strValueOf3).length() + 32 + String.valueOf(strValueOf4).length());
                    sb2.append("onPostInitHandler: Didn't add: ");
                    sb2.append(strValueOf3);
                    sb2.append("/");
                    sb2.append(strValueOf4);
                    Log.w("WearableClient", sb2.toString());
                }
            }
        }
    }

    public final void zza(zzhg zzhgVar, BaseImplementation.ResultHolder<Status> resultHolder, T t, zzhk<T> zzhkVar) throws RemoteException {
        synchronized (this.zzeb) {
            if (this.zzeb.get(t) != null) {
                if (Log.isLoggable("WearableClient", 2)) {
                    String strValueOf = String.valueOf(t);
                    StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 20);
                    sb.append("duplicate listener: ");
                    sb.append(strValueOf);
                    Log.v("WearableClient", sb.toString());
                }
                resultHolder.setResult(new Status(WearableStatusCodes.DUPLICATE_LISTENER));
                return;
            }
            if (Log.isLoggable("WearableClient", 2)) {
                String strValueOf2 = String.valueOf(t);
                StringBuilder sb2 = new StringBuilder(String.valueOf(strValueOf2).length() + 14);
                sb2.append("new listener: ");
                sb2.append(strValueOf2);
                Log.v("WearableClient", sb2.toString());
            }
            this.zzeb.put(t, zzhkVar);
            try {
                ((zzep) zzhgVar.getService()).zza(new zzes(this.zzeb, t, resultHolder), new zzd(zzhkVar));
            } catch (RemoteException e) {
                if (Log.isLoggable("WearableClient", 3)) {
                    String strValueOf3 = String.valueOf(t);
                    StringBuilder sb3 = new StringBuilder(String.valueOf(strValueOf3).length() + 39);
                    sb3.append("addListener failed, removing listener: ");
                    sb3.append(strValueOf3);
                    Log.d("WearableClient", sb3.toString());
                }
                this.zzeb.remove(t);
                throw e;
            }
        }
    }

    public final void zza(zzhg zzhgVar, BaseImplementation.ResultHolder<Status> resultHolder, T t) throws RemoteException {
        synchronized (this.zzeb) {
            zzhk<T> zzhkVarRemove = this.zzeb.remove(t);
            if (zzhkVarRemove == null) {
                if (Log.isLoggable("WearableClient", 2)) {
                    String strValueOf = String.valueOf(t);
                    StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 25);
                    sb.append("remove Listener unknown: ");
                    sb.append(strValueOf);
                    Log.v("WearableClient", sb.toString());
                }
                resultHolder.setResult(new Status(WearableStatusCodes.UNKNOWN_LISTENER));
                return;
            }
            zzhkVarRemove.clear();
            if (Log.isLoggable("WearableClient", 2)) {
                String strValueOf2 = String.valueOf(t);
                StringBuilder sb2 = new StringBuilder(String.valueOf(strValueOf2).length() + 24);
                sb2.append("service.removeListener: ");
                sb2.append(strValueOf2);
                Log.v("WearableClient", sb2.toString());
            }
            ((zzep) zzhgVar.getService()).zza(new zzet(this.zzeb, t, resultHolder), new zzfw(zzhkVarRemove));
        }
    }
}
