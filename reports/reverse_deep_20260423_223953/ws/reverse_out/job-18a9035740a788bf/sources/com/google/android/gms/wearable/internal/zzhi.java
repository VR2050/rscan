package com.google.android.gms.wearable.internal;

import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
final class zzhi implements Runnable {
    private final /* synthetic */ Uri zzco;
    private final /* synthetic */ boolean zzcp;
    private final /* synthetic */ String zzcs;
    private final /* synthetic */ BaseImplementation.ResultHolder zzfh;
    private final /* synthetic */ zzhg zzfi;

    zzhi(zzhg zzhgVar, Uri uri, BaseImplementation.ResultHolder resultHolder, boolean z, String str) {
        this.zzfi = zzhgVar;
        this.zzco = uri;
        this.zzfh = resultHolder;
        this.zzcp = z;
        this.zzcs = str;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v14, types: [android.os.ParcelFileDescriptor] */
    /* JADX WARN: Type inference failed for: r2v5, types: [java.io.File, java.lang.Object] */
    @Override // java.lang.Runnable
    public final void run() {
        if (Log.isLoggable("WearableClient", 2)) {
            Log.v("WearableClient", "Executing receiveFileFromChannelTask");
        }
        if (!"file".equals(this.zzco.getScheme())) {
            Log.w("WearableClient", "Channel.receiveFile used with non-file URI");
            this.zzfh.setFailedResult(new Status(10, "Channel.receiveFile used with non-file URI"));
            return;
        }
        ParcelFileDescriptor file = new File(this.zzco.getPath());
        try {
            try {
                file = ParcelFileDescriptor.open(file, 671088640 | (this.zzcp ? ConnectionsManager.FileTypeVideo : 0));
                try {
                    ((zzep) this.zzfi.getService()).zza(new zzhf(this.zzfh), this.zzcs, (ParcelFileDescriptor) file);
                } catch (RemoteException e) {
                    Log.w("WearableClient", "Channel.receiveFile failed.", e);
                    this.zzfh.setFailedResult(new Status(8));
                    try {
                        file.close();
                    } catch (IOException e2) {
                        Log.w("WearableClient", "Failed to close targetFd", e2);
                    }
                }
            } catch (FileNotFoundException e3) {
                String strValueOf = String.valueOf((Object) file);
                StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 49);
                sb.append("File couldn't be opened for Channel.receiveFile: ");
                sb.append(strValueOf);
                Log.w("WearableClient", sb.toString());
                this.zzfh.setFailedResult(new Status(13));
            }
        } finally {
            try {
                file.close();
            } catch (IOException e4) {
                Log.w("WearableClient", "Failed to close targetFd", e4);
            }
        }
    }
}
