package com.google.android.gms.wearable.internal;

import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.IOException;
import java.util.concurrent.Callable;

/* JADX INFO: loaded from: classes.dex */
final class zzhh implements Callable<Boolean> {
    private final /* synthetic */ byte[] zzee;
    private final /* synthetic */ ParcelFileDescriptor zzfg;

    zzhh(zzhg zzhgVar, ParcelFileDescriptor parcelFileDescriptor, byte[] bArr) {
        this.zzfg = parcelFileDescriptor;
        this.zzee = bArr;
    }

    /* JADX INFO: Access modifiers changed from: private */
    @Override // java.util.concurrent.Callable
    /* JADX INFO: renamed from: zzd, reason: merged with bridge method [inline-methods] */
    public final Boolean call() {
        if (Log.isLoggable("WearableClient", 3)) {
            String strValueOf = String.valueOf(this.zzfg);
            StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 36);
            sb.append("processAssets: writing data to FD : ");
            sb.append(strValueOf);
            Log.d("WearableClient", sb.toString());
        }
        ParcelFileDescriptor.AutoCloseOutputStream autoCloseOutputStream = new ParcelFileDescriptor.AutoCloseOutputStream(this.zzfg);
        try {
            try {
                autoCloseOutputStream.write(this.zzee);
                autoCloseOutputStream.flush();
                if (Log.isLoggable("WearableClient", 3)) {
                    String strValueOf2 = String.valueOf(this.zzfg);
                    StringBuilder sb2 = new StringBuilder(String.valueOf(strValueOf2).length() + 27);
                    sb2.append("processAssets: wrote data: ");
                    sb2.append(strValueOf2);
                    Log.d("WearableClient", sb2.toString());
                }
                return true;
            } catch (IOException e) {
                String strValueOf3 = String.valueOf(this.zzfg);
                StringBuilder sb3 = new StringBuilder(String.valueOf(strValueOf3).length() + 36);
                sb3.append("processAssets: writing data failed: ");
                sb3.append(strValueOf3);
                Log.w("WearableClient", sb3.toString());
                try {
                    if (Log.isLoggable("WearableClient", 3)) {
                        String strValueOf4 = String.valueOf(this.zzfg);
                        StringBuilder sb4 = new StringBuilder(String.valueOf(strValueOf4).length() + 24);
                        sb4.append("processAssets: closing: ");
                        sb4.append(strValueOf4);
                        Log.d("WearableClient", sb4.toString());
                    }
                    autoCloseOutputStream.close();
                } catch (IOException e2) {
                }
                return false;
            }
        } finally {
            try {
                if (Log.isLoggable("WearableClient", 3)) {
                    String strValueOf5 = String.valueOf(this.zzfg);
                    StringBuilder sb5 = new StringBuilder(String.valueOf(strValueOf5).length() + 24);
                    sb5.append("processAssets: closing: ");
                    sb5.append(strValueOf5);
                    Log.d("WearableClient", sb5.toString());
                }
                autoCloseOutputStream.close();
            } catch (IOException e3) {
            }
        }
    }
}
