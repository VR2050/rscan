package com.google.android.gms.wearable.internal;

import android.os.ParcelFileDescriptor;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.DataApi;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes.dex */
public final class zzci implements DataApi.GetFdForAssetResult {
    private volatile boolean closed = false;
    private volatile InputStream zzct;
    private volatile ParcelFileDescriptor zzf;
    private final Status zzp;

    public zzci(Status status, ParcelFileDescriptor parcelFileDescriptor) {
        this.zzp = status;
        this.zzf = parcelFileDescriptor;
    }

    @Override // com.google.android.gms.common.api.Result
    public final Status getStatus() {
        return this.zzp;
    }

    @Override // com.google.android.gms.wearable.DataApi.GetFdForAssetResult
    public final ParcelFileDescriptor getFd() {
        if (this.closed) {
            throw new IllegalStateException("Cannot access the file descriptor after release().");
        }
        return this.zzf;
    }

    @Override // com.google.android.gms.wearable.DataApi.GetFdForAssetResult
    public final InputStream getInputStream() {
        if (this.closed) {
            throw new IllegalStateException("Cannot access the input stream after release().");
        }
        if (this.zzf == null) {
            return null;
        }
        if (this.zzct == null) {
            this.zzct = new ParcelFileDescriptor.AutoCloseInputStream(this.zzf);
        }
        return this.zzct;
    }

    @Override // com.google.android.gms.common.api.Releasable
    public final void release() {
        if (this.zzf == null) {
            return;
        }
        if (this.closed) {
            throw new IllegalStateException("releasing an already released result.");
        }
        try {
            if (this.zzct != null) {
                this.zzct.close();
            } else {
                this.zzf.close();
            }
            this.closed = true;
            this.zzf = null;
            this.zzct = null;
        } catch (IOException e) {
        }
    }
}
