package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.wearable.ChannelIOException;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes.dex */
public final class zzbj extends InputStream {
    private final InputStream zzcv;

    @Nullable
    private volatile zzav zzcw;

    public zzbj(InputStream inputStream) {
        this.zzcv = (InputStream) Preconditions.checkNotNull(inputStream);
    }

    final void zza(zzav zzavVar) {
        this.zzcw = (zzav) Preconditions.checkNotNull(zzavVar);
    }

    @Override // java.io.InputStream
    public final int available() throws IOException {
        return this.zzcv.available();
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        this.zzcv.close();
    }

    @Override // java.io.InputStream
    public final void mark(int i) {
        this.zzcv.mark(i);
    }

    @Override // java.io.InputStream
    public final boolean markSupported() {
        return this.zzcv.markSupported();
    }

    @Override // java.io.InputStream
    public final int read() throws IOException {
        return zza(this.zzcv.read());
    }

    @Override // java.io.InputStream
    public final int read(byte[] bArr) throws IOException {
        return zza(this.zzcv.read(bArr));
    }

    @Override // java.io.InputStream
    public final int read(byte[] bArr, int i, int i2) throws IOException {
        return zza(this.zzcv.read(bArr, i, i2));
    }

    @Override // java.io.InputStream
    public final void reset() throws IOException {
        this.zzcv.reset();
    }

    @Override // java.io.InputStream
    public final long skip(long j) throws IOException {
        return this.zzcv.skip(j);
    }

    private final int zza(int i) throws ChannelIOException {
        zzav zzavVar;
        if (i == -1 && (zzavVar = this.zzcw) != null) {
            throw new ChannelIOException("Channel closed unexpectedly before stream was finished", zzavVar.zzg, zzavVar.zzcj);
        }
        return i;
    }
}
