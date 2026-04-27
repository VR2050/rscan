package com.facebook.soloader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/* JADX INFO: loaded from: classes.dex */
public class j implements h {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private InputStream f8359b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ZipEntry f8360c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ZipFile f8361d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final long f8362e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f8363f = true;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private long f8364g = 0;

    public j(ZipFile zipFile, ZipEntry zipEntry) throws IOException {
        this.f8361d = zipFile;
        this.f8360c = zipEntry;
        this.f8362e = zipEntry.getSize();
        InputStream inputStream = zipFile.getInputStream(zipEntry);
        this.f8359b = inputStream;
        if (inputStream != null) {
            return;
        }
        throw new IOException(zipEntry.getName() + "'s InputStream is null");
    }

    @Override // com.facebook.soloader.h
    public int Y(ByteBuffer byteBuffer, long j3) throws IOException {
        if (this.f8359b == null) {
            throw new IOException("InputStream is null");
        }
        int iRemaining = byteBuffer.remaining();
        long j4 = this.f8362e - j3;
        if (j4 <= 0) {
            return -1;
        }
        int i3 = (int) j4;
        if (iRemaining > i3) {
            iRemaining = i3;
        }
        b(j3);
        if (byteBuffer.hasArray()) {
            this.f8359b.read(byteBuffer.array(), 0, iRemaining);
            byteBuffer.position(byteBuffer.position() + iRemaining);
        } else {
            byte[] bArr = new byte[iRemaining];
            this.f8359b.read(bArr, 0, iRemaining);
            byteBuffer.put(bArr, 0, iRemaining);
        }
        this.f8364g += (long) iRemaining;
        return iRemaining;
    }

    public h b(long j3) throws IOException {
        InputStream inputStream = this.f8359b;
        if (inputStream == null) {
            throw new IOException(this.f8360c.getName() + "'s InputStream is null");
        }
        long j4 = this.f8364g;
        if (j3 == j4) {
            return this;
        }
        long j5 = this.f8362e;
        if (j3 > j5) {
            j3 = j5;
        }
        if (j3 >= j4) {
            inputStream.skip(j3 - j4);
        } else {
            inputStream.close();
            InputStream inputStream2 = this.f8361d.getInputStream(this.f8360c);
            this.f8359b = inputStream2;
            if (inputStream2 == null) {
                throw new IOException(this.f8360c.getName() + "'s InputStream is null");
            }
            inputStream2.skip(j3);
        }
        this.f8364g = j3;
        return this;
    }

    @Override // java.nio.channels.Channel, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        InputStream inputStream = this.f8359b;
        if (inputStream != null) {
            inputStream.close();
            this.f8363f = false;
        }
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return this.f8363f;
    }

    @Override // java.nio.channels.ReadableByteChannel
    public int read(ByteBuffer byteBuffer) {
        return Y(byteBuffer, this.f8364g);
    }

    @Override // java.nio.channels.WritableByteChannel
    public int write(ByteBuffer byteBuffer) {
        throw new UnsupportedOperationException("ElfZipFileChannel doesn't support write");
    }
}
