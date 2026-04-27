package com.facebook.soloader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

/* JADX INFO: loaded from: classes.dex */
public class i implements h {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private File f8356b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private FileInputStream f8357c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private FileChannel f8358d;

    public i(File file) {
        this.f8356b = file;
        b();
    }

    @Override // com.facebook.soloader.h
    public int Y(ByteBuffer byteBuffer, long j3) {
        return this.f8358d.read(byteBuffer, j3);
    }

    public void b() {
        FileInputStream fileInputStream = new FileInputStream(this.f8356b);
        this.f8357c = fileInputStream;
        this.f8358d = fileInputStream.getChannel();
    }

    @Override // java.nio.channels.Channel, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.f8357c.close();
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return this.f8358d.isOpen();
    }

    @Override // java.nio.channels.ReadableByteChannel
    public int read(ByteBuffer byteBuffer) {
        return this.f8358d.read(byteBuffer);
    }

    @Override // java.nio.channels.WritableByteChannel
    public int write(ByteBuffer byteBuffer) {
        return this.f8358d.write(byteBuffer);
    }
}
