package com.facebook.imagepipeline.memory;

import Q0.w;
import Q0.x;
import X.k;
import android.util.Log;
import java.io.Closeable;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public class NativeMemoryChunk implements w, Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final long f6044b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f6045c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f6046d;

    static {
        Z1.a.d("imagepipeline");
    }

    public NativeMemoryChunk(int i3) {
        k.b(Boolean.valueOf(i3 > 0));
        this.f6045c = i3;
        this.f6044b = nativeAllocate(i3);
        this.f6046d = false;
    }

    private void b(int i3, w wVar, int i4, int i5) {
        if (!(wVar instanceof NativeMemoryChunk)) {
            throw new IllegalArgumentException("Cannot copy two incompatible MemoryChunks");
        }
        k.i(!a());
        k.i(!wVar.a());
        x.b(i3, wVar.i(), i4, i5, this.f6045c);
        nativeMemcpy(wVar.x() + ((long) i4), this.f6044b + ((long) i3), i5);
    }

    private static native long nativeAllocate(int i3);

    private static native void nativeCopyFromByteArray(long j3, byte[] bArr, int i3, int i4);

    private static native void nativeCopyToByteArray(long j3, byte[] bArr, int i3, int i4);

    private static native void nativeFree(long j3);

    private static native void nativeMemcpy(long j3, long j4, int i3);

    private static native byte nativeReadByte(long j3);

    @Override // Q0.w
    public synchronized boolean a() {
        return this.f6046d;
    }

    @Override // Q0.w
    public synchronized int c(int i3, byte[] bArr, int i4, int i5) {
        int iA;
        k.g(bArr);
        k.i(!a());
        iA = x.a(i3, i5, this.f6045c);
        x.b(i3, bArr.length, i4, iA, this.f6045c);
        nativeCopyToByteArray(this.f6044b + ((long) i3), bArr, i4, iA);
        return iA;
    }

    @Override // Q0.w, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        if (!this.f6046d) {
            this.f6046d = true;
            nativeFree(this.f6044b);
        }
    }

    protected void finalize() throws Throwable {
        if (a()) {
            return;
        }
        Log.w("NativeMemoryChunk", "finalize: Chunk " + Integer.toHexString(System.identityHashCode(this)) + " still active. ");
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    @Override // Q0.w
    public synchronized byte g(int i3) {
        k.i(!a());
        k.b(Boolean.valueOf(i3 >= 0));
        k.b(Boolean.valueOf(i3 < this.f6045c));
        return nativeReadByte(this.f6044b + ((long) i3));
    }

    @Override // Q0.w
    public int i() {
        return this.f6045c;
    }

    @Override // Q0.w
    public long p() {
        return this.f6044b;
    }

    @Override // Q0.w
    public ByteBuffer r() {
        return null;
    }

    @Override // Q0.w
    public synchronized int v(int i3, byte[] bArr, int i4, int i5) {
        int iA;
        k.g(bArr);
        k.i(!a());
        iA = x.a(i3, i5, this.f6045c);
        x.b(i3, bArr.length, i4, iA, this.f6045c);
        nativeCopyFromByteArray(this.f6044b + ((long) i3), bArr, i4, iA);
        return iA;
    }

    @Override // Q0.w
    public long x() {
        return this.f6044b;
    }

    @Override // Q0.w
    public void y(int i3, w wVar, int i4, int i5) {
        k.g(wVar);
        if (wVar.p() == p()) {
            Log.w("NativeMemoryChunk", "Copying from NativeMemoryChunk " + Integer.toHexString(System.identityHashCode(this)) + " to NativeMemoryChunk " + Integer.toHexString(System.identityHashCode(wVar)) + " which share the same address " + Long.toHexString(this.f6044b));
            k.b(Boolean.FALSE);
        }
        if (wVar.p() < p()) {
            synchronized (wVar) {
                synchronized (this) {
                    b(i3, wVar, i4, i5);
                }
            }
        } else {
            synchronized (this) {
                synchronized (wVar) {
                    b(i3, wVar, i4, i5);
                }
            }
        }
    }

    public NativeMemoryChunk() {
        this.f6045c = 0;
        this.f6044b = 0L;
        this.f6046d = true;
    }
}
