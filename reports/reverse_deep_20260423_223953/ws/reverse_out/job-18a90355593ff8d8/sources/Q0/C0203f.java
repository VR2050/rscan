package Q0;

import android.os.SharedMemory;
import android.system.ErrnoException;
import android.util.Log;
import java.io.Closeable;
import java.nio.ByteBuffer;

/* JADX INFO: renamed from: Q0.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0203f implements w, Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private SharedMemory f2357b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private ByteBuffer f2358c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final long f2359d;

    public C0203f(int i3) {
        X.k.b(Boolean.valueOf(i3 > 0));
        try {
            SharedMemory sharedMemoryCreate = SharedMemory.create("AshmemMemoryChunk", i3);
            this.f2357b = sharedMemoryCreate;
            this.f2358c = sharedMemoryCreate.mapReadWrite();
            this.f2359d = System.identityHashCode(this);
        } catch (ErrnoException e3) {
            throw new RuntimeException("Fail to create AshmemMemory", e3);
        }
    }

    private void b(int i3, w wVar, int i4, int i5) {
        if (!(wVar instanceof C0203f)) {
            throw new IllegalArgumentException("Cannot copy two incompatible MemoryChunks");
        }
        X.k.i(!a());
        X.k.i(!wVar.a());
        X.k.g(this.f2358c);
        X.k.g(wVar.r());
        x.b(i3, wVar.i(), i4, i5, i());
        this.f2358c.position(i3);
        wVar.r().position(i4);
        byte[] bArr = new byte[i5];
        this.f2358c.get(bArr, 0, i5);
        wVar.r().put(bArr, 0, i5);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x000e  */
    @Override // Q0.w
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized boolean a() {
        /*
            r1 = this;
            monitor-enter(r1)
            java.nio.ByteBuffer r0 = r1.f2358c     // Catch: java.lang.Throwable -> Lc
            if (r0 == 0) goto Le
            android.os.SharedMemory r0 = r1.f2357b     // Catch: java.lang.Throwable -> Lc
            if (r0 != 0) goto La
            goto Le
        La:
            r0 = 0
            goto Lf
        Lc:
            r0 = move-exception
            goto L11
        Le:
            r0 = 1
        Lf:
            monitor-exit(r1)
            return r0
        L11:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> Lc
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: Q0.C0203f.a():boolean");
    }

    @Override // Q0.w
    public synchronized int c(int i3, byte[] bArr, int i4, int i5) {
        int iA;
        X.k.g(bArr);
        X.k.g(this.f2358c);
        iA = x.a(i3, i5, i());
        x.b(i3, bArr.length, i4, iA, i());
        this.f2358c.position(i3);
        this.f2358c.get(bArr, i4, iA);
        return iA;
    }

    @Override // Q0.w, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        try {
            if (!a()) {
                SharedMemory sharedMemory = this.f2357b;
                if (sharedMemory != null) {
                    sharedMemory.close();
                }
                ByteBuffer byteBuffer = this.f2358c;
                if (byteBuffer != null) {
                    SharedMemory.unmap(byteBuffer);
                }
                this.f2358c = null;
                this.f2357b = null;
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // Q0.w
    public synchronized byte g(int i3) {
        X.k.i(!a());
        X.k.b(Boolean.valueOf(i3 >= 0));
        X.k.b(Boolean.valueOf(i3 < i()));
        X.k.g(this.f2358c);
        return this.f2358c.get(i3);
    }

    @Override // Q0.w
    public int i() {
        X.k.g(this.f2357b);
        return this.f2357b.getSize();
    }

    @Override // Q0.w
    public long p() {
        return this.f2359d;
    }

    @Override // Q0.w
    public ByteBuffer r() {
        return this.f2358c;
    }

    @Override // Q0.w
    public synchronized int v(int i3, byte[] bArr, int i4, int i5) {
        int iA;
        X.k.g(bArr);
        X.k.g(this.f2358c);
        iA = x.a(i3, i5, i());
        x.b(i3, bArr.length, i4, iA, i());
        this.f2358c.position(i3);
        this.f2358c.put(bArr, i4, iA);
        return iA;
    }

    @Override // Q0.w
    public long x() {
        throw new UnsupportedOperationException("Cannot get the pointer of an  AshmemMemoryChunk");
    }

    @Override // Q0.w
    public void y(int i3, w wVar, int i4, int i5) {
        X.k.g(wVar);
        if (wVar.p() == p()) {
            Log.w("AshmemMemoryChunk", "Copying from AshmemMemoryChunk " + Long.toHexString(p()) + " to AshmemMemoryChunk " + Long.toHexString(wVar.p()) + " which are the same ");
            X.k.b(Boolean.FALSE);
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
}
