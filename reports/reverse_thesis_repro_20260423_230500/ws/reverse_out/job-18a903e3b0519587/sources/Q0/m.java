package Q0;

import android.util.Log;
import java.io.Closeable;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public class m implements w, Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private ByteBuffer f2378b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f2379c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final long f2380d = System.identityHashCode(this);

    public m(int i3) {
        this.f2378b = ByteBuffer.allocateDirect(i3);
        this.f2379c = i3;
    }

    private void b(int i3, w wVar, int i4, int i5) {
        if (!(wVar instanceof m)) {
            throw new IllegalArgumentException("Cannot copy two incompatible MemoryChunks");
        }
        X.k.i(!a());
        X.k.i(!wVar.a());
        X.k.g(this.f2378b);
        x.b(i3, wVar.i(), i4, i5, this.f2379c);
        this.f2378b.position(i3);
        ByteBuffer byteBuffer = (ByteBuffer) X.k.g(wVar.r());
        byteBuffer.position(i4);
        byte[] bArr = new byte[i5];
        this.f2378b.get(bArr, 0, i5);
        byteBuffer.put(bArr, 0, i5);
    }

    @Override // Q0.w
    public synchronized boolean a() {
        return this.f2378b == null;
    }

    @Override // Q0.w
    public synchronized int c(int i3, byte[] bArr, int i4, int i5) {
        int iA;
        X.k.g(bArr);
        X.k.i(!a());
        X.k.g(this.f2378b);
        iA = x.a(i3, i5, this.f2379c);
        x.b(i3, bArr.length, i4, iA, this.f2379c);
        this.f2378b.position(i3);
        this.f2378b.get(bArr, i4, iA);
        return iA;
    }

    @Override // Q0.w, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        this.f2378b = null;
    }

    @Override // Q0.w
    public synchronized byte g(int i3) {
        X.k.i(!a());
        X.k.b(Boolean.valueOf(i3 >= 0));
        X.k.b(Boolean.valueOf(i3 < this.f2379c));
        X.k.g(this.f2378b);
        return this.f2378b.get(i3);
    }

    @Override // Q0.w
    public int i() {
        return this.f2379c;
    }

    @Override // Q0.w
    public long p() {
        return this.f2380d;
    }

    @Override // Q0.w
    public synchronized ByteBuffer r() {
        return this.f2378b;
    }

    @Override // Q0.w
    public synchronized int v(int i3, byte[] bArr, int i4, int i5) {
        int iA;
        X.k.g(bArr);
        X.k.i(!a());
        X.k.g(this.f2378b);
        iA = x.a(i3, i5, this.f2379c);
        x.b(i3, bArr.length, i4, iA, this.f2379c);
        this.f2378b.position(i3);
        this.f2378b.put(bArr, i4, iA);
        return iA;
    }

    @Override // Q0.w
    public long x() {
        throw new UnsupportedOperationException("Cannot get the pointer of a BufferMemoryChunk");
    }

    @Override // Q0.w
    public void y(int i3, w wVar, int i4, int i5) {
        X.k.g(wVar);
        if (wVar.p() == p()) {
            Log.w("BufferMemoryChunk", "Copying from BufferMemoryChunk " + Long.toHexString(p()) + " to BufferMemoryChunk " + Long.toHexString(wVar.p()) + " which are the same ");
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
