package a0;

import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: renamed from: a0.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0221g extends InputStream {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InputStream f2917b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final byte[] f2918c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final b0.g f2919d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f2920e = 0;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f2921f = 0;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f2922g = false;

    public C0221g(InputStream inputStream, byte[] bArr, b0.g gVar) {
        this.f2917b = (InputStream) X.k.g(inputStream);
        this.f2918c = (byte[]) X.k.g(bArr);
        this.f2919d = (b0.g) X.k.g(gVar);
    }

    private boolean b() throws IOException {
        if (this.f2921f < this.f2920e) {
            return true;
        }
        int i3 = this.f2917b.read(this.f2918c);
        if (i3 <= 0) {
            return false;
        }
        this.f2920e = i3;
        this.f2921f = 0;
        return true;
    }

    private void i() throws IOException {
        if (this.f2922g) {
            throw new IOException("stream already closed");
        }
    }

    @Override // java.io.InputStream
    public int available() throws IOException {
        X.k.i(this.f2921f <= this.f2920e);
        i();
        return (this.f2920e - this.f2921f) + this.f2917b.available();
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        if (this.f2922g) {
            return;
        }
        this.f2922g = true;
        this.f2919d.a(this.f2918c);
        super.close();
    }

    protected void finalize() throws Throwable {
        if (!this.f2922g) {
            Y.a.m("PooledByteInputStream", "Finalized without closing");
            close();
        }
        super.finalize();
    }

    @Override // java.io.InputStream
    public int read() throws IOException {
        X.k.i(this.f2921f <= this.f2920e);
        i();
        if (!b()) {
            return -1;
        }
        byte[] bArr = this.f2918c;
        int i3 = this.f2921f;
        this.f2921f = i3 + 1;
        return bArr[i3] & 255;
    }

    @Override // java.io.InputStream
    public long skip(long j3) throws IOException {
        X.k.i(this.f2921f <= this.f2920e);
        i();
        int i3 = this.f2920e;
        int i4 = this.f2921f;
        long j4 = i3 - i4;
        if (j4 >= j3) {
            this.f2921f = (int) (((long) i4) + j3);
            return j3;
        }
        this.f2921f = i3;
        return j4 + this.f2917b.skip(j3 - j4);
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i3, int i4) throws IOException {
        X.k.i(this.f2921f <= this.f2920e);
        i();
        if (!b()) {
            return -1;
        }
        int iMin = Math.min(this.f2920e - this.f2921f, i4);
        System.arraycopy(this.f2918c, this.f2921f, bArr, i3, iMin);
        this.f2921f += iMin;
        return iMin;
    }
}
