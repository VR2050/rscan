package Q2;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public final class y implements j {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final i f2583b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public boolean f2584c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public final D f2585d;

    public y(D d3) {
        t2.j.f(d3, "sink");
        this.f2585d = d3;
        this.f2583b = new i();
    }

    @Override // Q2.j
    public j E(int i3) {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.E(i3);
        return S();
    }

    @Override // Q2.j
    public j L(int i3) {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.L(i3);
        return S();
    }

    @Override // Q2.j
    public j Q(byte[] bArr) {
        t2.j.f(bArr, "source");
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.Q(bArr);
        return S();
    }

    @Override // Q2.j
    public j S() {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        long jY = this.f2583b.y();
        if (jY > 0) {
            this.f2585d.m(this.f2583b, jY);
        }
        return this;
    }

    @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws Throwable {
        if (this.f2584c) {
            return;
        }
        try {
            if (this.f2583b.F0() > 0) {
                D d3 = this.f2585d;
                i iVar = this.f2583b;
                d3.m(iVar, iVar.F0());
            }
            th = null;
        } catch (Throwable th) {
            th = th;
        }
        try {
            this.f2585d.close();
        } catch (Throwable th2) {
            if (th == null) {
                th = th2;
            }
        }
        this.f2584c = true;
        if (th != null) {
            throw th;
        }
    }

    @Override // Q2.j
    public i e() {
        return this.f2583b;
    }

    @Override // Q2.D
    public G f() {
        return this.f2585d.f();
    }

    @Override // Q2.j, Q2.D, java.io.Flushable
    public void flush() {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        if (this.f2583b.F0() > 0) {
            D d3 = this.f2585d;
            i iVar = this.f2583b;
            d3.m(iVar, iVar.F0());
        }
        this.f2585d.flush();
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return !this.f2584c;
    }

    @Override // Q2.j
    public j j(byte[] bArr, int i3, int i4) {
        t2.j.f(bArr, "source");
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.j(bArr, i3, i4);
        return S();
    }

    @Override // Q2.j
    public j j0(String str) {
        t2.j.f(str, "string");
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.j0(str);
        return S();
    }

    @Override // Q2.j
    public j k0(long j3) {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.k0(j3);
        return S();
    }

    @Override // Q2.j
    public OutputStream l0() {
        return new a();
    }

    @Override // Q2.D
    public void m(i iVar, long j3) {
        t2.j.f(iVar, "source");
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.m(iVar, j3);
        S();
    }

    @Override // Q2.j
    public j n(long j3) {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.n(j3);
        return S();
    }

    @Override // Q2.j
    public long o(F f3) {
        t2.j.f(f3, "source");
        long j3 = 0;
        while (true) {
            long jR = f3.R(this.f2583b, 8192);
            if (jR == -1) {
                return j3;
            }
            j3 += jR;
            S();
        }
    }

    public String toString() {
        return "buffer(" + this.f2585d + ')';
    }

    @Override // Q2.j
    public j u() {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        long jF0 = this.f2583b.F0();
        if (jF0 > 0) {
            this.f2585d.m(this.f2583b, jF0);
        }
        return this;
    }

    @Override // Q2.j
    public j w(int i3) {
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.w(i3);
        return S();
    }

    @Override // java.nio.channels.WritableByteChannel
    public int write(ByteBuffer byteBuffer) {
        t2.j.f(byteBuffer, "source");
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        int iWrite = this.f2583b.write(byteBuffer);
        S();
        return iWrite;
    }

    @Override // Q2.j
    public j z(l lVar) {
        t2.j.f(lVar, "byteString");
        if (this.f2584c) {
            throw new IllegalStateException("closed");
        }
        this.f2583b.z(lVar);
        return S();
    }

    public static final class a extends OutputStream {
        a() {
        }

        @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws Throwable {
            y.this.close();
        }

        @Override // java.io.OutputStream, java.io.Flushable
        public void flush() {
            y yVar = y.this;
            if (yVar.f2584c) {
                return;
            }
            yVar.flush();
        }

        public String toString() {
            return y.this + ".outputStream()";
        }

        @Override // java.io.OutputStream
        public void write(int i3) throws IOException {
            y yVar = y.this;
            if (yVar.f2584c) {
                throw new IOException("closed");
            }
            yVar.f2583b.L((byte) i3);
            y.this.S();
        }

        @Override // java.io.OutputStream
        public void write(byte[] bArr, int i3, int i4) throws IOException {
            t2.j.f(bArr, "data");
            y yVar = y.this;
            if (!yVar.f2584c) {
                yVar.f2583b.j(bArr, i3, i4);
                y.this.S();
                return;
            }
            throw new IOException("closed");
        }
    }
}
