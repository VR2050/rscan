package Q2;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

/* JADX INFO: loaded from: classes.dex */
public final class z implements k {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final i f2587b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public boolean f2588c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public final F f2589d;

    public z(F f3) {
        t2.j.f(f3, "source");
        this.f2589d = f3;
        this.f2587b = new i();
    }

    @Override // Q2.k
    public int B() throws EOFException {
        i0(4L);
        return this.f2587b.B();
    }

    @Override // Q2.k
    public long G() throws EOFException {
        i0(8L);
        return this.f2587b.G();
    }

    @Override // Q2.k
    public String H() {
        return V(Long.MAX_VALUE);
    }

    @Override // Q2.k
    public byte[] I() {
        this.f2587b.o(this.f2589d);
        return this.f2587b.I();
    }

    @Override // Q2.k
    public void J(i iVar, long j3) throws EOFException {
        t2.j.f(iVar, "sink");
        try {
            i0(j3);
            this.f2587b.J(iVar, j3);
        } catch (EOFException e3) {
            iVar.o(this.f2587b);
            throw e3;
        }
    }

    @Override // Q2.k
    public boolean K() {
        if (this.f2588c) {
            throw new IllegalStateException("closed");
        }
        return this.f2587b.K() && this.f2589d.R(this.f2587b, (long) 8192) == -1;
    }

    @Override // Q2.k
    public byte[] M(long j3) throws EOFException {
        i0(j3);
        return this.f2587b.M(j3);
    }

    @Override // Q2.k
    public String O() {
        this.f2587b.o(this.f2589d);
        return this.f2587b.O();
    }

    @Override // Q2.F
    public long R(i iVar, long j3) {
        t2.j.f(iVar, "sink");
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
        }
        if (this.f2588c) {
            throw new IllegalStateException("closed");
        }
        if (this.f2587b.F0() == 0 && this.f2589d.R(this.f2587b, 8192) == -1) {
            return -1L;
        }
        return this.f2587b.R(iVar, Math.min(j3, this.f2587b.F0()));
    }

    @Override // Q2.k
    public long U() throws EOFException {
        byte bZ;
        i0(1L);
        long j3 = 0;
        while (true) {
            long j4 = j3 + 1;
            if (!v(j4)) {
                break;
            }
            bZ = this.f2587b.Z(j3);
            if ((bZ < ((byte) 48) || bZ > ((byte) 57)) && !(j3 == 0 && bZ == ((byte) 45))) {
                break;
            }
            j3 = j4;
        }
        if (j3 == 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("Expected leading [0-9] or '-' character but was 0x");
            String string = Integer.toString(bZ, z2.a.a(z2.a.a(16)));
            t2.j.e(string, "java.lang.Integer.toStri…(this, checkRadix(radix))");
            sb.append(string);
            throw new NumberFormatException(sb.toString());
        }
        return this.f2587b.U();
    }

    @Override // Q2.k
    public String V(long j3) throws EOFException {
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("limit < 0: " + j3).toString());
        }
        long j4 = j3 == Long.MAX_VALUE ? Long.MAX_VALUE : j3 + 1;
        byte b3 = (byte) 10;
        long jI = i(b3, 0L, j4);
        if (jI != -1) {
            return R2.a.c(this.f2587b, jI);
        }
        if (j4 < Long.MAX_VALUE && v(j4) && this.f2587b.Z(j4 - 1) == ((byte) 13) && v(1 + j4) && this.f2587b.Z(j4) == b3) {
            return R2.a.c(this.f2587b, j4);
        }
        i iVar = new i();
        i iVar2 = this.f2587b;
        iVar2.D(iVar, 0L, Math.min(32, iVar2.F0()));
        throw new EOFException("\\n not found: limit=" + Math.min(this.f2587b.F0(), j3) + " content=" + iVar.z0().k() + "…");
    }

    @Override // Q2.k
    public short X() throws EOFException {
        i0(2L);
        return this.f2587b.X();
    }

    public long b(byte b3) {
        return i(b3, 0L, Long.MAX_VALUE);
    }

    @Override // Q2.k
    public int c0(w wVar) throws EOFException {
        t2.j.f(wVar, "options");
        if (this.f2588c) {
            throw new IllegalStateException("closed");
        }
        while (true) {
            int iD = R2.a.d(this.f2587b, wVar, true);
            if (iD != -2) {
                if (iD != -1) {
                    this.f2587b.t(wVar.e()[iD].v());
                    return iD;
                }
            } else if (this.f2589d.R(this.f2587b, 8192) == -1) {
                break;
            }
        }
        return -1;
    }

    @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws EOFException {
        if (this.f2588c) {
            return;
        }
        this.f2588c = true;
        this.f2589d.close();
        this.f2587b.v();
    }

    @Override // Q2.k, Q2.j
    public i e() {
        return this.f2587b;
    }

    @Override // Q2.F
    public G f() {
        return this.f2589d.f();
    }

    @Override // Q2.k
    public long h0(D d3) {
        t2.j.f(d3, "sink");
        long j3 = 0;
        while (this.f2589d.R(this.f2587b, 8192) != -1) {
            long jY = this.f2587b.y();
            if (jY > 0) {
                j3 += jY;
                d3.m(this.f2587b, jY);
            }
        }
        if (this.f2587b.F0() <= 0) {
            return j3;
        }
        long jF0 = j3 + this.f2587b.F0();
        i iVar = this.f2587b;
        d3.m(iVar, iVar.F0());
        return jF0;
    }

    public long i(byte b3, long j3, long j4) {
        if (this.f2588c) {
            throw new IllegalStateException("closed");
        }
        if (!(0 <= j3 && j4 >= j3)) {
            throw new IllegalArgumentException(("fromIndex=" + j3 + " toIndex=" + j4).toString());
        }
        while (j3 < j4) {
            long jD0 = this.f2587b.d0(b3, j3, j4);
            if (jD0 != -1) {
                return jD0;
            }
            long jF0 = this.f2587b.F0();
            if (jF0 >= j4 || this.f2589d.R(this.f2587b, 8192) == -1) {
                return -1L;
            }
            j3 = Math.max(j3, jF0);
        }
        return -1L;
    }

    @Override // Q2.k
    public void i0(long j3) throws EOFException {
        if (!v(j3)) {
            throw new EOFException();
        }
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return !this.f2588c;
    }

    @Override // Q2.k
    public void l(byte[] bArr) throws EOFException {
        t2.j.f(bArr, "sink");
        try {
            i0(bArr.length);
            this.f2587b.l(bArr);
        } catch (EOFException e3) {
            int i3 = 0;
            while (this.f2587b.F0() > 0) {
                i iVar = this.f2587b;
                int iW0 = iVar.w0(bArr, i3, (int) iVar.F0());
                if (iW0 == -1) {
                    throw new AssertionError();
                }
                i3 += iW0;
            }
            throw e3;
        }
    }

    @Override // Q2.k
    public long o0() throws EOFException {
        byte bZ;
        i0(1L);
        int i3 = 0;
        while (true) {
            int i4 = i3 + 1;
            if (!v(i4)) {
                break;
            }
            bZ = this.f2587b.Z(i3);
            if ((bZ < ((byte) 48) || bZ > ((byte) 57)) && ((bZ < ((byte) 97) || bZ > ((byte) 102)) && (bZ < ((byte) 65) || bZ > ((byte) 70)))) {
                break;
            }
            i3 = i4;
        }
        if (i3 == 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("Expected leading [0-9a-fA-F] character but was 0x");
            String string = Integer.toString(bZ, z2.a.a(z2.a.a(16)));
            t2.j.e(string, "java.lang.Integer.toStri…(this, checkRadix(radix))");
            sb.append(string);
            throw new NumberFormatException(sb.toString());
        }
        return this.f2587b.o0();
    }

    public int p() throws EOFException {
        i0(4L);
        return this.f2587b.A0();
    }

    @Override // Q2.k
    public String p0(Charset charset) {
        t2.j.f(charset, "charset");
        this.f2587b.o(this.f2589d);
        return this.f2587b.p0(charset);
    }

    @Override // Q2.k
    public l q(long j3) throws EOFException {
        i0(j3);
        return this.f2587b.q(j3);
    }

    @Override // Q2.k
    public InputStream q0() {
        return new a();
    }

    public short r() throws EOFException {
        i0(2L);
        return this.f2587b.B0();
    }

    @Override // Q2.k
    public byte r0() throws EOFException {
        i0(1L);
        return this.f2587b.r0();
    }

    @Override // java.nio.channels.ReadableByteChannel
    public int read(ByteBuffer byteBuffer) {
        t2.j.f(byteBuffer, "sink");
        if (this.f2587b.F0() == 0 && this.f2589d.R(this.f2587b, 8192) == -1) {
            return -1;
        }
        return this.f2587b.read(byteBuffer);
    }

    @Override // Q2.k
    public void t(long j3) throws EOFException {
        if (this.f2588c) {
            throw new IllegalStateException("closed");
        }
        while (j3 > 0) {
            if (this.f2587b.F0() == 0 && this.f2589d.R(this.f2587b, 8192) == -1) {
                throw new EOFException();
            }
            long jMin = Math.min(j3, this.f2587b.F0());
            this.f2587b.t(jMin);
            j3 -= jMin;
        }
    }

    public String toString() {
        return "buffer(" + this.f2589d + ')';
    }

    public boolean v(long j3) {
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
        }
        if (this.f2588c) {
            throw new IllegalStateException("closed");
        }
        while (this.f2587b.F0() < j3) {
            if (this.f2589d.R(this.f2587b, 8192) == -1) {
                return false;
            }
        }
        return true;
    }

    public static final class a extends InputStream {
        a() {
        }

        @Override // java.io.InputStream
        public int available() throws IOException {
            z zVar = z.this;
            if (zVar.f2588c) {
                throw new IOException("closed");
            }
            return (int) Math.min(zVar.f2587b.F0(), Integer.MAX_VALUE);
        }

        @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws EOFException {
            z.this.close();
        }

        @Override // java.io.InputStream
        public int read() throws IOException {
            z zVar = z.this;
            if (zVar.f2588c) {
                throw new IOException("closed");
            }
            if (zVar.f2587b.F0() == 0) {
                z zVar2 = z.this;
                if (zVar2.f2589d.R(zVar2.f2587b, 8192) == -1) {
                    return -1;
                }
            }
            return z.this.f2587b.r0() & 255;
        }

        public String toString() {
            return z.this + ".inputStream()";
        }

        @Override // java.io.InputStream
        public int read(byte[] bArr, int i3, int i4) throws IOException {
            t2.j.f(bArr, "data");
            if (!z.this.f2588c) {
                AbstractC0210f.b(bArr.length, i3, i4);
                if (z.this.f2587b.F0() == 0) {
                    z zVar = z.this;
                    if (zVar.f2589d.R(zVar.f2587b, 8192) == -1) {
                        return -1;
                    }
                }
                return z.this.f2587b.w0(bArr, i3, i4);
            }
            throw new IOException("closed");
        }
    }
}
