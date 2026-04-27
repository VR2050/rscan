package Q2;

import i2.AbstractC0580h;
import java.io.Closeable;
import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.charset.Charset;
import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public final class i implements k, j, Cloneable, ByteChannel {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public A f2544b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f2545c;

    public static final class a implements Closeable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public i f2546b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public boolean f2547c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private A f2548d;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public byte[] f2550f;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public long f2549e = -1;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        public int f2551g = -1;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        public int f2552h = -1;

        public final int b() {
            long j3 = this.f2549e;
            i iVar = this.f2546b;
            t2.j.c(iVar);
            if (!(j3 != iVar.F0())) {
                throw new IllegalStateException("no more bytes");
            }
            long j4 = this.f2549e;
            return p(j4 == -1 ? 0L : j4 + ((long) (this.f2552h - this.f2551g)));
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (!(this.f2546b != null)) {
                throw new IllegalStateException("not attached to a buffer");
            }
            this.f2546b = null;
            this.f2548d = null;
            this.f2549e = -1L;
            this.f2550f = null;
            this.f2551g = -1;
            this.f2552h = -1;
        }

        public final long i(long j3) {
            i iVar = this.f2546b;
            if (iVar == null) {
                throw new IllegalStateException("not attached to a buffer");
            }
            if (!this.f2547c) {
                throw new IllegalStateException("resizeBuffer() only permitted for read/write buffers");
            }
            long jF0 = iVar.F0();
            int i3 = 1;
            if (j3 <= jF0) {
                if (!(j3 >= 0)) {
                    throw new IllegalArgumentException(("newSize < 0: " + j3).toString());
                }
                long j4 = jF0 - j3;
                while (true) {
                    if (j4 <= 0) {
                        break;
                    }
                    A a3 = iVar.f2544b;
                    t2.j.c(a3);
                    A a4 = a3.f2513g;
                    t2.j.c(a4);
                    int i4 = a4.f2509c;
                    long j5 = i4 - a4.f2508b;
                    if (j5 > j4) {
                        a4.f2509c = i4 - ((int) j4);
                        break;
                    }
                    iVar.f2544b = a4.b();
                    B.b(a4);
                    j4 -= j5;
                }
                this.f2548d = null;
                this.f2549e = j3;
                this.f2550f = null;
                this.f2551g = -1;
                this.f2552h = -1;
            } else if (j3 > jF0) {
                long j6 = j3 - jF0;
                boolean z3 = true;
                while (j6 > 0) {
                    A aI0 = iVar.I0(i3);
                    int iMin = (int) Math.min(j6, 8192 - aI0.f2509c);
                    int i5 = aI0.f2509c + iMin;
                    aI0.f2509c = i5;
                    j6 -= (long) iMin;
                    if (z3) {
                        this.f2548d = aI0;
                        this.f2549e = jF0;
                        this.f2550f = aI0.f2507a;
                        this.f2551g = i5 - iMin;
                        this.f2552h = i5;
                        z3 = false;
                    }
                    i3 = 1;
                }
            }
            iVar.E0(j3);
            return jF0;
        }

        public final int p(long j3) {
            A aC;
            i iVar = this.f2546b;
            if (iVar == null) {
                throw new IllegalStateException("not attached to a buffer");
            }
            if (j3 < -1 || j3 > iVar.F0()) {
                t2.w wVar = t2.w.f10219a;
                String str = String.format("offset=%s > size=%s", Arrays.copyOf(new Object[]{Long.valueOf(j3), Long.valueOf(iVar.F0())}, 2));
                t2.j.e(str, "java.lang.String.format(format, *args)");
                throw new ArrayIndexOutOfBoundsException(str);
            }
            if (j3 == -1 || j3 == iVar.F0()) {
                this.f2548d = null;
                this.f2549e = j3;
                this.f2550f = null;
                this.f2551g = -1;
                this.f2552h = -1;
                return -1;
            }
            long jF0 = iVar.F0();
            A a3 = iVar.f2544b;
            A a4 = this.f2548d;
            long j4 = 0;
            if (a4 != null) {
                long j5 = this.f2549e;
                int i3 = this.f2551g;
                t2.j.c(a4);
                long j6 = j5 - ((long) (i3 - a4.f2508b));
                if (j6 > j3) {
                    aC = a3;
                    a3 = this.f2548d;
                    jF0 = j6;
                } else {
                    aC = this.f2548d;
                    j4 = j6;
                }
            } else {
                aC = a3;
            }
            if (jF0 - j3 > j3 - j4) {
                while (true) {
                    t2.j.c(aC);
                    int i4 = aC.f2509c;
                    int i5 = aC.f2508b;
                    if (j3 < ((long) (i4 - i5)) + j4) {
                        break;
                    }
                    j4 += (long) (i4 - i5);
                    aC = aC.f2512f;
                }
            } else {
                while (jF0 > j3) {
                    t2.j.c(a3);
                    a3 = a3.f2513g;
                    t2.j.c(a3);
                    jF0 -= (long) (a3.f2509c - a3.f2508b);
                }
                j4 = jF0;
                aC = a3;
            }
            if (this.f2547c) {
                t2.j.c(aC);
                if (aC.f2510d) {
                    A aF = aC.f();
                    if (iVar.f2544b == aC) {
                        iVar.f2544b = aF;
                    }
                    aC = aC.c(aF);
                    A a5 = aC.f2513g;
                    t2.j.c(a5);
                    a5.b();
                }
            }
            this.f2548d = aC;
            this.f2549e = j3;
            t2.j.c(aC);
            this.f2550f = aC.f2507a;
            int i6 = aC.f2508b + ((int) (j3 - j4));
            this.f2551g = i6;
            int i7 = aC.f2509c;
            this.f2552h = i7;
            return i7 - i6;
        }
    }

    public static final class c extends OutputStream {
        c() {
        }

        public String toString() {
            return i.this + ".outputStream()";
        }

        @Override // java.io.OutputStream
        public void write(int i3) {
            i.this.L(i3);
        }

        @Override // java.io.OutputStream
        public void write(byte[] bArr, int i3, int i4) {
            t2.j.f(bArr, "data");
            i.this.j(bArr, i3, i4);
        }

        @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
        }

        @Override // java.io.OutputStream, java.io.Flushable
        public void flush() {
        }
    }

    public static /* synthetic */ a y0(i iVar, a aVar, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            aVar = new a();
        }
        return iVar.x0(aVar);
    }

    public final i A() {
        i iVar = new i();
        if (F0() != 0) {
            A a3 = this.f2544b;
            t2.j.c(a3);
            A aD = a3.d();
            iVar.f2544b = aD;
            aD.f2513g = aD;
            aD.f2512f = aD;
            for (A a4 = a3.f2512f; a4 != a3; a4 = a4.f2512f) {
                A a5 = aD.f2513g;
                t2.j.c(a5);
                t2.j.c(a4);
                a5.c(a4.d());
            }
            iVar.E0(F0());
        }
        return iVar;
    }

    public int A0() {
        return AbstractC0210f.c(B());
    }

    @Override // Q2.k
    public int B() throws EOFException {
        if (F0() < 4) {
            throw new EOFException();
        }
        A a3 = this.f2544b;
        t2.j.c(a3);
        int i3 = a3.f2508b;
        int i4 = a3.f2509c;
        if (i4 - i3 < 4) {
            return ((r0() & 255) << 24) | ((r0() & 255) << 16) | ((r0() & 255) << 8) | (r0() & 255);
        }
        byte[] bArr = a3.f2507a;
        int i5 = i3 + 3;
        int i6 = ((bArr[i3 + 1] & 255) << 16) | ((bArr[i3] & 255) << 24) | ((bArr[i3 + 2] & 255) << 8);
        int i7 = i3 + 4;
        int i8 = (bArr[i5] & 255) | i6;
        E0(F0() - 4);
        if (i7 == i4) {
            this.f2544b = a3.b();
            B.b(a3);
        } else {
            a3.f2508b = i7;
        }
        return i8;
    }

    public short B0() {
        return AbstractC0210f.d(X());
    }

    public String C0(long j3, Charset charset) throws EOFException {
        t2.j.f(charset, "charset");
        if (!(j3 >= 0 && j3 <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException(("byteCount: " + j3).toString());
        }
        if (this.f2545c < j3) {
            throw new EOFException();
        }
        if (j3 == 0) {
            return "";
        }
        A a3 = this.f2544b;
        t2.j.c(a3);
        int i3 = a3.f2508b;
        if (((long) i3) + j3 > a3.f2509c) {
            return new String(M(j3), charset);
        }
        int i4 = (int) j3;
        String str = new String(a3.f2507a, i3, i4, charset);
        int i5 = a3.f2508b + i4;
        a3.f2508b = i5;
        this.f2545c -= j3;
        if (i5 == a3.f2509c) {
            this.f2544b = a3.b();
            B.b(a3);
        }
        return str;
    }

    public final i D(i iVar, long j3, long j4) {
        t2.j.f(iVar, "out");
        AbstractC0210f.b(F0(), j3, j4);
        if (j4 != 0) {
            iVar.E0(iVar.F0() + j4);
            A a3 = this.f2544b;
            while (true) {
                t2.j.c(a3);
                int i3 = a3.f2509c;
                int i4 = a3.f2508b;
                if (j3 < i3 - i4) {
                    break;
                }
                j3 -= (long) (i3 - i4);
                a3 = a3.f2512f;
            }
            while (j4 > 0) {
                t2.j.c(a3);
                A aD = a3.d();
                int i5 = aD.f2508b + ((int) j3);
                aD.f2508b = i5;
                aD.f2509c = Math.min(i5 + ((int) j4), aD.f2509c);
                A a4 = iVar.f2544b;
                if (a4 == null) {
                    aD.f2513g = aD;
                    aD.f2512f = aD;
                    iVar.f2544b = aD;
                } else {
                    t2.j.c(a4);
                    A a5 = a4.f2513g;
                    t2.j.c(a5);
                    a5.c(aD);
                }
                j4 -= (long) (aD.f2509c - aD.f2508b);
                a3 = a3.f2512f;
                j3 = 0;
            }
        }
        return this;
    }

    public String D0(long j3) throws EOFException {
        return C0(j3, z2.d.f10544b);
    }

    public final void E0(long j3) {
        this.f2545c = j3;
    }

    public final long F0() {
        return this.f2545c;
    }

    @Override // Q2.k
    public long G() throws EOFException {
        if (F0() < 8) {
            throw new EOFException();
        }
        A a3 = this.f2544b;
        t2.j.c(a3);
        int i3 = a3.f2508b;
        int i4 = a3.f2509c;
        if (i4 - i3 < 8) {
            return ((((long) B()) & 4294967295L) << 32) | (4294967295L & ((long) B()));
        }
        byte[] bArr = a3.f2507a;
        int i5 = i3 + 7;
        long j3 = ((((long) bArr[i3]) & 255) << 56) | ((((long) bArr[i3 + 1]) & 255) << 48) | ((((long) bArr[i3 + 2]) & 255) << 40) | ((((long) bArr[i3 + 3]) & 255) << 32) | ((((long) bArr[i3 + 4]) & 255) << 24) | ((((long) bArr[i3 + 5]) & 255) << 16) | ((((long) bArr[i3 + 6]) & 255) << 8);
        int i6 = i3 + 8;
        long j4 = j3 | (((long) bArr[i5]) & 255);
        E0(F0() - 8);
        if (i6 == i4) {
            this.f2544b = a3.b();
            B.b(a3);
        } else {
            a3.f2508b = i6;
        }
        return j4;
    }

    public final l G0() {
        if (F0() <= ((long) Integer.MAX_VALUE)) {
            return H0((int) F0());
        }
        throw new IllegalStateException(("size > Int.MAX_VALUE: " + F0()).toString());
    }

    @Override // Q2.k
    public String H() {
        return V(Long.MAX_VALUE);
    }

    public final l H0(int i3) {
        if (i3 == 0) {
            return l.f2555e;
        }
        AbstractC0210f.b(F0(), 0L, i3);
        A a3 = this.f2544b;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        while (i5 < i3) {
            t2.j.c(a3);
            int i7 = a3.f2509c;
            int i8 = a3.f2508b;
            if (i7 == i8) {
                throw new AssertionError("s.limit == s.pos");
            }
            i5 += i7 - i8;
            i6++;
            a3 = a3.f2512f;
        }
        byte[][] bArr = new byte[i6][];
        int[] iArr = new int[i6 * 2];
        A a4 = this.f2544b;
        int i9 = 0;
        while (i4 < i3) {
            t2.j.c(a4);
            bArr[i9] = a4.f2507a;
            i4 += a4.f2509c - a4.f2508b;
            iArr[i9] = Math.min(i4, i3);
            iArr[i9 + i6] = a4.f2508b;
            a4.f2510d = true;
            i9++;
            a4 = a4.f2512f;
        }
        return new C(bArr, iArr);
    }

    @Override // Q2.k
    public byte[] I() {
        return M(F0());
    }

    public final A I0(int i3) {
        if (!(i3 >= 1 && i3 <= 8192)) {
            throw new IllegalArgumentException("unexpected capacity");
        }
        A a3 = this.f2544b;
        if (a3 != null) {
            t2.j.c(a3);
            A a4 = a3.f2513g;
            t2.j.c(a4);
            return (a4.f2509c + i3 > 8192 || !a4.f2511e) ? a4.c(B.c()) : a4;
        }
        A aC = B.c();
        this.f2544b = aC;
        aC.f2513g = aC;
        aC.f2512f = aC;
        return aC;
    }

    @Override // Q2.k
    public void J(i iVar, long j3) throws EOFException {
        t2.j.f(iVar, "sink");
        if (F0() >= j3) {
            iVar.m(this, j3);
        } else {
            iVar.m(this, F0());
            throw new EOFException();
        }
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: J0, reason: merged with bridge method [inline-methods] */
    public i z(l lVar) {
        t2.j.f(lVar, "byteString");
        lVar.A(this, 0, lVar.v());
        return this;
    }

    @Override // Q2.k
    public boolean K() {
        return this.f2545c == 0;
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: K0, reason: merged with bridge method [inline-methods] */
    public i Q(byte[] bArr) {
        t2.j.f(bArr, "source");
        return j(bArr, 0, bArr.length);
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: L0, reason: merged with bridge method [inline-methods] */
    public i j(byte[] bArr, int i3, int i4) {
        t2.j.f(bArr, "source");
        long j3 = i4;
        AbstractC0210f.b(bArr.length, i3, j3);
        int i5 = i4 + i3;
        while (i3 < i5) {
            A aI0 = I0(1);
            int iMin = Math.min(i5 - i3, 8192 - aI0.f2509c);
            int i6 = i3 + iMin;
            AbstractC0580h.e(bArr, aI0.f2507a, aI0.f2509c, i3, i6);
            aI0.f2509c += iMin;
            i3 = i6;
        }
        E0(F0() + j3);
        return this;
    }

    @Override // Q2.k
    public byte[] M(long j3) throws EOFException {
        if (!(j3 >= 0 && j3 <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException(("byteCount: " + j3).toString());
        }
        if (F0() < j3) {
            throw new EOFException();
        }
        byte[] bArr = new byte[(int) j3];
        l(bArr);
        return bArr;
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: M0, reason: merged with bridge method [inline-methods] */
    public i L(int i3) {
        A aI0 = I0(1);
        byte[] bArr = aI0.f2507a;
        int i4 = aI0.f2509c;
        aI0.f2509c = i4 + 1;
        bArr[i4] = (byte) i3;
        E0(F0() + 1);
        return this;
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: N0, reason: merged with bridge method [inline-methods] */
    public i k0(long j3) {
        boolean z3;
        if (j3 == 0) {
            return L(48);
        }
        int i3 = 1;
        if (j3 < 0) {
            j3 = -j3;
            if (j3 < 0) {
                return j0("-9223372036854775808");
            }
            z3 = true;
        } else {
            z3 = false;
        }
        if (j3 >= 100000000) {
            i3 = j3 < 1000000000000L ? j3 < 10000000000L ? j3 < 1000000000 ? 9 : 10 : j3 < 100000000000L ? 11 : 12 : j3 < 1000000000000000L ? j3 < 10000000000000L ? 13 : j3 < 100000000000000L ? 14 : 15 : j3 < 100000000000000000L ? j3 < 10000000000000000L ? 16 : 17 : j3 < 1000000000000000000L ? 18 : 19;
        } else if (j3 >= 10000) {
            i3 = j3 < 1000000 ? j3 < 100000 ? 5 : 6 : j3 < 10000000 ? 7 : 8;
        } else if (j3 >= 100) {
            i3 = j3 < 1000 ? 3 : 4;
        } else if (j3 >= 10) {
            i3 = 2;
        }
        if (z3) {
            i3++;
        }
        A aI0 = I0(i3);
        byte[] bArr = aI0.f2507a;
        int i4 = aI0.f2509c + i3;
        while (j3 != 0) {
            long j4 = 10;
            i4--;
            bArr[i4] = R2.a.a()[(int) (j3 % j4)];
            j3 /= j4;
        }
        if (z3) {
            bArr[i4 - 1] = (byte) 45;
        }
        aI0.f2509c += i3;
        E0(F0() + ((long) i3));
        return this;
    }

    @Override // Q2.k
    public String O() {
        return C0(this.f2545c, z2.d.f10544b);
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: O0, reason: merged with bridge method [inline-methods] */
    public i n(long j3) {
        if (j3 == 0) {
            return L(48);
        }
        long j4 = (j3 >>> 1) | j3;
        long j5 = j4 | (j4 >>> 2);
        long j6 = j5 | (j5 >>> 4);
        long j7 = j6 | (j6 >>> 8);
        long j8 = j7 | (j7 >>> 16);
        long j9 = j8 | (j8 >>> 32);
        long j10 = j9 - ((j9 >>> 1) & 6148914691236517205L);
        long j11 = ((j10 >>> 2) & 3689348814741910323L) + (j10 & 3689348814741910323L);
        long j12 = ((j11 >>> 4) + j11) & 1085102592571150095L;
        long j13 = j12 + (j12 >>> 8);
        long j14 = j13 + (j13 >>> 16);
        int i3 = (int) ((((j14 & 63) + ((j14 >>> 32) & 63)) + ((long) 3)) / ((long) 4));
        A aI0 = I0(i3);
        byte[] bArr = aI0.f2507a;
        int i4 = aI0.f2509c;
        for (int i5 = (i4 + i3) - 1; i5 >= i4; i5--) {
            bArr[i5] = R2.a.a()[(int) (15 & j3)];
            j3 >>>= 4;
        }
        aI0.f2509c += i3;
        E0(F0() + ((long) i3));
        return this;
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: P0, reason: merged with bridge method [inline-methods] */
    public i E(int i3) {
        A aI0 = I0(4);
        byte[] bArr = aI0.f2507a;
        int i4 = aI0.f2509c;
        bArr[i4] = (byte) ((i3 >>> 24) & 255);
        bArr[i4 + 1] = (byte) ((i3 >>> 16) & 255);
        bArr[i4 + 2] = (byte) ((i3 >>> 8) & 255);
        bArr[i4 + 3] = (byte) (i3 & 255);
        aI0.f2509c = i4 + 4;
        E0(F0() + 4);
        return this;
    }

    public i Q0(long j3) {
        A aI0 = I0(8);
        byte[] bArr = aI0.f2507a;
        int i3 = aI0.f2509c;
        bArr[i3] = (byte) ((j3 >>> 56) & 255);
        bArr[i3 + 1] = (byte) ((j3 >>> 48) & 255);
        bArr[i3 + 2] = (byte) ((j3 >>> 40) & 255);
        bArr[i3 + 3] = (byte) ((j3 >>> 32) & 255);
        bArr[i3 + 4] = (byte) ((j3 >>> 24) & 255);
        bArr[i3 + 5] = (byte) ((j3 >>> 16) & 255);
        bArr[i3 + 6] = (byte) ((j3 >>> 8) & 255);
        bArr[i3 + 7] = (byte) (j3 & 255);
        aI0.f2509c = i3 + 8;
        E0(F0() + 8);
        return this;
    }

    @Override // Q2.F
    public long R(i iVar, long j3) {
        t2.j.f(iVar, "sink");
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
        }
        if (F0() == 0) {
            return -1L;
        }
        if (j3 > F0()) {
            j3 = F0();
        }
        iVar.m(this, j3);
        return j3;
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: R0, reason: merged with bridge method [inline-methods] */
    public i w(int i3) {
        A aI0 = I0(2);
        byte[] bArr = aI0.f2507a;
        int i4 = aI0.f2509c;
        bArr[i4] = (byte) ((i3 >>> 8) & 255);
        bArr[i4 + 1] = (byte) (i3 & 255);
        aI0.f2509c = i4 + 2;
        E0(F0() + 2);
        return this;
    }

    public i S0(String str, int i3, int i4, Charset charset) {
        t2.j.f(str, "string");
        t2.j.f(charset, "charset");
        if (!(i3 >= 0)) {
            throw new IllegalArgumentException(("beginIndex < 0: " + i3).toString());
        }
        if (!(i4 >= i3)) {
            throw new IllegalArgumentException(("endIndex < beginIndex: " + i4 + " < " + i3).toString());
        }
        if (!(i4 <= str.length())) {
            throw new IllegalArgumentException(("endIndex > string.length: " + i4 + " > " + str.length()).toString());
        }
        if (t2.j.b(charset, z2.d.f10544b)) {
            return U0(str, i3, i4);
        }
        String strSubstring = str.substring(i3, i4);
        t2.j.e(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        if (strSubstring == null) {
            throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
        }
        byte[] bytes = strSubstring.getBytes(charset);
        t2.j.e(bytes, "(this as java.lang.String).getBytes(charset)");
        return j(bytes, 0, bytes.length);
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: T0, reason: merged with bridge method [inline-methods] */
    public i j0(String str) {
        t2.j.f(str, "string");
        return U0(str, 0, str.length());
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x00a1  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00b3 A[EDGE_INSN: B:48:0x00b3->B:38:0x00b3 BREAK  A[LOOP:0: B:5:0x0011->B:50:?], SYNTHETIC] */
    @Override // Q2.k
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long U() throws java.io.EOFException {
        /*
            r15 = this;
            long r0 = r15.F0()
            r2 = 0
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 == 0) goto Lc1
            r0 = 0
            r4 = -7
            r1 = r0
            r5 = r4
            r3 = r2
            r2 = r1
        L11:
            Q2.A r7 = r15.f2544b
            t2.j.c(r7)
            byte[] r8 = r7.f2507a
            int r9 = r7.f2508b
            int r10 = r7.f2509c
        L1c:
            if (r9 >= r10) goto L9f
            r11 = r8[r9]
            r12 = 48
            byte r12 = (byte) r12
            if (r11 < r12) goto L6f
            r13 = 57
            byte r13 = (byte) r13
            if (r11 > r13) goto L6f
            int r12 = r12 - r11
            r13 = -922337203685477580(0xf333333333333334, double:-8.390303882365713E246)
            int r13 = (r3 > r13 ? 1 : (r3 == r13 ? 0 : -1))
            if (r13 < 0) goto L42
            if (r13 != 0) goto L3c
            long r13 = (long) r12
            int r13 = (r13 > r5 ? 1 : (r13 == r5 ? 0 : -1))
            if (r13 >= 0) goto L3c
            goto L42
        L3c:
            r13 = 10
            long r3 = r3 * r13
            long r11 = (long) r12
            long r3 = r3 + r11
            goto L7b
        L42:
            Q2.i r0 = new Q2.i
            r0.<init>()
            Q2.i r0 = r0.k0(r3)
            Q2.i r0 = r0.L(r11)
            if (r1 != 0) goto L54
            r0.r0()
        L54:
            java.lang.NumberFormatException r1 = new java.lang.NumberFormatException
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.String r3 = "Number too large: "
            r2.append(r3)
            java.lang.String r0 = r0.O()
            r2.append(r0)
            java.lang.String r0 = r2.toString()
            r1.<init>(r0)
            throw r1
        L6f:
            r12 = 45
            byte r12 = (byte) r12
            r13 = 1
            if (r11 != r12) goto L80
            if (r0 != 0) goto L80
            r11 = 1
            long r5 = r5 - r11
            r1 = r13
        L7b:
            int r9 = r9 + 1
            int r0 = r0 + 1
            goto L1c
        L80:
            if (r0 == 0) goto L84
            r2 = r13
            goto L9f
        L84:
            java.lang.NumberFormatException r0 = new java.lang.NumberFormatException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "Expected leading [0-9] or '-' character but was 0x"
            r1.append(r2)
            java.lang.String r2 = Q2.AbstractC0210f.e(r11)
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L9f:
            if (r9 != r10) goto Lab
            Q2.A r8 = r7.b()
            r15.f2544b = r8
            Q2.B.b(r7)
            goto Lad
        Lab:
            r7.f2508b = r9
        Lad:
            if (r2 != 0) goto Lb3
            Q2.A r7 = r15.f2544b
            if (r7 != 0) goto L11
        Lb3:
            long r5 = r15.F0()
            long r7 = (long) r0
            long r5 = r5 - r7
            r15.E0(r5)
            if (r1 == 0) goto Lbf
            goto Lc0
        Lbf:
            long r3 = -r3
        Lc0:
            return r3
        Lc1:
            java.io.EOFException r0 = new java.io.EOFException
            r0.<init>()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: Q2.i.U():long");
    }

    public i U0(String str, int i3, int i4) {
        t2.j.f(str, "string");
        if (!(i3 >= 0)) {
            throw new IllegalArgumentException(("beginIndex < 0: " + i3).toString());
        }
        if (!(i4 >= i3)) {
            throw new IllegalArgumentException(("endIndex < beginIndex: " + i4 + " < " + i3).toString());
        }
        if (!(i4 <= str.length())) {
            throw new IllegalArgumentException(("endIndex > string.length: " + i4 + " > " + str.length()).toString());
        }
        while (i3 < i4) {
            char cCharAt = str.charAt(i3);
            if (cCharAt < 128) {
                A aI0 = I0(1);
                byte[] bArr = aI0.f2507a;
                int i5 = aI0.f2509c - i3;
                int iMin = Math.min(i4, 8192 - i5);
                int i6 = i3 + 1;
                bArr[i3 + i5] = (byte) cCharAt;
                while (i6 < iMin) {
                    char cCharAt2 = str.charAt(i6);
                    if (cCharAt2 >= 128) {
                        break;
                    }
                    bArr[i6 + i5] = (byte) cCharAt2;
                    i6++;
                }
                int i7 = aI0.f2509c;
                int i8 = (i5 + i6) - i7;
                aI0.f2509c = i7 + i8;
                E0(F0() + ((long) i8));
                i3 = i6;
            } else {
                if (cCharAt < 2048) {
                    A aI02 = I0(2);
                    byte[] bArr2 = aI02.f2507a;
                    int i9 = aI02.f2509c;
                    bArr2[i9] = (byte) ((cCharAt >> 6) | 192);
                    bArr2[i9 + 1] = (byte) ((cCharAt & '?') | 128);
                    aI02.f2509c = i9 + 2;
                    E0(F0() + 2);
                } else if (cCharAt < 55296 || cCharAt > 57343) {
                    A aI03 = I0(3);
                    byte[] bArr3 = aI03.f2507a;
                    int i10 = aI03.f2509c;
                    bArr3[i10] = (byte) ((cCharAt >> '\f') | 224);
                    bArr3[i10 + 1] = (byte) ((63 & (cCharAt >> 6)) | 128);
                    bArr3[i10 + 2] = (byte) ((cCharAt & '?') | 128);
                    aI03.f2509c = i10 + 3;
                    E0(F0() + 3);
                } else {
                    int i11 = i3 + 1;
                    char cCharAt3 = i11 < i4 ? str.charAt(i11) : (char) 0;
                    if (cCharAt > 56319 || 56320 > cCharAt3 || 57343 < cCharAt3) {
                        L(63);
                        i3 = i11;
                    } else {
                        int i12 = (((cCharAt & 1023) << 10) | (cCharAt3 & 1023)) + 65536;
                        A aI04 = I0(4);
                        byte[] bArr4 = aI04.f2507a;
                        int i13 = aI04.f2509c;
                        bArr4[i13] = (byte) ((i12 >> 18) | 240);
                        bArr4[i13 + 1] = (byte) (((i12 >> 12) & 63) | 128);
                        bArr4[i13 + 2] = (byte) (((i12 >> 6) & 63) | 128);
                        bArr4[i13 + 3] = (byte) ((i12 & 63) | 128);
                        aI04.f2509c = i13 + 4;
                        E0(F0() + 4);
                        i3 += 2;
                    }
                }
                i3++;
            }
        }
        return this;
    }

    @Override // Q2.k
    public String V(long j3) throws EOFException {
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("limit < 0: " + j3).toString());
        }
        long j4 = j3 != Long.MAX_VALUE ? j3 + 1 : Long.MAX_VALUE;
        byte b3 = (byte) 10;
        long jD0 = d0(b3, 0L, j4);
        if (jD0 != -1) {
            return R2.a.c(this, jD0);
        }
        if (j4 < F0() && Z(j4 - 1) == ((byte) 13) && Z(j4) == b3) {
            return R2.a.c(this, j4);
        }
        i iVar = new i();
        D(iVar, 0L, Math.min(32, F0()));
        throw new EOFException("\\n not found: limit=" + Math.min(F0(), j3) + " content=" + iVar.z0().k() + (char) 8230);
    }

    public i V0(int i3) {
        if (i3 < 128) {
            L(i3);
        } else if (i3 < 2048) {
            A aI0 = I0(2);
            byte[] bArr = aI0.f2507a;
            int i4 = aI0.f2509c;
            bArr[i4] = (byte) ((i3 >> 6) | 192);
            bArr[i4 + 1] = (byte) ((i3 & 63) | 128);
            aI0.f2509c = i4 + 2;
            E0(F0() + 2);
        } else if (55296 <= i3 && 57343 >= i3) {
            L(63);
        } else if (i3 < 65536) {
            A aI02 = I0(3);
            byte[] bArr2 = aI02.f2507a;
            int i5 = aI02.f2509c;
            bArr2[i5] = (byte) ((i3 >> 12) | 224);
            bArr2[i5 + 1] = (byte) (((i3 >> 6) & 63) | 128);
            bArr2[i5 + 2] = (byte) ((i3 & 63) | 128);
            aI02.f2509c = i5 + 3;
            E0(F0() + 3);
        } else {
            if (i3 > 1114111) {
                throw new IllegalArgumentException("Unexpected code point: 0x" + AbstractC0210f.f(i3));
            }
            A aI03 = I0(4);
            byte[] bArr3 = aI03.f2507a;
            int i6 = aI03.f2509c;
            bArr3[i6] = (byte) ((i3 >> 18) | 240);
            bArr3[i6 + 1] = (byte) (((i3 >> 12) & 63) | 128);
            bArr3[i6 + 2] = (byte) (((i3 >> 6) & 63) | 128);
            bArr3[i6 + 3] = (byte) ((i3 & 63) | 128);
            aI03.f2509c = i6 + 4;
            E0(F0() + 4);
        }
        return this;
    }

    @Override // Q2.k
    public short X() throws EOFException {
        if (F0() < 2) {
            throw new EOFException();
        }
        A a3 = this.f2544b;
        t2.j.c(a3);
        int i3 = a3.f2508b;
        int i4 = a3.f2509c;
        if (i4 - i3 < 2) {
            return (short) (((r0() & 255) << 8) | (r0() & 255));
        }
        byte[] bArr = a3.f2507a;
        int i5 = i3 + 1;
        int i6 = (bArr[i3] & 255) << 8;
        int i7 = i3 + 2;
        int i8 = (bArr[i5] & 255) | i6;
        E0(F0() - 2);
        if (i7 == i4) {
            this.f2544b = a3.b();
            B.b(a3);
        } else {
            a3.f2508b = i7;
        }
        return (short) i8;
    }

    public final byte Z(long j3) {
        AbstractC0210f.b(F0(), j3, 1L);
        A a3 = this.f2544b;
        if (a3 == null) {
            t2.j.c(null);
            throw null;
        }
        if (F0() - j3 < j3) {
            long jF0 = F0();
            while (jF0 > j3) {
                a3 = a3.f2513g;
                t2.j.c(a3);
                jF0 -= (long) (a3.f2509c - a3.f2508b);
            }
            t2.j.c(a3);
            return a3.f2507a[(int) ((((long) a3.f2508b) + j3) - jF0)];
        }
        long j4 = 0;
        while (true) {
            long j5 = ((long) (a3.f2509c - a3.f2508b)) + j4;
            if (j5 > j3) {
                t2.j.c(a3);
                return a3.f2507a[(int) ((((long) a3.f2508b) + j3) - j4)];
            }
            a3 = a3.f2512f;
            t2.j.c(a3);
            j4 = j5;
        }
    }

    @Override // Q2.k
    public int c0(w wVar) throws EOFException {
        t2.j.f(wVar, "options");
        int iE = R2.a.e(this, wVar, false, 2, null);
        if (iE == -1) {
            return -1;
        }
        t(wVar.e()[iE].v());
        return iE;
    }

    public long d0(byte b3, long j3, long j4) {
        A a3;
        int i3;
        long jF0 = 0;
        if (!(0 <= j3 && j4 >= j3)) {
            throw new IllegalArgumentException(("size=" + F0() + " fromIndex=" + j3 + " toIndex=" + j4).toString());
        }
        if (j4 > F0()) {
            j4 = F0();
        }
        if (j3 == j4 || (a3 = this.f2544b) == null) {
            return -1L;
        }
        if (F0() - j3 < j3) {
            jF0 = F0();
            while (jF0 > j3) {
                a3 = a3.f2513g;
                t2.j.c(a3);
                jF0 -= (long) (a3.f2509c - a3.f2508b);
            }
            while (jF0 < j4) {
                byte[] bArr = a3.f2507a;
                int iMin = (int) Math.min(a3.f2509c, (((long) a3.f2508b) + j4) - jF0);
                i3 = (int) ((((long) a3.f2508b) + j3) - jF0);
                while (i3 < iMin) {
                    if (bArr[i3] != b3) {
                        i3++;
                    }
                }
                jF0 += (long) (a3.f2509c - a3.f2508b);
                a3 = a3.f2512f;
                t2.j.c(a3);
                j3 = jF0;
            }
            return -1L;
        }
        while (true) {
            long j5 = ((long) (a3.f2509c - a3.f2508b)) + jF0;
            if (j5 > j3) {
                break;
            }
            a3 = a3.f2512f;
            t2.j.c(a3);
            jF0 = j5;
        }
        while (jF0 < j4) {
            byte[] bArr2 = a3.f2507a;
            int iMin2 = (int) Math.min(a3.f2509c, (((long) a3.f2508b) + j4) - jF0);
            i3 = (int) ((((long) a3.f2508b) + j3) - jF0);
            while (i3 < iMin2) {
                if (bArr2[i3] != b3) {
                    i3++;
                }
            }
            jF0 += (long) (a3.f2509c - a3.f2508b);
            a3 = a3.f2512f;
            t2.j.c(a3);
            j3 = jF0;
        }
        return -1L;
        return ((long) (i3 - a3.f2508b)) + jF0;
    }

    public long e0(l lVar) {
        t2.j.f(lVar, "bytes");
        return f0(lVar, 0L);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof i) {
            i iVar = (i) obj;
            if (F0() == iVar.F0()) {
                if (F0() == 0) {
                    return true;
                }
                A a3 = this.f2544b;
                t2.j.c(a3);
                A a4 = iVar.f2544b;
                t2.j.c(a4);
                int i3 = a3.f2508b;
                int i4 = a4.f2508b;
                long j3 = 0;
                while (j3 < F0()) {
                    long jMin = Math.min(a3.f2509c - i3, a4.f2509c - i4);
                    long j4 = 0;
                    while (j4 < jMin) {
                        int i5 = i3 + 1;
                        int i6 = i4 + 1;
                        if (a3.f2507a[i3] == a4.f2507a[i4]) {
                            j4++;
                            i3 = i5;
                            i4 = i6;
                        }
                    }
                    if (i3 == a3.f2509c) {
                        a3 = a3.f2512f;
                        t2.j.c(a3);
                        i3 = a3.f2508b;
                    }
                    if (i4 == a4.f2509c) {
                        a4 = a4.f2512f;
                        t2.j.c(a4);
                        i4 = a4.f2508b;
                    }
                    j3 += jMin;
                }
                return true;
            }
        }
        return false;
    }

    @Override // Q2.F
    public G f() {
        return G.f2522d;
    }

    public long f0(l lVar, long j3) {
        long j4 = j3;
        t2.j.f(lVar, "bytes");
        if (!(lVar.v() > 0)) {
            throw new IllegalArgumentException("bytes is empty");
        }
        long j5 = 0;
        if (!(j4 >= 0)) {
            throw new IllegalArgumentException(("fromIndex < 0: " + j4).toString());
        }
        A a3 = this.f2544b;
        if (a3 != null) {
            if (F0() - j4 < j4) {
                long jF0 = F0();
                while (jF0 > j4) {
                    a3 = a3.f2513g;
                    t2.j.c(a3);
                    jF0 -= (long) (a3.f2509c - a3.f2508b);
                }
                byte[] bArrL = lVar.l();
                byte b3 = bArrL[0];
                int iV = lVar.v();
                long jF02 = (F0() - ((long) iV)) + 1;
                while (jF0 < jF02) {
                    byte[] bArr = a3.f2507a;
                    long j6 = jF0;
                    int iMin = (int) Math.min(a3.f2509c, (((long) a3.f2508b) + jF02) - jF0);
                    for (int i3 = (int) ((((long) a3.f2508b) + j4) - j6); i3 < iMin; i3++) {
                        if (bArr[i3] == b3 && R2.a.b(a3, i3 + 1, bArrL, 1, iV)) {
                            return ((long) (i3 - a3.f2508b)) + j6;
                        }
                    }
                    jF0 = j6 + ((long) (a3.f2509c - a3.f2508b));
                    a3 = a3.f2512f;
                    t2.j.c(a3);
                    j4 = jF0;
                }
            } else {
                while (true) {
                    long j7 = ((long) (a3.f2509c - a3.f2508b)) + j5;
                    if (j7 > j4) {
                        break;
                    }
                    a3 = a3.f2512f;
                    t2.j.c(a3);
                    j5 = j7;
                }
                byte[] bArrL2 = lVar.l();
                byte b4 = bArrL2[0];
                int iV2 = lVar.v();
                long jF03 = (F0() - ((long) iV2)) + 1;
                while (j5 < jF03) {
                    byte[] bArr2 = a3.f2507a;
                    long j8 = jF03;
                    int iMin2 = (int) Math.min(a3.f2509c, (((long) a3.f2508b) + jF03) - j5);
                    for (int i4 = (int) ((((long) a3.f2508b) + j4) - j5); i4 < iMin2; i4++) {
                        if (bArr2[i4] == b4 && R2.a.b(a3, i4 + 1, bArrL2, 1, iV2)) {
                            return ((long) (i4 - a3.f2508b)) + j5;
                        }
                    }
                    j5 += (long) (a3.f2509c - a3.f2508b);
                    a3 = a3.f2512f;
                    t2.j.c(a3);
                    j4 = j5;
                    jF03 = j8;
                }
            }
        }
        return -1L;
    }

    @Override // Q2.k
    public long h0(D d3) {
        t2.j.f(d3, "sink");
        long jF0 = F0();
        if (jF0 > 0) {
            d3.m(this, jF0);
        }
        return jF0;
    }

    public int hashCode() {
        A a3 = this.f2544b;
        if (a3 == null) {
            return 0;
        }
        int i3 = 1;
        do {
            int i4 = a3.f2509c;
            for (int i5 = a3.f2508b; i5 < i4; i5++) {
                i3 = (i3 * 31) + a3.f2507a[i5];
            }
            a3 = a3.f2512f;
            t2.j.c(a3);
        } while (a3 != this.f2544b);
        return i3;
    }

    @Override // Q2.k
    public void i0(long j3) throws EOFException {
        if (this.f2545c < j3) {
            throw new EOFException();
        }
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return true;
    }

    @Override // Q2.k
    public void l(byte[] bArr) throws EOFException {
        t2.j.f(bArr, "sink");
        int i3 = 0;
        while (i3 < bArr.length) {
            int iW0 = w0(bArr, i3, bArr.length - i3);
            if (iW0 == -1) {
                throw new EOFException();
            }
            i3 += iW0;
        }
    }

    @Override // Q2.j
    public OutputStream l0() {
        return new c();
    }

    @Override // Q2.D
    public void m(i iVar, long j3) {
        A a3;
        t2.j.f(iVar, "source");
        if (!(iVar != this)) {
            throw new IllegalArgumentException("source == this");
        }
        AbstractC0210f.b(iVar.F0(), 0L, j3);
        while (j3 > 0) {
            A a4 = iVar.f2544b;
            t2.j.c(a4);
            int i3 = a4.f2509c;
            t2.j.c(iVar.f2544b);
            if (j3 < i3 - r2.f2508b) {
                A a5 = this.f2544b;
                if (a5 != null) {
                    t2.j.c(a5);
                    a3 = a5.f2513g;
                } else {
                    a3 = null;
                }
                if (a3 != null && a3.f2511e) {
                    if ((((long) a3.f2509c) + j3) - ((long) (a3.f2510d ? 0 : a3.f2508b)) <= 8192) {
                        A a6 = iVar.f2544b;
                        t2.j.c(a6);
                        a6.g(a3, (int) j3);
                        iVar.E0(iVar.F0() - j3);
                        E0(F0() + j3);
                        return;
                    }
                }
                A a7 = iVar.f2544b;
                t2.j.c(a7);
                iVar.f2544b = a7.e((int) j3);
            }
            A a8 = iVar.f2544b;
            t2.j.c(a8);
            long j4 = a8.f2509c - a8.f2508b;
            iVar.f2544b = a8.b();
            A a9 = this.f2544b;
            if (a9 == null) {
                this.f2544b = a8;
                a8.f2513g = a8;
                a8.f2512f = a8;
            } else {
                t2.j.c(a9);
                A a10 = a9.f2513g;
                t2.j.c(a10);
                a10.c(a8).a();
            }
            iVar.E0(iVar.F0() - j4);
            E0(F0() + j4);
            j3 -= j4;
        }
    }

    public long n0(l lVar) {
        t2.j.f(lVar, "targetBytes");
        return t0(lVar, 0L);
    }

    @Override // Q2.j
    public long o(F f3) {
        t2.j.f(f3, "source");
        long j3 = 0;
        while (true) {
            long jR = f3.R(this, 8192);
            if (jR == -1) {
                return j3;
            }
            j3 += jR;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00ae A[EDGE_INSN: B:43:0x00ae->B:37:0x00ae BREAK  A[LOOP:0: B:5:0x000d->B:45:?], SYNTHETIC] */
    @Override // Q2.k
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long o0() throws java.io.EOFException {
        /*
            r14 = this;
            long r0 = r14.F0()
            r2 = 0
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 == 0) goto Lb8
            r0 = 0
            r1 = r0
            r4 = r2
        Ld:
            Q2.A r6 = r14.f2544b
            t2.j.c(r6)
            byte[] r7 = r6.f2507a
            int r8 = r6.f2508b
            int r9 = r6.f2509c
        L18:
            if (r8 >= r9) goto L9a
            r10 = r7[r8]
            r11 = 48
            byte r11 = (byte) r11
            if (r10 < r11) goto L29
            r12 = 57
            byte r12 = (byte) r12
            if (r10 > r12) goto L29
            int r11 = r10 - r11
            goto L43
        L29:
            r11 = 97
            byte r11 = (byte) r11
            if (r10 < r11) goto L38
            r12 = 102(0x66, float:1.43E-43)
            byte r12 = (byte) r12
            if (r10 > r12) goto L38
        L33:
            int r11 = r10 - r11
            int r11 = r11 + 10
            goto L43
        L38:
            r11 = 65
            byte r11 = (byte) r11
            if (r10 < r11) goto L7b
            r12 = 70
            byte r12 = (byte) r12
            if (r10 > r12) goto L7b
            goto L33
        L43:
            r12 = -1152921504606846976(0xf000000000000000, double:-3.105036184601418E231)
            long r12 = r12 & r4
            int r12 = (r12 > r2 ? 1 : (r12 == r2 ? 0 : -1))
            if (r12 != 0) goto L53
            r10 = 4
            long r4 = r4 << r10
            long r10 = (long) r11
            long r4 = r4 | r10
            int r8 = r8 + 1
            int r0 = r0 + 1
            goto L18
        L53:
            Q2.i r0 = new Q2.i
            r0.<init>()
            Q2.i r0 = r0.n(r4)
            Q2.i r0 = r0.L(r10)
            java.lang.NumberFormatException r1 = new java.lang.NumberFormatException
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.String r3 = "Number too large: "
            r2.append(r3)
            java.lang.String r0 = r0.O()
            r2.append(r0)
            java.lang.String r0 = r2.toString()
            r1.<init>(r0)
            throw r1
        L7b:
            if (r0 == 0) goto L7f
            r1 = 1
            goto L9a
        L7f:
            java.lang.NumberFormatException r0 = new java.lang.NumberFormatException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "Expected leading [0-9a-fA-F] character but was 0x"
            r1.append(r2)
            java.lang.String r2 = Q2.AbstractC0210f.e(r10)
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L9a:
            if (r8 != r9) goto La6
            Q2.A r7 = r6.b()
            r14.f2544b = r7
            Q2.B.b(r6)
            goto La8
        La6:
            r6.f2508b = r8
        La8:
            if (r1 != 0) goto Lae
            Q2.A r6 = r14.f2544b
            if (r6 != 0) goto Ld
        Lae:
            long r1 = r14.F0()
            long r6 = (long) r0
            long r1 = r1 - r6
            r14.E0(r1)
            return r4
        Lb8:
            java.io.EOFException r0 = new java.io.EOFException
            r0.<init>()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: Q2.i.o0():long");
    }

    @Override // Q2.k
    public String p0(Charset charset) {
        t2.j.f(charset, "charset");
        return C0(this.f2545c, charset);
    }

    @Override // Q2.k
    public l q(long j3) throws EOFException {
        if (!(j3 >= 0 && j3 <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException(("byteCount: " + j3).toString());
        }
        if (F0() < j3) {
            throw new EOFException();
        }
        if (j3 < 4096) {
            return new l(M(j3));
        }
        l lVarH0 = H0((int) j3);
        t(j3);
        return lVarH0;
    }

    @Override // Q2.k
    public InputStream q0() {
        return new b();
    }

    @Override // Q2.k
    public byte r0() throws EOFException {
        if (F0() == 0) {
            throw new EOFException();
        }
        A a3 = this.f2544b;
        t2.j.c(a3);
        int i3 = a3.f2508b;
        int i4 = a3.f2509c;
        int i5 = i3 + 1;
        byte b3 = a3.f2507a[i3];
        E0(F0() - 1);
        if (i5 == i4) {
            this.f2544b = a3.b();
            B.b(a3);
        } else {
            a3.f2508b = i5;
        }
        return b3;
    }

    @Override // java.nio.channels.ReadableByteChannel
    public int read(ByteBuffer byteBuffer) {
        t2.j.f(byteBuffer, "sink");
        A a3 = this.f2544b;
        if (a3 == null) {
            return -1;
        }
        int iMin = Math.min(byteBuffer.remaining(), a3.f2509c - a3.f2508b);
        byteBuffer.put(a3.f2507a, a3.f2508b, iMin);
        int i3 = a3.f2508b + iMin;
        a3.f2508b = i3;
        this.f2545c -= (long) iMin;
        if (i3 == a3.f2509c) {
            this.f2544b = a3.b();
            B.b(a3);
        }
        return iMin;
    }

    @Override // Q2.k
    public void t(long j3) throws EOFException {
        while (j3 > 0) {
            A a3 = this.f2544b;
            if (a3 == null) {
                throw new EOFException();
            }
            int iMin = (int) Math.min(j3, a3.f2509c - a3.f2508b);
            long j4 = iMin;
            E0(F0() - j4);
            j3 -= j4;
            int i3 = a3.f2508b + iMin;
            a3.f2508b = i3;
            if (i3 == a3.f2509c) {
                this.f2544b = a3.b();
                B.b(a3);
            }
        }
    }

    public long t0(l lVar, long j3) {
        int i3;
        int i4;
        t2.j.f(lVar, "targetBytes");
        long jF0 = 0;
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("fromIndex < 0: " + j3).toString());
        }
        A a3 = this.f2544b;
        if (a3 == null) {
            return -1L;
        }
        if (F0() - j3 < j3) {
            jF0 = F0();
            while (jF0 > j3) {
                a3 = a3.f2513g;
                t2.j.c(a3);
                jF0 -= (long) (a3.f2509c - a3.f2508b);
            }
            if (lVar.v() == 2) {
                byte bF = lVar.f(0);
                byte bF2 = lVar.f(1);
                while (jF0 < F0()) {
                    byte[] bArr = a3.f2507a;
                    i3 = (int) ((((long) a3.f2508b) + j3) - jF0);
                    int i5 = a3.f2509c;
                    while (i3 < i5) {
                        byte b3 = bArr[i3];
                        if (b3 == bF || b3 == bF2) {
                            i4 = a3.f2508b;
                        } else {
                            i3++;
                        }
                    }
                    jF0 += (long) (a3.f2509c - a3.f2508b);
                    a3 = a3.f2512f;
                    t2.j.c(a3);
                    j3 = jF0;
                }
                return -1L;
            }
            byte[] bArrL = lVar.l();
            while (jF0 < F0()) {
                byte[] bArr2 = a3.f2507a;
                i3 = (int) ((((long) a3.f2508b) + j3) - jF0);
                int i6 = a3.f2509c;
                while (i3 < i6) {
                    byte b4 = bArr2[i3];
                    for (byte b5 : bArrL) {
                        if (b4 == b5) {
                            i4 = a3.f2508b;
                        }
                    }
                    i3++;
                }
                jF0 += (long) (a3.f2509c - a3.f2508b);
                a3 = a3.f2512f;
                t2.j.c(a3);
                j3 = jF0;
            }
            return -1L;
        }
        while (true) {
            long j4 = ((long) (a3.f2509c - a3.f2508b)) + jF0;
            if (j4 > j3) {
                break;
            }
            a3 = a3.f2512f;
            t2.j.c(a3);
            jF0 = j4;
        }
        if (lVar.v() == 2) {
            byte bF3 = lVar.f(0);
            byte bF4 = lVar.f(1);
            while (jF0 < F0()) {
                byte[] bArr3 = a3.f2507a;
                i3 = (int) ((((long) a3.f2508b) + j3) - jF0);
                int i7 = a3.f2509c;
                while (i3 < i7) {
                    byte b6 = bArr3[i3];
                    if (b6 == bF3 || b6 == bF4) {
                        i4 = a3.f2508b;
                    } else {
                        i3++;
                    }
                }
                jF0 += (long) (a3.f2509c - a3.f2508b);
                a3 = a3.f2512f;
                t2.j.c(a3);
                j3 = jF0;
            }
            return -1L;
        }
        byte[] bArrL2 = lVar.l();
        while (jF0 < F0()) {
            byte[] bArr4 = a3.f2507a;
            i3 = (int) ((((long) a3.f2508b) + j3) - jF0);
            int i8 = a3.f2509c;
            while (i3 < i8) {
                byte b7 = bArr4[i3];
                for (byte b8 : bArrL2) {
                    if (b7 == b8) {
                        i4 = a3.f2508b;
                    }
                }
                i3++;
            }
            jF0 += (long) (a3.f2509c - a3.f2508b);
            a3 = a3.f2512f;
            t2.j.c(a3);
            j3 = jF0;
        }
        return -1L;
        return ((long) (i3 - i4)) + jF0;
    }

    public String toString() {
        return G0().toString();
    }

    public boolean u0(long j3, l lVar) {
        t2.j.f(lVar, "bytes");
        return v0(j3, lVar, 0, lVar.v());
    }

    public final void v() throws EOFException {
        t(F0());
    }

    public boolean v0(long j3, l lVar, int i3, int i4) {
        t2.j.f(lVar, "bytes");
        if (j3 < 0 || i3 < 0 || i4 < 0 || F0() - j3 < i4 || lVar.v() - i3 < i4) {
            return false;
        }
        for (int i5 = 0; i5 < i4; i5++) {
            if (Z(((long) i5) + j3) != lVar.f(i3 + i5)) {
                return false;
            }
        }
        return true;
    }

    public int w0(byte[] bArr, int i3, int i4) {
        t2.j.f(bArr, "sink");
        AbstractC0210f.b(bArr.length, i3, i4);
        A a3 = this.f2544b;
        if (a3 == null) {
            return -1;
        }
        int iMin = Math.min(i4, a3.f2509c - a3.f2508b);
        byte[] bArr2 = a3.f2507a;
        int i5 = a3.f2508b;
        AbstractC0580h.e(bArr2, bArr, i3, i5, i5 + iMin);
        a3.f2508b += iMin;
        E0(F0() - ((long) iMin));
        if (a3.f2508b != a3.f2509c) {
            return iMin;
        }
        this.f2544b = a3.b();
        B.b(a3);
        return iMin;
    }

    @Override // java.nio.channels.WritableByteChannel
    public int write(ByteBuffer byteBuffer) {
        t2.j.f(byteBuffer, "source");
        int iRemaining = byteBuffer.remaining();
        int i3 = iRemaining;
        while (i3 > 0) {
            A aI0 = I0(1);
            int iMin = Math.min(i3, 8192 - aI0.f2509c);
            byteBuffer.get(aI0.f2507a, aI0.f2509c, iMin);
            i3 -= iMin;
            aI0.f2509c += iMin;
        }
        this.f2545c += (long) iRemaining;
        return iRemaining;
    }

    /* JADX INFO: renamed from: x, reason: merged with bridge method [inline-methods] */
    public i clone() {
        return A();
    }

    public final a x0(a aVar) {
        t2.j.f(aVar, "unsafeCursor");
        if (!(aVar.f2546b == null)) {
            throw new IllegalStateException("already attached to a buffer");
        }
        aVar.f2546b = this;
        aVar.f2547c = true;
        return aVar;
    }

    public final long y() {
        long jF0 = F0();
        if (jF0 == 0) {
            return 0L;
        }
        A a3 = this.f2544b;
        t2.j.c(a3);
        A a4 = a3.f2513g;
        t2.j.c(a4);
        int i3 = a4.f2509c;
        if (i3 < 8192 && a4.f2511e) {
            jF0 -= (long) (i3 - a4.f2508b);
        }
        return jF0;
    }

    public l z0() {
        return q(F0());
    }

    public static final class b extends InputStream {
        b() {
        }

        @Override // java.io.InputStream
        public int available() {
            return (int) Math.min(i.this.F0(), Integer.MAX_VALUE);
        }

        @Override // java.io.InputStream
        public int read() {
            if (i.this.F0() > 0) {
                return i.this.r0() & 255;
            }
            return -1;
        }

        public String toString() {
            return i.this + ".inputStream()";
        }

        @Override // java.io.InputStream
        public int read(byte[] bArr, int i3, int i4) {
            t2.j.f(bArr, "sink");
            return i.this.w0(bArr, i3, i4);
        }

        @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
        }
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: P, reason: merged with bridge method [inline-methods] */
    public i u() {
        return this;
    }

    @Override // Q2.j
    /* JADX INFO: renamed from: W, reason: merged with bridge method [inline-methods] */
    public i S() {
        return this;
    }

    @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @Override // Q2.k, Q2.j
    public i e() {
        return this;
    }

    @Override // Q2.j, Q2.D, java.io.Flushable
    public void flush() {
    }
}
