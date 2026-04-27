package Q2;

import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Inflater;

/* JADX INFO: loaded from: classes.dex */
public final class q implements F {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private byte f2566b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final z f2567c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Inflater f2568d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final r f2569e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final CRC32 f2570f;

    public q(F f3) {
        t2.j.f(f3, "source");
        z zVar = new z(f3);
        this.f2567c = zVar;
        Inflater inflater = new Inflater(true);
        this.f2568d = inflater;
        this.f2569e = new r((k) zVar, inflater);
        this.f2570f = new CRC32();
    }

    private final void b(String str, int i3, int i4) throws IOException {
        if (i4 == i3) {
            return;
        }
        String str2 = String.format("%s: actual 0x%08x != expected 0x%08x", Arrays.copyOf(new Object[]{str, Integer.valueOf(i4), Integer.valueOf(i3)}, 3));
        t2.j.e(str2, "java.lang.String.format(this, *args)");
        throw new IOException(str2);
    }

    private final void i() throws IOException {
        this.f2567c.i0(10L);
        byte bZ = this.f2567c.f2587b.Z(3L);
        boolean z3 = ((bZ >> 1) & 1) == 1;
        if (z3) {
            r(this.f2567c.f2587b, 0L, 10L);
        }
        b("ID1ID2", 8075, this.f2567c.X());
        this.f2567c.t(8L);
        if (((bZ >> 2) & 1) == 1) {
            this.f2567c.i0(2L);
            if (z3) {
                r(this.f2567c.f2587b, 0L, 2L);
            }
            long jB0 = this.f2567c.f2587b.B0();
            this.f2567c.i0(jB0);
            if (z3) {
                r(this.f2567c.f2587b, 0L, jB0);
            }
            this.f2567c.t(jB0);
        }
        if (((bZ >> 3) & 1) == 1) {
            long jB = this.f2567c.b((byte) 0);
            if (jB == -1) {
                throw new EOFException();
            }
            if (z3) {
                r(this.f2567c.f2587b, 0L, jB + 1);
            }
            this.f2567c.t(jB + 1);
        }
        if (((bZ >> 4) & 1) == 1) {
            long jB2 = this.f2567c.b((byte) 0);
            if (jB2 == -1) {
                throw new EOFException();
            }
            if (z3) {
                r(this.f2567c.f2587b, 0L, jB2 + 1);
            }
            this.f2567c.t(jB2 + 1);
        }
        if (z3) {
            b("FHCRC", this.f2567c.r(), (short) this.f2570f.getValue());
            this.f2570f.reset();
        }
    }

    private final void p() throws IOException {
        b("CRC", this.f2567c.p(), (int) this.f2570f.getValue());
        b("ISIZE", this.f2567c.p(), (int) this.f2568d.getBytesWritten());
    }

    private final void r(i iVar, long j3, long j4) {
        A a3 = iVar.f2544b;
        t2.j.c(a3);
        while (true) {
            int i3 = a3.f2509c;
            int i4 = a3.f2508b;
            if (j3 < i3 - i4) {
                break;
            }
            j3 -= (long) (i3 - i4);
            a3 = a3.f2512f;
            t2.j.c(a3);
        }
        while (j4 > 0) {
            int i5 = (int) (((long) a3.f2508b) + j3);
            int iMin = (int) Math.min(a3.f2509c - i5, j4);
            this.f2570f.update(a3.f2507a, i5, iMin);
            j4 -= (long) iMin;
            a3 = a3.f2512f;
            t2.j.c(a3);
            j3 = 0;
        }
    }

    @Override // Q2.F
    public long R(i iVar, long j3) throws IOException {
        t2.j.f(iVar, "sink");
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
        }
        if (j3 == 0) {
            return 0L;
        }
        if (this.f2566b == 0) {
            i();
            this.f2566b = (byte) 1;
        }
        if (this.f2566b == 1) {
            long jF0 = iVar.F0();
            long jR = this.f2569e.R(iVar, j3);
            if (jR != -1) {
                r(iVar, jF0, jR);
                return jR;
            }
            this.f2566b = (byte) 2;
        }
        if (this.f2566b == 2) {
            p();
            this.f2566b = (byte) 3;
            if (!this.f2567c.K()) {
                throw new IOException("gzip finished without exhausting source");
            }
        }
        return -1L;
    }

    @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f2569e.close();
    }

    @Override // Q2.F
    public G f() {
        return this.f2567c.f();
    }
}
