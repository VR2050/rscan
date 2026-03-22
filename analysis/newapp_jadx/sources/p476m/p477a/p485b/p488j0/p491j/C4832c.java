package p476m.p477a.p485b.p488j0.p491j;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4790a;
import p476m.p477a.p485b.C4803g0;
import p476m.p477a.p485b.C4873m;
import p476m.p477a.p485b.C4903w;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.p486h0.C4805a;
import p476m.p477a.p485b.p492k0.InterfaceC4847a;
import p476m.p477a.p485b.p492k0.InterfaceC4850d;
import p476m.p477a.p485b.p493l0.C4861i;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.j0.j.c */
/* loaded from: classes3.dex */
public class C4832c extends InputStream {

    /* renamed from: c */
    public final InterfaceC4850d f12376c;

    /* renamed from: e */
    public final C4893b f12377e;

    /* renamed from: f */
    public final C4805a f12378f;

    /* renamed from: g */
    public int f12379g;

    /* renamed from: h */
    public long f12380h;

    /* renamed from: i */
    public long f12381i;

    /* renamed from: j */
    public boolean f12382j = false;

    /* renamed from: k */
    public boolean f12383k = false;

    /* renamed from: l */
    public InterfaceC4800f[] f12384l = new InterfaceC4800f[0];

    public C4832c(InterfaceC4850d interfaceC4850d, C4805a c4805a) {
        C2354n.m2470e1(interfaceC4850d, "Session input buffer");
        this.f12376c = interfaceC4850d;
        this.f12381i = 0L;
        this.f12377e = new C4893b(16);
        this.f12378f = c4805a == null ? C4805a.f12283c : c4805a;
        this.f12379g = 1;
    }

    @Override // java.io.InputStream
    public int available() {
        if (this.f12376c instanceof InterfaceC4847a) {
            return (int) Math.min(((InterfaceC4847a) r0).length(), this.f12380h - this.f12381i);
        }
        return 0;
    }

    /* renamed from: b */
    public final long m5493b() {
        int i2 = this.f12379g;
        if (i2 != 1) {
            if (i2 != 3) {
                throw new IllegalStateException("Inconsistent codec state");
            }
            C4893b c4893b = this.f12377e;
            c4893b.f12498e = 0;
            if (this.f12376c.mo5498a(c4893b) == -1) {
                throw new C4903w("CRLF expected at end of chunk");
            }
            if (!(this.f12377e.f12498e == 0)) {
                throw new C4903w("Unexpected content at the end of chunk");
            }
            this.f12379g = 1;
        }
        C4893b c4893b2 = this.f12377e;
        c4893b2.f12498e = 0;
        if (this.f12376c.mo5498a(c4893b2) == -1) {
            throw new C4790a("Premature end of chunk coded message body: closing chunk expected");
        }
        C4893b c4893b3 = this.f12377e;
        int m5563f = c4893b3.m5563f(59, 0, c4893b3.f12498e);
        if (m5563f < 0) {
            m5563f = this.f12377e.f12498e;
        }
        String m5565h = this.f12377e.m5565h(0, m5563f);
        try {
            return Long.parseLong(m5565h, 16);
        } catch (NumberFormatException unused) {
            throw new C4903w(C1499a.m637w("Bad chunk header: ", m5565h));
        }
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12383k) {
            return;
        }
        try {
            if (!this.f12382j && this.f12379g != Integer.MAX_VALUE) {
                do {
                } while (read(new byte[2048]) >= 0);
            }
        } finally {
            this.f12382j = true;
            this.f12383k = true;
        }
    }

    /* renamed from: d */
    public final void m5494d() {
        if (this.f12379g == Integer.MAX_VALUE) {
            throw new C4903w("Corrupt data stream");
        }
        try {
            long m5493b = m5493b();
            this.f12380h = m5493b;
            if (m5493b < 0) {
                throw new C4903w("Negative chunk size");
            }
            this.f12379g = 2;
            this.f12381i = 0L;
            if (m5493b == 0) {
                this.f12382j = true;
                m5495e();
            }
        } catch (C4903w e2) {
            this.f12379g = Integer.MAX_VALUE;
            throw e2;
        }
    }

    /* renamed from: e */
    public final void m5495e() {
        try {
            InterfaceC4850d interfaceC4850d = this.f12376c;
            C4805a c4805a = this.f12378f;
            this.f12384l = AbstractC4830a.m5491b(interfaceC4850d, c4805a.f12285f, c4805a.f12284e, C4861i.f12450a, new ArrayList());
        } catch (C4873m e2) {
            StringBuilder m586H = C1499a.m586H("Invalid footer: ");
            m586H.append(e2.getMessage());
            C4903w c4903w = new C4903w(m586H.toString());
            c4903w.initCause(e2);
            throw c4903w;
        }
    }

    @Override // java.io.InputStream
    public int read() {
        if (this.f12383k) {
            throw new IOException("Attempted read from closed stream.");
        }
        if (this.f12382j) {
            return -1;
        }
        if (this.f12379g != 2) {
            m5494d();
            if (this.f12382j) {
                return -1;
            }
        }
        int read = this.f12376c.read();
        if (read != -1) {
            long j2 = this.f12381i + 1;
            this.f12381i = j2;
            if (j2 >= this.f12380h) {
                this.f12379g = 3;
            }
        }
        return read;
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i2, int i3) {
        if (!this.f12383k) {
            if (this.f12382j) {
                return -1;
            }
            if (this.f12379g != 2) {
                m5494d();
                if (this.f12382j) {
                    return -1;
                }
            }
            int read = this.f12376c.read(bArr, i2, (int) Math.min(i3, this.f12380h - this.f12381i));
            if (read != -1) {
                long j2 = this.f12381i + read;
                this.f12381i = j2;
                if (j2 >= this.f12380h) {
                    this.f12379g = 3;
                }
                return read;
            }
            this.f12382j = true;
            throw new C4803g0("Truncated chunk (expected size: %,d; actual size: %,d)", Long.valueOf(this.f12380h), Long.valueOf(this.f12381i));
        }
        throw new IOException("Attempted read from closed stream.");
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr) {
        return read(bArr, 0, bArr.length);
    }
}
