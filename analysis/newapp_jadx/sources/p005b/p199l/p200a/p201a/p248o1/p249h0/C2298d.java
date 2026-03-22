package p005b.p199l.p200a.p201a.p248o1.p249h0;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2319k;
import p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2363w;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.h0.d */
/* loaded from: classes.dex */
public final class C2298d implements InterfaceC2319k {

    /* renamed from: a */
    public final InterfaceC2297c f5821a;

    /* renamed from: b */
    public final long f5822b;

    /* renamed from: c */
    public final int f5823c;

    /* renamed from: d */
    public C2324p f5824d;

    /* renamed from: e */
    public long f5825e;

    /* renamed from: f */
    public File f5826f;

    /* renamed from: g */
    public OutputStream f5827g;

    /* renamed from: h */
    public long f5828h;

    /* renamed from: i */
    public long f5829i;

    /* renamed from: j */
    public C2363w f5830j;

    /* renamed from: b.l.a.a.o1.h0.d$a */
    public static class a extends InterfaceC2297c.a {
        public a(IOException iOException) {
            super(iOException);
        }
    }

    public C2298d(InterfaceC2297c interfaceC2297c, long j2, int i2) {
        C4195m.m4773J(j2 > 0 || j2 == -1, "fragmentSize must be positive or C.LENGTH_UNSET.");
        if (j2 != -1) {
            int i3 = (j2 > 2097152L ? 1 : (j2 == 2097152L ? 0 : -1));
        }
        Objects.requireNonNull(interfaceC2297c);
        this.f5821a = interfaceC2297c;
        this.f5822b = j2 == -1 ? Long.MAX_VALUE : j2;
        this.f5823c = i2;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2319k
    /* renamed from: a */
    public void mo2215a(byte[] bArr, int i2, int i3) {
        if (this.f5824d == null) {
            return;
        }
        int i4 = 0;
        while (i4 < i3) {
            try {
                if (this.f5828h == this.f5825e) {
                    m2216b();
                    m2217c();
                }
                int min = (int) Math.min(i3 - i4, this.f5825e - this.f5828h);
                this.f5827g.write(bArr, i2 + i4, min);
                i4 += min;
                long j2 = min;
                this.f5828h += j2;
                this.f5829i += j2;
            } catch (IOException e2) {
                throw new a(e2);
            }
        }
    }

    /* renamed from: b */
    public final void m2216b() {
        OutputStream outputStream = this.f5827g;
        if (outputStream == null) {
            return;
        }
        try {
            outputStream.flush();
            OutputStream outputStream2 = this.f5827g;
            int i2 = C2344d0.f6035a;
            if (outputStream2 != null) {
                try {
                    outputStream2.close();
                } catch (IOException unused) {
                }
            }
            this.f5827g = null;
            File file = this.f5826f;
            this.f5826f = null;
            this.f5821a.mo2206g(file, this.f5828h);
        } catch (Throwable th) {
            OutputStream outputStream3 = this.f5827g;
            int i3 = C2344d0.f6035a;
            if (outputStream3 != null) {
                try {
                    outputStream3.close();
                } catch (IOException unused2) {
                }
            }
            this.f5827g = null;
            File file2 = this.f5826f;
            this.f5826f = null;
            file2.delete();
            throw th;
        }
    }

    /* renamed from: c */
    public final void m2217c() {
        long j2 = this.f5824d.f5939g;
        long min = j2 != -1 ? Math.min(j2 - this.f5829i, this.f5825e) : -1L;
        InterfaceC2297c interfaceC2297c = this.f5821a;
        C2324p c2324p = this.f5824d;
        this.f5826f = interfaceC2297c.mo2200a(c2324p.f5940h, c2324p.f5937e + this.f5829i, min);
        FileOutputStream fileOutputStream = new FileOutputStream(this.f5826f);
        if (this.f5823c > 0) {
            C2363w c2363w = this.f5830j;
            if (c2363w == null) {
                this.f5830j = new C2363w(fileOutputStream, this.f5823c);
            } else {
                c2363w.m2605b(fileOutputStream);
            }
            this.f5827g = this.f5830j;
        } else {
            this.f5827g = fileOutputStream;
        }
        this.f5828h = 0L;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2319k
    public void close() {
        if (this.f5824d == null) {
            return;
        }
        try {
            m2216b();
        } catch (IOException e2) {
            throw new a(e2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2319k
    public void open(C2324p c2324p) {
        if (c2324p.f5939g == -1 && c2324p.m2267b(2)) {
            this.f5824d = null;
            return;
        }
        this.f5824d = c2324p;
        this.f5825e = c2324p.m2267b(4) ? this.f5822b : Long.MAX_VALUE;
        this.f5829i = 0L;
        try {
            m2217c();
        } catch (IOException e2) {
            throw new a(e2);
        }
    }
}
