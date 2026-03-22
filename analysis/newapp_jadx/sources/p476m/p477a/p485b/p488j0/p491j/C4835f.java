package p476m.p477a.p485b.p488j0.p491j;

import java.io.IOException;
import java.io.OutputStream;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.p492k0.InterfaceC4851e;

/* renamed from: m.a.b.j0.j.f */
/* loaded from: classes3.dex */
public class C4835f extends OutputStream {

    /* renamed from: c */
    public final InterfaceC4851e f12394c;

    /* renamed from: e */
    public final long f12395e;

    /* renamed from: f */
    public long f12396f;

    /* renamed from: g */
    public boolean f12397g;

    public C4835f(InterfaceC4851e interfaceC4851e, long j2) {
        C2354n.m2470e1(interfaceC4851e, "Session output buffer");
        this.f12394c = interfaceC4851e;
        C2354n.m2466d1(j2, "Content length");
        this.f12395e = j2;
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12397g) {
            return;
        }
        this.f12397g = true;
        this.f12394c.flush();
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() {
        this.f12394c.flush();
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i2, int i3) {
        if (this.f12397g) {
            throw new IOException("Attempted write to closed stream.");
        }
        long j2 = this.f12396f;
        long j3 = this.f12395e;
        if (j2 < j3) {
            long j4 = j3 - j2;
            if (i3 > j4) {
                i3 = (int) j4;
            }
            this.f12394c.mo5503a(bArr, i2, i3);
            this.f12396f += i3;
        }
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) {
        write(bArr, 0, bArr.length);
    }

    @Override // java.io.OutputStream
    public void write(int i2) {
        if (this.f12397g) {
            throw new IOException("Attempted write to closed stream.");
        }
        if (this.f12396f < this.f12395e) {
            this.f12394c.mo5506d(i2);
            this.f12396f++;
        }
    }
}
