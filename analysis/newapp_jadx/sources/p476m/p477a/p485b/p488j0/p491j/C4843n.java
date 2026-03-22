package p476m.p477a.p485b.p488j0.p491j;

import java.io.IOException;
import java.io.OutputStream;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.p492k0.InterfaceC4851e;

/* renamed from: m.a.b.j0.j.n */
/* loaded from: classes3.dex */
public class C4843n extends OutputStream {

    /* renamed from: c */
    public final InterfaceC4851e f12408c;

    /* renamed from: e */
    public boolean f12409e = false;

    public C4843n(InterfaceC4851e interfaceC4851e) {
        C2354n.m2470e1(interfaceC4851e, "Session output buffer");
        this.f12408c = interfaceC4851e;
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12409e) {
            return;
        }
        this.f12409e = true;
        this.f12408c.flush();
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() {
        this.f12408c.flush();
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i2, int i3) {
        if (this.f12409e) {
            throw new IOException("Attempted write to closed stream.");
        }
        this.f12408c.mo5503a(bArr, i2, i3);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) {
        write(bArr, 0, bArr.length);
    }

    @Override // java.io.OutputStream
    public void write(int i2) {
        if (!this.f12409e) {
            this.f12408c.mo5506d(i2);
            return;
        }
        throw new IOException("Attempted write to closed stream.");
    }
}
