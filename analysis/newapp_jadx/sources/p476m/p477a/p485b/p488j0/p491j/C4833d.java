package p476m.p477a.p485b.p488j0.p491j;

import java.io.IOException;
import java.io.OutputStream;
import p476m.p477a.p485b.p492k0.InterfaceC4851e;

/* renamed from: m.a.b.j0.j.d */
/* loaded from: classes3.dex */
public class C4833d extends OutputStream {

    /* renamed from: c */
    public final InterfaceC4851e f12385c;

    /* renamed from: e */
    public final byte[] f12386e;

    /* renamed from: f */
    public int f12387f = 0;

    /* renamed from: g */
    public boolean f12388g = false;

    /* renamed from: h */
    public boolean f12389h = false;

    public C4833d(int i2, InterfaceC4851e interfaceC4851e) {
        this.f12386e = new byte[i2];
        this.f12385c = interfaceC4851e;
    }

    /* renamed from: b */
    public void m5496b() {
        int i2 = this.f12387f;
        if (i2 > 0) {
            this.f12385c.mo5504b(Integer.toHexString(i2));
            this.f12385c.mo5503a(this.f12386e, 0, this.f12387f);
            this.f12385c.mo5504b("");
            this.f12387f = 0;
        }
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12389h) {
            return;
        }
        this.f12389h = true;
        if (!this.f12388g) {
            m5496b();
            this.f12385c.mo5504b("0");
            this.f12385c.mo5504b("");
            this.f12388g = true;
        }
        this.f12385c.flush();
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() {
        m5496b();
        this.f12385c.flush();
    }

    @Override // java.io.OutputStream
    public void write(int i2) {
        if (this.f12389h) {
            throw new IOException("Attempted write to closed stream.");
        }
        byte[] bArr = this.f12386e;
        int i3 = this.f12387f;
        bArr[i3] = (byte) i2;
        int i4 = i3 + 1;
        this.f12387f = i4;
        if (i4 == bArr.length) {
            m5496b();
        }
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) {
        write(bArr, 0, bArr.length);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i2, int i3) {
        if (!this.f12389h) {
            byte[] bArr2 = this.f12386e;
            int length = bArr2.length;
            int i4 = this.f12387f;
            if (i3 >= length - i4) {
                this.f12385c.mo5504b(Integer.toHexString(i4 + i3));
                this.f12385c.mo5503a(this.f12386e, 0, this.f12387f);
                this.f12385c.mo5503a(bArr, i2, i3);
                this.f12385c.mo5504b("");
                this.f12387f = 0;
                return;
            }
            System.arraycopy(bArr, i2, bArr2, i4, i3);
            this.f12387f += i3;
            return;
        }
        throw new IOException("Attempted write to closed stream.");
    }
}
