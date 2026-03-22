package p005b.p199l.p200a.p201a.p248o1;

import androidx.annotation.NonNull;
import java.io.InputStream;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.o */
/* loaded from: classes.dex */
public final class C2323o extends InputStream {

    /* renamed from: c */
    public final InterfaceC2321m f5927c;

    /* renamed from: e */
    public final C2324p f5928e;

    /* renamed from: i */
    public long f5932i;

    /* renamed from: g */
    public boolean f5930g = false;

    /* renamed from: h */
    public boolean f5931h = false;

    /* renamed from: f */
    public final byte[] f5929f = new byte[1];

    public C2323o(InterfaceC2321m interfaceC2321m, C2324p c2324p) {
        this.f5927c = interfaceC2321m;
        this.f5928e = c2324p;
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f5931h) {
            return;
        }
        this.f5927c.close();
        this.f5931h = true;
    }

    @Override // java.io.InputStream
    public int read() {
        if (read(this.f5929f) == -1) {
            return -1;
        }
        return this.f5929f[0] & 255;
    }

    @Override // java.io.InputStream
    public int read(@NonNull byte[] bArr) {
        return read(bArr, 0, bArr.length);
    }

    @Override // java.io.InputStream
    public int read(@NonNull byte[] bArr, int i2, int i3) {
        C4195m.m4771I(!this.f5931h);
        if (!this.f5930g) {
            this.f5927c.open(this.f5928e);
            this.f5930g = true;
        }
        int read = this.f5927c.read(bArr, i2, i3);
        if (read == -1) {
            return -1;
        }
        this.f5932i += read;
        return read;
    }
}
