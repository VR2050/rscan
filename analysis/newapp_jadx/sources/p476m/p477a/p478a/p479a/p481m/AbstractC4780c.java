package p476m.p477a.p478a.p479a.p481m;

import java.io.FilterInputStream;
import java.io.InputStream;

/* renamed from: m.a.a.a.m.c */
/* loaded from: classes3.dex */
public abstract class AbstractC4780c extends FilterInputStream implements InterfaceC4778a {

    /* renamed from: c */
    public final long f12250c;

    /* renamed from: e */
    public long f12251e;

    /* renamed from: f */
    public boolean f12252f;

    public AbstractC4780c(InputStream inputStream, long j2) {
        super(inputStream);
        this.f12250c = j2;
    }

    /* renamed from: b */
    public abstract void mo5439b(long j2, long j3);

    @Override // java.io.FilterInputStream, java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f12252f = true;
        super.close();
    }

    @Override // p476m.p477a.p478a.p479a.p481m.InterfaceC4778a
    public boolean isClosed() {
        return this.f12252f;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() {
        int read = super.read();
        if (read != -1) {
            long j2 = this.f12251e + 1;
            this.f12251e = j2;
            long j3 = this.f12250c;
            if (j2 > j3) {
                mo5439b(j3, j2);
            }
        }
        return read;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] bArr, int i2, int i3) {
        int read = super.read(bArr, i2, i3);
        if (read > 0) {
            long j2 = this.f12251e + read;
            this.f12251e = j2;
            long j3 = this.f12250c;
            if (j2 > j3) {
                mo5439b(j3, j2);
            }
        }
        return read;
    }
}
