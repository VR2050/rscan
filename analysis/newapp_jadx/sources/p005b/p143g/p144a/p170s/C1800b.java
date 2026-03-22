package p005b.p143g.p144a.p170s;

import androidx.annotation.NonNull;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.s.b */
/* loaded from: classes.dex */
public final class C1800b extends FilterInputStream {

    /* renamed from: c */
    public final long f2750c;

    /* renamed from: e */
    public int f2751e;

    public C1800b(@NonNull InputStream inputStream, long j2) {
        super(inputStream);
        this.f2750c = j2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized int available() {
        return (int) Math.max(this.f2750c - this.f2751e, ((FilterInputStream) this).in.available());
    }

    /* renamed from: b */
    public final int m1136b(int i2) {
        if (i2 >= 0) {
            this.f2751e += i2;
        } else if (this.f2750c - this.f2751e > 0) {
            StringBuilder m586H = C1499a.m586H("Failed to read all expected data, expected: ");
            m586H.append(this.f2750c);
            m586H.append(", but read: ");
            m586H.append(this.f2751e);
            throw new IOException(m586H.toString());
        }
        return i2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized int read() {
        int read;
        read = super.read();
        m1136b(read >= 0 ? 1 : -1);
        return read;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] bArr) {
        return read(bArr, 0, bArr.length);
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized int read(byte[] bArr, int i2, int i3) {
        int read;
        read = super.read(bArr, i2, i3);
        m1136b(read);
        return read;
    }
}
