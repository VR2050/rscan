package p005b.p143g.p144a.p170s;

import androidx.annotation.NonNull;
import java.io.FilterInputStream;
import java.io.InputStream;

/* renamed from: b.g.a.s.g */
/* loaded from: classes.dex */
public class C1805g extends FilterInputStream {

    /* renamed from: c */
    public int f2763c;

    public C1805g(@NonNull InputStream inputStream) {
        super(inputStream);
        this.f2763c = Integer.MIN_VALUE;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int available() {
        int i2 = this.f2763c;
        return i2 == Integer.MIN_VALUE ? super.available() : Math.min(i2, super.available());
    }

    /* renamed from: b */
    public final long m1142b(long j2) {
        int i2 = this.f2763c;
        if (i2 == 0) {
            return -1L;
        }
        return (i2 == Integer.MIN_VALUE || j2 <= ((long) i2)) ? j2 : i2;
    }

    /* renamed from: d */
    public final void m1143d(long j2) {
        int i2 = this.f2763c;
        if (i2 == Integer.MIN_VALUE || j2 == -1) {
            return;
        }
        this.f2763c = (int) (i2 - j2);
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized void mark(int i2) {
        super.mark(i2);
        this.f2763c = i2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() {
        if (m1142b(1L) == -1) {
            return -1;
        }
        int read = super.read();
        m1143d(1L);
        return read;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized void reset() {
        super.reset();
        this.f2763c = Integer.MIN_VALUE;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public long skip(long j2) {
        long m1142b = m1142b(j2);
        if (m1142b == -1) {
            return 0L;
        }
        long skip = super.skip(m1142b);
        m1143d(skip);
        return skip;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(@NonNull byte[] bArr, int i2, int i3) {
        int m1142b = (int) m1142b(i3);
        if (m1142b == -1) {
            return -1;
        }
        int read = super.read(bArr, i2, m1142b);
        m1143d(read);
        return read;
    }
}
