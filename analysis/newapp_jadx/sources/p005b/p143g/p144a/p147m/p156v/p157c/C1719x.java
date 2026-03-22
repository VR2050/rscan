package p005b.p143g.p144a.p147m.p156v.p157c;

import androidx.annotation.NonNull;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;

/* renamed from: b.g.a.m.v.c.x */
/* loaded from: classes.dex */
public class C1719x extends FilterInputStream {

    /* renamed from: c */
    public volatile byte[] f2540c;

    /* renamed from: e */
    public int f2541e;

    /* renamed from: f */
    public int f2542f;

    /* renamed from: g */
    public int f2543g;

    /* renamed from: h */
    public int f2544h;

    /* renamed from: i */
    public final InterfaceC1612b f2545i;

    /* renamed from: b.g.a.m.v.c.x$a */
    public static class a extends IOException {
        private static final long serialVersionUID = -4338378848813561757L;

        public a(String str) {
            super(str);
        }
    }

    public C1719x(@NonNull InputStream inputStream, @NonNull InterfaceC1612b interfaceC1612b) {
        super(inputStream);
        this.f2543g = -1;
        this.f2545i = interfaceC1612b;
        this.f2540c = (byte[]) interfaceC1612b.mo863d(65536, byte[].class);
    }

    /* renamed from: e */
    public static IOException m1024e() {
        throw new IOException("BufferedInputStream is closed");
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized int available() {
        InputStream inputStream;
        inputStream = ((FilterInputStream) this).in;
        if (this.f2540c == null || inputStream == null) {
            m1024e();
            throw null;
        }
        return (this.f2541e - this.f2544h) + inputStream.available();
    }

    /* renamed from: b */
    public final int m1025b(InputStream inputStream, byte[] bArr) {
        int i2 = this.f2543g;
        if (i2 != -1) {
            int i3 = this.f2544h - i2;
            int i4 = this.f2542f;
            if (i3 < i4) {
                if (i2 == 0 && i4 > bArr.length && this.f2541e == bArr.length) {
                    int length = bArr.length * 2;
                    if (length <= i4) {
                        i4 = length;
                    }
                    byte[] bArr2 = (byte[]) this.f2545i.mo863d(i4, byte[].class);
                    System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
                    this.f2540c = bArr2;
                    this.f2545i.put(bArr);
                    bArr = bArr2;
                } else if (i2 > 0) {
                    System.arraycopy(bArr, i2, bArr, 0, bArr.length - i2);
                }
                int i5 = this.f2544h - this.f2543g;
                this.f2544h = i5;
                this.f2543g = 0;
                this.f2541e = 0;
                int read = inputStream.read(bArr, i5, bArr.length - i5);
                int i6 = this.f2544h;
                if (read > 0) {
                    i6 += read;
                }
                this.f2541e = i6;
                return read;
            }
        }
        int read2 = inputStream.read(bArr);
        if (read2 > 0) {
            this.f2543g = -1;
            this.f2544h = 0;
            this.f2541e = read2;
        }
        return read2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f2540c != null) {
            this.f2545i.put(this.f2540c);
            this.f2540c = null;
        }
        InputStream inputStream = ((FilterInputStream) this).in;
        ((FilterInputStream) this).in = null;
        if (inputStream != null) {
            inputStream.close();
        }
    }

    /* renamed from: d */
    public synchronized void m1026d() {
        if (this.f2540c != null) {
            this.f2545i.put(this.f2540c);
            this.f2540c = null;
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized void mark(int i2) {
        this.f2542f = Math.max(this.f2542f, i2);
        this.f2543g = this.f2544h;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public boolean markSupported() {
        return true;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized int read() {
        byte[] bArr = this.f2540c;
        InputStream inputStream = ((FilterInputStream) this).in;
        if (bArr == null || inputStream == null) {
            m1024e();
            throw null;
        }
        if (this.f2544h >= this.f2541e && m1025b(inputStream, bArr) == -1) {
            return -1;
        }
        if (bArr != this.f2540c && (bArr = this.f2540c) == null) {
            m1024e();
            throw null;
        }
        int i2 = this.f2541e;
        int i3 = this.f2544h;
        if (i2 - i3 <= 0) {
            return -1;
        }
        this.f2544h = i3 + 1;
        return bArr[i3] & 255;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized void reset() {
        if (this.f2540c == null) {
            throw new IOException("Stream is closed");
        }
        int i2 = this.f2543g;
        if (-1 == i2) {
            throw new a("Mark has been invalidated, pos: " + this.f2544h + " markLimit: " + this.f2542f);
        }
        this.f2544h = i2;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized long skip(long j2) {
        if (j2 < 1) {
            return 0L;
        }
        byte[] bArr = this.f2540c;
        if (bArr == null) {
            m1024e();
            throw null;
        }
        InputStream inputStream = ((FilterInputStream) this).in;
        if (inputStream == null) {
            m1024e();
            throw null;
        }
        int i2 = this.f2541e;
        int i3 = this.f2544h;
        if (i2 - i3 >= j2) {
            this.f2544h = (int) (i3 + j2);
            return j2;
        }
        long j3 = i2 - i3;
        this.f2544h = i2;
        if (this.f2543g == -1 || j2 > this.f2542f) {
            return j3 + inputStream.skip(j2 - j3);
        }
        if (m1025b(inputStream, bArr) == -1) {
            return j3;
        }
        int i4 = this.f2541e;
        int i5 = this.f2544h;
        if (i4 - i5 >= j2 - j3) {
            this.f2544h = (int) ((i5 + j2) - j3);
            return j2;
        }
        long j4 = (j3 + i4) - i5;
        this.f2544h = i4;
        return j4;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized int read(@NonNull byte[] bArr, int i2, int i3) {
        int i4;
        int i5;
        byte[] bArr2 = this.f2540c;
        if (bArr2 == null) {
            m1024e();
            throw null;
        }
        if (i3 == 0) {
            return 0;
        }
        InputStream inputStream = ((FilterInputStream) this).in;
        if (inputStream != null) {
            int i6 = this.f2544h;
            int i7 = this.f2541e;
            if (i6 < i7) {
                int i8 = i7 - i6 >= i3 ? i3 : i7 - i6;
                System.arraycopy(bArr2, i6, bArr, i2, i8);
                this.f2544h += i8;
                if (i8 == i3 || inputStream.available() == 0) {
                    return i8;
                }
                i2 += i8;
                i4 = i3 - i8;
            } else {
                i4 = i3;
            }
            while (true) {
                if (this.f2543g == -1 && i4 >= bArr2.length) {
                    i5 = inputStream.read(bArr, i2, i4);
                    if (i5 == -1) {
                        return i4 != i3 ? i3 - i4 : -1;
                    }
                } else {
                    if (m1025b(inputStream, bArr2) == -1) {
                        return i4 != i3 ? i3 - i4 : -1;
                    }
                    if (bArr2 != this.f2540c && (bArr2 = this.f2540c) == null) {
                        m1024e();
                        throw null;
                    }
                    int i9 = this.f2541e;
                    int i10 = this.f2544h;
                    i5 = i9 - i10 >= i4 ? i4 : i9 - i10;
                    System.arraycopy(bArr2, i10, bArr, i2, i5);
                    this.f2544h += i5;
                }
                i4 -= i5;
                if (i4 == 0) {
                    return i3;
                }
                if (inputStream.available() == 0) {
                    return i3 - i4;
                }
                i2 += i5;
            }
        } else {
            m1024e();
            throw null;
        }
    }
}
