package p005b.p143g.p144a.p145k;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/* renamed from: b.g.a.k.b */
/* loaded from: classes.dex */
public class C1562b implements Closeable {

    /* renamed from: c */
    public final InputStream f1915c;

    /* renamed from: e */
    public final Charset f1916e;

    /* renamed from: f */
    public byte[] f1917f;

    /* renamed from: g */
    public int f1918g;

    /* renamed from: h */
    public int f1919h;

    /* renamed from: b.g.a.k.b$a */
    public class a extends ByteArrayOutputStream {
        public a(int i2) {
            super(i2);
        }

        @Override // java.io.ByteArrayOutputStream
        public String toString() {
            int i2 = ((ByteArrayOutputStream) this).count;
            if (i2 > 0 && ((ByteArrayOutputStream) this).buf[i2 - 1] == 13) {
                i2--;
            }
            try {
                return new String(((ByteArrayOutputStream) this).buf, 0, i2, C1562b.this.f1916e.name());
            } catch (UnsupportedEncodingException e2) {
                throw new AssertionError(e2);
            }
        }
    }

    public C1562b(InputStream inputStream, Charset charset) {
        if (charset == null) {
            throw null;
        }
        if (!charset.equals(C1563c.f1921a)) {
            throw new IllegalArgumentException("Unsupported encoding");
        }
        this.f1915c = inputStream;
        this.f1916e = charset;
        this.f1917f = new byte[8192];
    }

    /* renamed from: b */
    public final void m801b() {
        InputStream inputStream = this.f1915c;
        byte[] bArr = this.f1917f;
        int read = inputStream.read(bArr, 0, bArr.length);
        if (read == -1) {
            throw new EOFException();
        }
        this.f1918g = 0;
        this.f1919h = read;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        synchronized (this.f1915c) {
            if (this.f1917f != null) {
                this.f1917f = null;
                this.f1915c.close();
            }
        }
    }

    /* renamed from: d */
    public String m802d() {
        int i2;
        byte[] bArr;
        int i3;
        synchronized (this.f1915c) {
            if (this.f1917f == null) {
                throw new IOException("LineReader is closed");
            }
            if (this.f1918g >= this.f1919h) {
                m801b();
            }
            for (int i4 = this.f1918g; i4 != this.f1919h; i4++) {
                byte[] bArr2 = this.f1917f;
                if (bArr2[i4] == 10) {
                    if (i4 != this.f1918g) {
                        i3 = i4 - 1;
                        if (bArr2[i3] == 13) {
                            byte[] bArr3 = this.f1917f;
                            int i5 = this.f1918g;
                            String str = new String(bArr3, i5, i3 - i5, this.f1916e.name());
                            this.f1918g = i4 + 1;
                            return str;
                        }
                    }
                    i3 = i4;
                    byte[] bArr32 = this.f1917f;
                    int i52 = this.f1918g;
                    String str2 = new String(bArr32, i52, i3 - i52, this.f1916e.name());
                    this.f1918g = i4 + 1;
                    return str2;
                }
            }
            a aVar = new a((this.f1919h - this.f1918g) + 80);
            loop1: while (true) {
                byte[] bArr4 = this.f1917f;
                int i6 = this.f1918g;
                aVar.write(bArr4, i6, this.f1919h - i6);
                this.f1919h = -1;
                m801b();
                i2 = this.f1918g;
                while (i2 != this.f1919h) {
                    bArr = this.f1917f;
                    if (bArr[i2] == 10) {
                        break loop1;
                    }
                    i2++;
                }
            }
            int i7 = this.f1918g;
            if (i2 != i7) {
                aVar.write(bArr, i7, i2 - i7);
            }
            this.f1918g = i2 + 1;
            return aVar.toString();
        }
    }
}
