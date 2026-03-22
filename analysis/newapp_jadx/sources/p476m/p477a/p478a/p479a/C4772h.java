package p476m.p477a.p478a.p479a;

import java.io.IOException;
import java.io.InputStream;
import kotlin.UByte;
import p476m.p477a.p478a.p479a.AbstractC4769e;
import p476m.p477a.p478a.p479a.InterfaceC4767c;
import p476m.p477a.p478a.p479a.p481m.InterfaceC4778a;

/* renamed from: m.a.a.a.h */
/* loaded from: classes3.dex */
public class C4772h {

    /* renamed from: a */
    public static final byte[] f12205a = {13, 10, 13, 10};

    /* renamed from: b */
    public static final byte[] f12206b = {13, 10};

    /* renamed from: c */
    public static final byte[] f12207c = {45, 45};

    /* renamed from: d */
    public static final byte[] f12208d = {13, 10, 45, 45};

    /* renamed from: e */
    public final InputStream f12209e;

    /* renamed from: f */
    public int f12210f;

    /* renamed from: g */
    public final int f12211g;

    /* renamed from: h */
    public final byte[] f12212h;

    /* renamed from: i */
    public final int[] f12213i;

    /* renamed from: j */
    public final int f12214j;

    /* renamed from: k */
    public final byte[] f12215k;

    /* renamed from: l */
    public int f12216l;

    /* renamed from: m */
    public int f12217m;

    /* renamed from: n */
    public String f12218n;

    /* renamed from: o */
    public final d f12219o;

    /* renamed from: m.a.a.a.h$a */
    public static class a extends IOException {
        private static final long serialVersionUID = -161533165102632918L;

        public a(String str) {
            super(str);
        }
    }

    /* renamed from: m.a.a.a.h$c */
    public static class c extends IOException {
        private static final long serialVersionUID = 6466926458059796677L;

        public c(String str) {
            super(str);
        }
    }

    /* renamed from: m.a.a.a.h$d */
    public static class d {

        /* renamed from: a */
        public final long f12225a;

        /* renamed from: b */
        public long f12226b;

        /* renamed from: c */
        public int f12227c;

        public d(InterfaceC4774j interfaceC4774j, long j2) {
            this.f12225a = j2;
        }
    }

    public C4772h(InputStream inputStream, byte[] bArr, d dVar) {
        if (bArr == null) {
            throw new IllegalArgumentException("boundary may not be null");
        }
        int length = bArr.length;
        byte[] bArr2 = f12208d;
        int length2 = length + bArr2.length;
        this.f12210f = length2;
        if (4096 < length2 + 1) {
            throw new IllegalArgumentException("The buffer size specified for the MultipartStream is too small");
        }
        this.f12209e = inputStream;
        int max = Math.max(4096, length2 * 2);
        this.f12214j = max;
        this.f12215k = new byte[max];
        this.f12219o = dVar;
        int i2 = this.f12210f;
        byte[] bArr3 = new byte[i2];
        this.f12212h = bArr3;
        this.f12213i = new int[i2 + 1];
        this.f12211g = i2;
        System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length);
        System.arraycopy(bArr, 0, bArr3, bArr2.length, bArr.length);
        m5442b();
        this.f12216l = 0;
        this.f12217m = 0;
    }

    /* renamed from: a */
    public static boolean m5441a(byte[] bArr, byte[] bArr2, int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            if (bArr[i3] != bArr2[i3]) {
                return false;
            }
        }
        return true;
    }

    /* renamed from: b */
    public final void m5442b() {
        int[] iArr = this.f12213i;
        iArr[0] = -1;
        iArr[1] = 0;
        int i2 = 2;
        int i3 = 0;
        while (i2 <= this.f12210f) {
            byte[] bArr = this.f12212h;
            if (bArr[i2 - 1] == bArr[i3]) {
                i3++;
                this.f12213i[i2] = i3;
            } else if (i3 > 0) {
                i3 = this.f12213i[i3];
            } else {
                this.f12213i[i2] = 0;
            }
            i2++;
        }
    }

    /* renamed from: c */
    public boolean m5443c() {
        byte[] bArr = new byte[2];
        this.f12216l += this.f12210f;
        try {
            bArr[0] = m5444d();
            if (bArr[0] == 10) {
                return true;
            }
            bArr[1] = m5444d();
            if (m5441a(bArr, f12207c, 2)) {
                return false;
            }
            if (m5441a(bArr, f12206b, 2)) {
                return true;
            }
            throw new c("Unexpected characters follow a boundary");
        } catch (AbstractC4769e.c e2) {
            throw e2;
        } catch (IOException unused) {
            throw new c("Stream ended unexpectedly");
        }
    }

    /* renamed from: d */
    public byte m5444d() {
        if (this.f12216l == this.f12217m) {
            this.f12216l = 0;
            int read = this.f12209e.read(this.f12215k, 0, this.f12214j);
            this.f12217m = read;
            if (read == -1) {
                throw new IOException("No more data is available");
            }
            d dVar = this.f12219o;
            if (dVar != null) {
                dVar.f12226b += read;
            }
        }
        byte[] bArr = this.f12215k;
        int i2 = this.f12216l;
        this.f12216l = i2 + 1;
        return bArr[i2];
    }

    /* renamed from: e */
    public void m5445e(byte[] bArr) {
        int length = bArr.length;
        int i2 = this.f12210f;
        byte[] bArr2 = f12208d;
        if (length != i2 - bArr2.length) {
            throw new a("The length of a boundary token cannot be changed");
        }
        System.arraycopy(bArr, 0, this.f12212h, bArr2.length, bArr.length);
        m5442b();
    }

    /* renamed from: m.a.a.a.h$b */
    public class b extends InputStream implements InterfaceC4778a {

        /* renamed from: c */
        public long f12220c;

        /* renamed from: e */
        public int f12221e;

        /* renamed from: f */
        public int f12222f;

        /* renamed from: g */
        public boolean f12223g;

        public b() {
            m5447d();
        }

        @Override // java.io.InputStream
        public int available() {
            int i2 = this.f12222f;
            if (i2 != -1) {
                return i2 - C4772h.this.f12216l;
            }
            C4772h c4772h = C4772h.this;
            return (c4772h.f12217m - c4772h.f12216l) - this.f12221e;
        }

        /* renamed from: b */
        public void m5446b(boolean z) {
            if (this.f12223g) {
                return;
            }
            if (!z) {
                while (true) {
                    int available = available();
                    if (available == 0 && (available = m5448e()) == 0) {
                        break;
                    } else {
                        skip(available);
                    }
                }
            } else {
                this.f12223g = true;
                C4772h.this.f12209e.close();
            }
            this.f12223g = true;
        }

        @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            m5446b(false);
        }

        /* renamed from: d */
        public final void m5447d() {
            int i2;
            C4772h c4772h = C4772h.this;
            int i3 = c4772h.f12216l;
            int i4 = 0;
            while (true) {
                if (i3 >= c4772h.f12217m) {
                    i2 = -1;
                    break;
                }
                while (i4 >= 0 && c4772h.f12215k[i3] != c4772h.f12212h[i4]) {
                    i4 = c4772h.f12213i[i4];
                }
                i3++;
                i4++;
                int i5 = c4772h.f12210f;
                if (i4 == i5) {
                    i2 = i3 - i5;
                    break;
                }
            }
            this.f12222f = i2;
            if (i2 == -1) {
                C4772h c4772h2 = C4772h.this;
                int i6 = c4772h2.f12217m - c4772h2.f12216l;
                int i7 = c4772h2.f12211g;
                if (i6 > i7) {
                    this.f12221e = i7;
                } else {
                    this.f12221e = i6;
                }
            }
        }

        /* renamed from: e */
        public final int m5448e() {
            int available;
            if (this.f12222f != -1) {
                return 0;
            }
            long j2 = this.f12220c;
            C4772h c4772h = C4772h.this;
            int i2 = c4772h.f12217m;
            int i3 = i2 - c4772h.f12216l;
            int i4 = this.f12221e;
            this.f12220c = j2 + (i3 - i4);
            byte[] bArr = c4772h.f12215k;
            System.arraycopy(bArr, i2 - i4, bArr, 0, i4);
            C4772h c4772h2 = C4772h.this;
            c4772h2.f12216l = 0;
            c4772h2.f12217m = this.f12221e;
            do {
                C4772h c4772h3 = C4772h.this;
                InputStream inputStream = c4772h3.f12209e;
                byte[] bArr2 = c4772h3.f12215k;
                int i5 = c4772h3.f12217m;
                int read = inputStream.read(bArr2, i5, c4772h3.f12214j - i5);
                if (read == -1) {
                    throw new c("Stream ended unexpectedly");
                }
                C4772h c4772h4 = C4772h.this;
                d dVar = c4772h4.f12219o;
                if (dVar != null) {
                    dVar.f12226b += read;
                }
                c4772h4.f12217m += read;
                m5447d();
                available = available();
                if (available > 0) {
                    break;
                }
            } while (this.f12222f == -1);
            return available;
        }

        @Override // p476m.p477a.p478a.p479a.p481m.InterfaceC4778a
        public boolean isClosed() {
            return this.f12223g;
        }

        @Override // java.io.InputStream
        public int read() {
            if (this.f12223g) {
                throw new InterfaceC4767c.a();
            }
            if (available() == 0 && m5448e() == 0) {
                return -1;
            }
            this.f12220c++;
            C4772h c4772h = C4772h.this;
            byte[] bArr = c4772h.f12215k;
            int i2 = c4772h.f12216l;
            c4772h.f12216l = i2 + 1;
            byte b2 = bArr[i2];
            return b2 >= 0 ? b2 : b2 + UByte.MIN_VALUE;
        }

        @Override // java.io.InputStream
        public long skip(long j2) {
            if (this.f12223g) {
                throw new InterfaceC4767c.a();
            }
            int available = available();
            if (available == 0 && (available = m5448e()) == 0) {
                return 0L;
            }
            long min = Math.min(available, j2);
            C4772h.this.f12216l = (int) (r0.f12216l + min);
            return min;
        }

        @Override // java.io.InputStream
        public int read(byte[] bArr, int i2, int i3) {
            if (this.f12223g) {
                throw new InterfaceC4767c.a();
            }
            if (i3 == 0) {
                return 0;
            }
            int available = available();
            if (available == 0 && (available = m5448e()) == 0) {
                return -1;
            }
            int min = Math.min(available, i3);
            C4772h c4772h = C4772h.this;
            System.arraycopy(c4772h.f12215k, c4772h.f12216l, bArr, i2, min);
            C4772h.this.f12216l += min;
            this.f12220c += min;
            return min;
        }
    }
}
