package p476m.p477a.p485b.p488j0.p491j;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4904x;
import p476m.p477a.p485b.p486h0.C4805a;
import p476m.p477a.p485b.p492k0.InterfaceC4847a;
import p476m.p477a.p485b.p492k0.InterfaceC4850d;
import p476m.p477a.p485b.p495n0.C4892a;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.j0.j.o */
/* loaded from: classes3.dex */
public class C4844o implements InterfaceC4850d, InterfaceC4847a {

    /* renamed from: a */
    public final C4841l f12410a;

    /* renamed from: b */
    public final byte[] f12411b;

    /* renamed from: c */
    public final C4892a f12412c;

    /* renamed from: d */
    public final int f12413d;

    /* renamed from: e */
    public final C4805a f12414e;

    /* renamed from: f */
    public final CharsetDecoder f12415f;

    /* renamed from: g */
    public InputStream f12416g;

    /* renamed from: h */
    public int f12417h;

    /* renamed from: i */
    public int f12418i;

    /* renamed from: j */
    public CharBuffer f12419j;

    public C4844o(C4841l c4841l, int i2, int i3, C4805a c4805a, CharsetDecoder charsetDecoder) {
        C2354n.m2470e1(c4841l, "HTTP transport metrcis");
        C2354n.m2499n1(i2, "Buffer size");
        this.f12410a = c4841l;
        this.f12411b = new byte[i2];
        this.f12417h = 0;
        this.f12418i = 0;
        this.f12413d = i3 < 0 ? 512 : i3;
        this.f12414e = c4805a == null ? C4805a.f12283c : c4805a;
        this.f12412c = new C4892a(i2);
        this.f12415f = charsetDecoder;
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4850d
    /* renamed from: a */
    public int mo5498a(C4893b c4893b) {
        int i2;
        C2354n.m2470e1(c4893b, "Char array buffer");
        int i3 = this.f12414e.f12284e;
        boolean z = true;
        int i4 = 0;
        while (z) {
            int i5 = this.f12417h;
            while (true) {
                i2 = this.f12418i;
                if (i5 >= i2) {
                    i5 = -1;
                    break;
                }
                if (this.f12411b[i5] == 10) {
                    break;
                }
                i5++;
            }
            if (i3 > 0) {
                int i6 = this.f12412c.f12496e;
                if (i5 >= 0) {
                    i2 = i5;
                }
                if ((i6 + i2) - this.f12417h >= i3) {
                    throw new C4904x("Maximum line length limit exceeded");
                }
            }
            if (i5 != -1) {
                C4892a c4892a = this.f12412c;
                if (c4892a.f12496e == 0) {
                    int i7 = this.f12417h;
                    this.f12417h = i5 + 1;
                    if (i5 > i7) {
                        int i8 = i5 - 1;
                        if (this.f12411b[i8] == 13) {
                            i5 = i8;
                        }
                    }
                    int i9 = i5 - i7;
                    if (this.f12415f != null) {
                        return m5499b(c4893b, ByteBuffer.wrap(this.f12411b, i7, i9));
                    }
                    c4893b.m5560c(this.f12411b, i7, i9);
                    return i9;
                }
                int i10 = i5 + 1;
                int i11 = this.f12417h;
                c4892a.m5556a(this.f12411b, i11, i10 - i11);
                this.f12417h = i10;
            } else {
                if (m5502e()) {
                    int i12 = this.f12418i;
                    int i13 = this.f12417h;
                    this.f12412c.m5556a(this.f12411b, i13, i12 - i13);
                    this.f12417h = this.f12418i;
                }
                i4 = m5500c();
                if (i4 == -1) {
                }
            }
            z = false;
        }
        if (i4 == -1) {
            if (this.f12412c.f12496e == 0) {
                return -1;
            }
        }
        C4892a c4892a2 = this.f12412c;
        int i14 = c4892a2.f12496e;
        if (i14 > 0) {
            int i15 = i14 - 1;
            byte[] bArr = c4892a2.f12495c;
            if (bArr[i15] == 10) {
                i14 = i15;
            }
            if (i14 > 0) {
                int i16 = i14 - 1;
                if (bArr[i16] == 13) {
                    i14 = i16;
                }
            }
        }
        if (this.f12415f == null) {
            c4893b.m5560c(c4892a2.f12495c, 0, i14);
        } else {
            i14 = m5499b(c4893b, ByteBuffer.wrap(c4892a2.f12495c, 0, i14));
        }
        this.f12412c.f12496e = 0;
        return i14;
    }

    /* renamed from: b */
    public final int m5499b(C4893b c4893b, ByteBuffer byteBuffer) {
        int i2 = 0;
        if (!byteBuffer.hasRemaining()) {
            return 0;
        }
        if (this.f12419j == null) {
            this.f12419j = CharBuffer.allocate(1024);
        }
        this.f12415f.reset();
        while (byteBuffer.hasRemaining()) {
            i2 += m5501d(this.f12415f.decode(byteBuffer, this.f12419j, true), c4893b);
        }
        int m5501d = m5501d(this.f12415f.flush(this.f12419j), c4893b) + i2;
        this.f12419j.clear();
        return m5501d;
    }

    /* renamed from: c */
    public int m5500c() {
        int i2 = this.f12417h;
        if (i2 > 0) {
            int i3 = this.f12418i - i2;
            if (i3 > 0) {
                byte[] bArr = this.f12411b;
                System.arraycopy(bArr, i2, bArr, 0, i3);
            }
            this.f12417h = 0;
            this.f12418i = i3;
        }
        int i4 = this.f12418i;
        byte[] bArr2 = this.f12411b;
        int length = bArr2.length - i4;
        C2354n.m2478g1(this.f12416g, "Input stream");
        int read = this.f12416g.read(bArr2, i4, length);
        if (read == -1) {
            return -1;
        }
        this.f12418i = i4 + read;
        this.f12410a.m5497a(read);
        return read;
    }

    /* renamed from: d */
    public final int m5501d(CoderResult coderResult, C4893b c4893b) {
        if (coderResult.isError()) {
            coderResult.throwException();
        }
        this.f12419j.flip();
        int remaining = this.f12419j.remaining();
        while (this.f12419j.hasRemaining()) {
            c4893b.m5558a(this.f12419j.get());
        }
        this.f12419j.compact();
        return remaining;
    }

    /* renamed from: e */
    public boolean m5502e() {
        return this.f12417h < this.f12418i;
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4847a
    public int length() {
        return this.f12418i - this.f12417h;
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4850d
    public int read() {
        while (!m5502e()) {
            if (m5500c() == -1) {
                return -1;
            }
        }
        byte[] bArr = this.f12411b;
        int i2 = this.f12417h;
        this.f12417h = i2 + 1;
        return bArr[i2] & 255;
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4850d
    public int read(byte[] bArr, int i2, int i3) {
        if (bArr == null) {
            return 0;
        }
        if (m5502e()) {
            int min = Math.min(i3, this.f12418i - this.f12417h);
            System.arraycopy(this.f12411b, this.f12417h, bArr, i2, min);
            this.f12417h += min;
            return min;
        }
        if (i3 > this.f12413d) {
            C2354n.m2478g1(this.f12416g, "Input stream");
            int read = this.f12416g.read(bArr, i2, i3);
            if (read > 0) {
                this.f12410a.m5497a(read);
            }
            return read;
        }
        while (!m5502e()) {
            if (m5500c() == -1) {
                return -1;
            }
        }
        int min2 = Math.min(i3, this.f12418i - this.f12417h);
        System.arraycopy(this.f12411b, this.f12417h, bArr, i2, min2);
        this.f12417h += min2;
        return min2;
    }
}
