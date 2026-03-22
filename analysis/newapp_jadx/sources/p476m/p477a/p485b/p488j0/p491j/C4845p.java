package p476m.p477a.p485b.p488j0.p491j;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.p492k0.InterfaceC4847a;
import p476m.p477a.p485b.p492k0.InterfaceC4851e;
import p476m.p477a.p485b.p495n0.C4892a;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.j0.j.p */
/* loaded from: classes3.dex */
public class C4845p implements InterfaceC4851e, InterfaceC4847a {

    /* renamed from: a */
    public static final byte[] f12420a = {13, 10};

    /* renamed from: b */
    public final C4841l f12421b;

    /* renamed from: c */
    public final C4892a f12422c;

    /* renamed from: d */
    public final int f12423d;

    /* renamed from: e */
    public final CharsetEncoder f12424e;

    /* renamed from: f */
    public OutputStream f12425f;

    /* renamed from: g */
    public ByteBuffer f12426g;

    public C4845p(C4841l c4841l, int i2, int i3, CharsetEncoder charsetEncoder) {
        C2354n.m2499n1(i2, "Buffer size");
        C2354n.m2470e1(c4841l, "HTTP transport metrcis");
        this.f12421b = c4841l;
        this.f12422c = new C4892a(i2);
        this.f12423d = i3 < 0 ? 0 : i3;
        this.f12424e = charsetEncoder;
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4851e
    /* renamed from: a */
    public void mo5503a(byte[] bArr, int i2, int i3) {
        if (bArr == null) {
            return;
        }
        if (i3 <= this.f12423d) {
            C4892a c4892a = this.f12422c;
            byte[] bArr2 = c4892a.f12495c;
            if (i3 <= bArr2.length) {
                if (i3 > bArr2.length - c4892a.f12496e) {
                    m5507e();
                }
                this.f12422c.m5556a(bArr, i2, i3);
                return;
            }
        }
        m5507e();
        C2354n.m2478g1(this.f12425f, "Output stream");
        this.f12425f.write(bArr, i2, i3);
        this.f12421b.m5497a(i3);
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4851e
    /* renamed from: b */
    public void mo5504b(String str) {
        if (str == null) {
            return;
        }
        if (str.length() > 0) {
            if (this.f12424e == null) {
                for (int i2 = 0; i2 < str.length(); i2++) {
                    mo5506d(str.charAt(i2));
                }
            } else {
                m5509g(CharBuffer.wrap(str));
            }
        }
        byte[] bArr = f12420a;
        mo5503a(bArr, 0, bArr.length);
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4851e
    /* renamed from: c */
    public void mo5505c(C4893b c4893b) {
        int i2;
        if (c4893b == null) {
            return;
        }
        if (this.f12424e == null) {
            int i3 = c4893b.f12498e;
            int i4 = 0;
            while (i3 > 0) {
                C4892a c4892a = this.f12422c;
                int min = Math.min(c4892a.f12495c.length - c4892a.f12496e, i3);
                if (min > 0) {
                    C4892a c4892a2 = this.f12422c;
                    Objects.requireNonNull(c4892a2);
                    char[] cArr = c4893b.f12497c;
                    if (cArr != null) {
                        if (i4 < 0 || i4 > cArr.length || min < 0 || (i2 = i4 + min) < 0 || i2 > cArr.length) {
                            StringBuilder m589K = C1499a.m589K("off: ", i4, " len: ", min, " b.length: ");
                            m589K.append(cArr.length);
                            throw new IndexOutOfBoundsException(m589K.toString());
                        }
                        if (min != 0) {
                            int i5 = c4892a2.f12496e;
                            int i6 = min + i5;
                            if (i6 > c4892a2.f12495c.length) {
                                c4892a2.m5557b(i6);
                            }
                            int i7 = i4;
                            while (i5 < i6) {
                                char c2 = cArr[i7];
                                if ((c2 < ' ' || c2 > '~') && ((c2 < 160 || c2 > 255) && c2 != '\t')) {
                                    c4892a2.f12495c[i5] = 63;
                                } else {
                                    c4892a2.f12495c[i5] = (byte) c2;
                                }
                                i7++;
                                i5++;
                            }
                            c4892a2.f12496e = i6;
                        }
                    }
                }
                C4892a c4892a3 = this.f12422c;
                if (c4892a3.f12496e == c4892a3.f12495c.length) {
                    m5507e();
                }
                i4 += min;
                i3 -= min;
            }
        } else {
            m5509g(CharBuffer.wrap(c4893b.f12497c, 0, c4893b.f12498e));
        }
        byte[] bArr = f12420a;
        mo5503a(bArr, 0, bArr.length);
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4851e
    /* renamed from: d */
    public void mo5506d(int i2) {
        if (this.f12423d <= 0) {
            m5507e();
            this.f12425f.write(i2);
            return;
        }
        C4892a c4892a = this.f12422c;
        if (c4892a.f12496e == c4892a.f12495c.length) {
            m5507e();
        }
        C4892a c4892a2 = this.f12422c;
        int i3 = c4892a2.f12496e + 1;
        if (i3 > c4892a2.f12495c.length) {
            c4892a2.m5557b(i3);
        }
        c4892a2.f12495c[c4892a2.f12496e] = (byte) i2;
        c4892a2.f12496e = i3;
    }

    /* renamed from: e */
    public final void m5507e() {
        C4892a c4892a = this.f12422c;
        int i2 = c4892a.f12496e;
        if (i2 > 0) {
            byte[] bArr = c4892a.f12495c;
            C2354n.m2478g1(this.f12425f, "Output stream");
            this.f12425f.write(bArr, 0, i2);
            this.f12422c.f12496e = 0;
            this.f12421b.m5497a(i2);
        }
    }

    /* renamed from: f */
    public final void m5508f(CoderResult coderResult) {
        if (coderResult.isError()) {
            coderResult.throwException();
        }
        this.f12426g.flip();
        while (this.f12426g.hasRemaining()) {
            mo5506d(this.f12426g.get());
        }
        this.f12426g.compact();
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4851e
    public void flush() {
        m5507e();
        OutputStream outputStream = this.f12425f;
        if (outputStream != null) {
            outputStream.flush();
        }
    }

    /* renamed from: g */
    public final void m5509g(CharBuffer charBuffer) {
        if (charBuffer.hasRemaining()) {
            if (this.f12426g == null) {
                this.f12426g = ByteBuffer.allocate(1024);
            }
            this.f12424e.reset();
            while (charBuffer.hasRemaining()) {
                m5508f(this.f12424e.encode(charBuffer, this.f12426g, true));
            }
            m5508f(this.f12424e.flush(this.f12426g));
            this.f12426g.clear();
        }
    }

    @Override // p476m.p477a.p485b.p492k0.InterfaceC4847a
    public int length() {
        return this.f12422c.f12496e;
    }
}
