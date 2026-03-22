package p476m.p477a.p485b.p495n0;

import java.io.Serializable;
import java.nio.CharBuffer;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.p494m0.C4876c;

/* renamed from: m.a.b.n0.b */
/* loaded from: classes3.dex */
public final class C4893b implements CharSequence, Serializable {
    private static final long serialVersionUID = -6208952725094867135L;

    /* renamed from: c */
    public char[] f12497c;

    /* renamed from: e */
    public int f12498e;

    public C4893b(int i2) {
        C2354n.m2462c1(i2, "Buffer capacity");
        this.f12497c = new char[i2];
    }

    /* renamed from: a */
    public void m5558a(char c2) {
        int i2 = this.f12498e + 1;
        if (i2 > this.f12497c.length) {
            m5562e(i2);
        }
        this.f12497c[this.f12498e] = c2;
        this.f12498e = i2;
    }

    /* renamed from: b */
    public void m5559b(String str) {
        if (str == null) {
            str = "null";
        }
        int length = str.length();
        int i2 = this.f12498e + length;
        if (i2 > this.f12497c.length) {
            m5562e(i2);
        }
        str.getChars(0, length, this.f12497c, this.f12498e);
        this.f12498e = i2;
    }

    /* renamed from: c */
    public void m5560c(byte[] bArr, int i2, int i3) {
        int i4;
        if (bArr == null) {
            return;
        }
        if (i2 < 0 || i2 > bArr.length || i3 < 0 || (i4 = i2 + i3) < 0 || i4 > bArr.length) {
            StringBuilder m589K = C1499a.m589K("off: ", i2, " len: ", i3, " b.length: ");
            m589K.append(bArr.length);
            throw new IndexOutOfBoundsException(m589K.toString());
        }
        if (i3 == 0) {
            return;
        }
        int i5 = this.f12498e;
        int i6 = i3 + i5;
        if (i6 > this.f12497c.length) {
            m5562e(i6);
        }
        while (i5 < i6) {
            this.f12497c[i5] = (char) (bArr[i2] & 255);
            i2++;
            i5++;
        }
        this.f12498e = i6;
    }

    @Override // java.lang.CharSequence
    public char charAt(int i2) {
        return this.f12497c[i2];
    }

    /* renamed from: d */
    public void m5561d(int i2) {
        if (i2 <= 0) {
            return;
        }
        int length = this.f12497c.length;
        int i3 = this.f12498e;
        if (i2 > length - i3) {
            m5562e(i3 + i2);
        }
    }

    /* renamed from: e */
    public final void m5562e(int i2) {
        char[] cArr = new char[Math.max(this.f12497c.length << 1, i2)];
        System.arraycopy(this.f12497c, 0, cArr, 0, this.f12498e);
        this.f12497c = cArr;
    }

    /* renamed from: f */
    public int m5563f(int i2, int i3, int i4) {
        if (i3 < 0) {
            i3 = 0;
        }
        int i5 = this.f12498e;
        if (i4 > i5) {
            i4 = i5;
        }
        if (i3 > i4) {
            return -1;
        }
        while (i3 < i4) {
            if (this.f12497c[i3] == i2) {
                return i3;
            }
            i3++;
        }
        return -1;
    }

    /* renamed from: g */
    public String m5564g(int i2, int i3) {
        if (i2 < 0) {
            throw new IndexOutOfBoundsException(C1499a.m626l("Negative beginIndex: ", i2));
        }
        if (i3 <= this.f12498e) {
            if (i2 <= i3) {
                return new String(this.f12497c, i2, i3 - i2);
            }
            throw new IndexOutOfBoundsException(C1499a.m629o("beginIndex: ", i2, " > endIndex: ", i3));
        }
        StringBuilder m588J = C1499a.m588J("endIndex: ", i3, " > length: ");
        m588J.append(this.f12498e);
        throw new IndexOutOfBoundsException(m588J.toString());
    }

    /* renamed from: h */
    public String m5565h(int i2, int i3) {
        if (i2 < 0) {
            throw new IndexOutOfBoundsException(C1499a.m626l("Negative beginIndex: ", i2));
        }
        if (i3 > this.f12498e) {
            StringBuilder m588J = C1499a.m588J("endIndex: ", i3, " > length: ");
            m588J.append(this.f12498e);
            throw new IndexOutOfBoundsException(m588J.toString());
        }
        if (i2 > i3) {
            throw new IndexOutOfBoundsException(C1499a.m629o("beginIndex: ", i2, " > endIndex: ", i3));
        }
        while (i2 < i3 && C4876c.m5549a(this.f12497c[i2])) {
            i2++;
        }
        while (i3 > i2 && C4876c.m5549a(this.f12497c[i3 - 1])) {
            i3--;
        }
        return new String(this.f12497c, i2, i3 - i2);
    }

    @Override // java.lang.CharSequence
    public int length() {
        return this.f12498e;
    }

    @Override // java.lang.CharSequence
    public CharSequence subSequence(int i2, int i3) {
        if (i2 < 0) {
            throw new IndexOutOfBoundsException(C1499a.m626l("Negative beginIndex: ", i2));
        }
        if (i3 <= this.f12498e) {
            if (i2 <= i3) {
                return CharBuffer.wrap(this.f12497c, i2, i3);
            }
            throw new IndexOutOfBoundsException(C1499a.m629o("beginIndex: ", i2, " > endIndex: ", i3));
        }
        StringBuilder m588J = C1499a.m588J("endIndex: ", i3, " > length: ");
        m588J.append(this.f12498e);
        throw new IndexOutOfBoundsException(m588J.toString());
    }

    @Override // java.lang.CharSequence
    public String toString() {
        return new String(this.f12497c, 0, this.f12498e);
    }
}
