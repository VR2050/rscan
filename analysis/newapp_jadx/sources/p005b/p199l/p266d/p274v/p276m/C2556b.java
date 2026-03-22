package p005b.p199l.p266d.p274v.p276m;

import java.util.Objects;

/* renamed from: b.l.d.v.m.b */
/* loaded from: classes2.dex */
public final class C2556b {

    /* renamed from: a */
    public final C2555a f6980a;

    /* renamed from: b */
    public final int[] f6981b;

    public C2556b(C2555a c2555a, int[] iArr) {
        if (iArr.length == 0) {
            throw new IllegalArgumentException();
        }
        this.f6980a = c2555a;
        int length = iArr.length;
        if (length <= 1 || iArr[0] != 0) {
            this.f6981b = iArr;
            return;
        }
        int i2 = 1;
        while (i2 < length && iArr[i2] == 0) {
            i2++;
        }
        if (i2 == length) {
            this.f6981b = new int[]{0};
            return;
        }
        int[] iArr2 = new int[length - i2];
        this.f6981b = iArr2;
        System.arraycopy(iArr, i2, iArr2, 0, iArr2.length);
    }

    /* renamed from: a */
    public C2556b m2978a(C2556b c2556b) {
        if (!this.f6980a.equals(c2556b.f6980a)) {
            throw new IllegalArgumentException("GenericGFPolys do not have same GenericGF field");
        }
        if (m2982e()) {
            return c2556b;
        }
        if (c2556b.m2982e()) {
            return this;
        }
        int[] iArr = this.f6981b;
        int[] iArr2 = c2556b.f6981b;
        if (iArr.length <= iArr2.length) {
            iArr = iArr2;
            iArr2 = iArr;
        }
        int[] iArr3 = new int[iArr.length];
        int length = iArr.length - iArr2.length;
        System.arraycopy(iArr, 0, iArr3, 0, length);
        for (int i2 = length; i2 < iArr.length; i2++) {
            iArr3[i2] = iArr2[i2 - length] ^ iArr[i2];
        }
        return new C2556b(this.f6980a, iArr3);
    }

    /* renamed from: b */
    public int m2979b(int i2) {
        if (i2 == 0) {
            return m2980c(0);
        }
        if (i2 != 1) {
            int[] iArr = this.f6981b;
            int i3 = iArr[0];
            int length = iArr.length;
            for (int i4 = 1; i4 < length; i4++) {
                i3 = this.f6980a.m2977c(i2, i3) ^ this.f6981b[i4];
            }
            return i3;
        }
        int i5 = 0;
        for (int i6 : this.f6981b) {
            C2555a c2555a = C2555a.f6965a;
            i5 ^= i6;
        }
        return i5;
    }

    /* renamed from: c */
    public int m2980c(int i2) {
        return this.f6981b[(r0.length - 1) - i2];
    }

    /* renamed from: d */
    public int m2981d() {
        return this.f6981b.length - 1;
    }

    /* renamed from: e */
    public boolean m2982e() {
        return this.f6981b[0] == 0;
    }

    /* renamed from: f */
    public C2556b m2983f(int i2) {
        if (i2 == 0) {
            return this.f6980a.f6975k;
        }
        if (i2 == 1) {
            return this;
        }
        int length = this.f6981b.length;
        int[] iArr = new int[length];
        for (int i3 = 0; i3 < length; i3++) {
            iArr[i3] = this.f6980a.m2977c(this.f6981b[i3], i2);
        }
        return new C2556b(this.f6980a, iArr);
    }

    /* renamed from: g */
    public C2556b m2984g(C2556b c2556b) {
        if (!this.f6980a.equals(c2556b.f6980a)) {
            throw new IllegalArgumentException("GenericGFPolys do not have same GenericGF field");
        }
        if (m2982e() || c2556b.m2982e()) {
            return this.f6980a.f6975k;
        }
        int[] iArr = this.f6981b;
        int length = iArr.length;
        int[] iArr2 = c2556b.f6981b;
        int length2 = iArr2.length;
        int[] iArr3 = new int[(length + length2) - 1];
        for (int i2 = 0; i2 < length; i2++) {
            int i3 = iArr[i2];
            for (int i4 = 0; i4 < length2; i4++) {
                int i5 = i2 + i4;
                iArr3[i5] = iArr3[i5] ^ this.f6980a.m2977c(i3, iArr2[i4]);
            }
        }
        return new C2556b(this.f6980a, iArr3);
    }

    /* renamed from: h */
    public C2556b m2985h(int i2, int i3) {
        if (i2 < 0) {
            throw new IllegalArgumentException();
        }
        if (i3 == 0) {
            return this.f6980a.f6975k;
        }
        int length = this.f6981b.length;
        int[] iArr = new int[i2 + length];
        for (int i4 = 0; i4 < length; i4++) {
            iArr[i4] = this.f6980a.m2977c(this.f6981b[i4], i3);
        }
        return new C2556b(this.f6980a, iArr);
    }

    public String toString() {
        if (m2982e()) {
            return "0";
        }
        StringBuilder sb = new StringBuilder(m2981d() * 8);
        for (int m2981d = m2981d(); m2981d >= 0; m2981d--) {
            int m2980c = m2980c(m2981d);
            if (m2980c != 0) {
                if (m2980c < 0) {
                    if (m2981d == m2981d()) {
                        sb.append("-");
                    } else {
                        sb.append(" - ");
                    }
                    m2980c = -m2980c;
                } else if (sb.length() > 0) {
                    sb.append(" + ");
                }
                if (m2981d == 0 || m2980c != 1) {
                    C2555a c2555a = this.f6980a;
                    Objects.requireNonNull(c2555a);
                    if (m2980c == 0) {
                        throw new IllegalArgumentException();
                    }
                    int i2 = c2555a.f6974j[m2980c];
                    if (i2 == 0) {
                        sb.append('1');
                    } else if (i2 == 1) {
                        sb.append('a');
                    } else {
                        sb.append("a^");
                        sb.append(i2);
                    }
                }
                if (m2981d != 0) {
                    if (m2981d == 1) {
                        sb.append('x');
                    } else {
                        sb.append("x^");
                        sb.append(m2981d);
                    }
                }
            }
        }
        return sb.toString();
    }
}
