package p005b.p199l.p266d.p274v.p276m;

import java.util.Objects;

/* renamed from: b.l.d.v.m.c */
/* loaded from: classes2.dex */
public final class C2557c {

    /* renamed from: a */
    public final C2555a f6982a;

    public C2557c(C2555a c2555a) {
        this.f6982a = c2555a;
    }

    /* renamed from: a */
    public void m2986a(int[] iArr, int i2) {
        int[] iArr2;
        C2556b c2556b = new C2556b(this.f6982a, iArr);
        int[] iArr3 = new int[i2];
        boolean z = true;
        for (int i3 = 0; i3 < i2; i3++) {
            C2555a c2555a = this.f6982a;
            int m2979b = c2556b.m2979b(c2555a.f6973i[c2555a.f6979o + i3]);
            iArr3[(i2 - 1) - i3] = m2979b;
            if (m2979b != 0) {
                z = false;
            }
        }
        if (z) {
            return;
        }
        C2556b c2556b2 = new C2556b(this.f6982a, iArr3);
        C2556b m2975a = this.f6982a.m2975a(i2, 1);
        if (m2975a.m2981d() < c2556b2.m2981d()) {
            m2975a = c2556b2;
            c2556b2 = m2975a;
        }
        C2555a c2555a2 = this.f6982a;
        C2556b c2556b3 = c2555a2.f6975k;
        C2556b c2556b4 = c2555a2.f6976l;
        C2556b c2556b5 = c2556b3;
        while (c2556b2.m2981d() >= i2 / 2) {
            if (c2556b2.m2982e()) {
                throw new C2559e("r_{i-1} was zero");
            }
            C2556b c2556b6 = this.f6982a.f6975k;
            int m2976b = this.f6982a.m2976b(c2556b2.m2980c(c2556b2.m2981d()));
            while (m2975a.m2981d() >= c2556b2.m2981d() && !m2975a.m2982e()) {
                int m2981d = m2975a.m2981d() - c2556b2.m2981d();
                int m2977c = this.f6982a.m2977c(m2975a.m2980c(m2975a.m2981d()), m2976b);
                c2556b6 = c2556b6.m2978a(this.f6982a.m2975a(m2981d, m2977c));
                m2975a = m2975a.m2978a(c2556b2.m2985h(m2981d, m2977c));
            }
            C2556b m2978a = c2556b6.m2984g(c2556b4).m2978a(c2556b5);
            if (m2975a.m2981d() >= c2556b2.m2981d()) {
                throw new IllegalStateException("Division algorithm failed to reduce polynomial?");
            }
            C2556b c2556b7 = m2975a;
            m2975a = c2556b2;
            c2556b2 = c2556b7;
            C2556b c2556b8 = c2556b4;
            c2556b4 = m2978a;
            c2556b5 = c2556b8;
        }
        int m2980c = c2556b4.m2980c(0);
        if (m2980c == 0) {
            throw new C2559e("sigmaTilde(0) was zero");
        }
        int m2976b2 = this.f6982a.m2976b(m2980c);
        C2556b[] c2556bArr = {c2556b4.m2983f(m2976b2), c2556b2.m2983f(m2976b2)};
        C2556b c2556b9 = c2556bArr[0];
        C2556b c2556b10 = c2556bArr[1];
        int m2981d2 = c2556b9.m2981d();
        if (m2981d2 == 1) {
            iArr2 = new int[]{c2556b9.m2980c(1)};
        } else {
            int[] iArr4 = new int[m2981d2];
            int i4 = 0;
            for (int i5 = 1; i5 < this.f6982a.f6977m && i4 < m2981d2; i5++) {
                if (c2556b9.m2979b(i5) == 0) {
                    iArr4[i4] = this.f6982a.m2976b(i5);
                    i4++;
                }
            }
            if (i4 != m2981d2) {
                throw new C2559e("Error locator degree does not match number of roots");
            }
            iArr2 = iArr4;
        }
        int length = iArr2.length;
        int[] iArr5 = new int[length];
        for (int i6 = 0; i6 < length; i6++) {
            int m2976b3 = this.f6982a.m2976b(iArr2[i6]);
            int i7 = 1;
            for (int i8 = 0; i8 < length; i8++) {
                if (i6 != i8) {
                    int m2977c2 = this.f6982a.m2977c(iArr2[i8], m2976b3);
                    i7 = this.f6982a.m2977c(i7, (m2977c2 & 1) == 0 ? m2977c2 | 1 : m2977c2 & (-2));
                }
            }
            iArr5[i6] = this.f6982a.m2977c(c2556b10.m2979b(m2976b3), this.f6982a.m2976b(i7));
            C2555a c2555a3 = this.f6982a;
            if (c2555a3.f6979o != 0) {
                iArr5[i6] = c2555a3.m2977c(iArr5[i6], m2976b3);
            }
        }
        for (int i9 = 0; i9 < iArr2.length; i9++) {
            int length2 = iArr.length - 1;
            C2555a c2555a4 = this.f6982a;
            int i10 = iArr2[i9];
            Objects.requireNonNull(c2555a4);
            if (i10 == 0) {
                throw new IllegalArgumentException();
            }
            int i11 = length2 - c2555a4.f6974j[i10];
            if (i11 < 0) {
                throw new C2559e("Bad error location");
            }
            iArr[i11] = iArr[i11] ^ iArr5[i9];
        }
    }
}
