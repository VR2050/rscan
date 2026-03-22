package p005b.p199l.p200a.p201a.p250p1;

import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.p1.u */
/* loaded from: classes.dex */
public final class C2361u {

    /* renamed from: a */
    public byte[] f6136a;

    /* renamed from: b */
    public int f6137b;

    /* renamed from: c */
    public int f6138c;

    /* renamed from: d */
    public int f6139d = 0;

    public C2361u(byte[] bArr, int i2, int i3) {
        this.f6136a = bArr;
        this.f6138c = i2;
        this.f6137b = i3;
        m2595a();
    }

    /* renamed from: a */
    public final void m2595a() {
        int i2;
        int i3 = this.f6138c;
        C4195m.m4771I(i3 >= 0 && (i3 < (i2 = this.f6137b) || (i3 == i2 && this.f6139d == 0)));
    }

    /* renamed from: b */
    public boolean m2596b(int i2) {
        int i3 = this.f6138c;
        int i4 = i2 / 8;
        int i5 = i3 + i4;
        int i6 = (this.f6139d + i2) - (i4 * 8);
        if (i6 > 7) {
            i5++;
            i6 -= 8;
        }
        while (true) {
            i3++;
            if (i3 > i5 || i5 >= this.f6137b) {
                break;
            }
            if (m2602h(i3)) {
                i5++;
                i3 += 2;
            }
        }
        int i7 = this.f6137b;
        if (i5 >= i7) {
            return i5 == i7 && i6 == 0;
        }
        return true;
    }

    /* renamed from: c */
    public boolean m2597c() {
        int i2 = this.f6138c;
        int i3 = this.f6139d;
        int i4 = 0;
        while (this.f6138c < this.f6137b && !m2598d()) {
            i4++;
        }
        boolean z = this.f6138c == this.f6137b;
        this.f6138c = i2;
        this.f6139d = i3;
        return !z && m2596b((i4 * 2) + 1);
    }

    /* renamed from: d */
    public boolean m2598d() {
        boolean z = (this.f6136a[this.f6138c] & (128 >> this.f6139d)) != 0;
        m2603i();
        return z;
    }

    /* renamed from: e */
    public int m2599e(int i2) {
        int i3;
        this.f6139d += i2;
        int i4 = 0;
        while (true) {
            i3 = this.f6139d;
            if (i3 <= 8) {
                break;
            }
            int i5 = i3 - 8;
            this.f6139d = i5;
            byte[] bArr = this.f6136a;
            int i6 = this.f6138c;
            i4 |= (bArr[i6] & 255) << i5;
            if (!m2602h(i6 + 1)) {
                r3 = 1;
            }
            this.f6138c = i6 + r3;
        }
        byte[] bArr2 = this.f6136a;
        int i7 = this.f6138c;
        int i8 = ((-1) >>> (32 - i2)) & (i4 | ((bArr2[i7] & 255) >> (8 - i3)));
        if (i3 == 8) {
            this.f6139d = 0;
            this.f6138c = i7 + (m2602h(i7 + 1) ? 2 : 1);
        }
        m2595a();
        return i8;
    }

    /* renamed from: f */
    public final int m2600f() {
        int i2 = 0;
        while (!m2598d()) {
            i2++;
        }
        return ((1 << i2) - 1) + (i2 > 0 ? m2599e(i2) : 0);
    }

    /* renamed from: g */
    public int m2601g() {
        int m2600f = m2600f();
        return ((m2600f + 1) / 2) * (m2600f % 2 == 0 ? -1 : 1);
    }

    /* renamed from: h */
    public final boolean m2602h(int i2) {
        if (2 <= i2 && i2 < this.f6137b) {
            byte[] bArr = this.f6136a;
            if (bArr[i2] == 3 && bArr[i2 - 2] == 0 && bArr[i2 - 1] == 0) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: i */
    public void m2603i() {
        int i2 = this.f6139d + 1;
        this.f6139d = i2;
        if (i2 == 8) {
            this.f6139d = 0;
            int i3 = this.f6138c;
            this.f6138c = i3 + (m2602h(i3 + 1) ? 2 : 1);
        }
        m2595a();
    }

    /* renamed from: j */
    public void m2604j(int i2) {
        int i3 = this.f6138c;
        int i4 = i2 / 8;
        int i5 = i3 + i4;
        this.f6138c = i5;
        int i6 = (i2 - (i4 * 8)) + this.f6139d;
        this.f6139d = i6;
        if (i6 > 7) {
            this.f6138c = i5 + 1;
            this.f6139d = i6 - 8;
        }
        while (true) {
            i3++;
            if (i3 > this.f6138c) {
                m2595a();
                return;
            } else if (m2602h(i3)) {
                this.f6138c++;
                i3 += 2;
            }
        }
    }
}
