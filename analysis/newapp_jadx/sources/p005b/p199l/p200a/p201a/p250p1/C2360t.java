package p005b.p199l.p200a.p201a.p250p1;

import androidx.annotation.Nullable;
import java.nio.charset.Charset;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.p1.t */
/* loaded from: classes.dex */
public final class C2360t {

    /* renamed from: a */
    public byte[] f6133a;

    /* renamed from: b */
    public int f6134b;

    /* renamed from: c */
    public int f6135c;

    public C2360t() {
        this.f6133a = C2344d0.f6040f;
    }

    /* renamed from: A */
    public void m2565A(byte[] bArr, int i2) {
        this.f6133a = bArr;
        this.f6135c = i2;
        this.f6134b = 0;
    }

    /* renamed from: B */
    public void m2566B(int i2) {
        C4195m.m4765F(i2 >= 0 && i2 <= this.f6133a.length);
        this.f6135c = i2;
    }

    /* renamed from: C */
    public void m2567C(int i2) {
        C4195m.m4765F(i2 >= 0 && i2 <= this.f6135c);
        this.f6134b = i2;
    }

    /* renamed from: D */
    public void m2568D(int i2) {
        m2567C(this.f6134b + i2);
    }

    /* renamed from: a */
    public int m2569a() {
        return this.f6135c - this.f6134b;
    }

    /* renamed from: b */
    public int m2570b() {
        return this.f6133a[this.f6134b] & 255;
    }

    /* renamed from: c */
    public void m2571c(C2359s c2359s, int i2) {
        m2572d(c2359s.f6129a, 0, i2);
        c2359s.m2562j(0);
    }

    /* renamed from: d */
    public void m2572d(byte[] bArr, int i2, int i3) {
        System.arraycopy(this.f6133a, this.f6134b, bArr, i2, i3);
        this.f6134b += i3;
    }

    /* renamed from: e */
    public int m2573e() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = (bArr[i2] & 255) << 24;
        int i5 = i3 + 1;
        this.f6134b = i5;
        int i6 = i4 | ((bArr[i3] & 255) << 16);
        int i7 = i5 + 1;
        this.f6134b = i7;
        int i8 = i6 | ((bArr[i5] & 255) << 8);
        this.f6134b = i7 + 1;
        return (bArr[i7] & 255) | i8;
    }

    @Nullable
    /* renamed from: f */
    public String m2574f() {
        if (m2569a() == 0) {
            return null;
        }
        int i2 = this.f6134b;
        while (i2 < this.f6135c && !C2344d0.m2347y(this.f6133a[i2])) {
            i2++;
        }
        int i3 = this.f6134b;
        if (i2 - i3 >= 3) {
            byte[] bArr = this.f6133a;
            if (bArr[i3] == -17 && bArr[i3 + 1] == -69 && bArr[i3 + 2] == -65) {
                this.f6134b = i3 + 3;
            }
        }
        byte[] bArr2 = this.f6133a;
        int i4 = this.f6134b;
        String m2333k = C2344d0.m2333k(bArr2, i4, i2 - i4);
        this.f6134b = i2;
        int i5 = this.f6135c;
        if (i2 == i5) {
            return m2333k;
        }
        byte[] bArr3 = this.f6133a;
        if (bArr3[i2] == 13) {
            int i6 = i2 + 1;
            this.f6134b = i6;
            if (i6 == i5) {
                return m2333k;
            }
        }
        int i7 = this.f6134b;
        if (bArr3[i7] == 10) {
            this.f6134b = i7 + 1;
        }
        return m2333k;
    }

    /* renamed from: g */
    public int m2575g() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = bArr[i2] & 255;
        int i5 = i3 + 1;
        this.f6134b = i5;
        int i6 = i4 | ((bArr[i3] & 255) << 8);
        int i7 = i5 + 1;
        this.f6134b = i7;
        int i8 = i6 | ((bArr[i5] & 255) << 16);
        this.f6134b = i7 + 1;
        return ((bArr[i7] & 255) << 24) | i8;
    }

    /* renamed from: h */
    public long m2576h() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b + 1;
        this.f6134b = i2;
        long j2 = bArr[r1] & 255;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = i3 + 1;
        this.f6134b = i4;
        long j3 = j2 | ((bArr[i2] & 255) << 8) | ((bArr[i3] & 255) << 16);
        this.f6134b = i4 + 1;
        return j3 | ((bArr[i4] & 255) << 24);
    }

    /* renamed from: i */
    public int m2577i() {
        int m2575g = m2575g();
        if (m2575g >= 0) {
            return m2575g;
        }
        throw new IllegalStateException(C1499a.m626l("Top bit not zero: ", m2575g));
    }

    /* renamed from: j */
    public int m2578j() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = bArr[i2] & 255;
        this.f6134b = i3 + 1;
        return ((bArr[i3] & 255) << 8) | i4;
    }

    /* renamed from: k */
    public long m2579k() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b + 1;
        this.f6134b = i2;
        long j2 = (bArr[r1] & 255) << 56;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = i3 + 1;
        this.f6134b = i4;
        long j3 = j2 | ((bArr[i2] & 255) << 48) | ((bArr[i3] & 255) << 40);
        int i5 = i4 + 1;
        this.f6134b = i5;
        long j4 = j3 | ((bArr[i4] & 255) << 32);
        int i6 = i5 + 1;
        this.f6134b = i6;
        long j5 = j4 | ((bArr[i5] & 255) << 24);
        int i7 = i6 + 1;
        this.f6134b = i7;
        long j6 = j5 | ((bArr[i6] & 255) << 16);
        int i8 = i7 + 1;
        this.f6134b = i8;
        long j7 = j6 | ((bArr[i7] & 255) << 8);
        this.f6134b = i8 + 1;
        return j7 | (bArr[i8] & 255);
    }

    @Nullable
    /* renamed from: l */
    public String m2580l() {
        if (m2569a() == 0) {
            return null;
        }
        int i2 = this.f6134b;
        while (i2 < this.f6135c && this.f6133a[i2] != 0) {
            i2++;
        }
        byte[] bArr = this.f6133a;
        int i3 = this.f6134b;
        String m2333k = C2344d0.m2333k(bArr, i3, i2 - i3);
        this.f6134b = i2;
        if (i2 < this.f6135c) {
            this.f6134b = i2 + 1;
        }
        return m2333k;
    }

    /* renamed from: m */
    public String m2581m(int i2) {
        if (i2 == 0) {
            return "";
        }
        int i3 = this.f6134b;
        int i4 = (i3 + i2) - 1;
        String m2333k = C2344d0.m2333k(this.f6133a, i3, (i4 >= this.f6135c || this.f6133a[i4] != 0) ? i2 : i2 - 1);
        this.f6134b += i2;
        return m2333k;
    }

    /* renamed from: n */
    public String m2582n(int i2) {
        return m2583o(i2, Charset.forName("UTF-8"));
    }

    /* renamed from: o */
    public String m2583o(int i2, Charset charset) {
        String str = new String(this.f6133a, this.f6134b, i2, charset);
        this.f6134b += i2;
        return str;
    }

    /* renamed from: p */
    public int m2584p() {
        return (m2585q() << 21) | (m2585q() << 14) | (m2585q() << 7) | m2585q();
    }

    /* renamed from: q */
    public int m2585q() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b;
        this.f6134b = i2 + 1;
        return bArr[i2] & 255;
    }

    /* renamed from: r */
    public long m2586r() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b + 1;
        this.f6134b = i2;
        long j2 = (bArr[r1] & 255) << 24;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = i3 + 1;
        this.f6134b = i4;
        long j3 = j2 | ((bArr[i2] & 255) << 16) | ((bArr[i3] & 255) << 8);
        this.f6134b = i4 + 1;
        return j3 | (bArr[i4] & 255);
    }

    /* renamed from: s */
    public int m2587s() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = (bArr[i2] & 255) << 16;
        int i5 = i3 + 1;
        this.f6134b = i5;
        int i6 = i4 | ((bArr[i3] & 255) << 8);
        this.f6134b = i5 + 1;
        return (bArr[i5] & 255) | i6;
    }

    /* renamed from: t */
    public int m2588t() {
        int m2573e = m2573e();
        if (m2573e >= 0) {
            return m2573e;
        }
        throw new IllegalStateException(C1499a.m626l("Top bit not zero: ", m2573e));
    }

    /* renamed from: u */
    public long m2589u() {
        long m2579k = m2579k();
        if (m2579k >= 0) {
            return m2579k;
        }
        throw new IllegalStateException(C1499a.m630p("Top bit not zero: ", m2579k));
    }

    /* renamed from: v */
    public int m2590v() {
        byte[] bArr = this.f6133a;
        int i2 = this.f6134b;
        int i3 = i2 + 1;
        this.f6134b = i3;
        int i4 = (bArr[i2] & 255) << 8;
        this.f6134b = i3 + 1;
        return (bArr[i3] & 255) | i4;
    }

    /* renamed from: w */
    public long m2591w() {
        int i2;
        int i3;
        long j2 = this.f6133a[this.f6134b];
        int i4 = 7;
        while (true) {
            if (i4 < 0) {
                break;
            }
            if (((1 << i4) & j2) != 0) {
                i4--;
            } else if (i4 < 6) {
                j2 &= r6 - 1;
                i3 = 7 - i4;
            } else if (i4 == 7) {
                i3 = 1;
            }
        }
        i3 = 0;
        if (i3 == 0) {
            throw new NumberFormatException(C1499a.m630p("Invalid UTF-8 sequence first byte: ", j2));
        }
        for (i2 = 1; i2 < i3; i2++) {
            if ((this.f6133a[this.f6134b + i2] & 192) != 128) {
                throw new NumberFormatException(C1499a.m630p("Invalid UTF-8 sequence continuation byte: ", j2));
            }
            j2 = (j2 << 6) | (r3 & 63);
        }
        this.f6134b += i3;
        return j2;
    }

    /* renamed from: x */
    public void m2592x() {
        this.f6134b = 0;
        this.f6135c = 0;
    }

    /* renamed from: y */
    public void m2593y(int i2) {
        byte[] bArr = this.f6133a;
        if (bArr.length < i2) {
            bArr = new byte[i2];
        }
        m2565A(bArr, i2);
    }

    /* renamed from: z */
    public void m2594z(byte[] bArr) {
        int length = bArr.length;
        this.f6133a = bArr;
        this.f6135c = length;
        this.f6134b = 0;
    }

    public C2360t(int i2) {
        this.f6133a = new byte[i2];
        this.f6135c = i2;
    }

    public C2360t(byte[] bArr) {
        this.f6133a = bArr;
        this.f6135c = bArr.length;
    }

    public C2360t(byte[] bArr, int i2) {
        this.f6133a = bArr;
        this.f6135c = i2;
    }
}
