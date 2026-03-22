package p005b.p199l.p266d.p282y;

import java.util.Arrays;
import java.util.Map;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.a */
/* loaded from: classes2.dex */
public final class C2571a extends AbstractC2581k {

    /* renamed from: a */
    public static final char[] f7017a = "0123456789-$:/.+ABCD".toCharArray();

    /* renamed from: b */
    public static final int[] f7018b = {3, 6, 9, 96, 18, 66, 33, 36, 48, 72, 12, 24, 69, 81, 84, 21, 26, 41, 11, 14};

    /* renamed from: c */
    public static final char[] f7019c = {'A', 'B', 'C', 'D'};

    /* renamed from: d */
    public final StringBuilder f7020d = new StringBuilder(20);

    /* renamed from: e */
    public int[] f7021e = new int[80];

    /* renamed from: f */
    public int f7022f = 0;

    /* renamed from: g */
    public static boolean m2999g(char[] cArr, char c2) {
        if (cArr != null) {
            for (char c3 : cArr) {
                if (c3 == c2) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        Arrays.fill(this.f7021e, 0);
        this.f7022f = 0;
        int m2952i = c2543a.m2952i(0);
        int i3 = c2543a.f6892e;
        if (m2952i >= i3) {
            throw C2529k.f6843f;
        }
        int i4 = 0;
        boolean z = true;
        while (m2952i < i3) {
            if (c2543a.m2950g(m2952i) != z) {
                i4++;
            } else {
                m3001h(i4);
                z = !z;
                i4 = 1;
            }
            m2952i++;
        }
        m3001h(i4);
        int i5 = 1;
        while (i5 < this.f7022f) {
            int m3002i = m3002i(i5);
            if (m3002i != -1 && m2999g(f7019c, f7017a[m3002i])) {
                int i6 = 0;
                for (int i7 = i5; i7 < i5 + 7; i7++) {
                    i6 += this.f7021e[i7];
                }
                if (i5 == 1 || this.f7021e[i5 - 1] >= i6 / 2) {
                    this.f7020d.setLength(0);
                    int i8 = i5;
                    do {
                        int m3002i2 = m3002i(i8);
                        if (m3002i2 == -1) {
                            throw C2529k.f6843f;
                        }
                        this.f7020d.append((char) m3002i2);
                        i8 += 8;
                        if (this.f7020d.length() > 1 && m2999g(f7019c, f7017a[m3002i2])) {
                            break;
                        }
                    } while (i8 < this.f7022f);
                    int i9 = i8 - 1;
                    int i10 = this.f7021e[i9];
                    int i11 = 0;
                    for (int i12 = -8; i12 < -1; i12++) {
                        i11 += this.f7021e[i8 + i12];
                    }
                    if (i8 < this.f7022f && i10 < i11 / 2) {
                        throw C2529k.f6843f;
                    }
                    int[] iArr = {0, 0, 0, 0};
                    int[] iArr2 = {0, 0, 0, 0};
                    int length = this.f7020d.length() - 1;
                    int i13 = i5;
                    int i14 = 0;
                    while (true) {
                        int i15 = f7018b[this.f7020d.charAt(i14)];
                        for (int i16 = 6; i16 >= 0; i16--) {
                            int i17 = (i16 & 1) + ((i15 & 1) << 1);
                            iArr[i17] = iArr[i17] + this.f7021e[i13 + i16];
                            iArr2[i17] = iArr2[i17] + 1;
                            i15 >>= 1;
                        }
                        if (i14 >= length) {
                            break;
                        }
                        i13 += 8;
                        i14++;
                    }
                    float[] fArr = new float[4];
                    float[] fArr2 = new float[4];
                    int i18 = 0;
                    for (int i19 = 2; i18 < i19; i19 = 2) {
                        fArr2[i18] = 0.0f;
                        int i20 = i18 + 2;
                        fArr2[i20] = ((iArr[i20] / iArr2[i20]) + (iArr[i18] / iArr2[i18])) / 2.0f;
                        fArr[i18] = fArr2[i20];
                        fArr[i20] = ((iArr[i20] * 2.0f) + 1.5f) / iArr2[i20];
                        i18++;
                    }
                    int i21 = i5;
                    int i22 = 0;
                    loop8: while (true) {
                        int i23 = f7018b[this.f7020d.charAt(i22)];
                        for (int i24 = 6; i24 >= 0; i24--) {
                            int i25 = (i24 & 1) + ((i23 & 1) << 1);
                            float f2 = this.f7021e[i21 + i24];
                            if (f2 < fArr2[i25] || f2 > fArr[i25]) {
                                break loop8;
                            }
                            i23 >>= 1;
                        }
                        if (i22 >= length) {
                            for (int i26 = 0; i26 < this.f7020d.length(); i26++) {
                                StringBuilder sb = this.f7020d;
                                sb.setCharAt(i26, f7017a[sb.charAt(i26)]);
                            }
                            char charAt = this.f7020d.charAt(0);
                            char[] cArr = f7019c;
                            if (!m2999g(cArr, charAt)) {
                                throw C2529k.f6843f;
                            }
                            StringBuilder sb2 = this.f7020d;
                            if (!m2999g(cArr, sb2.charAt(sb2.length() - 1))) {
                                throw C2529k.f6843f;
                            }
                            if (this.f7020d.length() <= 3) {
                                throw C2529k.f6843f;
                            }
                            if (map == null || !map.containsKey(EnumC2523e.RETURN_CODABAR_START_END)) {
                                StringBuilder sb3 = this.f7020d;
                                sb3.deleteCharAt(sb3.length() - 1);
                                this.f7020d.deleteCharAt(0);
                            }
                            int i27 = 0;
                            for (int i28 = 0; i28 < i5; i28++) {
                                i27 += this.f7021e[i28];
                            }
                            float f3 = i27;
                            while (i5 < i9) {
                                i27 += this.f7021e[i5];
                                i5++;
                            }
                            float f4 = i2;
                            return new C2534p(this.f7020d.toString(), null, new C2536r[]{new C2536r(f3, f4), new C2536r(i27, f4)}, EnumC2497a.CODABAR);
                        }
                        i21 += 8;
                        i22++;
                    }
                    throw C2529k.f6843f;
                }
            }
            i5 += 2;
        }
        throw C2529k.f6843f;
    }

    /* renamed from: h */
    public final void m3001h(int i2) {
        int[] iArr = this.f7021e;
        int i3 = this.f7022f;
        iArr[i3] = i2;
        int i4 = i3 + 1;
        this.f7022f = i4;
        if (i4 >= iArr.length) {
            int[] iArr2 = new int[i4 << 1];
            System.arraycopy(iArr, 0, iArr2, 0, i4);
            this.f7021e = iArr2;
        }
    }

    /* renamed from: i */
    public final int m3002i(int i2) {
        int i3 = i2 + 7;
        if (i3 >= this.f7022f) {
            return -1;
        }
        int[] iArr = this.f7021e;
        int i4 = Integer.MAX_VALUE;
        int i5 = 0;
        int i6 = Integer.MAX_VALUE;
        int i7 = 0;
        for (int i8 = i2; i8 < i3; i8 += 2) {
            int i9 = iArr[i8];
            if (i9 < i6) {
                i6 = i9;
            }
            if (i9 > i7) {
                i7 = i9;
            }
        }
        int i10 = (i6 + i7) / 2;
        int i11 = 0;
        for (int i12 = i2 + 1; i12 < i3; i12 += 2) {
            int i13 = iArr[i12];
            if (i13 < i4) {
                i4 = i13;
            }
            if (i13 > i11) {
                i11 = i13;
            }
        }
        int i14 = (i4 + i11) / 2;
        int i15 = 128;
        int i16 = 0;
        for (int i17 = 0; i17 < 7; i17++) {
            i15 >>= 1;
            if (iArr[i2 + i17] > ((i17 & 1) == 0 ? i10 : i14)) {
                i16 |= i15;
            }
        }
        while (true) {
            int[] iArr2 = f7018b;
            if (i5 >= iArr2.length) {
                return -1;
            }
            if (iArr2[i5] == i16) {
                return i5;
            }
            i5++;
        }
    }
}
