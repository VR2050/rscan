package p005b.p199l.p200a.p201a.p202a1;

import java.util.Arrays;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.a1.z */
/* loaded from: classes.dex */
public final class C1934z {

    /* renamed from: a */
    public final int f3222a;

    /* renamed from: b */
    public final int f3223b;

    /* renamed from: c */
    public final float f3224c;

    /* renamed from: d */
    public final float f3225d;

    /* renamed from: e */
    public final float f3226e;

    /* renamed from: f */
    public final int f3227f;

    /* renamed from: g */
    public final int f3228g;

    /* renamed from: h */
    public final int f3229h;

    /* renamed from: i */
    public final short[] f3230i;

    /* renamed from: j */
    public short[] f3231j;

    /* renamed from: k */
    public int f3232k;

    /* renamed from: l */
    public short[] f3233l;

    /* renamed from: m */
    public int f3234m;

    /* renamed from: n */
    public short[] f3235n;

    /* renamed from: o */
    public int f3236o;

    /* renamed from: p */
    public int f3237p;

    /* renamed from: q */
    public int f3238q;

    /* renamed from: r */
    public int f3239r;

    /* renamed from: s */
    public int f3240s;

    /* renamed from: t */
    public int f3241t;

    /* renamed from: u */
    public int f3242u;

    /* renamed from: v */
    public int f3243v;

    public C1934z(int i2, int i3, float f2, float f3, int i4) {
        this.f3222a = i2;
        this.f3223b = i3;
        this.f3224c = f2;
        this.f3225d = f3;
        this.f3226e = i2 / i4;
        this.f3227f = i2 / 400;
        int i5 = i2 / 65;
        this.f3228g = i5;
        int i6 = i5 * 2;
        this.f3229h = i6;
        this.f3230i = new short[i6];
        this.f3231j = new short[i6 * i3];
        this.f3233l = new short[i6 * i3];
        this.f3235n = new short[i6 * i3];
    }

    /* renamed from: e */
    public static void m1332e(int i2, int i3, short[] sArr, int i4, short[] sArr2, int i5, short[] sArr3, int i6) {
        for (int i7 = 0; i7 < i3; i7++) {
            int i8 = (i4 * i3) + i7;
            int i9 = (i6 * i3) + i7;
            int i10 = (i5 * i3) + i7;
            for (int i11 = 0; i11 < i2; i11++) {
                sArr[i8] = (short) (((sArr3[i9] * i11) + ((i2 - i11) * sArr2[i10])) / i2);
                i8 += i3;
                i10 += i3;
                i9 += i3;
            }
        }
    }

    /* renamed from: a */
    public final void m1333a(short[] sArr, int i2, int i3) {
        short[] m1335c = m1335c(this.f3233l, this.f3234m, i3);
        this.f3233l = m1335c;
        int i4 = this.f3223b;
        System.arraycopy(sArr, i2 * i4, m1335c, this.f3234m * i4, i4 * i3);
        this.f3234m += i3;
    }

    /* renamed from: b */
    public final void m1334b(short[] sArr, int i2, int i3) {
        int i4 = this.f3229h / i3;
        int i5 = this.f3223b;
        int i6 = i3 * i5;
        int i7 = i2 * i5;
        for (int i8 = 0; i8 < i4; i8++) {
            int i9 = 0;
            for (int i10 = 0; i10 < i6; i10++) {
                i9 += sArr[(i8 * i6) + i7 + i10];
            }
            this.f3230i[i8] = (short) (i9 / i6);
        }
    }

    /* renamed from: c */
    public final short[] m1335c(short[] sArr, int i2, int i3) {
        int length = sArr.length;
        int i4 = this.f3223b;
        int i5 = length / i4;
        return i2 + i3 <= i5 ? sArr : Arrays.copyOf(sArr, (((i5 * 3) / 2) + i3) * i4);
    }

    /* renamed from: d */
    public final int m1336d(short[] sArr, int i2, int i3, int i4) {
        int i5 = i2 * this.f3223b;
        int i6 = 1;
        int i7 = 255;
        int i8 = 0;
        int i9 = 0;
        while (i3 <= i4) {
            int i10 = 0;
            for (int i11 = 0; i11 < i3; i11++) {
                i10 += Math.abs(sArr[i5 + i11] - sArr[(i5 + i3) + i11]);
            }
            if (i10 * i8 < i6 * i3) {
                i8 = i3;
                i6 = i10;
            }
            if (i10 * i7 > i9 * i3) {
                i7 = i3;
                i9 = i10;
            }
            i3++;
        }
        this.f3242u = i6 / i8;
        this.f3243v = i9 / i7;
        return i8;
    }

    /* renamed from: f */
    public final void m1337f() {
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9 = this.f3234m;
        float f2 = this.f3224c;
        float f3 = this.f3225d;
        float f4 = f2 / f3;
        float f5 = this.f3226e * f3;
        double d2 = f4;
        float f6 = 1.0f;
        int i10 = 1;
        if (d2 > 1.00001d || d2 < 0.99999d) {
            int i11 = this.f3232k;
            if (i11 >= this.f3229h) {
                int i12 = 0;
                while (true) {
                    int i13 = this.f3239r;
                    if (i13 > 0) {
                        int min = Math.min(this.f3229h, i13);
                        m1333a(this.f3231j, i12, min);
                        this.f3239r -= min;
                        i12 += min;
                    } else {
                        short[] sArr = this.f3231j;
                        int i14 = this.f3222a;
                        int i15 = i14 > 4000 ? i14 / 4000 : 1;
                        if (this.f3223b == i10 && i15 == i10) {
                            i2 = m1336d(sArr, i12, this.f3227f, this.f3228g);
                        } else {
                            m1334b(sArr, i12, i15);
                            int m1336d = m1336d(this.f3230i, 0, this.f3227f / i15, this.f3228g / i15);
                            if (i15 != i10) {
                                int i16 = m1336d * i15;
                                int i17 = i15 * 4;
                                int i18 = i16 - i17;
                                int i19 = i16 + i17;
                                int i20 = this.f3227f;
                                if (i18 < i20) {
                                    i18 = i20;
                                }
                                int i21 = this.f3228g;
                                if (i19 > i21) {
                                    i19 = i21;
                                }
                                if (this.f3223b == i10) {
                                    i2 = m1336d(sArr, i12, i18, i19);
                                } else {
                                    m1334b(sArr, i12, i10);
                                    i2 = m1336d(this.f3230i, 0, i18, i19);
                                }
                            } else {
                                i2 = m1336d;
                            }
                        }
                        int i22 = this.f3242u;
                        int i23 = i22 != 0 && this.f3240s != 0 && this.f3243v <= i22 * 3 && i22 * 2 > this.f3241t * 3 ? this.f3240s : i2;
                        this.f3241t = i22;
                        this.f3240s = i2;
                        if (d2 > 1.0d) {
                            short[] sArr2 = this.f3231j;
                            if (f4 >= 2.0f) {
                                i4 = (int) (i23 / (f4 - f6));
                            } else {
                                this.f3239r = (int) (((2.0f - f4) * i23) / (f4 - f6));
                                i4 = i23;
                            }
                            short[] m1335c = m1335c(this.f3233l, this.f3234m, i4);
                            this.f3233l = m1335c;
                            int i24 = i4;
                            m1332e(i4, this.f3223b, m1335c, this.f3234m, sArr2, i12, sArr2, i12 + i23);
                            this.f3234m += i24;
                            i12 = i23 + i24 + i12;
                        } else {
                            int i25 = i23;
                            short[] sArr3 = this.f3231j;
                            if (f4 < 0.5f) {
                                i3 = (int) ((i25 * f4) / (f6 - f4));
                            } else {
                                this.f3239r = (int) ((((2.0f * f4) - f6) * i25) / (f6 - f4));
                                i3 = i25;
                            }
                            int i26 = i25 + i3;
                            short[] m1335c2 = m1335c(this.f3233l, this.f3234m, i26);
                            this.f3233l = m1335c2;
                            int i27 = this.f3223b;
                            System.arraycopy(sArr3, i12 * i27, m1335c2, this.f3234m * i27, i27 * i25);
                            m1332e(i3, this.f3223b, this.f3233l, this.f3234m + i25, sArr3, i12 + i25, sArr3, i12);
                            this.f3234m += i26;
                            i12 += i3;
                        }
                    }
                    if (this.f3229h + i12 > i11) {
                        break;
                    }
                    f6 = 1.0f;
                    i10 = 1;
                }
                int i28 = this.f3232k - i12;
                short[] sArr4 = this.f3231j;
                int i29 = this.f3223b;
                System.arraycopy(sArr4, i12 * i29, sArr4, 0, i29 * i28);
                this.f3232k = i28;
            }
            f6 = 1.0f;
        } else {
            m1333a(this.f3231j, 0, this.f3232k);
            this.f3232k = 0;
        }
        if (f5 == f6 || this.f3234m == i9) {
            return;
        }
        int i30 = this.f3222a;
        int i31 = (int) (i30 / f5);
        while (true) {
            if (i31 <= 16384 && i30 <= 16384) {
                break;
            }
            i31 /= 2;
            i30 /= 2;
        }
        int i32 = this.f3234m - i9;
        short[] m1335c3 = m1335c(this.f3235n, this.f3236o, i32);
        this.f3235n = m1335c3;
        short[] sArr5 = this.f3233l;
        int i33 = this.f3223b;
        System.arraycopy(sArr5, i9 * i33, m1335c3, this.f3236o * i33, i33 * i32);
        this.f3234m = i9;
        this.f3236o += i32;
        int i34 = 0;
        while (true) {
            i5 = this.f3236o;
            i6 = i5 - 1;
            if (i34 >= i6) {
                break;
            }
            while (true) {
                i7 = this.f3237p + 1;
                int i35 = i7 * i31;
                i8 = this.f3238q;
                if (i35 <= i8 * i30) {
                    break;
                }
                this.f3233l = m1335c(this.f3233l, this.f3234m, 1);
                int i36 = 0;
                while (true) {
                    int i37 = this.f3223b;
                    if (i36 < i37) {
                        short[] sArr6 = this.f3233l;
                        int i38 = (this.f3234m * i37) + i36;
                        short[] sArr7 = this.f3235n;
                        int i39 = (i34 * i37) + i36;
                        short s = sArr7[i39];
                        short s2 = sArr7[i39 + i37];
                        int i40 = this.f3238q * i30;
                        int i41 = this.f3237p;
                        int i42 = i41 * i31;
                        int i43 = (i41 + 1) * i31;
                        int i44 = i43 - i40;
                        int i45 = i43 - i42;
                        sArr6[i38] = (short) ((((i45 - i44) * s2) + (s * i44)) / i45);
                        i36++;
                    }
                }
                this.f3238q++;
                this.f3234m++;
            }
            this.f3237p = i7;
            if (i7 == i30) {
                this.f3237p = 0;
                C4195m.m4771I(i8 == i31);
                this.f3238q = 0;
            }
            i34++;
        }
        if (i6 == 0) {
            return;
        }
        short[] sArr8 = this.f3235n;
        int i46 = this.f3223b;
        System.arraycopy(sArr8, i6 * i46, sArr8, 0, (i5 - i6) * i46);
        this.f3236o -= i6;
    }
}
