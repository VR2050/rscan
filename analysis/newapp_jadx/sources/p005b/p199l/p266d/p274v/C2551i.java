package p005b.p199l.p266d.p274v;

import java.lang.reflect.Array;
import p005b.p199l.p266d.AbstractC2520b;
import p005b.p199l.p266d.AbstractC2527i;

/* renamed from: b.l.d.v.i */
/* loaded from: classes2.dex */
public final class C2551i extends C2550h {

    /* renamed from: e */
    public C2544b f6946e;

    public C2551i(AbstractC2527i abstractC2527i) {
        super(abstractC2527i);
    }

    @Override // p005b.p199l.p266d.p274v.C2550h, p005b.p199l.p266d.AbstractC2520b
    /* renamed from: a */
    public AbstractC2520b mo2920a(AbstractC2527i abstractC2527i) {
        return new C2551i(abstractC2527i);
    }

    @Override // p005b.p199l.p266d.p274v.C2550h, p005b.p199l.p266d.AbstractC2520b
    /* renamed from: b */
    public C2544b mo2921b() {
        int i2;
        int i3;
        int i4;
        int i5;
        C2544b c2544b = this.f6946e;
        if (c2544b != null) {
            return c2544b;
        }
        AbstractC2527i abstractC2527i = this.f6807a;
        int i6 = abstractC2527i.f6838a;
        int i7 = abstractC2527i.f6839b;
        if (i6 < 40 || i7 < 40) {
            this.f6946e = super.mo2921b();
        } else {
            byte[] mo2926a = abstractC2527i.mo2926a();
            int i8 = i6 >> 3;
            if ((i6 & 7) != 0) {
                i8++;
            }
            int i9 = i7 >> 3;
            if ((i7 & 7) != 0) {
                i9++;
            }
            int i10 = i7 - 8;
            int i11 = i6 - 8;
            int i12 = 0;
            int[][] iArr = (int[][]) Array.newInstance((Class<?>) int.class, i9, i8);
            int i13 = 0;
            while (true) {
                int i14 = 8;
                if (i13 >= i9) {
                    break;
                }
                int i15 = i13 << 3;
                if (i15 > i10) {
                    i15 = i10;
                }
                while (i12 < i8) {
                    int i16 = i12 << 3;
                    if (i16 > i11) {
                        i16 = i11;
                    }
                    int i17 = (i15 * i6) + i16;
                    int i18 = 0;
                    int i19 = 0;
                    int i20 = 0;
                    int i21 = 255;
                    while (i18 < i14) {
                        int i22 = i20;
                        int i23 = i21;
                        int i24 = 0;
                        while (i24 < i14) {
                            int i25 = i18;
                            int i26 = mo2926a[i17 + i24] & 255;
                            i19 += i26;
                            int i27 = i23;
                            i23 = i26 < i27 ? i26 : i27;
                            if (i26 > i22) {
                                i22 = i26;
                            }
                            i24++;
                            i18 = i25;
                            i14 = 8;
                        }
                        int i28 = i18;
                        int i29 = i23;
                        if (i22 - i29 > 24) {
                            while (true) {
                                i5 = i28 + 1;
                                i17 += i6;
                                i2 = i29;
                                if (i5 >= 8) {
                                    break;
                                }
                                int i30 = 0;
                                for (int i31 = 8; i30 < i31; i31 = 8) {
                                    i19 += mo2926a[i17 + i30] & 255;
                                    i30++;
                                    i22 = i22;
                                }
                                i28 = i5;
                                i29 = i2;
                            }
                            i3 = i22;
                            i4 = i5;
                        } else {
                            i2 = i29;
                            i3 = i22;
                            i4 = i28;
                        }
                        i18 = i4 + 1;
                        i17 += i6;
                        i14 = 8;
                        int i32 = i3;
                        i21 = i2;
                        i20 = i32;
                    }
                    int i33 = i19 >> 6;
                    int i34 = i21;
                    if (i20 - i34 <= 24) {
                        i33 = i34 / 2;
                        if (i13 > 0 && i12 > 0) {
                            int i35 = i13 - 1;
                            int i36 = i12 - 1;
                            int i37 = (((iArr[i13][i36] * 2) + iArr[i35][i12]) + iArr[i35][i36]) / 4;
                            if (i34 < i37) {
                                i33 = i37;
                            }
                        }
                    }
                    iArr[i13][i12] = i33;
                    i12++;
                    i14 = 8;
                }
                i13++;
                i12 = 0;
            }
            C2544b c2544b2 = new C2544b(i6, i7);
            for (int i38 = 0; i38 < i9; i38++) {
                int i39 = i38 << 3;
                if (i39 > i10) {
                    i39 = i10;
                }
                int i40 = i9 - 3;
                if (i38 < 2) {
                    i40 = 2;
                } else if (i38 <= i40) {
                    i40 = i38;
                }
                int i41 = 0;
                while (i41 < i8) {
                    int i42 = i41 << 3;
                    if (i42 > i11) {
                        i42 = i11;
                    }
                    int i43 = i8 - 3;
                    if (i41 < 2) {
                        i43 = 2;
                    } else if (i41 <= i43) {
                        i43 = i41;
                    }
                    int i44 = i8;
                    int i45 = -2;
                    int i46 = 0;
                    for (int i47 = 2; i45 <= i47; i47 = 2) {
                        int[] iArr2 = iArr[i40 + i45];
                        i46 = iArr2[i43 - 2] + iArr2[i43 - 1] + iArr2[i43] + iArr2[i43 + 1] + iArr2[i43 + 2] + i46;
                        i45++;
                    }
                    int i48 = i46 / 25;
                    int i49 = (i39 * i6) + i42;
                    int i50 = i9;
                    int i51 = 8;
                    int i52 = 0;
                    while (i52 < i51) {
                        int i53 = i10;
                        int i54 = 0;
                        while (i54 < i51) {
                            byte[] bArr = mo2926a;
                            if ((mo2926a[i49 + i54] & 255) <= i48) {
                                c2544b2.m2962h(i42 + i54, i39 + i52);
                            }
                            i54++;
                            mo2926a = bArr;
                            i51 = 8;
                        }
                        i52++;
                        i49 += i6;
                        i10 = i53;
                        i51 = 8;
                    }
                    i41++;
                    i8 = i44;
                    i9 = i50;
                }
            }
            this.f6946e = c2544b2;
        }
        return this.f6946e;
    }
}
