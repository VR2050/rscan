package p005b.p199l.p266d.p274v;

import p005b.p199l.p266d.AbstractC2520b;
import p005b.p199l.p266d.AbstractC2527i;
import p005b.p199l.p266d.C2529k;

/* renamed from: b.l.d.v.h */
/* loaded from: classes2.dex */
public class C2550h extends AbstractC2520b {

    /* renamed from: b */
    public static final byte[] f6943b = new byte[0];

    /* renamed from: c */
    public byte[] f6944c;

    /* renamed from: d */
    public final int[] f6945d;

    public C2550h(AbstractC2527i abstractC2527i) {
        super(abstractC2527i);
        this.f6944c = f6943b;
        this.f6945d = new int[32];
    }

    /* renamed from: c */
    public static int m2968c(int[] iArr) {
        int length = iArr.length;
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < length; i5++) {
            if (iArr[i5] > i2) {
                i2 = iArr[i5];
                i4 = i5;
            }
            if (iArr[i5] > i3) {
                i3 = iArr[i5];
            }
        }
        int i6 = 0;
        int i7 = 0;
        for (int i8 = 0; i8 < length; i8++) {
            int i9 = i8 - i4;
            int i10 = iArr[i8] * i9 * i9;
            if (i10 > i7) {
                i6 = i8;
                i7 = i10;
            }
        }
        if (i4 <= i6) {
            int i11 = i4;
            i4 = i6;
            i6 = i11;
        }
        if (i4 - i6 <= length / 16) {
            throw C2529k.f6843f;
        }
        int i12 = i4 - 1;
        int i13 = i12;
        int i14 = -1;
        while (i12 > i6) {
            int i15 = i12 - i6;
            int i16 = (i3 - iArr[i12]) * (i4 - i12) * i15 * i15;
            if (i16 > i14) {
                i13 = i12;
                i14 = i16;
            }
            i12--;
        }
        return i13 << 3;
    }

    @Override // p005b.p199l.p266d.AbstractC2520b
    /* renamed from: a */
    public AbstractC2520b mo2920a(AbstractC2527i abstractC2527i) {
        return new C2550h(abstractC2527i);
    }

    @Override // p005b.p199l.p266d.AbstractC2520b
    /* renamed from: b */
    public C2544b mo2921b() {
        AbstractC2527i abstractC2527i = this.f6807a;
        int i2 = abstractC2527i.f6838a;
        int i3 = abstractC2527i.f6839b;
        C2544b c2544b = new C2544b(i2, i3);
        m2969d(i2);
        int[] iArr = this.f6945d;
        for (int i4 = 1; i4 < 5; i4++) {
            byte[] mo2927b = abstractC2527i.mo2927b((i3 * i4) / 5, this.f6944c);
            int i5 = (i2 << 2) / 5;
            for (int i6 = i2 / 5; i6 < i5; i6++) {
                int i7 = (mo2927b[i6] & 255) >> 3;
                iArr[i7] = iArr[i7] + 1;
            }
        }
        int m2968c = m2968c(iArr);
        byte[] mo2926a = abstractC2527i.mo2926a();
        for (int i8 = 0; i8 < i3; i8++) {
            int i9 = i8 * i2;
            for (int i10 = 0; i10 < i2; i10++) {
                if ((mo2926a[i9 + i10] & 255) < m2968c) {
                    c2544b.m2962h(i10, i8);
                }
            }
        }
        return c2544b;
    }

    /* renamed from: d */
    public final void m2969d(int i2) {
        if (this.f6944c.length < i2) {
            this.f6944c = new byte[i2];
        }
        for (int i3 = 0; i3 < 32; i3++) {
            this.f6945d[i3] = 0;
        }
    }
}
