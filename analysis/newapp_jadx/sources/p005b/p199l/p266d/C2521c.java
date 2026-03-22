package p005b.p199l.p266d;

import p005b.p199l.p266d.p274v.C2543a;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p199l.p266d.p274v.C2550h;

/* renamed from: b.l.d.c */
/* loaded from: classes2.dex */
public final class C2521c {

    /* renamed from: a */
    public final AbstractC2520b f6808a;

    /* renamed from: b */
    public C2544b f6809b;

    public C2521c(AbstractC2520b abstractC2520b) {
        if (abstractC2520b == null) {
            throw new IllegalArgumentException("Binarizer must be non-null.");
        }
        this.f6808a = abstractC2520b;
    }

    /* renamed from: a */
    public C2544b m2922a() {
        if (this.f6809b == null) {
            this.f6809b = this.f6808a.mo2921b();
        }
        return this.f6809b;
    }

    /* renamed from: b */
    public C2543a m2923b(int i2, C2543a c2543a) {
        int i3;
        C2550h c2550h = (C2550h) this.f6808a;
        AbstractC2527i abstractC2527i = c2550h.f6807a;
        int i4 = abstractC2527i.f6838a;
        if (c2543a.f6892e < i4) {
            c2543a = new C2543a(i4);
        } else {
            int length = c2543a.f6891c.length;
            for (int i5 = 0; i5 < length; i5++) {
                c2543a.f6891c[i5] = 0;
            }
        }
        c2550h.m2969d(i4);
        byte[] mo2927b = abstractC2527i.mo2927b(i2, c2550h.f6944c);
        int[] iArr = c2550h.f6945d;
        int i6 = 0;
        while (true) {
            i3 = 1;
            if (i6 >= i4) {
                break;
            }
            int i7 = (mo2927b[i6] & 255) >> 3;
            iArr[i7] = iArr[i7] + 1;
            i6++;
        }
        int m2968c = C2550h.m2968c(iArr);
        if (i4 < 3) {
            for (int i8 = 0; i8 < i4; i8++) {
                if ((mo2927b[i8] & 255) < m2968c) {
                    c2543a.m2956n(i8);
                }
            }
        } else {
            int i9 = mo2927b[0] & 255;
            int i10 = mo2927b[1] & 255;
            while (i3 < i4 - 1) {
                int i11 = i3 + 1;
                int i12 = mo2927b[i11] & 255;
                if ((((i10 << 2) - i9) - i12) / 2 < m2968c) {
                    c2543a.m2956n(i3);
                }
                i9 = i10;
                i3 = i11;
                i10 = i12;
            }
        }
        return c2543a;
    }

    public String toString() {
        try {
            return m2922a().toString();
        } catch (C2529k unused) {
            return "";
        }
    }
}
