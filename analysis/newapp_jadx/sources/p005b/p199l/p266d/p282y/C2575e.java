package p005b.p199l.p266d.p282y;

import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.e */
/* loaded from: classes2.dex */
public final class C2575e extends AbstractC2586p {

    /* renamed from: h */
    public static final int[] f7033h = {0, 11, 13, 14, 19, 25, 28, 21, 22, 26};

    /* renamed from: i */
    public final int[] f7034i = new int[4];

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: j */
    public int mo3006j(C2543a c2543a, int[] iArr, StringBuilder sb) {
        int[] iArr2 = this.f7034i;
        iArr2[0] = 0;
        iArr2[1] = 0;
        iArr2[2] = 0;
        iArr2[3] = 0;
        int i2 = c2543a.f6892e;
        int i3 = iArr[1];
        int i4 = 0;
        for (int i5 = 0; i5 < 6 && i3 < i2; i5++) {
            int m3021h = AbstractC2586p.m3021h(c2543a, iArr2, i3, AbstractC2586p.f7059d);
            sb.append((char) ((m3021h % 10) + 48));
            for (int i6 : iArr2) {
                i3 += i6;
            }
            if (m3021h >= 10) {
                i4 |= 1 << (5 - i5);
            }
        }
        for (int i7 = 0; i7 < 10; i7++) {
            if (i4 == f7033h[i7]) {
                sb.insert(0, (char) (i7 + 48));
                int[] iArr3 = AbstractC2586p.f7057b;
                int i8 = AbstractC2586p.m3022l(c2543a, i3, true, iArr3, new int[iArr3.length])[1];
                for (int i9 = 0; i9 < 6 && i8 < i2; i9++) {
                    sb.append((char) (AbstractC2586p.m3021h(c2543a, iArr2, i8, AbstractC2586p.f7058c) + 48));
                    for (int i10 : iArr2) {
                        i8 += i10;
                    }
                }
                return i8;
            }
        }
        throw C2529k.f6843f;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: n */
    public EnumC2497a mo3007n() {
        return EnumC2497a.EAN_13;
    }
}
