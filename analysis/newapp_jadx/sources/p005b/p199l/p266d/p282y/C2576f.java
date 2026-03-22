package p005b.p199l.p266d.p282y;

import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.f */
/* loaded from: classes2.dex */
public final class C2576f extends AbstractC2586p {

    /* renamed from: h */
    public final int[] f7035h = new int[4];

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: j */
    public int mo3006j(C2543a c2543a, int[] iArr, StringBuilder sb) {
        int[] iArr2 = this.f7035h;
        iArr2[0] = 0;
        iArr2[1] = 0;
        iArr2[2] = 0;
        iArr2[3] = 0;
        int i2 = c2543a.f6892e;
        int i3 = iArr[1];
        for (int i4 = 0; i4 < 4 && i3 < i2; i4++) {
            sb.append((char) (AbstractC2586p.m3021h(c2543a, iArr2, i3, AbstractC2586p.f7058c) + 48));
            for (int i5 : iArr2) {
                i3 += i5;
            }
        }
        int[] iArr3 = AbstractC2586p.f7057b;
        int i6 = AbstractC2586p.m3022l(c2543a, i3, true, iArr3, new int[iArr3.length])[1];
        for (int i7 = 0; i7 < 4 && i6 < i2; i7++) {
            sb.append((char) (AbstractC2586p.m3021h(c2543a, iArr2, i6, AbstractC2586p.f7058c) + 48));
            for (int i8 : iArr2) {
                i6 += i8;
            }
        }
        return i6;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: n */
    public EnumC2497a mo3007n() {
        return EnumC2497a.EAN_8;
    }
}
