package p005b.p199l.p266d.p282y;

import java.util.EnumMap;
import p005b.p199l.p266d.AbstractC2533o;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2535q;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.o */
/* loaded from: classes2.dex */
public final class C2585o {

    /* renamed from: a */
    public static final int[] f7053a = {1, 1, 2};

    /* renamed from: b */
    public final C2583m f7054b = new C2583m();

    /* renamed from: c */
    public final C2584n f7055c = new C2584n();

    /* renamed from: a */
    public C2534p m3020a(int i2, C2543a c2543a, int i3) {
        EnumMap enumMap;
        int[] iArr = f7053a;
        int[] m3022l = AbstractC2586p.m3022l(c2543a, i3, false, iArr, new int[iArr.length]);
        try {
            return this.f7055c.m3019a(i2, c2543a, m3022l);
        } catch (AbstractC2533o unused) {
            C2583m c2583m = this.f7054b;
            StringBuilder sb = c2583m.f7049b;
            sb.setLength(0);
            int[] iArr2 = c2583m.f7048a;
            iArr2[0] = 0;
            iArr2[1] = 0;
            iArr2[2] = 0;
            iArr2[3] = 0;
            int i4 = c2543a.f6892e;
            int i5 = m3022l[1];
            int i6 = 0;
            for (int i7 = 0; i7 < 2 && i5 < i4; i7++) {
                int m3021h = AbstractC2586p.m3021h(c2543a, iArr2, i5, AbstractC2586p.f7059d);
                sb.append((char) ((m3021h % 10) + 48));
                for (int i8 : iArr2) {
                    i5 += i8;
                }
                if (m3021h >= 10) {
                    i6 |= 1 << (1 - i7);
                }
                if (i7 != 1) {
                    i5 = c2543a.m2952i(c2543a.m2951h(i5));
                }
            }
            if (sb.length() != 2) {
                throw C2529k.f6843f;
            }
            if (Integer.parseInt(sb.toString()) % 4 != i6) {
                throw C2529k.f6843f;
            }
            String sb2 = sb.toString();
            if (sb2.length() != 2) {
                enumMap = null;
            } else {
                enumMap = new EnumMap(EnumC2535q.class);
                enumMap.put((EnumMap) EnumC2535q.ISSUE_NUMBER, (EnumC2535q) Integer.valueOf(sb2));
            }
            float f2 = i2;
            C2534p c2534p = new C2534p(sb2, null, new C2536r[]{new C2536r((m3022l[0] + m3022l[1]) / 2.0f, f2), new C2536r(i5, f2)}, EnumC2497a.UPC_EAN_EXTENSION);
            if (enumMap != null) {
                c2534p.m2932a(enumMap);
            }
            return c2534p;
        }
    }
}
