package p005b.p199l.p266d.p282y.p283r.p284f.p285d;

import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.r.f.d.h */
/* loaded from: classes2.dex */
public abstract class AbstractC2603h extends AbstractC2605j {
    public AbstractC2603h(C2543a c2543a) {
        super(c2543a);
    }

    /* renamed from: b */
    public final void m3046b(StringBuilder sb, int i2) {
        sb.append("(01)");
        int length = sb.length();
        sb.append('9');
        m3047c(sb, i2, length);
    }

    /* renamed from: c */
    public final void m3047c(StringBuilder sb, int i2, int i3) {
        for (int i4 = 0; i4 < 4; i4++) {
            int m3056c = this.f7107b.m3056c((i4 * 10) + i2, 10);
            if (m3056c / 100 == 0) {
                sb.append('0');
            }
            if (m3056c / 10 == 0) {
                sb.append('0');
            }
            sb.append(m3056c);
        }
        int i5 = 0;
        for (int i6 = 0; i6 < 13; i6++) {
            int charAt = sb.charAt(i6 + i3) - '0';
            if ((i6 & 1) == 0) {
                charAt *= 3;
            }
            i5 += charAt;
        }
        int i7 = 10 - (i5 % 10);
        sb.append(i7 != 10 ? i7 : 0);
    }
}
