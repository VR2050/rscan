package p005b.p199l.p266d.p282y.p283r.p284f.p285d;

import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.r.f.d.i */
/* loaded from: classes2.dex */
public abstract class AbstractC2604i extends AbstractC2603h {
    public AbstractC2604i(C2543a c2543a) {
        super(c2543a);
    }

    /* renamed from: d */
    public abstract void mo3043d(StringBuilder sb, int i2);

    /* renamed from: e */
    public abstract int mo3044e(int i2);

    /* renamed from: f */
    public final void m3048f(StringBuilder sb, int i2, int i3) {
        int m3053d = C2614s.m3053d(this.f7107b.f7124a, i2, i3);
        mo3043d(sb, m3053d);
        int mo3044e = mo3044e(m3053d);
        int i4 = 100000;
        for (int i5 = 0; i5 < 5; i5++) {
            if (mo3044e / i4 == 0) {
                sb.append('0');
            }
            i4 /= 10;
        }
        sb.append(mo3044e);
    }
}
