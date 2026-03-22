package p005b.p199l.p266d.p282y.p283r.p284f.p285d;

import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.r.f.d.d */
/* loaded from: classes2.dex */
public final class C2599d extends AbstractC2603h {
    public C2599d(C2543a c2543a) {
        super(c2543a);
    }

    @Override // p005b.p199l.p266d.p282y.p283r.p284f.p285d.AbstractC2605j
    /* renamed from: a */
    public String mo3045a() {
        if (this.f7106a.f6892e < 48) {
            throw C2529k.f6843f;
        }
        StringBuilder sb = new StringBuilder();
        m3046b(sb, 8);
        int m3056c = this.f7107b.m3056c(48, 2);
        sb.append("(393");
        sb.append(m3056c);
        sb.append(')');
        int m3056c2 = this.f7107b.m3056c(50, 10);
        if (m3056c2 / 100 == 0) {
            sb.append('0');
        }
        if (m3056c2 / 10 == 0) {
            sb.append('0');
        }
        sb.append(m3056c2);
        sb.append(this.f7107b.m3055b(60, null).f7113b);
        return sb.toString();
    }
}
