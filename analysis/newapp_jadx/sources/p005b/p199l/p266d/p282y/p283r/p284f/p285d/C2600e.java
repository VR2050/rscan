package p005b.p199l.p266d.p282y.p283r.p284f.p285d;

import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.r.f.d.e */
/* loaded from: classes2.dex */
public final class C2600e extends AbstractC2604i {

    /* renamed from: c */
    public final String f7104c;

    /* renamed from: d */
    public final String f7105d;

    public C2600e(C2543a c2543a, String str, String str2) {
        super(c2543a);
        this.f7104c = str2;
        this.f7105d = str;
    }

    @Override // p005b.p199l.p266d.p282y.p283r.p284f.p285d.AbstractC2605j
    /* renamed from: a */
    public String mo3045a() {
        if (this.f7106a.f6892e != 84) {
            throw C2529k.f6843f;
        }
        StringBuilder sb = new StringBuilder();
        m3046b(sb, 8);
        m3048f(sb, 48, 20);
        int m3053d = C2614s.m3053d(this.f7107b.f7124a, 68, 16);
        if (m3053d != 38400) {
            sb.append('(');
            sb.append(this.f7104c);
            sb.append(')');
            int i2 = m3053d % 32;
            int i3 = m3053d / 32;
            int i4 = (i3 % 12) + 1;
            int i5 = i3 / 12;
            if (i5 / 10 == 0) {
                sb.append('0');
            }
            sb.append(i5);
            if (i4 / 10 == 0) {
                sb.append('0');
            }
            sb.append(i4);
            if (i2 / 10 == 0) {
                sb.append('0');
            }
            sb.append(i2);
        }
        return sb.toString();
    }

    @Override // p005b.p199l.p266d.p282y.p283r.p284f.p285d.AbstractC2604i
    /* renamed from: d */
    public void mo3043d(StringBuilder sb, int i2) {
        sb.append('(');
        sb.append(this.f7105d);
        sb.append(i2 / 100000);
        sb.append(')');
    }

    @Override // p005b.p199l.p266d.p282y.p283r.p284f.p285d.AbstractC2604i
    /* renamed from: e */
    public int mo3044e(int i2) {
        return i2 % 100000;
    }
}
