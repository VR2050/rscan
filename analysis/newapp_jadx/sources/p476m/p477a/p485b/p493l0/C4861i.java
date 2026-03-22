package p476m.p477a.p485b.p493l0;

import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4791a0;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.C4902v;
import p476m.p477a.p485b.p494m0.C4876c;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.l0.i */
/* loaded from: classes3.dex */
public class C4861i implements InterfaceC4870r {

    /* renamed from: a */
    public static final C4861i f12450a;

    /* renamed from: b */
    public final C4795c0 f12451b = C4902v.f12501i;

    static {
        C4902v c4902v = C4902v.f12501i;
        f12450a = new C4861i();
    }

    /* renamed from: a */
    public C4795c0 m5535a(C4893b c4893b, C4871s c4871s) {
        C2354n.m2470e1(c4893b, "Char array buffer");
        C2354n.m2470e1(c4871s, "Parser cursor");
        String str = this.f12451b.f12279c;
        int length = str.length();
        int i2 = c4871s.f12474b;
        int i3 = c4871s.f12473a;
        m5536b(c4893b, c4871s);
        int i4 = c4871s.f12474b;
        int i5 = i4 + length;
        if (i5 + 4 > i3) {
            StringBuilder m586H = C1499a.m586H("Not a valid protocol version: ");
            m586H.append(c4893b.m5564g(i2, i3));
            throw new C4791a0(m586H.toString());
        }
        boolean z = true;
        for (int i6 = 0; z && i6 < length; i6++) {
            z = c4893b.f12497c[i4 + i6] == str.charAt(i6);
        }
        if (z) {
            z = c4893b.f12497c[i5] == '/';
        }
        if (!z) {
            StringBuilder m586H2 = C1499a.m586H("Not a valid protocol version: ");
            m586H2.append(c4893b.m5564g(i2, i3));
            throw new C4791a0(m586H2.toString());
        }
        int i7 = length + 1 + i4;
        int m5563f = c4893b.m5563f(46, i7, i3);
        if (m5563f == -1) {
            StringBuilder m586H3 = C1499a.m586H("Invalid protocol version number: ");
            m586H3.append(c4893b.m5564g(i2, i3));
            throw new C4791a0(m586H3.toString());
        }
        try {
            int parseInt = Integer.parseInt(c4893b.m5565h(i7, m5563f));
            int i8 = m5563f + 1;
            int m5563f2 = c4893b.m5563f(32, i8, i3);
            if (m5563f2 == -1) {
                m5563f2 = i3;
            }
            try {
                int parseInt2 = Integer.parseInt(c4893b.m5565h(i8, m5563f2));
                c4871s.m5542b(m5563f2);
                return this.f12451b.mo5469a(parseInt, parseInt2);
            } catch (NumberFormatException unused) {
                StringBuilder m586H4 = C1499a.m586H("Invalid protocol minor version number: ");
                m586H4.append(c4893b.m5564g(i2, i3));
                throw new C4791a0(m586H4.toString());
            }
        } catch (NumberFormatException unused2) {
            StringBuilder m586H5 = C1499a.m586H("Invalid protocol major version number: ");
            m586H5.append(c4893b.m5564g(i2, i3));
            throw new C4791a0(m586H5.toString());
        }
    }

    /* renamed from: b */
    public void m5536b(C4893b c4893b, C4871s c4871s) {
        int i2 = c4871s.f12474b;
        int i3 = c4871s.f12473a;
        while (i2 < i3 && C4876c.m5549a(c4893b.f12497c[i2])) {
            i2++;
        }
        c4871s.m5542b(i2);
    }
}
