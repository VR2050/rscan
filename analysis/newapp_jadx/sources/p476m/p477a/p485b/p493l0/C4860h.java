package p476m.p477a.p485b.p493l0;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.InterfaceC4798e;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4801f0;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.l0.h */
/* loaded from: classes3.dex */
public class C4860h implements InterfaceC4869q {

    /* renamed from: a */
    public static final C4860h f12449a = new C4860h();

    /* renamed from: a */
    public C4893b m5530a(C4893b c4893b, C4795c0 c4795c0) {
        C2354n.m2470e1(c4795c0, "Protocol version");
        c4893b.m5561d(m5531b(c4795c0));
        c4893b.m5559b(c4795c0.f12279c);
        c4893b.m5558a('/');
        c4893b.m5559b(Integer.toString(c4795c0.f12280e));
        c4893b.m5558a('.');
        c4893b.m5559b(Integer.toString(c4795c0.f12281f));
        return c4893b;
    }

    /* renamed from: b */
    public int m5531b(C4795c0 c4795c0) {
        return c4795c0.f12279c.length() + 4;
    }

    /* renamed from: c */
    public C4893b m5532c(C4893b c4893b, InterfaceC4800f interfaceC4800f) {
        C2354n.m2470e1(interfaceC4800f, "Header");
        if (interfaceC4800f instanceof InterfaceC4798e) {
            return ((InterfaceC4798e) interfaceC4800f).getBuffer();
        }
        C4893b m5534e = m5534e(c4893b);
        String name = interfaceC4800f.getName();
        String value = interfaceC4800f.getValue();
        int length = name.length() + 2;
        if (value != null) {
            length += value.length();
        }
        m5534e.m5561d(length);
        m5534e.m5559b(name);
        m5534e.m5559b(": ");
        if (value == null) {
            return m5534e;
        }
        m5534e.m5561d(value.length() + m5534e.f12498e);
        for (int i2 = 0; i2 < value.length(); i2++) {
            char charAt = value.charAt(i2);
            if (charAt == '\r' || charAt == '\n' || charAt == '\f' || charAt == 11) {
                charAt = ' ';
            }
            m5534e.m5558a(charAt);
        }
        return m5534e;
    }

    /* renamed from: d */
    public C4893b m5533d(C4893b c4893b, InterfaceC4801f0 interfaceC4801f0) {
        C2354n.m2470e1(interfaceC4801f0, "Status line");
        C4893b m5534e = m5534e(c4893b);
        int m5531b = m5531b(interfaceC4801f0.mo5475a()) + 1 + 3 + 1;
        String mo5477d = interfaceC4801f0.mo5477d();
        if (mo5477d != null) {
            m5531b += mo5477d.length();
        }
        m5534e.m5561d(m5531b);
        m5530a(m5534e, interfaceC4801f0.mo5475a());
        m5534e.m5558a(' ');
        m5534e.m5559b(Integer.toString(interfaceC4801f0.mo5476c()));
        m5534e.m5558a(' ');
        if (mo5477d != null) {
            m5534e.m5559b(mo5477d);
        }
        return m5534e;
    }

    /* renamed from: e */
    public C4893b m5534e(C4893b c4893b) {
        if (c4893b == null) {
            return new C4893b(64);
        }
        c4893b.f12498e = 0;
        return c4893b;
    }
}
