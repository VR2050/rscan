package p476m.p477a.p485b.p493l0;

import java.io.Serializable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.InterfaceC4799e0;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.l0.l */
/* loaded from: classes3.dex */
public class C4864l implements InterfaceC4799e0, Cloneable, Serializable {
    private static final long serialVersionUID = 2810581718468737193L;

    /* renamed from: c */
    public final C4795c0 f12458c;

    /* renamed from: e */
    public final String f12459e;

    /* renamed from: f */
    public final String f12460f;

    public C4864l(String str, String str2, C4795c0 c4795c0) {
        C2354n.m2470e1(str, "Method");
        this.f12459e = str;
        C2354n.m2470e1(str2, "URI");
        this.f12460f = str2;
        C2354n.m2470e1(c4795c0, "Version");
        this.f12458c = c4795c0;
    }

    @Override // p476m.p477a.p485b.InterfaceC4799e0
    /* renamed from: a */
    public C4795c0 mo5473a() {
        return this.f12458c;
    }

    public Object clone() {
        return super.clone();
    }

    @Override // p476m.p477a.p485b.InterfaceC4799e0
    /* renamed from: d */
    public String mo5474d() {
        return this.f12459e;
    }

    @Override // p476m.p477a.p485b.InterfaceC4799e0
    public String getUri() {
        return this.f12460f;
    }

    public String toString() {
        C2354n.m2470e1(this, "Request line");
        C4893b c4893b = new C4893b(64);
        String mo5474d = mo5474d();
        String uri = getUri();
        c4893b.m5561d(mo5473a().f12279c.length() + 4 + uri.length() + mo5474d.length() + 1 + 1);
        c4893b.m5559b(mo5474d);
        c4893b.m5558a(' ');
        c4893b.m5559b(uri);
        c4893b.m5558a(' ');
        C4795c0 mo5473a = mo5473a();
        C2354n.m2470e1(mo5473a, "Protocol version");
        c4893b.m5561d(mo5473a.f12279c.length() + 4);
        c4893b.m5559b(mo5473a.f12279c);
        c4893b.m5558a('/');
        c4893b.m5559b(Integer.toString(mo5473a.f12280e));
        c4893b.m5558a('.');
        c4893b.m5559b(Integer.toString(mo5473a.f12281f));
        return c4893b.toString();
    }
}
