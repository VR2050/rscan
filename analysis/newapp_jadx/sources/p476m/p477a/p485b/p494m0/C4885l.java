package p476m.p477a.p485b.p494m0;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.C4902v;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4846k;
import p476m.p477a.p485b.InterfaceC4895o;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4900t;

/* renamed from: m.a.b.m0.l */
/* loaded from: classes3.dex */
public class C4885l implements InterfaceC4900t {
    @Override // p476m.p477a.p485b.InterfaceC4900t
    /* renamed from: a */
    public void mo5554a(InterfaceC4898r interfaceC4898r, InterfaceC4877d interfaceC4877d) {
        C2354n.m2470e1(interfaceC4898r, "HTTP response");
        C2354n.m2470e1(interfaceC4877d, "HTTP context");
        C4878e c4878e = interfaceC4877d instanceof C4878e ? (C4878e) interfaceC4877d : new C4878e(interfaceC4877d);
        int mo5476c = interfaceC4898r.mo5528h().mo5476c();
        if (mo5476c == 400 || mo5476c == 408 || mo5476c == 411 || mo5476c == 413 || mo5476c == 414 || mo5476c == 503 || mo5476c == 501) {
            interfaceC4898r.mo5520o("Connection", "Close");
            return;
        }
        InterfaceC4800f mo5519n = interfaceC4898r.mo5519n("Connection");
        if (mo5519n == null || !"Close".equalsIgnoreCase(mo5519n.getValue())) {
            InterfaceC4846k mo5526b = interfaceC4898r.mo5526b();
            if (mo5526b != null) {
                C4795c0 mo5475a = interfaceC4898r.mo5528h().mo5475a();
                if (mo5526b.mo541c() < 0 && (!mo5526b.mo544g() || mo5475a.m5470c(C4902v.f12500h))) {
                    interfaceC4898r.mo5520o("Connection", "Close");
                    return;
                }
            }
            C2354n.m2470e1(InterfaceC4895o.class, "Attribute class");
            Object mo5545a = c4878e.f12479a.mo5545a("http.request");
            InterfaceC4895o interfaceC4895o = (InterfaceC4895o) (mo5545a == null ? null : InterfaceC4895o.class.cast(mo5545a));
            if (interfaceC4895o != null) {
                InterfaceC4800f mo5519n2 = interfaceC4895o.mo5519n("Connection");
                if (mo5519n2 != null) {
                    interfaceC4898r.mo5520o("Connection", mo5519n2.getValue());
                } else if (interfaceC4895o.mo5524a().m5470c(C4902v.f12500h)) {
                    interfaceC4898r.mo5520o("Connection", "Close");
                }
            }
        }
    }
}
