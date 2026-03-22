package p476m.p477a.p485b.p494m0;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4900t;

/* renamed from: m.a.b.m0.o */
/* loaded from: classes3.dex */
public class C4888o implements InterfaceC4900t {

    /* renamed from: a */
    public final String f12492a;

    public C4888o(String str) {
        this.f12492a = str;
    }

    @Override // p476m.p477a.p485b.InterfaceC4900t
    /* renamed from: a */
    public void mo5554a(InterfaceC4898r interfaceC4898r, InterfaceC4877d interfaceC4877d) {
        String str;
        C2354n.m2470e1(interfaceC4898r, "HTTP response");
        if (interfaceC4898r.mo5518m("Server") || (str = this.f12492a) == null) {
            return;
        }
        interfaceC4898r.mo5516j("Server", str);
    }
}
