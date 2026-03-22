package p476m.p477a.p485b.p494m0;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4793b0;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.C4902v;
import p476m.p477a.p485b.InterfaceC4846k;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4900t;

/* renamed from: m.a.b.m0.m */
/* loaded from: classes3.dex */
public class C4886m implements InterfaceC4900t {
    @Override // p476m.p477a.p485b.InterfaceC4900t
    /* renamed from: a */
    public void mo5554a(InterfaceC4898r interfaceC4898r, InterfaceC4877d interfaceC4877d) {
        C2354n.m2470e1(interfaceC4898r, "HTTP response");
        if (interfaceC4898r.mo5518m("Transfer-Encoding")) {
            throw new C4793b0("Transfer-encoding header already present");
        }
        if (interfaceC4898r.mo5518m("Content-Length")) {
            throw new C4793b0("Content-Length header already present");
        }
        C4795c0 mo5475a = interfaceC4898r.mo5528h().mo5475a();
        InterfaceC4846k mo5526b = interfaceC4898r.mo5526b();
        if (mo5526b == null) {
            int mo5476c = interfaceC4898r.mo5528h().mo5476c();
            if (mo5476c == 204 || mo5476c == 304 || mo5476c == 205) {
                return;
            }
            interfaceC4898r.mo5516j("Content-Length", "0");
            return;
        }
        long mo541c = mo5526b.mo541c();
        if (mo5526b.mo544g() && !mo5475a.m5470c(C4902v.f12500h)) {
            interfaceC4898r.mo5516j("Transfer-Encoding", "chunked");
        } else if (mo541c >= 0) {
            interfaceC4898r.mo5516j("Content-Length", Long.toString(mo5526b.mo541c()));
        }
        if (mo5526b.getContentType() != null && !interfaceC4898r.mo5518m("Content-Type")) {
            interfaceC4898r.mo5517l(mo5526b.getContentType());
        }
        if (mo5526b.mo543f() == null || interfaceC4898r.mo5518m("Content-Encoding")) {
            return;
        }
        interfaceC4898r.mo5517l(mo5526b.mo543f());
    }
}
