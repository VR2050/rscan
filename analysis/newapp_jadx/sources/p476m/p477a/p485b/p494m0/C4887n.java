package p476m.p477a.p485b.p494m0;

import java.util.Date;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4900t;

/* renamed from: m.a.b.m0.n */
/* loaded from: classes3.dex */
public class C4887n implements InterfaceC4900t {

    /* renamed from: a */
    public static final C4879f f12491a = new C4879f();

    @Override // p476m.p477a.p485b.InterfaceC4900t
    /* renamed from: a */
    public void mo5554a(InterfaceC4898r interfaceC4898r, InterfaceC4877d interfaceC4877d) {
        String str;
        C2354n.m2470e1(interfaceC4898r, "HTTP response");
        if (interfaceC4898r.mo5528h().mo5476c() < 200 || interfaceC4898r.mo5518m("Date")) {
            return;
        }
        C4879f c4879f = f12491a;
        synchronized (c4879f) {
            long currentTimeMillis = System.currentTimeMillis();
            if (currentTimeMillis - c4879f.f12482c > 1000) {
                c4879f.f12483d = c4879f.f12481b.format(new Date(currentTimeMillis));
                c4879f.f12482c = currentTimeMillis;
            }
            str = c4879f.f12483d;
        }
        interfaceC4898r.mo5520o("Date", str);
    }
}
