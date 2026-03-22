package p005b.p327w.p328a;

import java.util.LinkedHashMap;
import java.util.Map;
import p005b.p113c0.p114a.p116h.p120j.AbstractC1438b;
import p005b.p113c0.p114a.p116h.p120j.InterfaceC1442f;
import p005b.p113c0.p114a.p116h.p121k.C1443a;
import p005b.p113c0.p114a.p116h.p121k.C1444b;
import p005b.p113c0.p114a.p116h.p121k.C1445c;
import p005b.p113c0.p114a.p116h.p121k.C1446d;
import p005b.p113c0.p114a.p124i.EnumC1456b;

/* renamed from: b.w.a.b */
/* loaded from: classes2.dex */
public final class C2822b extends AbstractC1438b {

    /* renamed from: e */
    public C2821a f7665e = new C2821a();

    /* renamed from: f */
    public Map<C1444b, InterfaceC1442f> f7666f = new LinkedHashMap();

    public C2822b() {
        C1444b c1444b = new C1444b();
        C1446d c1446d = new C1446d();
        c1446d.m510a("/videos");
        c1446d.m510a("/videos/");
        c1444b.f1396a = c1446d;
        C1445c c1445c = new C1445c();
        c1445c.f1398a.add(EnumC1456b.m520b("GET"));
        c1444b.f1397b = c1445c;
        this.f7666f.put(c1444b, new C2823c(this.f7665e, c1444b, new C1443a()));
        C1444b c1444b2 = new C1444b();
        C1446d c1446d2 = new C1446d();
        c1446d2.m510a("/videos/test/");
        c1446d2.m510a("/videos/test");
        c1444b2.f1396a = c1446d2;
        C1445c c1445c2 = new C1445c();
        c1445c2.f1398a.add(EnumC1456b.m520b("GET"));
        c1444b2.f1397b = c1445c2;
        this.f7666f.put(c1444b2, new C2824d(this.f7665e, c1444b2, new C1443a()));
    }
}
