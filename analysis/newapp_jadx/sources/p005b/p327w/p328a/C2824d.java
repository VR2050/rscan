package p005b.p327w.p328a;

import java.util.Objects;
import p005b.p113c0.p114a.p116h.InterfaceC1429e;
import p005b.p113c0.p114a.p116h.p120j.AbstractC1439c;
import p005b.p113c0.p114a.p116h.p121k.C1443a;
import p005b.p113c0.p114a.p116h.p121k.C1444b;
import p005b.p113c0.p114a.p116h.p122l.C1448b;
import p005b.p113c0.p114a.p116h.p122l.InterfaceC1449c;
import p005b.p113c0.p114a.p124i.EnumC1456b;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p124i.p126o.InterfaceC1473c;

/* renamed from: b.w.a.d */
/* loaded from: classes2.dex */
public final class C2824d extends AbstractC1439c {

    /* renamed from: g */
    public Object f7668g;

    public C2824d(Object obj, C1444b c1444b, C1443a c1443a) {
        super(obj, c1444b, c1443a);
        this.f7668g = obj;
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.AbstractC1439c
    /* renamed from: b */
    public InterfaceC1449c mo504b(InterfaceC1457c interfaceC1457c, InterfaceC1458d interfaceC1458d) {
        String path = interfaceC1457c.getPath();
        EnumC1456b mo523d = interfaceC1457c.mo523d();
        Object mo518a = interfaceC1457c.mo518a("http.message.converter");
        if (mo518a != null && (mo518a instanceof InterfaceC1429e)) {
        }
        if (interfaceC1457c instanceof InterfaceC1473c) {
        }
        if (mo523d.m521a()) {
            interfaceC1457c.mo526h();
        }
        m503a(path);
        Objects.requireNonNull((C2821a) this.f7668g);
        return new C1448b(true, "Test Ok");
    }
}
