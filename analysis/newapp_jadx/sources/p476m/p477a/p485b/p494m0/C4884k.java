package p476m.p477a.p485b.p494m0;

import java.util.List;
import p476m.p477a.p485b.InterfaceC4895o;
import p476m.p477a.p485b.InterfaceC4897q;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.InterfaceC4900t;

/* renamed from: m.a.b.m0.k */
/* loaded from: classes3.dex */
public final class C4884k implements InterfaceC4881h {

    /* renamed from: a */
    public final InterfaceC4897q[] f12489a;

    /* renamed from: b */
    public final InterfaceC4900t[] f12490b;

    public C4884k(List<InterfaceC4897q> list, List<InterfaceC4900t> list2) {
        if (list != null) {
            this.f12489a = (InterfaceC4897q[]) list.toArray(new InterfaceC4897q[list.size()]);
        } else {
            this.f12489a = new InterfaceC4897q[0];
        }
        if (list2 != null) {
            this.f12490b = (InterfaceC4900t[]) list2.toArray(new InterfaceC4900t[list2.size()]);
        } else {
            this.f12490b = new InterfaceC4900t[0];
        }
    }

    @Override // p476m.p477a.p485b.InterfaceC4900t
    /* renamed from: a */
    public void mo5554a(InterfaceC4898r interfaceC4898r, InterfaceC4877d interfaceC4877d) {
        for (InterfaceC4900t interfaceC4900t : this.f12490b) {
            interfaceC4900t.mo5554a(interfaceC4898r, interfaceC4877d);
        }
    }

    @Override // p476m.p477a.p485b.InterfaceC4897q
    /* renamed from: b */
    public void mo5555b(InterfaceC4895o interfaceC4895o, InterfaceC4877d interfaceC4877d) {
        for (InterfaceC4897q interfaceC4897q : this.f12489a) {
            interfaceC4897q.mo5555b(interfaceC4895o, interfaceC4877d);
        }
    }
}
