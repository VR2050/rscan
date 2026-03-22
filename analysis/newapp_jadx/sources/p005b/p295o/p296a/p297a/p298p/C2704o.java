package p005b.p295o.p296a.p297a.p298p;

import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.o */
/* loaded from: classes2.dex */
public class C2704o extends AbstractC2703n {

    /* renamed from: a */
    public static final C2704o f7366a = new C2704o();

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: a */
    public void mo3228a(InterfaceC2715z interfaceC2715z) {
        C2687o c2687o = (C2687o) interfaceC2715z;
        c2687o.f7344c.m3186c();
        C2676d c2676d = c2687o.f7349h.f7282b;
        if (c2676d == null) {
            throw new C2691b0(c2687o.f7351j, "Illegal attempt to apply \"..\" to node with no parent.");
        }
        c2687o.f7344c.m3185a(c2676d, 1);
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: b */
    public boolean mo3229b() {
        return false;
    }

    public String toString() {
        return "..";
    }
}
