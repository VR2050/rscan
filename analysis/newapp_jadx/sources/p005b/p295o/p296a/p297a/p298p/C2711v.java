package p005b.p295o.p296a.p297a.p298p;

import p005b.p295o.p296a.p297a.AbstractC2678f;
import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2686n;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.v */
/* loaded from: classes2.dex */
public class C2711v extends AbstractC2708s {
    public C2711v(String str) {
        super(str);
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2700k
    /* renamed from: a */
    public void mo3233a(InterfaceC2701l interfaceC2701l) {
        C2687o c2687o = (C2687o) interfaceC2701l;
        Object obj = c2687o.f7347f;
        if (!(obj instanceof C2676d)) {
            throw new C2691b0(c2687o.f7351j, "Cannot test attribute of document");
        }
        for (AbstractC2678f abstractC2678f = ((C2676d) obj).f7275f; abstractC2678f != null; abstractC2678f = abstractC2678f.f7284d) {
            if ((abstractC2678f instanceof C2686n) && !((C2686n) abstractC2678f).m3224f().equals(this.f7380a)) {
                c2687o.f7348g.m3227a(C2687o.f7342a);
                return;
            }
        }
        c2687o.f7348g.m3227a(C2687o.f7343b);
    }

    public String toString() {
        return m3236b("!=");
    }
}
