package p005b.p295o.p296a.p297a.p298p;

import p005b.p131d.p132a.p133a.C1499a;
import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2679g;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.p */
/* loaded from: classes2.dex */
public class C2705p extends AbstractC2700k {

    /* renamed from: a */
    public final int f7367a;

    public C2705p(int i2) {
        this.f7367a = i2;
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2700k
    /* renamed from: a */
    public void mo3233a(InterfaceC2701l interfaceC2701l) {
        C2687o c2687o = (C2687o) interfaceC2701l;
        Object obj = c2687o.f7347f;
        if (!(obj instanceof C2676d)) {
            throw new C2691b0(c2687o.f7351j, "Cannot test position of document");
        }
        c2687o.f7348g.m3227a(((Integer) c2687o.f7344c.f7297l.get(C2679g.m3184b((C2676d) obj))).intValue() == this.f7367a ? C2687o.f7342a : C2687o.f7343b);
    }

    public String toString() {
        return C1499a.m580B(C1499a.m586H("["), this.f7367a, "]");
    }
}
