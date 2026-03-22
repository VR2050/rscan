package p005b.p295o.p296a.p297a.p298p;

import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.g */
/* loaded from: classes2.dex */
public class C2696g extends AbstractC2698i {
    public C2696g(String str, int i2) {
        super(str, i2);
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2700k
    /* renamed from: a */
    public void mo3233a(InterfaceC2701l interfaceC2701l) {
        C2687o c2687o = (C2687o) interfaceC2701l;
        Object obj = c2687o.f7347f;
        if (!(obj instanceof C2676d)) {
            throw new C2691b0(c2687o.f7351j, "Cannot test attribute of document");
        }
        c2687o.f7348g.m3227a((((double) Long.parseLong(((C2676d) obj).m3179i(this.f7362a))) > ((double) this.f7363b) ? 1 : (((double) Long.parseLong(((C2676d) obj).m3179i(this.f7362a))) == ((double) this.f7363b) ? 0 : -1)) < 0 ? C2687o.f7342a : C2687o.f7343b);
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2694e
    public String toString() {
        return m3234b("<");
    }
}
