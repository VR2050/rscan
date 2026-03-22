package p005b.p295o.p296a.p297a.p298p;

import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.h */
/* loaded from: classes2.dex */
public class C2697h extends AbstractC2690b {
    public C2697h(String str, String str2) {
        super(str, str2);
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2700k
    /* renamed from: a */
    public void mo3233a(InterfaceC2701l interfaceC2701l) {
        C2687o c2687o = (C2687o) interfaceC2701l;
        Object obj = c2687o.f7347f;
        if (!(obj instanceof C2676d)) {
            throw new C2691b0(c2687o.f7351j, "Cannot test attribute of document");
        }
        c2687o.f7348g.m3227a(this.f7360b.equals(((C2676d) obj).m3179i(this.f7362a)) ^ true ? C2687o.f7342a : C2687o.f7343b);
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2694e
    public String toString() {
        return m3231b("!=");
    }
}
