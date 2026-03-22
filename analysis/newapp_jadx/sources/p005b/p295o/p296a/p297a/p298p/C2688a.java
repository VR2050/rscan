package p005b.p295o.p296a.p297a.p298p;

import java.util.Enumeration;
import java.util.Vector;
import p005b.p295o.p296a.p297a.C2675c;
import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.a */
/* loaded from: classes2.dex */
public class C2688a extends AbstractC2703n {

    /* renamed from: a */
    public static final C2688a f7355a = new C2688a();

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: a */
    public void mo3228a(InterfaceC2715z interfaceC2715z) {
        C2687o c2687o = (C2687o) interfaceC2715z;
        Vector vector = c2687o.f7345d;
        c2687o.f7344c.m3186c();
        Enumeration elements = vector.elements();
        while (elements.hasMoreElements()) {
            Object nextElement = elements.nextElement();
            if (nextElement instanceof C2676d) {
                c2687o.m3225a((C2676d) nextElement);
            } else if (nextElement instanceof C2675c) {
                C2676d c2676d = ((C2675c) nextElement).f7272f;
                c2687o.f7344c.m3185a(c2676d, 1);
                if (c2687o.f7350i) {
                    c2687o.m3225a(c2676d);
                }
            }
        }
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: b */
    public boolean mo3229b() {
        return false;
    }

    public String toString() {
        return "*";
    }
}
