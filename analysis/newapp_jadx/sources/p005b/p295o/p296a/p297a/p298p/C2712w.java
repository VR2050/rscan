package p005b.p295o.p296a.p297a.p298p;

import java.util.Enumeration;
import java.util.Vector;
import p005b.p295o.p296a.p297a.AbstractC2678f;
import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2679g;
import p005b.p295o.p296a.p297a.C2686n;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.w */
/* loaded from: classes2.dex */
public class C2712w extends AbstractC2703n {

    /* renamed from: a */
    public static final C2712w f7382a = new C2712w();

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
                for (AbstractC2678f abstractC2678f = ((C2676d) nextElement).f7275f; abstractC2678f != null; abstractC2678f = abstractC2678f.f7284d) {
                    if (abstractC2678f instanceof C2686n) {
                        C2679g c2679g = c2687o.f7344c;
                        c2679g.f7296k.addElement(((C2686n) abstractC2678f).m3224f());
                    }
                }
            }
        }
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: b */
    public boolean mo3229b() {
        return true;
    }

    public String toString() {
        return "text()";
    }
}
