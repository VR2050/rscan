package p005b.p295o.p296a.p297a.p298p;

import java.util.Enumeration;
import java.util.Vector;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p295o.p296a.p297a.AbstractC2678f;
import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.j */
/* loaded from: classes2.dex */
public class C2699j extends AbstractC2703n {

    /* renamed from: a */
    public final String f7364a;

    public C2699j(String str) {
        this.f7364a = str;
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: a */
    public void mo3228a(InterfaceC2715z interfaceC2715z) {
        String m3179i;
        C2687o c2687o = (C2687o) interfaceC2715z;
        Vector vector = c2687o.f7345d;
        c2687o.f7344c.m3186c();
        Enumeration elements = vector.elements();
        while (elements.hasMoreElements()) {
            AbstractC2678f abstractC2678f = (AbstractC2678f) elements.nextElement();
            if ((abstractC2678f instanceof C2676d) && (m3179i = ((C2676d) abstractC2678f).m3179i(this.f7364a)) != null) {
                c2687o.f7344c.f7296k.addElement(m3179i);
            }
        }
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: b */
    public boolean mo3229b() {
        return true;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("@");
        m586H.append(this.f7364a);
        return m586H.toString();
    }
}
