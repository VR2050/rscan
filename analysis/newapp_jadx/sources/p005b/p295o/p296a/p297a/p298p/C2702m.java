package p005b.p295o.p296a.p297a.p298p;

import java.util.Vector;
import p005b.p295o.p296a.p297a.C2675c;
import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2685m;
import p005b.p295o.p296a.p297a.C2687o;

/* renamed from: b.o.a.a.p.m */
/* loaded from: classes2.dex */
public class C2702m extends AbstractC2703n {

    /* renamed from: a */
    public final String f7365a;

    public C2702m(String str) {
        this.f7365a = C2685m.m3223a(str);
    }

    @Override // p005b.p295o.p296a.p297a.p298p.AbstractC2703n
    /* renamed from: a */
    public void mo3228a(InterfaceC2715z interfaceC2715z) {
        C2676d c2676d;
        C2687o c2687o = (C2687o) interfaceC2715z;
        String str = this.f7365a;
        Vector vector = c2687o.f7345d;
        int size = vector.size();
        c2687o.f7344c.m3186c();
        for (int i2 = 0; i2 < size; i2++) {
            Object elementAt = vector.elementAt(i2);
            if (elementAt instanceof C2676d) {
                c2687o.m3226b((C2676d) elementAt, str);
            } else if ((elementAt instanceof C2675c) && (c2676d = ((C2675c) elementAt).f7272f) != null) {
                if (c2676d.f7279j == str) {
                    c2687o.f7344c.m3185a(c2676d, 1);
                }
                if (c2687o.f7350i) {
                    c2687o.m3226b(c2676d, str);
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
        return this.f7365a;
    }
}
