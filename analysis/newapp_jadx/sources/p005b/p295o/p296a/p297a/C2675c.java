package p005b.p295o.p296a.p297a;

import java.io.Writer;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Vector;
import p005b.p295o.p296a.p297a.C2685m;
import p005b.p295o.p296a.p297a.p298p.C2689a0;
import p005b.p295o.p296a.p297a.p298p.C2691b0;
import p005b.p295o.p296a.p297a.p298p.C2707r;

/* renamed from: b.o.a.a.c */
/* loaded from: classes2.dex */
public class C2675c extends AbstractC2678f {

    /* renamed from: f */
    public C2676d f7272f = null;

    /* renamed from: g */
    public String f7273g;

    /* renamed from: h */
    public Vector f7274h;

    /* renamed from: b.o.a.a.c$a */
    public interface a {
        /* renamed from: a */
        void m3175a(C2675c c2675c);
    }

    static {
        new Integer(1);
    }

    public C2675c(String str) {
        Objects.requireNonNull((C2685m.b) C2685m.f7339b);
        new C2685m.d(null);
        this.f7274h = new Vector();
        this.f7273g = str;
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: a */
    public int mo3169a() {
        return this.f7272f.hashCode();
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: c */
    public void mo3170c() {
        Enumeration elements = this.f7274h.elements();
        while (elements.hasMoreElements()) {
            ((a) elements.nextElement()).m3175a(this);
        }
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    public Object clone() {
        C2675c c2675c = new C2675c(this.f7273g);
        c2675c.f7272f = (C2676d) this.f7272f.clone();
        return c2675c;
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: d */
    public void mo3171d(Writer writer) {
        for (AbstractC2678f abstractC2678f = this.f7272f.f7275f; abstractC2678f != null; abstractC2678f = abstractC2678f.f7284d) {
            abstractC2678f.mo3171d(writer);
        }
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: e */
    public void mo3172e(Writer writer) {
        writer.write("<?xml version=\"1.0\" ?>\n");
        this.f7272f.mo3172e(writer);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C2675c) {
            return this.f7272f.equals(((C2675c) obj).f7272f);
        }
        return false;
    }

    /* renamed from: f */
    public C2687o m3173f(C2689a0 c2689a0, boolean z) {
        if (((C2707r) c2689a0.f7357b.peek()).f7377a.mo3229b() == z) {
            return new C2687o(c2689a0, this);
        }
        throw new C2691b0(c2689a0, "\"" + c2689a0 + "\" evaluates to " + (z ? "evaluates to element not string" : "evaluates to string not element"));
    }

    /* renamed from: g */
    public C2676d m3174g(String str) {
        try {
            if (str.charAt(0) != '/') {
                str = "/" + str;
            }
            C2687o m3173f = m3173f(C2689a0.m3230a(str), false);
            if (m3173f.f7345d.size() == 0) {
                return null;
            }
            return (C2676d) m3173f.f7345d.elementAt(0);
        } catch (C2691b0 e2) {
            throw new C2682j("XPath problem", e2);
        }
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    public String toString() {
        return this.f7273g;
    }

    public C2675c() {
        Objects.requireNonNull((C2685m.b) C2685m.f7339b);
        new C2685m.d(null);
        this.f7274h = new Vector();
        this.f7273g = "MEMORY";
    }
}
