package p005b.p295o.p296a.p297a;

import java.io.Writer;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p295o.p296a.p297a.p298p.C2689a0;
import p005b.p295o.p296a.p297a.p298p.C2691b0;
import p005b.p295o.p296a.p297a.p298p.C2707r;

/* renamed from: b.o.a.a.d */
/* loaded from: classes2.dex */
public class C2676d extends AbstractC2678f {

    /* renamed from: f */
    public AbstractC2678f f7275f;

    /* renamed from: g */
    public AbstractC2678f f7276g;

    /* renamed from: h */
    public Hashtable f7277h;

    /* renamed from: i */
    public Vector f7278i;

    /* renamed from: j */
    public String f7279j;

    public C2676d(String str) {
        this.f7275f = null;
        this.f7276g = null;
        this.f7277h = null;
        this.f7278i = null;
        this.f7279j = null;
        this.f7279j = C2685m.m3223a(str);
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: a */
    public int mo3169a() {
        int hashCode = this.f7279j.hashCode();
        Hashtable hashtable = this.f7277h;
        if (hashtable != null) {
            Enumeration keys = hashtable.keys();
            while (keys.hasMoreElements()) {
                String str = (String) keys.nextElement();
                int hashCode2 = str.hashCode() + (hashCode * 31);
                hashCode = ((String) this.f7277h.get(str)).hashCode() + (hashCode2 * 31);
            }
        }
        for (AbstractC2678f abstractC2678f = this.f7275f; abstractC2678f != null; abstractC2678f = abstractC2678f.f7284d) {
            hashCode = (hashCode * 31) + abstractC2678f.hashCode();
        }
        return hashCode;
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    public Object clone() {
        C2676d c2676d = new C2676d(this.f7279j);
        Vector vector = this.f7278i;
        if (vector != null) {
            Enumeration elements = vector.elements();
            while (elements.hasMoreElements()) {
                String str = (String) elements.nextElement();
                c2676d.m3180j(str, (String) this.f7277h.get(str));
            }
        }
        for (AbstractC2678f abstractC2678f = this.f7275f; abstractC2678f != null; abstractC2678f = abstractC2678f.f7284d) {
            c2676d.m3176f((AbstractC2678f) abstractC2678f.clone());
        }
        return c2676d;
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: d */
    public void mo3171d(Writer writer) {
        for (AbstractC2678f abstractC2678f = this.f7275f; abstractC2678f != null; abstractC2678f = abstractC2678f.f7284d) {
            abstractC2678f.mo3171d(writer);
        }
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: e */
    public void mo3172e(Writer writer) {
        StringBuilder m586H = C1499a.m586H("<");
        m586H.append(this.f7279j);
        writer.write(m586H.toString());
        Vector vector = this.f7278i;
        if (vector != null) {
            Enumeration elements = vector.elements();
            while (elements.hasMoreElements()) {
                String str = (String) elements.nextElement();
                String str2 = (String) this.f7277h.get(str);
                writer.write(" " + str + "=\"");
                AbstractC2678f.m3183b(writer, str2);
                writer.write("\"");
            }
        }
        if (this.f7275f == null) {
            writer.write("/>");
            return;
        }
        writer.write(">");
        for (AbstractC2678f abstractC2678f = this.f7275f; abstractC2678f != null; abstractC2678f = abstractC2678f.f7284d) {
            abstractC2678f.mo3172e(writer);
        }
        StringBuilder m586H2 = C1499a.m586H("</");
        m586H2.append(this.f7279j);
        m586H2.append(">");
        writer.write(m586H2.toString());
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2676d)) {
            return false;
        }
        C2676d c2676d = (C2676d) obj;
        if (!this.f7279j.equals(c2676d.f7279j)) {
            return false;
        }
        Hashtable hashtable = this.f7277h;
        int size = hashtable == null ? 0 : hashtable.size();
        Hashtable hashtable2 = c2676d.f7277h;
        if (size != (hashtable2 == null ? 0 : hashtable2.size())) {
            return false;
        }
        Hashtable hashtable3 = this.f7277h;
        if (hashtable3 != null) {
            Enumeration keys = hashtable3.keys();
            while (keys.hasMoreElements()) {
                String str = (String) keys.nextElement();
                if (!((String) this.f7277h.get(str)).equals((String) c2676d.f7277h.get(str))) {
                    return false;
                }
            }
        }
        AbstractC2678f abstractC2678f = this.f7275f;
        AbstractC2678f abstractC2678f2 = c2676d.f7275f;
        while (abstractC2678f != null) {
            if (!abstractC2678f.equals(abstractC2678f2)) {
                return false;
            }
            abstractC2678f = abstractC2678f.f7284d;
            abstractC2678f2 = abstractC2678f2.f7284d;
        }
        return true;
    }

    /* renamed from: f */
    public void m3176f(AbstractC2678f abstractC2678f) {
        boolean m3178h;
        if (abstractC2678f == this) {
            m3178h = false;
        } else {
            C2676d c2676d = this.f7282b;
            m3178h = c2676d == null ? true : c2676d.m3178h(abstractC2678f);
        }
        if (!m3178h) {
            abstractC2678f = (C2676d) abstractC2678f.clone();
        }
        m3177g(abstractC2678f);
        mo3170c();
    }

    /* renamed from: g */
    public void m3177g(AbstractC2678f abstractC2678f) {
        C2676d c2676d = abstractC2678f.f7282b;
        if (c2676d != null) {
            AbstractC2678f abstractC2678f2 = c2676d.f7275f;
            while (true) {
                if (abstractC2678f2 == null) {
                    break;
                }
                if (abstractC2678f2.equals(abstractC2678f)) {
                    if (c2676d.f7275f == abstractC2678f2) {
                        c2676d.f7275f = abstractC2678f2.f7284d;
                    }
                    if (c2676d.f7276g == abstractC2678f2) {
                        c2676d.f7276g = abstractC2678f2.f7283c;
                    }
                    AbstractC2678f abstractC2678f3 = abstractC2678f2.f7283c;
                    if (abstractC2678f3 != null) {
                        abstractC2678f3.f7284d = abstractC2678f2.f7284d;
                    }
                    AbstractC2678f abstractC2678f4 = abstractC2678f2.f7284d;
                    if (abstractC2678f4 != null) {
                        abstractC2678f4.f7283c = abstractC2678f3;
                    }
                    abstractC2678f2.f7284d = null;
                    abstractC2678f2.f7283c = null;
                    abstractC2678f2.f7282b = null;
                    abstractC2678f2.f7281a = null;
                } else {
                    abstractC2678f2 = abstractC2678f2.f7284d;
                }
            }
        }
        AbstractC2678f abstractC2678f5 = this.f7276g;
        abstractC2678f.f7283c = abstractC2678f5;
        if (abstractC2678f5 != null) {
            abstractC2678f5.f7284d = abstractC2678f;
        }
        if (this.f7275f == null) {
            this.f7275f = abstractC2678f;
        }
        abstractC2678f.f7282b = this;
        this.f7276g = abstractC2678f;
        abstractC2678f.f7281a = this.f7281a;
    }

    /* renamed from: h */
    public boolean m3178h(AbstractC2678f abstractC2678f) {
        if (abstractC2678f == this) {
            return false;
        }
        C2676d c2676d = this.f7282b;
        if (c2676d == null) {
            return true;
        }
        return c2676d.m3178h(abstractC2678f);
    }

    /* renamed from: i */
    public String m3179i(String str) {
        Hashtable hashtable = this.f7277h;
        if (hashtable == null) {
            return null;
        }
        return (String) hashtable.get(str);
    }

    /* renamed from: j */
    public void m3180j(String str, String str2) {
        if (this.f7277h == null) {
            this.f7277h = new Hashtable();
            this.f7278i = new Vector();
        }
        if (this.f7277h.get(str) == null) {
            this.f7278i.addElement(str);
        }
        this.f7277h.put(str, str2);
        mo3170c();
    }

    /* renamed from: k */
    public final C2687o m3181k(String str, boolean z) {
        C2689a0 m3230a = C2689a0.m3230a(str);
        if (((C2707r) m3230a.f7357b.peek()).f7377a.mo3229b() == z) {
            C2687o c2687o = new C2687o(m3230a, this);
            if (m3230a.f7358c) {
                throw new C2691b0(m3230a, "Cannot use element as context node for absolute xpath");
            }
            return c2687o;
        }
        throw new C2691b0(m3230a, "\"" + m3230a + "\" evaluates to " + (z ? "evaluates to element not string" : "evaluates to string not element"));
    }

    /* renamed from: l */
    public String m3182l(String str) {
        try {
            C2687o m3181k = m3181k(str, true);
            if (m3181k.f7345d.size() == 0) {
                return null;
            }
            return m3181k.f7345d.elementAt(0).toString();
        } catch (C2691b0 e2) {
            throw new C2682j("XPath problem", e2);
        }
    }

    public C2676d() {
        this.f7275f = null;
        this.f7276g = null;
        this.f7277h = null;
        this.f7278i = null;
        this.f7279j = null;
    }
}
