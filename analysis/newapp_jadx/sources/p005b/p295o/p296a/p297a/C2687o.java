package p005b.p295o.p296a.p297a;

import java.util.Enumeration;
import java.util.Vector;
import p005b.p295o.p296a.p297a.p298p.AbstractC2700k;
import p005b.p295o.p296a.p297a.p298p.C2689a0;
import p005b.p295o.p296a.p297a.p298p.C2707r;
import p005b.p295o.p296a.p297a.p298p.InterfaceC2715z;

/* renamed from: b.o.a.a.o */
/* loaded from: classes2.dex */
public class C2687o implements InterfaceC2715z {

    /* renamed from: a */
    public static final Boolean f7342a = new Boolean(true);

    /* renamed from: b */
    public static final Boolean f7343b = new Boolean(false);

    /* renamed from: d */
    public Vector f7345d;

    /* renamed from: e */
    public Enumeration f7346e;

    /* renamed from: f */
    public Object f7347f;

    /* renamed from: h */
    public AbstractC2678f f7349h;

    /* renamed from: i */
    public boolean f7350i;

    /* renamed from: j */
    public C2689a0 f7351j;

    /* renamed from: c */
    public final C2679g f7344c = new C2679g();

    /* renamed from: g */
    public final b f7348g = new b(null);

    /* renamed from: b.o.a.a.o$b */
    public static class b {

        /* renamed from: a */
        public a f7352a = null;

        /* renamed from: b.o.a.a.o$b$a */
        public static class a {

            /* renamed from: a */
            public final Boolean f7353a;

            /* renamed from: b */
            public final a f7354b;

            public a(Boolean bool, a aVar) {
                this.f7353a = bool;
                this.f7354b = aVar;
            }
        }

        public b(a aVar) {
        }

        /* renamed from: a */
        public void m3227a(Boolean bool) {
            this.f7352a = new a(bool, this.f7352a);
        }
    }

    public C2687o(C2689a0 c2689a0, AbstractC2678f abstractC2678f) {
        this.f7345d = new Vector();
        this.f7346e = null;
        this.f7347f = null;
        this.f7351j = c2689a0;
        this.f7349h = abstractC2678f;
        Vector vector = new Vector(1);
        this.f7345d = vector;
        vector.addElement(this.f7349h);
        Enumeration elements = c2689a0.f7357b.elements();
        while (elements.hasMoreElements()) {
            C2707r c2707r = (C2707r) elements.nextElement();
            this.f7350i = c2707r.f7379c;
            this.f7346e = null;
            c2707r.f7377a.mo3228a(this);
            this.f7346e = this.f7344c.f7296k.elements();
            this.f7345d.removeAllElements();
            AbstractC2700k abstractC2700k = c2707r.f7378b;
            while (this.f7346e.hasMoreElements()) {
                this.f7347f = this.f7346e.nextElement();
                abstractC2700k.mo3233a(this);
                b bVar = this.f7348g;
                b.a aVar = bVar.f7352a;
                Boolean bool = aVar.f7353a;
                bVar.f7352a = aVar.f7354b;
                if (bool.booleanValue()) {
                    this.f7345d.addElement(this.f7347f);
                }
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v1, types: [b.o.a.a.f] */
    /* JADX WARN: Type inference failed for: r3v3, types: [b.o.a.a.f] */
    /* renamed from: a */
    public final void m3225a(C2676d c2676d) {
        int i2 = 0;
        for (C2676d c2676d2 = c2676d.f7275f; c2676d2 != null; c2676d2 = c2676d2.f7284d) {
            if (c2676d2 instanceof C2676d) {
                i2++;
                this.f7344c.m3185a(c2676d2, i2);
                if (this.f7350i) {
                    m3225a(c2676d2);
                }
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v1, types: [b.o.a.a.f] */
    /* JADX WARN: Type inference failed for: r4v3, types: [b.o.a.a.f] */
    /* renamed from: b */
    public final void m3226b(C2676d c2676d, String str) {
        int i2 = 0;
        for (C2676d c2676d2 = c2676d.f7275f; c2676d2 != null; c2676d2 = c2676d2.f7284d) {
            if (c2676d2 instanceof C2676d) {
                C2676d c2676d3 = c2676d2;
                if (c2676d3.f7279j == str) {
                    i2++;
                    this.f7344c.m3185a(c2676d3, i2);
                }
                if (this.f7350i) {
                    m3226b(c2676d3, str);
                }
            }
        }
    }
}
