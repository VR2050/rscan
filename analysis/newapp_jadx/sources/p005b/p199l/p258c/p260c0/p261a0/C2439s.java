package p005b.p199l.p258c.p260c0.p261a0;

import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.C2493w;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.c0.a0.s */
/* loaded from: classes2.dex */
public final class C2439s implements InterfaceC2415a0 {

    /* renamed from: c */
    public final /* synthetic */ Class f6578c;

    /* renamed from: e */
    public final /* synthetic */ AbstractC2496z f6579e;

    /* JADX INFO: Add missing generic type declarations: [T1] */
    /* renamed from: b.l.c.c0.a0.s$a */
    public class a<T1> extends AbstractC2496z<T1> {

        /* renamed from: a */
        public final /* synthetic */ Class f6580a;

        public a(Class cls) {
            this.f6580a = cls;
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: b */
        public T1 mo2766b(C2472a c2472a) {
            T1 t1 = (T1) C2439s.this.f6579e.mo2766b(c2472a);
            if (t1 == null || this.f6580a.isInstance(t1)) {
                return t1;
            }
            StringBuilder m586H = C1499a.m586H("Expected a ");
            m586H.append(this.f6580a.getName());
            m586H.append(" but was ");
            m586H.append(t1.getClass().getName());
            throw new C2493w(m586H.toString());
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: c */
        public void mo2767c(C2474c c2474c, T1 t1) {
            C2439s.this.f6579e.mo2767c(c2474c, t1);
        }
    }

    public C2439s(Class cls, AbstractC2496z abstractC2496z) {
        this.f6578c = cls;
        this.f6579e = abstractC2496z;
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T2> AbstractC2496z<T2> mo2753a(C2480j c2480j, C2470a<T2> c2470a) {
        Class<? super T2> rawType = c2470a.getRawType();
        if (this.f6578c.isAssignableFrom(rawType)) {
            return new a(rawType);
        }
        return null;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Factory[typeHierarchy=");
        m586H.append(this.f6578c.getName());
        m586H.append(",adapter=");
        m586H.append(this.f6579e);
        m586H.append("]");
        return m586H.toString();
    }
}
