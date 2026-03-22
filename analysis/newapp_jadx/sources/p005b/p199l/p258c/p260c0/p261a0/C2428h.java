package p005b.p199l.p258c.p260c0.p261a0;

import java.util.ArrayList;
import java.util.Objects;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p260c0.C2461s;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.c0.a0.h */
/* loaded from: classes2.dex */
public final class C2428h extends AbstractC2496z<Object> {

    /* renamed from: a */
    public static final InterfaceC2415a0 f6484a = new a();

    /* renamed from: b */
    public final C2480j f6485b;

    /* renamed from: b.l.c.c0.a0.h$a */
    public static class a implements InterfaceC2415a0 {
        @Override // p005b.p199l.p258c.InterfaceC2415a0
        /* renamed from: a */
        public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
            if (c2470a.getRawType() == Object.class) {
                return new C2428h(c2480j);
            }
            return null;
        }
    }

    public C2428h(C2480j c2480j) {
        this.f6485b = c2480j;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public Object mo2766b(C2472a c2472a) {
        int ordinal = c2472a.mo2777Z().ordinal();
        if (ordinal == 0) {
            ArrayList arrayList = new ArrayList();
            c2472a.mo2778b();
            while (c2472a.mo2787t()) {
                arrayList.add(mo2766b(c2472a));
            }
            c2472a.mo2785o();
            return arrayList;
        }
        if (ordinal == 2) {
            C2461s c2461s = new C2461s();
            c2472a.mo2779d();
            while (c2472a.mo2787t()) {
                c2461s.put(c2472a.mo2774S(), mo2766b(c2472a));
            }
            c2472a.mo2786q();
            return c2461s;
        }
        if (ordinal == 5) {
            return c2472a.mo2776X();
        }
        if (ordinal == 6) {
            return Double.valueOf(c2472a.mo2771E());
        }
        if (ordinal == 7) {
            return Boolean.valueOf(c2472a.mo2770D());
        }
        if (ordinal != 8) {
            throw new IllegalStateException();
        }
        c2472a.mo2775V();
        return null;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, Object obj) {
        if (obj == null) {
            c2474c.mo2800v();
            return;
        }
        C2480j c2480j = this.f6485b;
        Class<?> cls = obj.getClass();
        Objects.requireNonNull(c2480j);
        AbstractC2496z m2850d = c2480j.m2850d(C2470a.get((Class) cls));
        if (!(m2850d instanceof C2428h)) {
            m2850d.mo2767c(c2474c, obj);
        } else {
            c2474c.mo2796e();
            c2474c.mo2798q();
        }
    }
}
