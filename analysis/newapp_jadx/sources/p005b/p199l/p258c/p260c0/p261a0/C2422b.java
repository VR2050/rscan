package p005b.p199l.p258c.p260c0.p261a0;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.util.Collection;
import java.util.Iterator;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p260c0.C2420a;
import p005b.p199l.p258c.p260c0.C2449g;
import p005b.p199l.p258c.p260c0.InterfaceC2462t;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.b */
/* loaded from: classes2.dex */
public final class C2422b implements InterfaceC2415a0 {

    /* renamed from: c */
    public final C2449g f6462c;

    /* renamed from: b.l.c.c0.a0.b$a */
    public static final class a<E> extends AbstractC2496z<Collection<E>> {

        /* renamed from: a */
        public final AbstractC2496z<E> f6463a;

        /* renamed from: b */
        public final InterfaceC2462t<? extends Collection<E>> f6464b;

        public a(C2480j c2480j, Type type, AbstractC2496z<E> abstractC2496z, InterfaceC2462t<? extends Collection<E>> interfaceC2462t) {
            this.f6463a = new C2434n(c2480j, abstractC2496z, type);
            this.f6464b = interfaceC2462t;
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: b */
        public Object mo2766b(C2472a c2472a) {
            if (c2472a.mo2777Z() == EnumC2473b.NULL) {
                c2472a.mo2775V();
                return null;
            }
            Collection<E> mo2810a = this.f6464b.mo2810a();
            c2472a.mo2778b();
            while (c2472a.mo2787t()) {
                mo2810a.add(this.f6463a.mo2766b(c2472a));
            }
            c2472a.mo2785o();
            return mo2810a;
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: c */
        public void mo2767c(C2474c c2474c, Object obj) {
            Collection collection = (Collection) obj;
            if (collection == null) {
                c2474c.mo2800v();
                return;
            }
            c2474c.mo2795d();
            Iterator<E> it = collection.iterator();
            while (it.hasNext()) {
                this.f6463a.mo2767c(c2474c, it.next());
            }
            c2474c.mo2797o();
        }
    }

    public C2422b(C2449g c2449g) {
        this.f6462c = c2449g;
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
        Type type = c2470a.getType();
        Class<? super T> rawType = c2470a.getRawType();
        if (!Collection.class.isAssignableFrom(rawType)) {
            return null;
        }
        Type m2762f = C2420a.m2762f(type, rawType, Collection.class);
        if (m2762f instanceof WildcardType) {
            m2762f = ((WildcardType) m2762f).getUpperBounds()[0];
        }
        Class cls = m2762f instanceof ParameterizedType ? ((ParameterizedType) m2762f).getActualTypeArguments()[0] : Object.class;
        return new a(c2480j, cls, c2480j.m2850d(C2470a.get(cls)), this.f6462c.m2812a(c2470a));
    }
}
