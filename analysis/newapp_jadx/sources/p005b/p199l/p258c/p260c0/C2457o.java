package p005b.p199l.p258c.p260c0;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.InterfaceC2414a;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.c0.o */
/* loaded from: classes2.dex */
public final class C2457o implements InterfaceC2415a0, Cloneable {

    /* renamed from: c */
    public static final C2457o f6598c = new C2457o();

    /* renamed from: e */
    public List<InterfaceC2414a> f6599e = Collections.emptyList();

    /* renamed from: f */
    public List<InterfaceC2414a> f6600f = Collections.emptyList();

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.l.c.c0.o$a */
    public class a<T> extends AbstractC2496z<T> {

        /* renamed from: a */
        public AbstractC2496z<T> f6601a;

        /* renamed from: b */
        public final /* synthetic */ boolean f6602b;

        /* renamed from: c */
        public final /* synthetic */ boolean f6603c;

        /* renamed from: d */
        public final /* synthetic */ C2480j f6604d;

        /* renamed from: e */
        public final /* synthetic */ C2470a f6605e;

        public a(boolean z, boolean z2, C2480j c2480j, C2470a c2470a) {
            this.f6602b = z;
            this.f6603c = z2;
            this.f6604d = c2480j;
            this.f6605e = c2470a;
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: b */
        public T mo2766b(C2472a c2472a) {
            if (this.f6602b) {
                c2472a.mo2780e0();
                return null;
            }
            AbstractC2496z<T> abstractC2496z = this.f6601a;
            if (abstractC2496z == null) {
                abstractC2496z = this.f6604d.m2851e(C2457o.this, this.f6605e);
                this.f6601a = abstractC2496z;
            }
            return abstractC2496z.mo2766b(c2472a);
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: c */
        public void mo2767c(C2474c c2474c, T t) {
            if (this.f6603c) {
                c2474c.mo2800v();
                return;
            }
            AbstractC2496z<T> abstractC2496z = this.f6601a;
            if (abstractC2496z == null) {
                abstractC2496z = this.f6604d.m2851e(C2457o.this, this.f6605e);
                this.f6601a = abstractC2496z;
            }
            abstractC2496z.mo2767c(c2474c, t);
        }
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
        Class<? super T> rawType = c2470a.getRawType();
        boolean m2814d = m2814d(rawType);
        boolean z = m2814d || m2813c(rawType, true);
        boolean z2 = m2814d || m2813c(rawType, false);
        if (z || z2) {
            return new a(z2, z, c2480j, c2470a);
        }
        return null;
    }

    /* renamed from: c */
    public final boolean m2813c(Class<?> cls, boolean z) {
        Iterator<InterfaceC2414a> it = (z ? this.f6599e : this.f6600f).iterator();
        while (it.hasNext()) {
            if (it.next().m2752b(cls)) {
                return true;
            }
        }
        return false;
    }

    public Object clone() {
        try {
            return (C2457o) super.clone();
        } catch (CloneNotSupportedException e2) {
            throw new AssertionError(e2);
        }
    }

    /* renamed from: d */
    public final boolean m2814d(Class<?> cls) {
        return !Enum.class.isAssignableFrom(cls) && (cls.isAnonymousClass() || cls.isLocalClass());
    }
}
