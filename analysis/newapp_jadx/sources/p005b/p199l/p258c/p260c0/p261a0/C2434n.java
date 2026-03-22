package p005b.p199l.p258c.p260c0.p261a0;

import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.p260c0.p261a0.C2430j;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.c0.a0.n */
/* loaded from: classes2.dex */
public final class C2434n<T> extends AbstractC2496z<T> {

    /* renamed from: a */
    public final C2480j f6512a;

    /* renamed from: b */
    public final AbstractC2496z<T> f6513b;

    /* renamed from: c */
    public final Type f6514c;

    public C2434n(C2480j c2480j, AbstractC2496z<T> abstractC2496z, Type type) {
        this.f6512a = c2480j;
        this.f6513b = abstractC2496z;
        this.f6514c = type;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public T mo2766b(C2472a c2472a) {
        return this.f6513b.mo2766b(c2472a);
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, T t) {
        AbstractC2496z<T> abstractC2496z = this.f6513b;
        Type type = this.f6514c;
        if (t != null && (type == Object.class || (type instanceof TypeVariable) || (type instanceof Class))) {
            type = t.getClass();
        }
        if (type != this.f6514c) {
            abstractC2496z = this.f6512a.m2850d(C2470a.get(type));
            if (abstractC2496z instanceof C2430j.a) {
                AbstractC2496z<T> abstractC2496z2 = this.f6513b;
                if (!(abstractC2496z2 instanceof C2430j.a)) {
                    abstractC2496z = abstractC2496z2;
                }
            }
        }
        abstractC2496z.mo2767c(c2474c, t);
    }
}
